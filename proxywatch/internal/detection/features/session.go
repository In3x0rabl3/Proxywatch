package features

import (
	"strings"
	"time"

	"proxywatch/internal/detection/model"
	"proxywatch/internal/shared"
)

// extractSession computes session-role features (indices 24-47).
func extractSession(c *shared.Candidate, behavior *shared.ProcessBehavior, profile *model.ProcessProfile, fv *FeatureVector) {
	// (N) FSessionControlDurationSec — control channel hold time.
	fv.Values[FSessionControlDurationSec] = float64(c.ControlDurationSeconds)

	// (N) FSessionConnLifetimeMaxSec — longest single connection.
	lifetimes := connectionLifetimes(c)
	if len(lifetimes) > 0 {
		maxL := lifetimes[0]
		for _, v := range lifetimes[1:] {
			if v > maxL {
				maxL = v
			}
		}
		fv.Values[FSessionConnLifetimeMaxSec] = maxL
	}

	// (N) FSessionDistinctTargets — unique targets.
	fv.Values[FSessionDistinctTargets] = float64(countDistinctTargets(c.Conns))

	// (N) FSessionExternalConnCount — external connections.
	fv.Values[FSessionExternalConnCount] = float64(c.OutExternal)

	// (N) FSessionConnChurnRate — connections per minute.
	total := c.OutTotal + c.InboundTotal
	if c.SeenSeconds > 0 && total > 0 {
		fv.Values[FSessionConnChurnRate] = float64(total) / (float64(c.SeenSeconds) / 60.0)
	}

	// (N) FSessionIOWriteRatio — write/(read+write).
	if c.Proc != nil {
		totalIO := float64(c.Proc.IOReadBytes + c.Proc.IOWriteBytes)
		fv.Values[FSessionIOWriteRatio] = safeDiv(float64(c.Proc.IOWriteBytes), totalIO)
	}

	// (N) FSessionASNMismatch — vendor/ASN alignment flag.
	for _, sig := range c.Signals {
		if sig == "asn-org-mismatch" {
			fv.Values[FSessionASNMismatch] = 1
			break
		}
	}

	// (N) FSessionPreExisting — had connections on first observation.
	fv.Values[FSessionPreExisting] = boolFloat(c.SeenSeconds > 0 && c.OutTotal > 0 && c.ControlChannel != nil)

	// (N) FSessionControlChannelAgeSec — oldest ESTABLISHED age.
	if c.ControlChannel != nil && c.Proc != nil {
		key := makeConnKey(c, *c.ControlChannel)
		if first, ok := shared.ConnFirstSeen[key]; ok {
			fv.Values[FSessionControlChannelAgeSec] = time.Since(first).Seconds()
		}
	}

	// (N) FSessionInternalConnCount — internal connections.
	fv.Values[FSessionInternalConnCount] = float64(c.OutInternal)

	// (N) FSessionIOCurrentRate — instantaneous IO rate.
	if c.Proc != nil {
		fv.Values[FSessionIOCurrentRate] = float64(c.Proc.IOReadBps + c.Proc.IOWriteBps)
	}

	// (H) FSessionIORWBalance — read/write ratio.
	if c.Proc != nil {
		totalIO := float64(c.Proc.IOReadBytes + c.Proc.IOWriteBytes)
		fv.Values[FSessionIORWBalance] = safeDiv(float64(c.Proc.IOReadBytes), totalIO)
	}

	// (H) FSessionIOBurstiness — stddev of IO rate / mean.
	if c.Proc != nil {
		if tracker := shared.IOBurstHistory[c.Proc.Pid]; tracker != nil && len(tracker.Samples) >= 2 {
			mean, stddev := sampleMeanStddev(tracker.Samples)
			fv.Values[FSessionIOBurstiness] = safeDiv(stddev, mean)
		}
	}

	// (H) FSessionIntegrityLevel — 0=low, 1=med, 2=high, 3=system.
	if c.Proc != nil {
		fv.Values[FSessionIntegrityLevel] = integrityToFloat(c.Proc.Integrity)
	}

	// (H) FSessionCmdLength — command line length.
	if c.Proc != nil {
		fv.Values[FSessionCmdLength] = float64(len(c.Proc.CmdLine))
	}

	// (H) FSessionCmdHasEncoded — encoded content flag.
	if c.Proc != nil {
		cmd := strings.ToLower(c.Proc.CmdLine)
		fv.Values[FSessionCmdHasEncoded] = boolFloat(
			strings.Contains(cmd, "-encodedcommand") || strings.Contains(cmd, "-enc ") ||
				strings.Contains(cmd, "base64"))
	}

	// (H) FSessionChildProcessCount — children spawned.
	if c.Proc != nil {
		fv.Values[FSessionChildProcessCount] = float64(c.Proc.ChildCount)
	}

	// (H) FSessionChildIsLOLBin — children are system binaries.
	if c.Proc != nil {
		fv.Values[FSessionChildIsLOLBin] = boolFloat(shared.IsLOLBinProcess(c.Proc))
	}

	// (H) FSessionDelegatedEgressStrong — delegated egress flag.
	fv.Values[FSessionDelegatedEgressStrong] = boolFloat(c.DelegatedStrong)

	// (H) FSessionParentScore — parent detection score.
	if c.Proc != nil {
		if parentHist := shared.ProcHistoryByPID[c.Proc.ParentPid]; parentHist != nil {
			fv.Values[FSessionParentScore] = float64(parentHist.StickyScore)
		}
	}

	// (H) FSessionRareParent — rare parent-child combo flag.
	if c.Proc != nil {
		fv.Values[FSessionRareParent] = boolFloat(shared.ParentChildFreq[strings.ToLower(c.Proc.Name)] <= 1)
	}

	// (H) FSessionCPUToIORatio — CPU per MB IO.
	if c.Proc != nil {
		totalIO := float64(c.Proc.IOReadBytes + c.Proc.IOWriteBytes)
		if totalIO > 0 {
			fv.Values[FSessionCPUToIORatio] = c.Proc.CpuTime.Seconds() / (totalIO / 1e6)
		}
	}

	// (H) FSessionIOOtherRatio — IOOther/(total IO).
	if c.Proc != nil {
		totalAll := float64(c.Proc.IOReadBytes + c.Proc.IOWriteBytes + c.Proc.IOOtherBytes)
		fv.Values[FSessionIOOtherRatio] = safeDiv(float64(c.Proc.IOOtherBytes), totalAll)
	}

	// (H) FSessionIdleActiveRatio — idle vs active cycles.
	if behavior != nil && behavior.Observations > 0 {
		active := float64(behavior.SuspiciousObservations + behavior.StrongObservations + behavior.ActiveObservations)
		fv.Values[FSessionIdleActiveRatio] = safeDiv(float64(behavior.Observations)-active, active)
	}

	// (H) FSessionIOActiveRatio — fraction of observation time with active IO.
	// Sessions have continuous interactive IO; beacons have IO only during brief callbacks.
	if behavior != nil && behavior.Observations > 0 {
		fv.Values[FSessionIOActiveRatio] = safeDiv(float64(behavior.ActiveObservations), float64(behavior.Observations))
	}
}
