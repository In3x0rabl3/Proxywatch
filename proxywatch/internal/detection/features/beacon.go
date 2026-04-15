package features

import (
	"strings"
	"time"

	"proxywatch/internal/detection/model"
	"proxywatch/internal/shared"
)

// extractBeacon computes beacon-role features (indices 0-23).
func extractBeacon(c *shared.Candidate, behavior *shared.ProcessBehavior, profile *model.ProcessProfile, fv *FeatureVector) {
	// (N) FBeaconIntervalMsConfirmed — confirmed beacon interval in ms.
	fv.Values[FBeaconIntervalMsConfirmed] = float64(c.BeaconIntervalMs)

	// (N) FBeaconJitterCoV — jitter coefficient of variation.
	fv.Values[FBeaconJitterCoV] = c.BeaconJitter

	// (N) FBeaconSynCycleCount — SYN cycling events.
	if c.Proc != nil {
		if synHist := shared.SYNCycleByPID[c.Proc.Pid]; synHist != nil {
			fv.Values[FBeaconSynCycleCount] = float64(synHist.Cycles)
		}
	}

	// (N) FBeaconCallbackSuccessRate — ESTABLISHED / SYN attempts.
	if c.Proc != nil {
		if synHist := shared.SYNCycleByPID[c.Proc.Pid]; synHist != nil && synHist.Cycles > 0 {
			est := 0
			for _, cn := range c.Conns {
				if cn.State == "ESTABLISHED" && cn.RemoteAddress != "" {
					est++
				}
			}
			fv.Values[FBeaconCallbackSuccessRate] = safeDiv(float64(est), float64(synHist.Cycles))
		}
	}

	// (N) FBeaconTargetStability — target IP consistency.
	if c.ControlChannel != nil && c.OutTotal <= 2 {
		fv.Values[FBeaconTargetStability] = 1
	}

	// (N) FBeaconPortConsistency — always same dest port.
	if c.ControlChannel != nil && c.OutTotal <= 2 {
		fv.Values[FBeaconPortConsistency] = 1
	} else if c.OutTotal > 0 {
		ports := make(map[int]struct{})
		for _, cn := range c.Conns {
			if cn.RemotePort > 0 && cn.RemoteAddress != "" && !shared.IsLoopbackIP(cn.RemoteAddress) {
				ports[cn.RemotePort] = struct{}{}
			}
		}
		if len(ports) == 1 {
			fv.Values[FBeaconPortConsistency] = 1
		}
	}

	// (N) FBeaconSSLLikely — uses 443/8443.
	if c.BeaconIntervalMs > 0 {
		fv.Values[FBeaconSSLLikely] = boolFloat(hasPortInConns(c.Conns, 443) || hasPortInConns(c.Conns, 8443))
	}

	// (N) FBeaconMultiTarget — failover across IPs.
	if c.BeaconIntervalMs > 0 && countDistinctTargets(c.Conns) > 1 {
		fv.Values[FBeaconMultiTarget] = 1
	}

	// (N) FBeaconConnPerBurst — connections per cycle.
	if c.Proc != nil {
		burstCount := shared.ShortLivedBurstCount[c.Proc.Pid]
		burstHits := shared.ShortLivedBurstHits[c.Proc.Pid]
		if burstHits > 0 {
			fv.Values[FBeaconConnPerBurst] = safeDiv(float64(burstCount), float64(burstHits))
		}
		// (N) FBeaconHitsCount — total confirmed beacon bursts.
		fv.Values[FBeaconHitsCount] = float64(burstHits)
	}

	// (N) FBeaconDriftRate — interval trend over time.
	if profile != nil && profile.BeaconIntervalMs > 0 && c.BeaconIntervalMs > 0 {
		diff := float64(c.BeaconIntervalMs) - float64(profile.BeaconIntervalMs)
		if diff < 0 {
			diff = -diff
		}
		fv.Values[FBeaconDriftRate] = diff / float64(profile.BeaconIntervalMs)
	}

	// (N) FBeaconIntervalAutocorr — periodicity strength.
	if c.Proc != nil {
		if synHist := shared.SYNCycleByPID[c.Proc.Pid]; synHist != nil && len(synHist.Intervals) >= 2 {
			fv.Values[FBeaconIntervalAutocorr] = intervalAutocorrelation(synHist.Intervals)
		}
	}

	// (H) FBeaconIOPerSecondAvg — total IO / process age.
	if c.Proc != nil && !c.Proc.StartTime.IsZero() {
		age := time.Since(c.Proc.StartTime).Seconds()
		if age > 0 {
			totalIO := float64(c.Proc.IOReadBytes + c.Proc.IOWriteBytes)
			fv.Values[FBeaconIOPerSecondAvg] = totalIO / age
		}
	}

	// (H) FBeaconIOReadRatio — read/(read+write).
	if c.Proc != nil {
		total := float64(c.Proc.IOReadBytes + c.Proc.IOWriteBytes)
		fv.Values[FBeaconIOReadRatio] = safeDiv(float64(c.Proc.IOReadBytes), total)
	}

	// (H) FBeaconPayloadSizeMean — avg bytes per burst.
	if c.Proc != nil {
		burstHits := shared.ShortLivedBurstHits[c.Proc.Pid]
		if burstHits > 0 {
			totalIO := float64(c.Proc.IOReadBytes + c.Proc.IOWriteBytes)
			fv.Values[FBeaconPayloadSizeMean] = totalIO / float64(burstHits)
		}
	}

	// (H) FBeaconSleepRegularity — silence period consistency.
	if c.Proc != nil {
		if synHist := shared.SYNCycleByPID[c.Proc.Pid]; synHist != nil && len(synHist.Intervals) >= 2 {
			mean, stddev := intervalMeanStddev(synHist.Intervals)
			if mean > 0 {
				reg := 1.0 - stddev/mean
				if reg < 0 {
					reg = 0
				}
				fv.Values[FBeaconSleepRegularity] = reg
			}
		}
	}

	// (H) FBeaconBurstSilenceShape — burst-to-silence ratio.
	if c.Proc != nil {
		if tracker := shared.IOBurstHistory[c.Proc.Pid]; tracker != nil && tracker.BurstRuns > 0 {
			fv.Values[FBeaconBurstSilenceShape] = safeDiv(float64(tracker.BurstRuns), float64(tracker.BurstRuns+tracker.ZeroRuns))
		}
	}

	// (H) FBeaconCPUToAgeRatio — CPU seconds / process age.
	if c.Proc != nil && !c.Proc.StartTime.IsZero() {
		age := time.Since(c.Proc.StartTime).Seconds()
		if age > 0 {
			fv.Values[FBeaconCPUToAgeRatio] = c.Proc.CpuTime.Seconds() / age
		}
	}

	// (H) FBeaconMemoryVariance — working set variance from rolling samples.
	if c.Proc != nil {
		if hist := shared.ProcHistoryByPID[c.Proc.Pid]; hist != nil && len(hist.MemSamples) >= 3 {
			mean := float64(0)
			for _, s := range hist.MemSamples {
				mean += float64(s)
			}
			mean /= float64(len(hist.MemSamples))
			variance := float64(0)
			for _, s := range hist.MemSamples {
				diff := float64(s) - mean
				variance += diff * diff
			}
			variance /= float64(len(hist.MemSamples))
			fv.Values[FBeaconMemoryVariance] = variance / (1024 * 1024 * 1024 * 1024) // normalize to GB²
		}
	}

	// (H) FBeaconChildCount — child processes spawned.
	if c.Proc != nil {
		fv.Values[FBeaconChildCount] = float64(c.Proc.ChildCount)
	}

	// (H) FBeaconHasCryptoLib — loaded crypto/TLS library.
	if c.Proc != nil {
		for _, lib := range c.Proc.LoadedLibs {
			l := strings.ToLower(lib)
			if strings.Contains(l, "crypto") || strings.Contains(l, "ssl") || strings.Contains(l, "tls") {
				fv.Values[FBeaconHasCryptoLib] = 1
				break
			}
		}
	}

	// (H) FBeaconJitterEntropy — entropy of interval differences.
	if c.Proc != nil {
		if synHist := shared.SYNCycleByPID[c.Proc.Pid]; synHist != nil && len(synHist.Intervals) >= 2 {
			fv.Values[FBeaconJitterEntropy] = intervalEntropy(synHist.Intervals)
		}
	}

	// (H) FBeaconLongInterval — interval >5min flag.
	if c.BeaconIntervalMs >= 300000 {
		fv.Values[FBeaconLongInterval] = 1
	}

	// (H) FBeaconIOZeroPeriods — observation cycles with zero IO.
	if c.Proc != nil {
		if tracker := shared.IOBurstHistory[c.Proc.Pid]; tracker != nil {
			fv.Values[FBeaconIOZeroPeriods] = float64(tracker.ZeroRuns)
		}
	}

	// (N) FBeaconOutLongLivedCount — long-lived outbound connections.
	// 0 for beacons (short callbacks), >=1 for sessions (persistent).
	// Single most discriminative beacon vs session feature.
	fv.Values[FBeaconOutLongLivedCount] = float64(c.OutLongLived)

	// (N) FBeaconReconnectCount — short-lived outbound connections indicate
	// repeated connect/disconnect cycles (beacon callback pattern).
	fv.Values[FBeaconReconnectCount] = float64(c.OutShortLived)
}
