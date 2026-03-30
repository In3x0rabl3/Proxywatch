package calibration

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"proxywatch/internal/safeio"
	"proxywatch/internal/shared"
)

const (
	learningModelVersion = 1
	learningDecayFactor  = 0.92
)

type learningModel struct {
	Version            int                       `json:"version"`
	UpdatedAt          time.Time                 `json:"updated_at"`
	Runs               int                       `json:"runs"`
	WeightedSamples    float64                   `json:"weighted_samples"`
	SuspiciousWeighted float64                   `json:"suspicious_weighted"`
	ObservedSamples    float64                   `json:"observed_samples"`
	ObservedSuspicious float64                   `json:"observed_suspicious"`
	RoleWeighted       map[string]float64        `json:"role_weighted"`
	StateWeighted      map[string]float64        `json:"state_weighted"`
	Processes          map[string]learnedProcess `json:"processes"`

	// Contamination recovery tracking.
	HighContaminationRuns int       `json:"high_contamination_runs,omitempty"`
	LastRecovery          time.Time `json:"last_recovery,omitempty"`
}

type learnedProcess struct {
	Name             string    `json:"name"`
	SeenWeight       float64   `json:"seen_weight"`
	AvgOutbound      float64   `json:"avg_outbound"`
	AvgInbound       float64   `json:"avg_inbound"`
	SuspiciousWeight float64   `json:"suspicious_weight"`
	StrongWeight     float64   `json:"strong_weight"`
	ActiveWeight     float64   `json:"active_weight"`
	LastSeen         time.Time `json:"last_seen"`
}

type LearningContext struct {
	ModelPath          string
	Runs               int
	WeightedSamples    float64
	SuspiciousRatio    float64
	ContaminationPct   int
	TopNormalProcesses []string
	RoleRatios         map[string]float64
	StateRatios        map[string]float64
	Notes              []string
}

func learningModelPath() string {
	return filepath.Join(calibrationRoot(), "training", "environment-model.json")
}

func loadLearningModel() (*learningModel, error) {
	path := learningModelPath()
	raw, err := safeio.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultLearningModel(), nil
		}
		return nil, err
	}
	var model learningModel
	if err := json.Unmarshal(raw, &model); err != nil {
		return nil, err
	}
	return ensureLearningModel(&model), nil
}

func saveLearningModel(model *learningModel) error {
	model = ensureLearningModel(model)
	path := learningModelPath()
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(model, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func defaultLearningModel() *learningModel {
	return &learningModel{
		Version:       learningModelVersion,
		RoleWeighted:  make(map[string]float64),
		StateWeighted: make(map[string]float64),
		Processes:     make(map[string]learnedProcess),
	}
}

func ensureLearningModel(model *learningModel) *learningModel {
	if model == nil {
		return defaultLearningModel()
	}
	if model.Version <= 0 {
		model.Version = learningModelVersion
	}
	if model.RoleWeighted == nil {
		model.RoleWeighted = make(map[string]float64)
	}
	if model.StateWeighted == nil {
		model.StateWeighted = make(map[string]float64)
	}
	if model.Processes == nil {
		model.Processes = make(map[string]learnedProcess)
	}
	sanitizeLearningProcesses(model)
	return model
}

func updateLearningModel(model *learningModel, samples []shared.Candidate, now time.Time) *learningModel {
	model = ensureLearningModel(model)
	if now.IsZero() {
		now = time.Now().UTC()
	}
	applyLearningDecay(model, learningDecayFactor)
	contaminationBefore := learningContaminationRatio(model)
	runContamination := runSuspiciousRatio(samples)
	quarantineNormalLearning := contaminationBefore >= 0.20 || runContamination >= 0.15

	// Contamination recovery: if contamination stays above 50% for 3+
	// consecutive runs, reset the suspicious weights so the model can
	// self-heal after a red-team engagement or prolonged incident.
	if contaminationBefore >= 0.50 {
		model.HighContaminationRuns++
	} else {
		model.HighContaminationRuns = 0
	}
	if model.HighContaminationRuns >= 3 {
		recoverLearningModel(model, now)
	}
	for _, sample := range samples {
		if sample.Proc == nil {
			continue
		}
		family := shared.RoleFamily(sample.Role)
		state := sampleState(sample)
		weight := learningSampleWeight(sample, family)
		if weight <= 0 {
			continue
		}
		model.ObservedSamples++
		if isSuspiciousFamily(family) {
			model.ObservedSuspicious++
		}

		model.WeightedSamples += weight
		model.RoleWeighted[family] += weight
		model.StateWeighted[state] += weight
		if isSuspiciousFamily(family) {
			model.SuspiciousWeighted += weight
		}
		if !learningProcessEligible(sample, family, quarantineNormalLearning) {
			continue
		}

		key := learningProcessKey(sample)
		entry := model.Processes[key]
		if strings.TrimSpace(entry.Name) == "" {
			entry.Name = strings.TrimSpace(sample.Proc.Name)
			if entry.Name == "" {
				entry.Name = "(unknown)"
			}
		}
		prevSeen := entry.SeenWeight
		entry.SeenWeight += weight
		entry.AvgOutbound = weightedAvg(entry.AvgOutbound, prevSeen, float64(sample.OutTotal), weight)
		entry.AvgInbound = weightedAvg(entry.AvgInbound, prevSeen, float64(sample.InboundTotal), weight)
		if isSuspiciousFamily(family) {
			entry.SuspiciousWeight += weight
		}
		if sample.StrongEvidence {
			entry.StrongWeight += weight
		}
		if sample.ActiveProxying {
			entry.ActiveWeight += weight
		}
		entry.LastSeen = now
		model.Processes[key] = entry
	}
	model.Runs++
	model.UpdatedAt = now
	pruneLearningModel(model)
	return model
}

func buildLearningContext(model *learningModel, currentSamples ...[]shared.Candidate) LearningContext {
	model = ensureLearningModel(model)
	ctx := LearningContext{
		ModelPath:       learningModelPath(),
		Runs:            model.Runs,
		WeightedSamples: round1(model.WeightedSamples),
		RoleRatios:      make(map[string]float64),
		StateRatios:     make(map[string]float64),
	}
	total := model.WeightedSamples
	if total <= 0 {
		ctx.Notes = []string{"No historical baseline yet. Complete a few calibrations to learn normal traffic shape."}
		return ctx
	}
	// Use the higher of the model's accumulated ratio and the current run's
	// ratio so operators see the real contamination level, not a value diluted
	// by historical decay.
	modelRatio := learningContaminationRatio(model)
	ctx.SuspiciousRatio = modelRatio
	if len(currentSamples) > 0 && len(currentSamples[0]) > 0 {
		runRatio := runSuspiciousRatio(currentSamples[0])
		if runRatio > ctx.SuspiciousRatio {
			ctx.SuspiciousRatio = runRatio
		}
	}
	ctx.ContaminationPct = int(math.Round(ctx.SuspiciousRatio * 100))

	for role, v := range model.RoleWeighted {
		if v <= 0 {
			continue
		}
		ctx.RoleRatios[role] = v / total
	}
	for state, v := range model.StateWeighted {
		if v <= 0 {
			continue
		}
		ctx.StateRatios[state] = v / total
	}

	type processScore struct {
		name string
		seen float64
		out  float64
		in   float64
	}
	items := make([]processScore, 0, len(model.Processes))
	quarantineNormalList := ctx.ContaminationPct >= 20
	for _, p := range model.Processes {
		if p.SeenWeight < 1.0 {
			continue
		}
		if quarantineNormalList {
			continue
		}
		suspFrac := 0.0
		strongFrac := 0.0
		activeFrac := 0.0
		if p.SeenWeight > 0 {
			suspFrac = p.SuspiciousWeight / p.SeenWeight
			strongFrac = p.StrongWeight / p.SeenWeight
			activeFrac = p.ActiveWeight / p.SeenWeight
		}
		if suspFrac > 0.20 || strongFrac > 0.15 || activeFrac > 0.15 {
			continue
		}
		items = append(items, processScore{
			name: p.Name,
			seen: p.SeenWeight,
			out:  p.AvgOutbound,
			in:   p.AvgInbound,
		})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].seen == items[j].seen {
			return strings.ToLower(items[i].name) < strings.ToLower(items[j].name)
		}
		return items[i].seen > items[j].seen
	})
	if len(items) > 6 {
		items = items[:6]
	}
	for _, item := range items {
		ctx.TopNormalProcesses = append(
			ctx.TopNormalProcesses,
			fmt.Sprintf("%s (obs %.1f, out %.1f, in %.1f)", item.name, round1(item.seen), round1(item.out), round1(item.in)),
		)
	}

	if ctx.Runs < 3 {
		ctx.Notes = append(ctx.Notes, "Baseline is warming up; confidence increases after several runs.")
	}
	if ctx.ContaminationPct >= 35 {
		ctx.Notes = append(ctx.Notes, "Potentially suspicious traffic is significant; baseline weighting reduced those samples to avoid poisoning normal profile.")
		ctx.Notes = append(ctx.Notes, "Normal-process list is temporarily quarantined until contamination drops.")
	} else if ctx.ContaminationPct >= 20 {
		ctx.Notes = append(ctx.Notes, "Suspicious-role contamination is elevated; tightening normal-process learning safeguards.")
		ctx.Notes = append(ctx.Notes, "Normal-process list is temporarily quarantined until contamination drops.")
	} else {
		ctx.Notes = append(ctx.Notes, "Suspicious-role contamination is currently low-to-moderate.")
	}
	if len(ctx.TopNormalProcesses) == 0 {
		ctx.Notes = append(ctx.Notes, "No stable normal-process set identified yet.")
	}
	return ctx
}

func applyLearningDecay(model *learningModel, factor float64) {
	if factor <= 0 || factor >= 1 {
		return
	}
	model.WeightedSamples *= factor
	model.SuspiciousWeighted *= factor
	model.ObservedSamples *= factor
	model.ObservedSuspicious *= factor
	for k, v := range model.RoleWeighted {
		model.RoleWeighted[k] = v * factor
	}
	for k, v := range model.StateWeighted {
		model.StateWeighted[k] = v * factor
	}
	for k, v := range model.Processes {
		v.SeenWeight *= factor
		v.SuspiciousWeight *= factor
		v.StrongWeight *= factor
		v.ActiveWeight *= factor
		model.Processes[k] = v
	}
}

func pruneLearningModel(model *learningModel) {
	if len(model.Processes) <= 400 {
		return
	}
	type kv struct {
		key  string
		seen float64
		last time.Time
	}
	items := make([]kv, 0, len(model.Processes))
	for key, proc := range model.Processes {
		items = append(items, kv{key: key, seen: proc.SeenWeight, last: proc.LastSeen})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].seen == items[j].seen {
			return items[i].last.After(items[j].last)
		}
		return items[i].seen > items[j].seen
	})
	keep := 300
	if len(items) < keep {
		keep = len(items)
	}
	allowed := make(map[string]struct{}, keep)
	for i := 0; i < keep; i++ {
		allowed[items[i].key] = struct{}{}
	}
	for key := range model.Processes {
		if _, ok := allowed[key]; !ok {
			delete(model.Processes, key)
		}
	}
}

func learningProcessKey(sample shared.Candidate) string {
	if sample.Proc == nil {
		return "(unknown)"
	}
	name := strings.ToLower(strings.TrimSpace(sample.Proc.Name))
	if name == "" {
		return "(unknown)"
	}
	return name
}

func sampleState(sample shared.Candidate) string {
	if sample.ActiveProxying {
		return "active"
	}
	if sample.StrongEvidence {
		return "strong"
	}
	return "watch"
}

func learningSampleWeight(sample shared.Candidate, family string) float64 {
	weight := 1.0
	switch family {
	case "session", "beacon", "tunnel", "smb-pipe":
		weight = 0.20
	case "other":
		weight = 0.5
	}
	if sample.StrongEvidence {
		weight *= 0.5
	}
	if sample.ActiveProxying {
		weight *= 0.35
	}
	if weight < 0.1 {
		return 0.1
	}
	return weight
}

// isSuspiciousFamily returns true for roles that indicate C2, tunneling,
// or lateral movement.
func isSuspiciousFamily(family string) bool {
	switch family {
	case "session", "beacon", "tunnel", "smb-pipe":
		return true
	default:
		return false
	}
}

func learningContaminationRatio(model *learningModel) float64 {
	if model == nil {
		return 0
	}
	// Use the observed ratio (actual count of suspicious candidates) rather
	// than the weighted ratio. The weighted ratio suppresses suspicious roles
	// to 0.20x which makes contamination appear artificially low. Operators
	// need to see the real proportion of suspicious candidates.
	if model.ObservedSamples > 0 {
		return model.ObservedSuspicious / model.ObservedSamples
	}
	return 0
}

func runSuspiciousRatio(samples []shared.Candidate) float64 {
	if len(samples) == 0 {
		return 0
	}
	total := 0
	susp := 0
	for _, sample := range samples {
		if sample.Proc == nil {
			continue
		}
		total++
		family := shared.RoleFamily(sample.Role)
		if isSuspiciousFamily(family) {
			susp++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(susp) / float64(total)
}

func learningProcessEligible(sample shared.Candidate, family string, quarantine bool) bool {
	if sample.Proc == nil {
		return false
	}
	if isSuspiciousFamily(family) {
		return false
	}
	if sample.ActiveProxying || sample.StrongEvidence {
		return false
	}
	if sample.OutInternal > 0 {
		return false
	}
	if hasSuspiciousLearningSignals(sample.Signals) {
		return false
	}
	trustedPath := shared.IsLikelyBenignControlClient(sample.Proc)
	if quarantine {
		return trustedPath && sample.TrafficVerified
	}
	if trustedPath {
		return true
	}
	return sample.TrafficVerified && sample.OutExternal <= 2 && sample.ControlDurationSeconds == 0
}

func hasSuspiciousLearningSignals(signals []string) bool {
	for _, sig := range signals {
		s := strings.TrimSpace(strings.ToLower(sig))
		if s == "" {
			continue
		}
		if strings.Contains(s, "reverse-") ||
			strings.Contains(s, "susp-") ||
			strings.Contains(s, "control-channel") ||
			strings.Contains(s, "control-session") ||
			strings.Contains(s, "beacon") ||
			strings.Contains(s, "tunnel") ||
			strings.Contains(s, "internal-lateral") ||
			strings.Contains(s, "proxy") ||
			strings.Contains(s, "smb-pipe") {
			return true
		}
	}
	return false
}

func sanitizeLearningProcesses(model *learningModel) {
	if model == nil || len(model.Processes) == 0 {
		return
	}
	for key, proc := range model.Processes {
		if proc.SeenWeight <= 0 {
			delete(model.Processes, key)
			continue
		}
		suspFrac := proc.SuspiciousWeight / proc.SeenWeight
		strongFrac := proc.StrongWeight / proc.SeenWeight
		activeFrac := proc.ActiveWeight / proc.SeenWeight
		if suspFrac > 0.25 || strongFrac > 0.25 || activeFrac > 0.25 {
			delete(model.Processes, key)
		}
	}
}

func weightedAvg(current, currentWeight, value, weight float64) float64 {
	total := currentWeight + weight
	if total <= 0 {
		return 0
	}
	return ((current * currentWeight) + (value * weight)) / total
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}

// recoverLearningModel resets suspicious weights so the model can self-heal
// after prolonged contamination (e.g. red-team exercise, ongoing incident).
func recoverLearningModel(model *learningModel, now time.Time) {
	// Clear suspicious process entries.
	for key, proc := range model.Processes {
		if proc.SuspiciousWeight > 0 {
			proc.SuspiciousWeight = 0
			proc.StrongWeight = 0
			proc.ActiveWeight = 0
			model.Processes[key] = proc
		}
	}
	// Reset global suspicious counters to 10% of current weighted samples
	// so the model retains some baseline awareness without being poisoned.
	model.SuspiciousWeighted = model.WeightedSamples * 0.10
	model.ObservedSuspicious = model.ObservedSamples * 0.10
	model.HighContaminationRuns = 0
	model.LastRecovery = now
}
