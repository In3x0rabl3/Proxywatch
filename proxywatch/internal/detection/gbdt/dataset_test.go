package gbdt

import "testing"

func TestRoleIndex(t *testing.T) {
	cases := map[string]int{
		"outbound":        0,
		"listener":        1,
		"control-channel": 2,
		"control-pivot":   3,
		"":                -1,
		"unknown":         -1,
	}
	for role, want := range cases {
		if got := roleIndex(role); got != want {
			t.Errorf("roleIndex(%q) = %d, want %d", role, got, want)
		}
	}
}

func TestLabelToRole(t *testing.T) {
	cases := map[string]string{
		"malicious": "control-channel",
		"session":   "control-channel",
		"beacon":    "control-channel",
		"tunnel":    "control-pivot",
		"pivot":     "control-pivot",
		"benign":    "outbound",
		"listen":    "listener",
		"listener":  "listener",
		// Direct role names (case-insensitive).
		"control-channel": "control-channel",
		"CONTROL-PIVOT":   "control-pivot",
		"Outbound":        "outbound",
		// Unknown → fallback to outbound.
		"garbage": "outbound",
		"":        "outbound",
	}
	for input, want := range cases {
		if got := labelToRole(input); got != want {
			t.Errorf("labelToRole(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestVerdictToRole(t *testing.T) {
	cases := map[string]string{
		"kill":      "control-channel",
		"malicious": "control-channel",
		"KILL":      "control-channel",
		"whitelist": "outbound",
		"benign":    "outbound",
		"unknown":   "outbound",
		"":          "outbound",
	}
	for input, want := range cases {
		if got := verdictToRole(input); got != want {
			t.Errorf("verdictToRole(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSourceWeight(t *testing.T) {
	// Weights must follow the trust hierarchy: operator > user > exp > rule > default.
	cases := []struct {
		src  LabelSource
		want float64
	}{
		{LabelOperator, 5.0},
		{LabelUserVerdict, 3.0},
		{LabelExperience, 2.0},
		{LabelRule, 1.0},
		{LabelDefault, 0.5},
	}
	for _, tc := range cases {
		if got := sourceWeight(tc.src); got != tc.want {
			t.Errorf("sourceWeight(%v) = %f, want %f", tc.src, got, tc.want)
		}
	}
	// Trust ordering — each tier should be strictly higher than the next.
	prev := sourceWeight(LabelOperator)
	for _, s := range []LabelSource{LabelUserVerdict, LabelExperience, LabelRule, LabelDefault} {
		curr := sourceWeight(s)
		if curr >= prev {
			t.Errorf("trust ordering violated: %v weight %f >= prior %f", s, curr, prev)
		}
		prev = curr
	}
}

func TestResolveLabel_OperatorWins(t *testing.T) {
	// Operator label present → dominates even when other fields disagree.
	label := "session"
	rec := TrainingRecord{
		OperatorLabel:          &label,
		UserVerdict:            "whitelist",
		RuleRole:               "outbound",
		ExperienceRole:         "outbound",
		ExperienceObservations: 100,
		ExperienceStability:    0.9,
	}
	idx, src := resolveLabel(rec)
	if src != LabelOperator {
		t.Errorf("source = %v, want LabelOperator", src)
	}
	if idx != 2 { // control-channel
		t.Errorf("idx = %d, want 2 (control-channel)", idx)
	}
}

func TestResolveLabel_UserVerdictNextPriority(t *testing.T) {
	rec := TrainingRecord{
		UserVerdict:            "kill",
		RuleRole:               "outbound",
		ExperienceRole:         "outbound",
		ExperienceObservations: 100,
		ExperienceStability:    0.9,
	}
	idx, src := resolveLabel(rec)
	if src != LabelUserVerdict {
		t.Errorf("source = %v, want LabelUserVerdict", src)
	}
	if idx != 2 { // kill → control-channel
		t.Errorf("idx = %d, want 2", idx)
	}
}

func TestResolveLabel_ExperienceRequiresStability(t *testing.T) {
	// Experience only counts with 10+ observations AND stability >= 0.5.
	rec := TrainingRecord{
		ExperienceRole:         "control-channel",
		ExperienceObservations: 50,
		ExperienceStability:    0.8,
	}
	_, src := resolveLabel(rec)
	if src != LabelExperience {
		t.Errorf("source = %v, want LabelExperience", src)
	}
	// Insufficient observations → drops to rule or default.
	rec.ExperienceObservations = 5
	rec.RuleRole = "outbound"
	_, src2 := resolveLabel(rec)
	if src2 != LabelRule {
		t.Errorf("low obs: source = %v, want LabelRule", src2)
	}
	// Low stability → drops.
	rec.ExperienceObservations = 50
	rec.ExperienceStability = 0.3
	_, src3 := resolveLabel(rec)
	if src3 != LabelRule {
		t.Errorf("low stability: source = %v, want LabelRule", src3)
	}
}

func TestResolveLabel_FallbackToDefault(t *testing.T) {
	// Empty record → LabelDefault at outbound.
	idx, src := resolveLabel(TrainingRecord{})
	if src != LabelDefault {
		t.Errorf("empty: source = %v, want LabelDefault", src)
	}
	if idx != 0 { // outbound
		t.Errorf("idx = %d, want 0", idx)
	}
}

func TestRoleClasses_Invariants(t *testing.T) {
	if len(RoleClasses) != NumClasses {
		t.Errorf("len(RoleClasses) = %d, want NumClasses=%d", len(RoleClasses), NumClasses)
	}
	// Index 0 must be outbound (the baseline-exists requirement in
	// ValidateDataset).
	if RoleClasses[0] != "outbound" {
		t.Errorf("RoleClasses[0] = %q, want outbound", RoleClasses[0])
	}
}
