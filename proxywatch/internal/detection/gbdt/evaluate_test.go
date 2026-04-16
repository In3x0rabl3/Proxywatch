package gbdt

import "testing"

func TestQualityGateForSize(t *testing.T) {
	cases := []struct {
		name string
		size int
		// Check relationships, not exact values, so future threshold
		// tuning doesn't break tests unless the invariants break.
		earlyTraining      bool // zero-gate
		intermediateOrProd bool // any non-zero gate
	}{
		{"tiny dataset (0)", 0, true, false},
		{"under threshold (4999)", 4999, true, false},
		{"intermediate (5000)", 5000, false, true},
		{"mid (10000)", 10000, false, true},
		{"production (20000)", 20000, false, true},
		{"large (100000)", 100000, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := QualityGateForSize(tc.size)
			isZero := g.MinMacroF1 == 0 && g.MinControlRecall == 0 && g.MinOutboundPrec == 0
			if tc.earlyTraining && !isZero {
				t.Errorf("size %d: expected zero gate (early training), got %+v", tc.size, g)
			}
			if tc.intermediateOrProd && isZero {
				t.Errorf("size %d: expected non-zero gate, got %+v", tc.size, g)
			}
		})
	}

	// Production thresholds should be STRICTLY tighter than intermediate.
	inter := QualityGateForSize(10000)
	prod := QualityGateForSize(50000)
	if prod.MinMacroF1 <= inter.MinMacroF1 {
		t.Errorf("production MacroF1 threshold not tighter than intermediate")
	}
	if prod.MinControlRecall <= inter.MinControlRecall {
		t.Errorf("production ControlRecall threshold not tighter than intermediate")
	}
	if prod.MinOutboundPrec <= inter.MinOutboundPrec {
		t.Errorf("production OutboundPrec threshold not tighter than intermediate")
	}
}

func TestCheckQualityGate_Pass(t *testing.T) {
	metrics := &EvalMetrics{
		MacroF1:       0.80,
		ControlRecall: 0.75,
		OutboundPrec:  0.85,
	}
	gate := QualityGate{
		MinMacroF1:       0.55,
		MinControlRecall: 0.65,
		MinOutboundPrec:  0.75,
	}
	pass, failures := CheckQualityGate(metrics, gate)
	if !pass {
		t.Errorf("expected pass, got failures: %v", failures)
	}
	if len(failures) != 0 {
		t.Errorf("expected 0 failures, got %v", failures)
	}
}

func TestCheckQualityGate_EachFailureReported(t *testing.T) {
	// Every metric below its gate → every failure reported.
	metrics := &EvalMetrics{
		MacroF1:       0.30,
		ControlRecall: 0.20,
		OutboundPrec:  0.40,
	}
	gate := QualityGate{
		MinMacroF1:       0.55,
		MinControlRecall: 0.65,
		MinOutboundPrec:  0.75,
	}
	pass, failures := CheckQualityGate(metrics, gate)
	if pass {
		t.Errorf("expected fail")
	}
	if len(failures) != 3 {
		t.Errorf("expected 3 failures (one per metric), got %d: %v", len(failures), failures)
	}
}

func TestCheckQualityGate_PartialFailure(t *testing.T) {
	metrics := &EvalMetrics{
		MacroF1:       0.80, // passes
		ControlRecall: 0.30, // fails
		OutboundPrec:  0.85, // passes
	}
	gate := QualityGate{
		MinMacroF1:       0.55,
		MinControlRecall: 0.65,
		MinOutboundPrec:  0.75,
	}
	pass, failures := CheckQualityGate(metrics, gate)
	if pass {
		t.Errorf("expected fail (control recall below threshold)")
	}
	if len(failures) != 1 {
		t.Errorf("expected exactly 1 failure, got %d: %v", len(failures), failures)
	}
}

func TestCheckQualityGate_ZeroGatePassesAnything(t *testing.T) {
	// Early-training zero gate lets any metric pass (this is the whole
	// point — let the model train during bootstrap).
	metrics := &EvalMetrics{
		MacroF1:       0.01,
		ControlRecall: 0.01,
		OutboundPrec:  0.01,
	}
	gate := QualityGateForSize(100) // zero gate
	pass, failures := CheckQualityGate(metrics, gate)
	if !pass {
		t.Errorf("zero gate should pass anything; got failures: %v", failures)
	}
}
