package ml

// ModelMetrics holds evaluation results for a trained model.
// The runtime reads this struct; the training orchestrator is the canonical
// owner. Evaluation functions previously in this file were unused and have
// been removed.
type ModelMetrics struct {
	MacroF1        float64 `json:"macro_f1"`
	ControlRecall  float64 `json:"control_recall"` // min recall across control-* classes
	OutboundPrec   float64 `json:"outbound_prec"`
	Stability      float64 `json:"stability"`
	LocalObs       int     `json:"local_obs"`
	OperatorLabels int     `json:"operator_labels"`
	MeetsThreshold bool    `json:"meets_threshold"`
}

// Transition thresholds — model becomes primary when ALL are met.
const (
	ThresholdMacroF1        = 0.70
	ThresholdControlRecall  = 0.90
	ThresholdOutboundPrec   = 0.85
	ThresholdStability      = 0.80
	ThresholdMaturityScore  = 60
	ThresholdLocalObs       = 5000
	ThresholdOperatorLabels = 10
)
