// Package inference provides ML model loading and prediction for role
// classification. It implements a pure-Go LightGBM leaf-walk predictor
// that requires no CGo dependencies.
package ml

import (
	"proxywatch/internal/detection/features"
)

// RoleProb pairs a role name with its probability.
type RoleProb struct {
	Role string
	Prob float64
}

// RolePrediction contains the model's output for a single candidate.
type RolePrediction struct {
	// TopRole is the highest-probability role.
	TopRole string
	// TopProb is the probability of the top role.
	TopProb float64
	// Probabilities maps each role class to its predicted probability.
	Probabilities map[string]float64
	// TopN is the top-3 roles by probability.
	TopN []RoleProb
	// Confident is true when TopProb exceeds the confidence threshold.
	Confident bool
}

// Predictor loads a trained model and produces role predictions.
type Predictor interface {
	// PredictRole returns class probabilities for the multiclass head.
	PredictRole(fv features.FeatureVector) RolePrediction

	// ModelVersion returns the active model version string.
	ModelVersion() string

	// RoleClasses returns the role class names in order.
	RoleClasses() []string

	// Close releases model resources.
	Close() error
}

// DefaultConfidenceThreshold is the minimum top probability for a
// prediction to be considered confident.
const DefaultConfidenceThreshold = 0.40
