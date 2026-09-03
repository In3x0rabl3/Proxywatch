package detection

import (
	"proxywatch/internal/detection/output"
	"proxywatch/internal/detection/scoring"
	"proxywatch/internal/shared"
)

// ProcessBehaviorKey is a thin wrapper so external callers (inspector, workflow,
// dashboard) can continue to call detection.ProcessBehaviorKey.
func ProcessBehaviorKey(c *shared.Candidate) string {
	return scoring.ProcessBehaviorKey(c)
}

// ConfigureDetectionOutputs delegates to output.ConfigureDetectionOutputs.
func ConfigureDetectionOutputs(debugPath, defenderPath string) error {
	return output.ConfigureDetectionOutputs(debugPath, defenderPath)
}
