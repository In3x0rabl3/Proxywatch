package calibration

import (
	"context"
)

// RequestSIEMAI exposes the shared calibration AI request pipeline for the
// SIEM package, so SIEM generation can remain outside the calibration package
// while reusing provider/runtime auth and retry behavior.
func RequestSIEMAI(ctx context.Context, provider, model, system, user string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return requestCalibrationAI(ctx, provider, model, system, user)
}
