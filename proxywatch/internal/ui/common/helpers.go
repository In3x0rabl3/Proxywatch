package common

import "time"

func SpinnerFrame() string {
	frames := []string{"-", "\\", "|", "/"}
	return frames[int(time.Now().UnixNano()/int64(250*time.Millisecond))%len(frames)]
}

func SpinnerElapsed(start time.Time) time.Duration {
	if start.IsZero() {
		return 0
	}
	elapsed := time.Since(start).Round(time.Second)
	if elapsed < 0 {
		return 0
	}
	return elapsed
}

const CalibrationReportLabelWidth = 18

