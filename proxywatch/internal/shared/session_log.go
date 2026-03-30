package shared

import (
	"encoding/json"
	"time"
)

type SessionEvent struct {
	Timestamp time.Time `json:"ts"`
	Host      string    `json:"host"`
	PID       int       `json:"pid"`
	Process   string    `json:"process"`
	Role      string    `json:"role"`
	State     string    `json:"state"`
	Score     int       `json:"score"`
	Event     string    `json:"event"` // "new", "promoted", "demoted", "removed"
}

func LogSessionEvent(app *AppState, event SessionEvent) {
	if app == nil || app.SessionLogFile == nil {
		return
	}
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	_, _ = app.SessionLogFile.Write(append(data, '\n'))
}
