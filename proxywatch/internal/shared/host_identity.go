package shared

import (
	"os"
	"strings"
)

func DefaultHostID(fallback string) string {
	name, err := os.Hostname()
	if err == nil {
		name = strings.TrimSpace(name)
	}
	if name == "" {
		return fallback
	}
	return name
}

func DisplayHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return "local"
	}
	return host
}
