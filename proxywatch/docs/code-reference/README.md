# Code Reference Documentation

This documentation provides a complete reference for understanding the codebase after comment removal.

## What Was Done

1. **All comments removed** from source files (254 Go files processed)
2. **Build constraints preserved** - platform-specific files work correctly
3. **Documentation created** - detailed reference for all packages

## Documentation Files

- **ARCHITECTURE.md** - High-level package structure and purpose
- **FUNCTIONS.md** - Detailed function and type reference
- **README.md** - This file

## Quick Reference

### Main Entry Points

| Mode | Flag | Description |
|------|------|-------------|
| Standalone | (none) | Local monitoring with TUI |
| Agent | `-connect <addr>` | Stream telemetry to server |
| Server | `-listen <addr>` | Accept agent connections |
| Service | `-service` | Run as Windows service |
| Tunnel Server | `-contour-server` | Protocol tunnel server |
| Tunnel Client | `-contour-client <addr>` | Protocol tunnel client |

### Key Packages

| Package | Purpose |
|---------|---------|
| cmd/proxywatch | Entry point, CLI parsing |
| internal/detection | Main detection engine |
| internal/detection/scoring | Candidate scoring |
| internal/detection/behavior | Behavior analysis |
| internal/detection/ml | Machine learning |
| internal/agent | Remote agent/server |
| internal/contour | Tunnel system |
| internal/ui | Terminal interface |
| internal/shared | Shared types/utilities |
| internal/keystore | Secure storage |

### Detection Roles

| Role | Description |
|------|-------------|
| c2-beacon | Command & control beaconing |
| c2-shell | Interactive C2 shell |
| tunnel-child | Tunnel child process |
| tunnel-forward | Forward tunnel |
| tunnel-reverse | Reverse tunnel |
| pivot | Lateral movement |
| listener | Network listener |
| exfil | Data exfiltration |
| outbound | Standard outbound |

### Data Flow

```
[Telemetry Collection]
       ↓
[Process + Network Snapshot]
       ↓
[Candidate Building]
       ↓
[Behavior Analysis]
       ↓
[ML Feature Extraction]
       ↓
[Scoring & Classification]
       ↓
[Role Assignment]
       ↓
[UI Display / Agent Streaming]
```

## Building

```bash
# Linux
GOOS=linux go build ./cmd/proxywatch

# macOS
GOOS=darwin go build ./cmd/proxywatch

# Windows
GOOS=windows go build ./cmd/proxywatch
```

## Notes

- Comments were stripped using Go AST parsing to preserve syntax
- Build constraints are explicit (`//go:build`) to ensure cross-platform compilation
- The identifier names remain unchanged for code maintainability
- All functionality is preserved; only documentation comments were removed
