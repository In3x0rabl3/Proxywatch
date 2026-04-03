package model

// TopSignals returns the most effective signals (highest precision with
// sufficient observations). Used for model quality display.
func TopSignals(limit int) []signalEfficiency {
	mu.RLock()
	defer mu.RUnlock()
	if current == nil || current.SignalStats == nil {
		return nil
	}

	var results []signalEfficiency
	for name, ss := range current.SignalStats {
		if ss.Total < 3 {
			continue
		}
		results = append(results, signalEfficiency{
			Name:      name,
			Precision: ss.Precision,
			Total:     ss.Total,
			TP:        ss.TruePositive,
			FP:        ss.FalsePositive,
		})
	}

	// Sort by precision descending.
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[j].Precision > results[i].Precision {
				results[i], results[j] = results[j], results[i]
			}
		}
	}
	if len(results) > limit {
		results = results[:limit]
	}
	return results
}

// signalEfficiency represents a signal's effectiveness.
type signalEfficiency struct {
	Name      string
	Precision float64
	Total     int
	TP        int
	FP        int
}
