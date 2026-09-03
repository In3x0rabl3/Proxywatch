package shared

import (
	"math"
	"sort"
)

// Statistical helpers for beacon shape scoring. Uses Bowley skewness +
// Median-Absolute-Deviation for TS/DS sub-scores. Operates on per-flow
// byte sizes and inter-connection time deltas.

// BowleySkewness measures distribution symmetry using the quartile
// formula `(Q1 + Q3 - 2*Q2) / (Q3 - Q1)`. Perfect symmetry → 0.
// Returns (skew, score) where score = 1 - |skew| clamped to [0, 1].
//
// A perfect beacon's intervals (or sizes) sit symmetrically around the
// median — score → 1.0. Bursty / chaotic distributions skew heavily
// → score → 0.
//
// Returns (0, 0) when len(data) < 3 or the IQR is too small to be
// meaningful (denom < 10).
func BowleySkewness(data []float64) (skew, score float64) {
	if len(data) < 3 {
		return 0, 0
	}
	sorted := make([]float64, len(data))
	copy(sorted, data)
	sort.Float64s(sorted)
	q1, q2, q3 := quartiles(sorted)
	num := q1 + q3 - 2*q2
	den := q3 - q1
	// Skew is zero when IQR < 10 or median equals a quartile
	// (under-sampled distribution; treating it as symmetric avoids
	// false-positive scores from tiny sample sets).
	if den < 10 || q2 == q1 || q2 == q3 {
		skew = 0
	} else {
		skew = num / den
	}
	score = 1 - math.Abs(skew)
	if score < 0 {
		score = 0
	}
	return skew, score
}

// MedianAbsoluteDeviation measures dispersion. Returns (mad, score)
// where score = (median - mad) / median, clamped to [0, 1]. Perfectly
// uniform data → mad=0 → score=1. Chaotic data → mad approaches median
// → score → 0.
//
// `defaultScore` is returned when median < 1 (avoids divide-by-zero
// for tiny-byte distributions where the median rounds to 0). Pass 1
// for timestamps and 0 for byte sizes.
func MedianAbsoluteDeviation(data []float64, defaultScore float64) (mad, score float64) {
	if len(data) == 0 {
		return 0, 0
	}
	sorted := make([]float64, len(data))
	copy(sorted, data)
	sort.Float64s(sorted)
	median := medianSorted(sorted)
	deviations := make([]float64, len(sorted))
	for i, v := range sorted {
		deviations[i] = math.Abs(v - median)
	}
	sort.Float64s(deviations)
	mad = medianSorted(deviations)
	if median < 1 {
		return mad, defaultScore
	}
	score = (median - mad) / median
	if score < 0 || math.IsNaN(score) {
		score = 0
	}
	return mad, score
}

// StatisticalScore combines BowleySkewness and MAD for a 0-1 "how
// uniform is this distribution" score. Averages the two equally for
// both TS and DS. `defaultMadScore` is 1 for timestamps, 0 for byte sizes.
func StatisticalScore(data []float64, defaultMadScore float64) float64 {
	if len(data) < 3 {
		return 0
	}
	_, skewScore := BowleySkewness(data)
	_, madScore := MedianAbsoluteDeviation(data, defaultMadScore)
	return (skewScore + madScore) / 2
}

// quartiles returns Q1, Q2 (median), Q3 of a SORTED slice.
// Uses linear interpolation between the two nearest ranks (R-7 method).
func quartiles(sorted []float64) (q1, q2, q3 float64) {
	n := len(sorted)
	if n == 0 {
		return 0, 0, 0
	}
	q1 = percentileSorted(sorted, 25)
	q2 = percentileSorted(sorted, 50)
	q3 = percentileSorted(sorted, 75)
	return
}

// percentileSorted returns the linear-interpolated percentile of a
// SORTED slice. p in [0, 100].
func percentileSorted(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n == 1 {
		return sorted[0]
	}
	rank := (p / 100) * float64(n-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if lo == hi {
		return sorted[lo]
	}
	frac := rank - float64(lo)
	return sorted[lo] + frac*(sorted[hi]-sorted[lo])
}

// medianSorted returns the median of a SORTED slice.
func medianSorted(sorted []float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// CoefficientOfVariation returns stddev/mean for a slice of values.
// Used by histogram-flatness scoring (CV check on hour-of-day
// connection counts). Returns 0 when mean is zero.
func CoefficientOfVariation(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	mean := 0.0
	for _, v := range data {
		mean += v
	}
	mean /= float64(len(data))
	if mean == 0 {
		return 0
	}
	variance := 0.0
	for _, v := range data {
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(data))
	stddev := math.Sqrt(variance)
	return stddev / mean
}
