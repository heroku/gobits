package testmetrics

import (
	"sync"

	"github.com/go-kit/kit/metrics"
)

// Counter accumulates a value based on Add calls.
type Counter struct{ value float64 }

// Add implements the metrics.Counter interface.
func (c *Counter) Add(delta float64) { c.value += delta }

// With implements the metrics.Counter interface.
func (c *Counter) With(...string) metrics.Counter { return c }

// Gauge stores a value based on Add/Set calls.
type Gauge struct {
	value float64
	sync.RWMutex
}

// Add implements the metrics.Gauge interface.
func (g *Gauge) Add(delta float64) {
	g.Lock()
	defer g.Unlock()
	g.value += delta
}

// Set implements the metrics.Gauge interface.
func (g *Gauge) Set(v float64) {
	g.Lock()
	defer g.Unlock()
	g.value = v
}

// With implements the metrics.Gauge interface.
func (g *Gauge) With(...string) metrics.Gauge { return g }

func (g *Gauge) getValue() float64 {
	g.RLock()
	defer g.RUnlock()
	return g.value
}

// Histogram collects observations without computing quantiles
// so the observations can be checked by tests.
type Histogram struct {
	observations []float64
	sync.RWMutex
}

func (h *Histogram) getObservations() []float64 {
	h.RLock()
	defer h.RUnlock()

	o := h.observations
	return o
}

// Observe implements the metrics.Histogram interface.
func (h *Histogram) Observe(v float64) {
	h.Lock()
	defer h.Unlock()
	h.observations = append(h.observations, v)
}

// With implements the metrics.Histogram interface.
func (h *Histogram) With(...string) metrics.Histogram { return h }
