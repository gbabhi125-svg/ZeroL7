// Package metrics exposes ZeroL7's Prometheus metrics.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	RequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "zerol7_requests_total",
		Help: "Total requests received by the proxy, by outcome.",
	}, []string{"outcome"}) // forwarded | blocked_waf | rate_limited | bad_request | no_upstream

	WAFBlocksTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "zerol7_waf_blocks_total",
		Help: "Requests blocked by the WAF, by rule category.",
	}, []string{"category", "rule"})

	WAFInspectionSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "zerol7_waf_inspection_seconds",
		Help:    "Time spent running the WAF engine against a single payload.",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.002, 0.003, 0.005, 0.01, 0.02, 0.05},
	})

	RateLimitDropsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "zerol7_rate_limit_drops_total",
		Help: "Requests dropped by the per-IP token bucket limiter.",
	})

	UpstreamLatencySeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "zerol7_upstream_latency_seconds",
		Help:    "Time spent waiting for an upstream response.",
		Buckets: prometheus.DefBuckets,
	}, []string{"backend"})

	BackendHealthy = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "zerol7_backend_healthy",
		Help: "1 if the backend is currently considered healthy, else 0.",
	}, []string{"backend"})

	ActiveConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "zerol7_active_connections",
		Help: "Number of currently-open client connections.",
	})
)

// Handler returns the HTTP handler to mount at /metrics.
func Handler() http.Handler {
	return promhttp.Handler()
}
