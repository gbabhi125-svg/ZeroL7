// Package tracing wires up OpenTelemetry so each request's path through the
// proxy — inspection, then forwarding — shows up as a trace exportable to
// Jaeger (or any OTLP-HTTP backend). This is deliberately a thin layer: one
// span per request with child spans for the WAF and upstream-forward
// stages, not a claim of full distributed context propagation into
// arbitrary downstream backends.
package tracing

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

var tracer trace.Tracer = otel.Tracer("zerol7-noop")

// Init configures the global tracer provider to export spans over OTLP/HTTP
// to endpoint (e.g. "jaeger:4318"). Call once at startup; until it succeeds
// (or if it's never called) spans are recorded against a no-op tracer, so
// tracing is strictly optional and failure to reach Jaeger never blocks
// request handling.
func Init(ctx context.Context, serviceName, endpoint string) (shutdown func(context.Context) error, err error) {
	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	res, err := resource.New(ctx, resource.WithAttributes(
		semconv.ServiceName(serviceName),
	))
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(2*time.Second)),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	tracer = tp.Tracer("zerol7")
	return tp.Shutdown, nil
}

func StartRequestSpan(ctx context.Context, method, path string) (context.Context, trace.Span) {
	return tracer.Start(ctx, "zerol7.request", trace.WithAttributes(
		attribute.String("http.method", method),
		attribute.String("http.target", path),
	))
}

func StartChildSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	return tracer.Start(ctx, name)
}

func SetOutcome(span trace.Span, outcome string) {
	span.SetAttributes(attribute.String("zerol7.outcome", outcome))
}
