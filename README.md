# ZeroL7

A custom L7 reverse proxy and Web Application Firewall, written in Go
without `net/http` on the request path: a raw TCP listener, a hand-rolled
HTTP/1.1 byte-stream parser, a streaming WAF (regex + structural/AST-style
analysis), a thread-safe per-IP token-bucket rate limiter, and a
round-robin/least-connections load balancer with active health checks —
plus hot-reloadable config, Prometheus metrics, OpenTelemetry tracing, a
Docker Compose deployment, a GitHub Actions CI/CD pipeline that runs k6
load/attack tests, and a Terraform skeleton for AWS infra.

This document is deliberately specific about what is actually implemented
and verified versus what's aspirational. See [ROADMAP.md](ROADMAP.md) for
the "extreme" features (eBPF/XDP, DPDK, Raft clustering, custom QUIC, GPU
inference, ACME) that are **not** implemented here.

## Architecture

```
 Client
   │ TCP (or TLS, if tls_cert_file/tls_key_file are set)
   ▼
 pkg/proxy.Server           - net.Listen, one goroutine per connection
   │
   ▼
 pkg/proxy.ParseRequest     - state-machine byte parser (no net/http)
   │
   ▼
 per-IP token bucket        - pkg/ratelimit (429 if exhausted)
   │
   ▼
 WAF engine                 - pkg/waf (regex signatures + structural
   │                           token-shape analysis; 403 if blocked)
   ▼
 Router + balancer          - pkg/router (longest-prefix match,
   │                           round_robin / least_conn, health-checked)
   ▼
 Upstream (pooled TCP conn, response parsed to forward exact framing)
```

Each stage is covered by its own package and unit tests
(`go test ./...`); `tests/load_test.js` exercises the whole chain under
concurrent benign *and* attack traffic via k6.

## What's real here

- **No `net/http` on the hot path.** `pkg/proxy/parser.go` is a bounded
  state machine that finds the request line, headers, and the
  `\r\n\r\n` boundary itself, tracking `Content-Length` / chunked framing.
  The same approach parses upstream responses (`ParseResponse`) so pooled
  backend connections can be reused safely — forwarding relies on knowing
  the exact body length, not on waiting for EOF.
- **Concurrency model**: one goroutine per connection. This *is* Go's
  non-blocking I/O model — the runtime's netpoller (epoll/kqueue) parks a
  goroutine on a blocking read/write without blocking an OS thread, so
  "thousands of concurrent connections" costs goroutine stacks (KBs), not
  OS threads. This is the honest Go equivalent of the C10K-style
  async/non-blocking servers described in the original brief; it is not a
  hand-rolled epoll event loop.
- **WAF engine** (`pkg/waf`): a regex signature set for common
  SQLi/XSS/path-traversal strings, plus a second, independent pass
  (`ast_matcher.go`) that tokenizes the payload once (O(n), no
  backtracking) and matches *shapes* — a `<keyword> <operand> <operator>
  <operand>` predicate clause, multiple SQL clause keywords, an
  event-handler attribute directly followed by `=` — so casing/spacing
  obfuscation that defeats a literal string list still gets caught. This
  is an honest, single-pass **structural token analyzer**, not a
  recursive-descent SQL/HTML parser; see Limitations below for what that
  means it misses. Go's `regexp` is RE2-based, so the regex pass itself
  cannot suffer catastrophic-backtracking ReDoS regardless of input.
  Payloads are percent-decoded before inspection (attackers encode `'` as
  `%27`, `<` as `%3C`, etc.) — the original bytes are still what's
  forwarded upstream. `pkg/waf/engine_test.go` includes a latency-budget
  test asserting inspection stays under 3ms for representative payloads.
- **Rate limiting** (`pkg/ratelimit`): a real thread-safe token bucket per
  client IP (mutex per bucket, not a global lock), with a background
  janitor evicting idle buckets so long-running processes don't leak
  memory over an unbounded set of client IPs.
- **Routing/load balancing** (`pkg/router`): longest-prefix-match routing
  to a pool of backends, round-robin or least-connections selection among
  currently-healthy backends only, and an active health checker that
  flips backends in/out of rotation without touching in-flight
  connections.
- **Hot config reload** (`pkg/configwatch`): `fsnotify` watches
  `config.yaml`, and `SIGHUP` also triggers a reload; a new `Config` is
  parsed and swapped in behind an `atomic.Pointer` — in-flight requests
  keep running against the old snapshot, new ones see the new one. No
  restart, no dropped connections.
- **TLS termination** (`pkg/proxy/tls.go`): real `crypto/tls` termination
  from a cert/key file pair (TLS 1.2+, a modern cipher suite list) — not
  mocked. An ACME/Let's-Encrypt client is explicitly *not* implemented
  (see Roadmap).
- **Observability**: Prometheus metrics
  (`zerol7_requests_total{outcome=...}`, `zerol7_waf_blocks_total`,
  `zerol7_waf_inspection_seconds`, `zerol7_rate_limit_drops_total`,
  `zerol7_upstream_latency_seconds`, `zerol7_active_connections`) served
  at `:9090/metrics`, a Grafana dashboard provisioned automatically in
  Docker Compose, and OpenTelemetry tracing (one span per request with
  `waf.inspect` / `upstream.forward` child spans) exported over OTLP/HTTP
  to Jaeger. Tracing is optional and fails open — if the collector is
  unreachable, requests are still served.
- **CI/CD** (`.github/workflows/ci-cd.yml`): build + `go vet` + unit tests
  with the race detector → build both container images → spin up the real
  proxy + a mock backend in Docker on the runner → **assert WAF blocks a
  live SQLi/XSS request** → run the k6 scenario that mixes 50 concurrent
  benign users with simulated attack traffic → `terraform fmt`/`validate`.
  A load test that passes only verifies throughput; this pipeline also
  gates on the WAF actually blocking something before measuring load.

## Running it

### Locally (Go toolchain)

```bash
go run ./cmd/mockbackend   # in one terminal, LISTEN_ADDR=:8090
go run ./cmd/proxy -config config/config.yaml
```

### Docker Compose (proxy + 3 backends + Prometheus + Grafana + Jaeger)

```bash
docker compose up --build
```

- Proxy: `http://localhost:8080`
- Metrics: `http://localhost:9090/metrics`
- Prometheus: `http://localhost:9091`
- Grafana: `http://localhost:3000` (anonymous viewer access; admin/admin)
- Jaeger UI: `http://localhost:16686`

Try it:

```bash
curl -i http://localhost:8080/api/users           # 200, round-robins across backends
curl -i "http://localhost:8080/search?q=1%27%20OR%20%271%27%3D%271"   # 403, blocked by the WAF
```

### Load + attack test

```bash
k6 run -e BASE_URL=http://localhost:8080 tests/load_test.js
```

### Hot-reloading config

```bash
$EDITOR config/config.yaml   # e.g. add a WAF rule or an upstream
kill -HUP $(pgrep -f cmd/proxy)   # or just save the file — fsnotify picks it up too
```

## Deploying

`terraform/` provisions the declarative AWS side (VPC, public/private
subnets, NAT, an ALB, an ECS Fargate cluster/service/task running the
proxy image, CloudWatch logs, security groups scoped so only the ALB can
reach the task). It has been format-checked and HCL-syntax-validated
(`terraform fmt -check`); actually applying it needs real AWS credentials
and an already-pushed container image (`var.proxy_image`), neither of
which exist in this build environment — the CI job runs
`terraform validate` on every push instead of `apply`. A GitOps
controller (ArgoCD, per the original brief) is not wired up here: see
[ROADMAP.md](ROADMAP.md).

```bash
cd terraform
terraform init
terraform apply -var="proxy_image=<your-ecr-repo>:<tag>"
```

## Limitations (read this before relying on it)

- **Structural analyzer, not a parser.** `ast_matcher.go` is a one-pass
  tokenizer with shape-matching, not a real SQL/HTML grammar. It will
  miss sufficiently creative obfuscation (e.g. SQL hidden inside a valid
  JSON string value with no predicate-shaped token run) and can in
  principle false-positive on legitimate text that happens to contain
  several SQL keywords close together. It trades completeness for a
  hard latency ceiling, by design.
- **Chunked request bodies bypass body inspection.** URL, headers, and
  non-chunked bodies (up to `waf.max_body_bytes`) are inspected; a
  chunked request body is relayed chunk-by-chunk without being buffered
  or scanned. Fixing this means dechunking into the inspection path
  without losing the proxy's streaming property — not done here.
- **HTTP/2 is not implemented.** The parser is HTTP/1.1 only.
- **No eBPF/XDP, no DPDK, no Raft clustering, no custom QUIC/HTTP-3, no
  GPU/ONNX semantic WAF, no Intel QAT offload, no ACME client, no custom
  arena allocator.** These were all discussed as "extreme" stretch goals;
  building any one of them correctly is its own multi-week project, and
  faking them would be worse than not having them. They're listed with
  honest scope estimates in [ROADMAP.md](ROADMAP.md).
- **ArgoCD/GitOps isn't wired up.** CI builds and tests; it does not
  push to a registry or trigger a cluster sync, since there's no cluster
  or registry credential available in this environment.

## Repository layout

```
cmd/proxy/           entry point: wires config, router, WAF, rate limiter, tracing, metrics
cmd/mockbackend/      trivial JSON backend used by docker-compose and CI
pkg/proxy/            raw listener, HTTP/1.1 parser (request + response), TLS, dial pool
pkg/router/           path routing, round_robin/least_conn balancing, health checks
pkg/waf/              regex signatures, structural analyzer, inspection engine
pkg/ratelimit/        per-IP token bucket
pkg/configwatch/      YAML config + fsnotify/SIGHUP hot reload
pkg/metrics/          Prometheus collectors
pkg/tracing/          OpenTelemetry/OTLP wiring
config/               config.yaml (local), config.docker.yaml, config.ci.yaml
tests/                k6 load/attack test + exploit_payloads.json
terraform/            AWS VPC/ALB/ECS Fargate declarative infra
grafana/, prometheus/ dashboard + scrape config for docker-compose
.github/workflows/    CI: build/test/vet -> docker build -> live WAF+load test -> terraform validate
```
