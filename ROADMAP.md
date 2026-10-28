# ZeroL7 Roadmap — the "extreme" tier

Everything in this file is **not implemented** in the current codebase.
Each item below is a real, large body of systems-engineering work on its
own — the honest estimate is weeks each, not an afternoon — and faking any
of them (stub code that doesn't do what its name claims) would be worse
than leaving them out. This file exists so the gap between "what the
original brief described" and "what's actually in `pkg/`" is explicit
rather than something a reader has to discover by reading code.

## 1. eBPF/XDP kernel-level packet dropping
Hook an eBPF program into the NIC driver's XDP layer so a blacklisted IP's
packets are dropped (`XDP_DROP`) before they reach the kernel's TCP stack,
driven by a shared BPF map the Go process updates when the rate
limiter/WAF flags an IP. Needs: a C eBPF program compiled with clang,
`cilium/ebpf` (Go) to load/pin it and talk to the map, a privileged
container or host networking (XDP needs `CAP_NET_ADMIN` / `CAP_BPF` and
direct NIC access — it does not work inside an unprivileged Fargate task
at all), and a kernel recent enough to support the XDP hooks used.

## 2. DPDK userspace NIC bypass
Hand the physical NIC to the application and read raw Ethernet frames in
userspace, skipping the kernel network stack entirely. Requires DPDK's C
bindings (or a Go wrapper, with real caveats), a NIC that supports
DPDK-compatible drivers, hugepages configured on the host, and essentially
rewriting the TCP/IP handling this project currently gets for free from
`net.Listen`. Mutually exclusive with running in most container
orchestrators.

## 3. Raft-based cluster state sync
Replace the per-instance in-memory rate limiter/blacklist with a
Raft-replicated one so N proxy instances agree on one IP's token-bucket
state without a shared store like Redis. Requires implementing (or
carefully adopting) a Raft library (`hashicorp/raft` is the realistic
choice over hand-rolling consensus), a replicated log, leader election,
and a decision on consistency vs. latency trade-offs for a per-request hot
path — naively calling into Raft on every request would itself blow the
latency budget.

## 4. Custom QUIC/HTTP-3 engine
HTTP/3 over raw UDP: custom congestion control, loss recovery, and
connection migration. In practice no serious production system hand-rolls
QUIC from scratch (quic-go exists for exactly this reason); doing it from
raw UDP sockets as the brief describes is a research-grade project.

## 5. Semantic/AI WAF (ONNX embeddings + vector search)
Run a quantized embedding model over request bodies and match against a
vector index of known exploit shapes, as a third WAF layer alongside
regex + structural. Needs an ONNX runtime binding, a vetted small model, a
vector index (even an in-memory one), and real latency engineering to
keep inference inside the 2-3ms budget — likely requiring batching and
async scoring with a fallback to the cheaper layers under load.

## 6. Hardware offload (Intel QAT, SIMD/AVX-512, GPU/CUDA batching)
Offload TLS crypto to QAT hardware, vectorize the regex/token scan with
AVX-512, and batch WAF scoring to a GPU. Each needs specific hardware
present on the host (QAT cards, AVX-512-capable CPUs, a GPU) that a
generic container host does not provide, plus the corresponding
driver/SDK integration (`cloudflare/zlib-ng`-style SIMD tricks, CUDA
bindings).

## 7. Custom arena/zero-allocation memory architecture
Pre-allocate a large arena and hand out offsets instead of using Go's
allocator/GC for the per-request hot path. This fights Go's own memory
model (which this project otherwise leans on for the goroutine-per-
connection concurrency model); doing it right in Go specifically would
mean `unsafe`-heavy manual memory management, which is a different
engineering trade-off than "use Go" implies. More natural in Rust/C/C++;
noted here as a deliberately-not-pursued direction rather than a gap.

## 8. ACME (Let's Encrypt) client
Automate certificate issuance/renewal instead of loading a static
cert/key pair. `golang.org/x/crypto/acme/autocert` makes this a
relatively small addition on top of the existing `pkg/proxy/tls.go` — of
everything in this file, this is the one actually worth picking up next
if TLS automation becomes a real need.

## 9. GitOps (ArgoCD) deployment
CI here builds and tests; it does not push images to a registry or
trigger a cluster sync. Wiring ArgoCD needs a running Kubernetes cluster,
a registry to push to, and an Application manifest pointing at this
repo's `terraform/` or a Helm chart — none of which exist as reachable
infrastructure in this build environment. The honest next step, if a
cluster is available, is: CI pushes an image tag, a Kustomize/Helm overlay
in this repo (or a separate `gitops` repo) is updated with that tag, and
ArgoCD watches that repo rather than this one directly.
