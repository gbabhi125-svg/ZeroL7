package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"context"

	"github.com/gbabhi125-svg/ZeroL7/pkg/configwatch"
	"github.com/gbabhi125-svg/ZeroL7/pkg/metrics"
	"github.com/gbabhi125-svg/ZeroL7/pkg/ratelimit"
	"github.com/gbabhi125-svg/ZeroL7/pkg/router"
	"github.com/gbabhi125-svg/ZeroL7/pkg/tracing"
	"github.com/gbabhi125-svg/ZeroL7/pkg/waf"
)

// Server is the L7 proxy's raw-socket listener. It is "asynchronous /
// non-blocking" in the sense Go's runtime provides out of the box: each
// connection is a goroutine, and goroutines that block on network I/O are
// descheduled from their OS thread by the Go scheduler's own netpoller
// (epoll/kqueue under the hood), so thousands of concurrent connections cost
// kilobytes of goroutine stack each, not one OS thread each.
type Server struct {
	cfgWatcher *configwatch.Watcher
	router     *router.Router
	limiter    *ratelimit.Limiter
	wafEngine  *waf.Engine
	dialPool   *DialPool

	maxHeaderBytes int
	readTimeout    time.Duration
	writeTimeout   time.Duration
	maxWAFBody     int64
	blockOnAST     bool
}

func NewServer(cfgWatcher *configwatch.Watcher, rtr *router.Router) *Server {
	cfg := cfgWatcher.Current()
	s := &Server{
		cfgWatcher:     cfgWatcher,
		router:         rtr,
		limiter:        ratelimit.New(cfg.RateLimit.RequestsPerSecond, cfg.RateLimit.Burst),
		dialPool:       NewDialPool(32, 3*time.Second),
		maxHeaderBytes: cfg.Server.MaxHeaderBytes,
		readTimeout:    time.Duration(cfg.Server.ReadTimeoutMs) * time.Millisecond,
		writeTimeout:   time.Duration(cfg.Server.WriteTimeoutMs) * time.Millisecond,
		maxWAFBody:     cfg.WAF.MaxBodyBytes,
		blockOnAST:     cfg.WAF.BlockOnAST,
	}
	s.rebuildWAF(cfg)

	cfgWatcher.OnReload(func(newCfg *configwatch.Config) {
		s.rebuildWAF(newCfg)
		s.maxHeaderBytes = newCfg.Server.MaxHeaderBytes
		s.readTimeout = time.Duration(newCfg.Server.ReadTimeoutMs) * time.Millisecond
		s.writeTimeout = time.Duration(newCfg.Server.WriteTimeoutMs) * time.Millisecond
		s.maxWAFBody = newCfg.WAF.MaxBodyBytes
		s.blockOnAST = newCfg.WAF.BlockOnAST
	})
	return s
}

func (s *Server) rebuildWAF(cfg *configwatch.Config) {
	var compiled []*waf.CompiledRule
	if len(cfg.WAF.Rules) == 0 {
		compiled = waf.CompileDefaultRules()
	} else {
		for _, r := range cfg.WAF.Rules {
			cr, err := waf.CompileRule(r.Name, r.Pattern, r.Category, r.Action)
			if err != nil {
				log.Printf("waf: skipping invalid rule %q: %v", r.Name, err)
				continue
			}
			compiled = append(compiled, cr)
		}
	}
	s.wafEngine = waf.NewEngine(compiled, cfg.WAF.BlockOnAST)
}

// ListenAndServe opens the raw TCP listener and accepts connections until
// the listener is closed.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("zerol7: listening on %s (plaintext)", addr)
	return s.serve(ln)
}

// ListenAndServeTLS opens a TLS-terminating TCP listener. The HTTP parser,
// WAF, rate limiter and router downstream of Accept() are identical in
// either mode — net.Conn hides whether a connection is tls.Conn.
func (s *Server) ListenAndServeTLS(addr, certFile, keyFile string) error {
	tlsCfg, err := LoadTLSConfig(certFile, keyFile)
	if err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return err
	}
	log.Printf("zerol7: listening on %s (TLS)", addr)
	return s.serve(ln)
}

func (s *Server) serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	metrics.ActiveConnections.Inc()
	defer metrics.ActiveConnections.Dec()
	defer conn.Close()

	clientIP := remoteIP(conn)
	br := bufio.NewReader(conn)

	for {
		if s.readTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(s.readTimeout))
		}

		if !s.limiter.Allow(clientIP) {
			metrics.RateLimitDropsTotal.Inc()
			metrics.RequestsTotal.WithLabelValues("rate_limited").Inc()
			writeSimpleResponse(conn, 429, "Too Many Requests", "rate limit exceeded")
			return
		}

		req, err := ParseRequest(br, s.maxHeaderBytes)
		if err != nil {
			if err != io.EOF {
				metrics.RequestsTotal.WithLabelValues("bad_request").Inc()
				writeSimpleResponse(conn, 400, "Bad Request", err.Error())
			}
			return
		}

		keepAlive := s.handleRequest(conn, br, req, clientIP)
		if !keepAlive {
			return
		}
	}
}

// handleRequest inspects and forwards one request. It returns whether the
// client connection should stay open for another request (keep-alive).
func (s *Server) handleRequest(conn net.Conn, br *bufio.Reader, req *Request, clientIP string) bool {
	ctx, reqSpan := tracing.StartRequestSpan(context.Background(), req.Method, req.Path)
	defer reqSpan.End()

	keepAlive := !strings.EqualFold(req.Header("Connection"), "close") && req.Version != "HTTP/1.0"

	// Drain/buffer a bounded prefix of the body up front: the WAF must see
	// it before any byte reaches an upstream, but a slow/huge body must not
	// let a client stall other work or exhaust memory.
	bodyPrefix, remaining, err := s.readBodyPrefix(br, req)
	if err != nil {
		metrics.RequestsTotal.WithLabelValues("bad_request").Inc()
		tracing.SetOutcome(reqSpan, "bad_request")
		writeSimpleResponse(conn, 400, "Bad Request", "invalid request body")
		return false
	}

	_, wafSpan := tracing.StartChildSpan(ctx, "waf.inspect")
	// Attackers routinely percent-encode payloads (%27 for ', %3C for <);
	// decode before inspection or literal-character signatures and the
	// structural tokenizer both miss them entirely.
	inspectPayload := decodeForInspection(req.RawPath) + " " +
		decodeForInspection(req.Header("User-Agent")) + " " +
		decodeForInspection(req.Header("Cookie")) + " " +
		decodeForInspection(string(bodyPrefix))
	start := time.Now()
	decision := s.wafEngine.Inspect(inspectPayload)
	metrics.WAFInspectionSeconds.Observe(time.Since(start).Seconds())
	wafSpan.End()

	if decision.Blocked {
		metrics.WAFBlocksTotal.WithLabelValues(decision.Category, decision.RuleName).Inc()
		metrics.RequestsTotal.WithLabelValues("blocked_waf").Inc()
		tracing.SetOutcome(reqSpan, "blocked_waf")
		writeSimpleResponse(conn, 403, "Forbidden", fmt.Sprintf("request blocked by WAF rule %q", decision.RuleName))
		drainRemaining(br, remaining)
		return false
	}

	pool := s.router.Match(req.Path)
	if pool == nil {
		metrics.RequestsTotal.WithLabelValues("no_upstream").Inc()
		tracing.SetOutcome(reqSpan, "no_upstream")
		writeSimpleResponse(conn, 404, "Not Found", "no route for path")
		drainRemaining(br, remaining)
		return false
	}
	backend := pool.Pick()
	if backend == nil {
		metrics.RequestsTotal.WithLabelValues("no_upstream").Inc()
		tracing.SetOutcome(reqSpan, "no_upstream")
		writeSimpleResponse(conn, 503, "Service Unavailable", "no healthy backend")
		drainRemaining(br, remaining)
		return false
	}

	backend.Acquire()
	defer backend.Release()

	_, fwdSpan := tracing.StartChildSpan(ctx, "upstream.forward")
	upstreamStart := time.Now()
	ok := s.forward(conn, br, req, bodyPrefix, remaining, backend)
	metrics.UpstreamLatencySeconds.WithLabelValues(backend.Address).Observe(time.Since(upstreamStart).Seconds())
	fwdSpan.End()
	if !ok {
		tracing.SetOutcome(reqSpan, "upstream_error")
		return false
	}
	metrics.RequestsTotal.WithLabelValues("forwarded").Inc()
	tracing.SetOutcome(reqSpan, "forwarded")
	return keepAlive
}

// readBodyPrefix reads up to maxWAFBody bytes of a non-chunked body for
// inspection and returns the remaining declared length still to be streamed
// from the client. Chunked bodies are not buffered for inspection (only the
// URL/headers are inspected) — see docs/LIMITATIONS.md.
func (s *Server) readBodyPrefix(br *bufio.Reader, req *Request) (prefix []byte, remaining int64, err error) {
	if req.Chunked || req.ContentLen == 0 {
		return nil, 0, nil
	}
	toRead := req.ContentLen
	if toRead > s.maxWAFBody {
		toRead = s.maxWAFBody
	}
	buf := make([]byte, toRead)
	if _, err := io.ReadFull(br, buf); err != nil {
		return nil, 0, err
	}
	return buf, req.ContentLen - toRead, nil
}

func drainRemaining(br *bufio.Reader, remaining int64) {
	if remaining > 0 {
		io.CopyN(io.Discard, br, remaining)
	}
}

// forward writes the request to the chosen backend (reusing a pooled
// connection when available) and relays the response back to the client.
func (s *Server) forward(client net.Conn, clientBR *bufio.Reader, req *Request, bodyPrefix []byte, remaining int64, backend *router.Backend) bool {
	upstream, err := s.dialPool.Get(backend.Address)
	if err != nil {
		writeSimpleResponse(client, 502, "Bad Gateway", "could not reach upstream")
		return false
	}

	if err := writeUpstreamRequest(upstream, req, bodyPrefix); err != nil {
		s.dialPool.Discard(upstream)
		writeSimpleResponse(client, 502, "Bad Gateway", "upstream write failed")
		return false
	}
	if remaining > 0 {
		if _, err := io.CopyN(upstream, clientBR, remaining); err != nil {
			s.dialPool.Discard(upstream)
			writeSimpleResponse(client, 502, "Bad Gateway", "upstream write failed")
			return false
		}
	}
	if req.Chunked {
		// Chunked request bodies bypass body inspection (see readBodyPrefix)
		// and are relayed chunk-by-chunk as received.
		if err := copyChunked(upstream, clientBR); err != nil {
			s.dialPool.Discard(upstream)
			writeSimpleResponse(client, 502, "Bad Gateway", "upstream write failed")
			return false
		}
	}

	upstreamBR := bufio.NewReader(upstream)
	resp, err := ParseResponse(upstreamBR, s.maxHeaderBytes)
	if err != nil {
		s.dialPool.Discard(upstream)
		writeSimpleResponse(client, 502, "Bad Gateway", "invalid upstream response")
		return false
	}

	if err := writeResponseHead(client, resp); err != nil {
		s.dialPool.Discard(upstream)
		return false
	}

	reusable := true
	switch {
	case resp.NoBody || req.Method == "HEAD":
		// no body to relay
	case resp.Chunked:
		if err := copyChunked(client, upstreamBR); err != nil {
			reusable = false
		}
	case resp.ContentLen > 0:
		if _, err := io.CopyN(client, upstreamBR, resp.ContentLen); err != nil {
			reusable = false
		}
	default:
		// No Content-Length and not chunked: upstream intends to close the
		// connection after this response (HTTP/1.0-style framing).
		io.Copy(client, upstreamBR)
		reusable = false
	}

	if strings.EqualFold(resp.Header("Connection"), "close") {
		reusable = false
	}

	if reusable {
		s.dialPool.Put(backend.Address, upstream)
	} else {
		s.dialPool.Discard(upstream)
	}
	return true
}

func writeResponseHead(w io.Writer, resp *Response) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %d %s\r\n", resp.Version, resp.StatusCode, resp.StatusText)
	for _, line := range resp.HeaderLine {
		b.Write(line)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// copyChunked relays a chunked body chunk-by-chunk, preserving exact framing
// without buffering the whole body in memory.
func copyChunked(dst io.Writer, src *bufio.Reader) error {
	for {
		sizeLine, err := src.ReadString('\n')
		if err != nil {
			return err
		}
		if _, err := io.WriteString(dst, sizeLine); err != nil {
			return err
		}
		sizeHex := strings.TrimSpace(strings.SplitN(sizeLine, ";", 2)[0])
		size, err := strconv.ParseInt(sizeHex, 16, 64)
		if err != nil {
			return fmt.Errorf("bad chunk size %q: %w", sizeHex, err)
		}
		if size == 0 {
			// trailing headers (trailers), terminated by a blank line
			for {
				line, err := src.ReadString('\n')
				if err != nil {
					return err
				}
				io.WriteString(dst, line)
				if strings.TrimRight(line, "\r\n") == "" {
					return nil
				}
			}
		}
		if _, err := io.CopyN(dst, src, size); err != nil {
			return err
		}
		crlf := make([]byte, 2)
		if _, err := io.ReadFull(src, crlf); err != nil {
			return err
		}
		dst.Write(crlf)
	}
}

func writeUpstreamRequest(w io.Writer, req *Request, bodyPrefix []byte) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\n", req.Method, req.RawPath, req.Version)
	for name, vals := range req.Headers {
		for _, v := range vals {
			fmt.Fprintf(&b, "%s: %s\r\n", name, v)
		}
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(w, b.String()); err != nil {
		return err
	}
	if len(bodyPrefix) > 0 {
		if _, err := w.Write(bodyPrefix); err != nil {
			return err
		}
	}
	return nil
}

func writeSimpleResponse(w io.Writer, status int, statusText, body string) {
	resp := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, statusText, len(body), body,
	)
	io.WriteString(w, resp)
}

// decodeForInspection best-effort percent-decodes a value for WAF purposes
// only (the original bytes are what's actually forwarded upstream). Falling
// back to the raw string on a decode error is deliberate: a malformed
// %-sequence should still be scanned, not dropped.
func decodeForInspection(s string) string {
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return decoded
}

func remoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}
