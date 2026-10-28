// Package proxy implements ZeroL7's raw-socket listener and a hand-rolled
// HTTP/1.1 byte-stream parser. net/http is deliberately not used: the proxy
// needs to see and forward the exact header/body boundary itself so the WAF
// can inspect the stream before any bytes reach an upstream.
package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

var (
	ErrMalformedRequest = errors.New("malformed http request")
	ErrHeadersTooLarge  = errors.New("request headers exceed limit")
)

// Request is a parsed HTTP/1.1 request line + headers. Body is read
// separately (streamed) once headers are known, so large bodies never need
// to be buffered whole before routing decisions are made.
type Request struct {
	Method      string
	Path        string
	RawPath     string
	Query       string
	Version     string
	Headers     map[string][]string
	ContentLen  int64
	Chunked     bool
	HeaderBytes []byte // raw header block, for size accounting / logging
}

func (r *Request) Header(name string) string {
	vals := r.Headers[strings.ToLower(name)]
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// ParseRequest reads a request line and headers from br, stopping at the
// \r\n\r\n boundary. It is a small explicit state machine: request-line ->
// headers -> done. maxHeaderBytes bounds memory used per connection.
func ParseRequest(br *bufio.Reader, maxHeaderBytes int) (*Request, error) {
	req := &Request{Headers: make(map[string][]string)}
	var headerBuf []byte

	line, err := readLine(br, maxHeaderBytes)
	if err != nil {
		return nil, err
	}
	headerBuf = append(headerBuf, line...)
	headerBuf = append(headerBuf, '\n')
	if err := parseRequestLine(line, req); err != nil {
		return nil, err
	}

	for {
		if len(headerBuf) > maxHeaderBytes {
			return nil, ErrHeadersTooLarge
		}
		line, err = readLine(br, maxHeaderBytes)
		if err != nil {
			return nil, err
		}
		if len(line) == 0 {
			break // blank line => \r\n\r\n boundary reached
		}
		headerBuf = append(headerBuf, line...)
		headerBuf = append(headerBuf, '\n')

		name, value, err := parseHeaderLine(line)
		if err != nil {
			return nil, err
		}
		key := strings.ToLower(name)
		req.Headers[key] = append(req.Headers[key], value)
	}
	req.HeaderBytes = headerBuf

	if cl := req.Header("Content-Length"); cl != "" {
		n, err := strconv.ParseInt(strings.TrimSpace(cl), 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%w: bad content-length", ErrMalformedRequest)
		}
		req.ContentLen = n
	}
	if strings.EqualFold(req.Header("Transfer-Encoding"), "chunked") {
		req.Chunked = true
	}
	return req, nil
}

// readLine reads up to and excluding a trailing \r\n (or \n), bounding the
// line length so a client cannot exhaust memory with an unterminated line.
func readLine(br *bufio.Reader, max int) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		buf = append(buf, chunk...)
		if err == bufio.ErrBufferFull {
			if len(buf) > max {
				return nil, ErrHeadersTooLarge
			}
			continue
		}
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				break
			}
			return nil, err
		}
		break
	}
	buf = trimCRLF(buf)
	if len(buf) > max {
		return nil, ErrHeadersTooLarge
	}
	return buf, nil
}

// trimCRLF strips a single trailing \n and, if present, \r before it.
func trimCRLF(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	if n := len(b); n > 0 && b[n-1] == '\r' {
		b = b[:n-1]
	}
	return b
}

func parseRequestLine(line []byte, req *Request) error {
	parts := strings.SplitN(string(line), " ", 3)
	if len(parts) != 3 {
		return fmt.Errorf("%w: bad request line %q", ErrMalformedRequest, line)
	}
	req.Method = parts[0]
	target := parts[1]
	req.Version = parts[2]

	if !strings.HasPrefix(req.Version, "HTTP/1.") {
		return fmt.Errorf("%w: unsupported version %q", ErrMalformedRequest, req.Version)
	}
	req.RawPath = target
	if i := strings.IndexByte(target, '?'); i >= 0 {
		req.Path = target[:i]
		req.Query = target[i+1:]
	} else {
		req.Path = target
	}
	if req.Method == "" || req.Path == "" {
		return fmt.Errorf("%w: empty method/path", ErrMalformedRequest)
	}
	return nil
}

func parseHeaderLine(line []byte) (name, value string, err error) {
	i := strings_IndexByte(line, ':')
	if i < 0 {
		return "", "", fmt.Errorf("%w: bad header %q", ErrMalformedRequest, line)
	}
	name = string(line[:i])
	value = strings.TrimSpace(string(line[i+1:]))
	if name == "" {
		return "", "", fmt.Errorf("%w: empty header name", ErrMalformedRequest)
	}
	return name, value, nil
}

// Response is a parsed HTTP/1.1 status line + headers, read the same way
// Request is: a bounded state machine stopping at \r\n\r\n.
type Response struct {
	Version    string
	StatusCode int
	StatusText string
	Headers    map[string][]string
	StatusLine []byte
	HeaderLine [][]byte
	ContentLen int64
	Chunked    bool
	NoBody     bool // HEAD responses, 204, 304 — no body regardless of headers
}

func (r *Response) Header(name string) string {
	vals := r.Headers[strings.ToLower(name)]
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func ParseResponse(br *bufio.Reader, maxHeaderBytes int) (*Response, error) {
	resp := &Response{Headers: make(map[string][]string)}

	line, err := readLine(br, maxHeaderBytes)
	if err != nil {
		return nil, err
	}
	resp.StatusLine = line
	parts := strings.SplitN(string(line), " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("%w: bad status line %q", ErrMalformedRequest, line)
	}
	resp.Version = parts[0]
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: bad status code %q", ErrMalformedRequest, parts[1])
	}
	resp.StatusCode = code
	if len(parts) == 3 {
		resp.StatusText = parts[2]
	}

	total := len(line)
	for {
		line, err = readLine(br, maxHeaderBytes)
		if err != nil {
			return nil, err
		}
		if len(line) == 0 {
			break
		}
		total += len(line)
		if total > maxHeaderBytes {
			return nil, ErrHeadersTooLarge
		}
		resp.HeaderLine = append(resp.HeaderLine, line)
		name, value, err := parseHeaderLine(line)
		if err != nil {
			return nil, err
		}
		key := strings.ToLower(name)
		resp.Headers[key] = append(resp.Headers[key], value)
	}

	if cl := resp.Header("Content-Length"); cl != "" {
		n, err := strconv.ParseInt(strings.TrimSpace(cl), 10, 64)
		if err == nil && n >= 0 {
			resp.ContentLen = n
		}
	}
	if strings.EqualFold(resp.Header("Transfer-Encoding"), "chunked") {
		resp.Chunked = true
	}
	resp.NoBody = resp.StatusCode == 204 || resp.StatusCode == 304
	return resp, nil
}

func strings_IndexByte(b []byte, c byte) int {
	for i, bb := range b {
		if bb == c {
			return i
		}
	}
	return -1
}
