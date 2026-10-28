package proxy

import (
	"bufio"
	"strings"
	"testing"
)

func TestParseRequestBasic(t *testing.T) {
	raw := "GET /api/users?id=42 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(raw))

	req, err := ParseRequest(br, 4096)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "GET" || req.Path != "/api/users" || req.Query != "id=42" {
		t.Fatalf("parsed request wrong: %+v", req)
	}
	if req.Header("Host") != "example.com" {
		t.Fatalf("expected Host header, got %q", req.Header("Host"))
	}
}

func TestParseRequestWithContentLength(t *testing.T) {
	raw := "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello world"
	br := bufio.NewReader(strings.NewReader(raw))

	req, err := ParseRequest(br, 4096)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.ContentLen != 11 {
		t.Fatalf("expected content length 11, got %d", req.ContentLen)
	}
	body := make([]byte, 11)
	if _, err := br.Read(body); err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	if string(body) != "hello world" {
		t.Fatalf("unexpected body: %q", body)
	}
}

func TestParseRequestRejectsMalformedLine(t *testing.T) {
	raw := "NOTAREALREQUESTLINE\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(raw))

	if _, err := ParseRequest(br, 4096); err == nil {
		t.Fatal("expected malformed request line to error")
	}
}

func TestParseRequestEnforcesHeaderLimit(t *testing.T) {
	huge := strings.Repeat("X-Pad: "+strings.Repeat("a", 200)+"\r\n", 100)
	raw := "GET / HTTP/1.1\r\n" + huge + "\r\n"
	br := bufio.NewReader(strings.NewReader(raw))

	if _, err := ParseRequest(br, 256); err == nil {
		t.Fatal("expected oversized headers to be rejected")
	}
}

func TestParseResponseBasic(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	br := bufio.NewReader(strings.NewReader(raw))

	resp, err := ParseResponse(br, 4096)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 || resp.ContentLen != 5 {
		t.Fatalf("parsed response wrong: %+v", resp)
	}
}
