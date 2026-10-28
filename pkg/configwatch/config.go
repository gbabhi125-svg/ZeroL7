// Package configwatch loads ZeroL7's YAML configuration and keeps it
// hot-reloadable: a file change or SIGHUP produces a new immutable Config
// snapshot without dropping in-flight connections.
package configwatch

import (
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

type RateLimitConfig struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
}

type WAFRule struct {
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	Category string `yaml:"category"`
	Action   string `yaml:"action"` // "block" or "log"
}

type WAFConfig struct {
	Enabled      bool      `yaml:"enabled"`
	MaxBodyBytes int64     `yaml:"max_body_bytes"`
	BlockOnAST   bool      `yaml:"block_on_ast_anomaly"`
	Rules        []WAFRule `yaml:"rules"`
}

type Upstream struct {
	Address string `yaml:"address"`
	Weight  int    `yaml:"weight"`
}

type Route struct {
	PathPrefix string     `yaml:"path_prefix"`
	Strategy   string     `yaml:"strategy"` // round_robin | least_conn
	Upstreams  []Upstream `yaml:"upstreams"`
}

type HealthCheckConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Path     string `yaml:"path"`
	Interval int    `yaml:"interval_seconds"`
	Timeout  int    `yaml:"timeout_seconds"`
}

type ServerConfig struct {
	ListenAddr     string `yaml:"listen_addr"`
	MetricsAddr    string `yaml:"metrics_addr"`
	MaxHeaderBytes int    `yaml:"max_header_bytes"`
	ReadTimeoutMs  int    `yaml:"read_timeout_ms"`
	WriteTimeoutMs int    `yaml:"write_timeout_ms"`
	TLSCertFile    string `yaml:"tls_cert_file"`
	TLSKeyFile     string `yaml:"tls_key_file"`
}

type TracingConfig struct {
	Enabled          bool   `yaml:"enabled"`
	OTLPHTTPEndpoint string `yaml:"otlp_http_endpoint"`
}

type Config struct {
	Server      ServerConfig      `yaml:"server"`
	RateLimit   RateLimitConfig   `yaml:"rate_limit"`
	WAF         WAFConfig         `yaml:"waf"`
	HealthCheck HealthCheckConfig `yaml:"health_check"`
	Tracing     TracingConfig     `yaml:"tracing"`
	Routes      []Route           `yaml:"routes"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// Watcher holds the current Config behind an atomic pointer so readers never
// block on, or observe a half-applied, reload.
type Watcher struct {
	path     string
	current  atomic.Pointer[Config]
	onReload []func(*Config)
}

func NewWatcher(path string) (*Watcher, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	w := &Watcher{path: path}
	w.current.Store(cfg)
	return w, nil
}

func (w *Watcher) Current() *Config {
	return w.current.Load()
}

func (w *Watcher) OnReload(fn func(*Config)) {
	w.onReload = append(w.onReload, fn)
}

func (w *Watcher) reload() {
	cfg, err := Load(w.path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config reload failed, keeping previous config: %v\n", err)
		return
	}
	w.current.Store(cfg)
	for _, fn := range w.onReload {
		fn(cfg)
	}
	fmt.Println("config reloaded:", w.path)
}

// Watch blocks, reloading on file-system changes to the config file and on
// SIGHUP, until the stop channel is closed.
func (w *Watcher) Watch(stop <-chan struct{}) error {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer fsw.Close()
	if err := fsw.Add(w.path); err != nil {
		return err
	}

	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)

	for {
		select {
		case <-stop:
			return nil
		case ev, ok := <-fsw.Events:
			if !ok {
				return nil
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				w.reload()
			}
		case <-sighup:
			w.reload()
		case err, ok := <-fsw.Errors:
			if !ok {
				return nil
			}
			fmt.Fprintln(os.Stderr, "config watcher error:", err)
		}
	}
}
