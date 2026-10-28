// Command proxy is ZeroL7's entry point: loads config, builds the router
// and WAF, starts the raw-socket listener, the health checker, the hot
// config watcher, and the Prometheus /metrics endpoint.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gbabhi125-svg/ZeroL7/pkg/configwatch"
	"github.com/gbabhi125-svg/ZeroL7/pkg/metrics"
	"github.com/gbabhi125-svg/ZeroL7/pkg/proxy"
	"github.com/gbabhi125-svg/ZeroL7/pkg/router"
	"github.com/gbabhi125-svg/ZeroL7/pkg/tracing"
)

func main() {
	configPath := flag.String("config", "config/config.yaml", "path to config.yaml")
	flag.Parse()

	cfgWatcher, err := configwatch.NewWatcher(*configPath)
	if err != nil {
		log.Fatalf("zerol7: failed to load config: %v", err)
	}
	cfg := cfgWatcher.Current()

	if cfg.Tracing.Enabled {
		shutdown, err := tracing.Init(context.Background(), "zerol7-proxy", cfg.Tracing.OTLPHTTPEndpoint)
		if err != nil {
			log.Printf("zerol7: tracing init failed, continuing without tracing: %v", err)
		} else {
			defer shutdown(context.Background())
		}
	}

	rtr := router.NewRouter(buildPools(cfg))
	cfgWatcher.OnReload(func(newCfg *configwatch.Config) {
		rtr.Replace(buildPools(newCfg))
	})

	hc := router.NewHealthChecker(
		rtr,
		cfg.HealthCheck.Path,
		time.Duration(cfg.HealthCheck.Interval)*time.Second,
		time.Duration(cfg.HealthCheck.Timeout)*time.Second,
	)
	if cfg.HealthCheck.Enabled {
		hc.Start()
		defer hc.Stop()
	}

	srv := proxy.NewServer(cfgWatcher, rtr)

	stop := make(chan struct{})
	go func() {
		if err := cfgWatcher.Watch(stop); err != nil {
			log.Printf("zerol7: config watcher stopped: %v", err)
		}
	}()

	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", metrics.Handler())
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		})
		log.Printf("zerol7: metrics listening on %s", cfg.Server.MetricsAddr)
		if err := http.ListenAndServe(cfg.Server.MetricsAddr, mux); err != nil {
			log.Printf("zerol7: metrics server stopped: %v", err)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Println("zerol7: shutting down")
		close(stop)
		os.Exit(0)
	}()

	var listenErr error
	if cfg.Server.TLSCertFile != "" && cfg.Server.TLSKeyFile != "" {
		listenErr = srv.ListenAndServeTLS(cfg.Server.ListenAddr, cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
	} else {
		listenErr = srv.ListenAndServe(cfg.Server.ListenAddr)
	}
	if listenErr != nil {
		log.Fatalf("zerol7: listener failed: %v", listenErr)
	}
}

func buildPools(cfg *configwatch.Config) []*router.Pool {
	pools := make([]*router.Pool, 0, len(cfg.Routes))
	for _, route := range cfg.Routes {
		pools = append(pools, router.NewPool(route.PathPrefix, route.Strategy, route.Upstreams))
	}
	return pools
}
