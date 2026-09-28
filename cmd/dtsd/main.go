// Command dtsd runs a local DNS tunnel detection service.
//
// It reads newline-delimited DNS query events (JSON) from stdin, tolerates
// out-of-order and late arrival, applies the multi-feature sliding-window
// detector, and emits one deduplicated JSON alert per line on stdout.
//
// Usage:
//
//	dtsd [-config path.json] [-state-dir dir]
//
// Signals:
//
//	SIGHUP  reload the config file atomically (new rule generation;
//	        in-flight windows keep their old semantics until they expire)
//	SIGINT/SIGTERM  flush a final snapshot and exit
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/guoyyit/dns-tunnel-detection-go/internal/config"
	"github.com/guoyyit/dns-tunnel-detection-go/internal/detector"
	"github.com/guoyyit/dns-tunnel-detection-go/internal/model"
	"github.com/guoyyit/dns-tunnel-detection-go/internal/persist"
)

func main() {
	cfgPath := flag.String("config", "", "path to JSON configuration (defaults are used when empty)")
	stateDir := flag.String("state-dir", "", "directory for WAL and snapshots (empty disables persistence)")
	flag.Parse()

	cfg, err := config.LoadFile(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if *stateDir != "" {
		cfg.Persistence.Dir = *stateDir
	}

	out := json.NewEncoder(os.Stdout)
	sink := func(a model.Alert) {
		_ = out.Encode(a)
	}

	store, err := persist.NewFileStore(cfg.Persistence.Dir)
	if err != nil {
		log.Fatalf("open state store: %v", err)
	}
	eng := detector.New(cfg, store, sink)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := eng.Recover(ctx); err != nil {
		log.Fatalf("recover state: %v", err)
	}
	if err := eng.Start(ctx); err != nil {
		log.Fatalf("start engine: %v", err)
	}

	// SIGHUP -> atomic config reload (new generation)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			nc, err := config.LoadFile(*cfgPath)
			if err != nil {
				log.Printf("config reload failed, keeping old rules: %v", err)
				continue
			}
			nc.Persistence.Dir = cfg.Persistence.Dir
			if err := eng.UpdateConfig(nc); err != nil {
				log.Printf("config reload rejected: %v", err)
				continue
			}
			log.Printf("config reloaded as new rule generation")
		}
	}()

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var dropped int
	for in.Scan() {
		line := in.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev model.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			log.Printf("skip malformed event: %v", err)
			continue
		}
		if err := eng.Submit(ev); err != nil {
			if err == detector.ErrQueueFull {
				dropped++
				if dropped == 1 || dropped%1000 == 0 {
					log.Printf("backpressure: %d event(s) dropped", dropped)
				}
				continue
			}
			log.Printf("ingest error: %v", err)
		}
	}
	if err := in.Err(); err != nil {
		log.Printf("stdin error: %v", err)
	}

	cancel()
	if err := eng.Close(); err != nil {
		log.Printf("close: %v", err)
	}
	if dropped > 0 {
		fmt.Fprintf(os.Stderr, "total dropped due to backpressure: %d\n", dropped)
	}
}
