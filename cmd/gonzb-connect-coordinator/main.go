package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/datallboy/gonzb-connect/coordinator"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, err := coordinator.OpenStore(ctx, requiredValue("DATABASE_URL"))
	if err != nil {
		log.Fatal("open coordinator database failed")
	}
	defer store.Close()
	cfg := coordinator.Config{
		AdminToken: requiredValue("ADMIN_TOKEN"), TURNSecret: requiredValue("TURN_SHARED_SECRET"),
		TURNURIs: splitEnv("TURN_URIS"), STUNURIs: splitEnv("STUN_URIS"),
		AllowedOrigins: splitEnv("ALLOWED_ORIGINS"), TrustProxyHeaders: strings.EqualFold(strings.TrimSpace(os.Getenv("TRUST_PROXY_HEADERS")), "true"),
		MaxConcurrentAuth: positiveIntEnv("MAX_CONCURRENT_AUTH", 1, 16),
	}
	if err := coordinator.ValidateConfig(cfg); err != nil {
		log.Fatal(err)
	}
	server := coordinator.NewServer(store, cfg)
	httpServer := &http.Server{
		Addr: firstNonBlank(os.Getenv("LISTEN_ADDR"), ":8080"), Handler: server.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	log.Printf("gonzb-connect coordinator listening on %s", httpServer.Addr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func requiredValue(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if filename := strings.TrimSpace(os.Getenv(name + "_FILE")); filename != "" {
		if value != "" {
			log.Fatalf("only one of %s and %s_FILE may be set", name, name)
		}
		// #nosec G304,G703 -- *_FILE is an explicit operator-controlled secret
		// mount path. It must remain usable with Docker/Kubernetes secret mounts.
		file, err := os.Open(filename)
		if err != nil {
			log.Fatal(fmt.Errorf("read %s_FILE: %w", name, err))
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, (64<<10)+1))
		closeErr := file.Close()
		if readErr != nil {
			log.Fatal(fmt.Errorf("read %s_FILE: %w", name, readErr))
		}
		if closeErr != nil {
			log.Fatal(fmt.Errorf("close %s_FILE: %w", name, closeErr))
		}
		if len(raw) > 64<<10 {
			log.Fatalf("%s_FILE exceeds 64 KiB", name)
		}
		value = strings.TrimSpace(string(raw))
	}
	if value == "" {
		log.Fatalf("%s or %s_FILE is required", name, name)
	}
	return value
}
func splitEnv(name string) []string {
	values := []string{}
	for _, value := range strings.Split(os.Getenv(name), ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}
func firstNonBlank(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func positiveIntEnv(name string, defaultValue, maximum int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > maximum {
		log.Fatalf("%s must be an integer from 1 through %d", name, maximum)
	}
	return value
}
