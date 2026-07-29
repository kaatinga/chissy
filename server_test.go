package chissy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var (
	validConfig = Config{
		Port:              8089,
		ReadTimeout:       1 * time.Minute,
		ReadHeaderTimeout: 15 * time.Second,
		WriteTimeout:      1 * time.Minute,
	}
)

func TestServer_newHTTP1And2Server(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		ctx := context.Background()
		server := NewServer(ctx, validConfig)
		router := chi.NewRouter()

		server.newHTTP1And2Server(router)

		srv := server.http1And2Server
		if !strings.Contains(srv.Addr, fmt.Sprintf(":%d", validConfig.Port)) {
			t.Error("incorrect http port")
		}

		if srv.ReadTimeout != validConfig.ReadTimeout {
			t.Error("invalid read timeout")
		}

		if srv.WriteTimeout != validConfig.WriteTimeout {
			t.Error("invalid write timeout")
		}

		if srv.ReadHeaderTimeout != validConfig.ReadHeaderTimeout {
			t.Error("invalid read header timeout")
		}
	})
}

func TestServer_getDomainsPlusWWWDomains(t *testing.T) {
	tests := []struct {
		name           string
		config         Config
		wantWithWWW    []string
		wantWithoutWWW []string
	}{
		{
			name:           "single domain",
			config:         Config{SSL: SSL{DomainList: []string{"yandex.ru"}}},
			wantWithWWW:    []string{"yandex.ru", "www.yandex.ru"},
			wantWithoutWWW: []string{"yandex.ru"},
		},
		{
			name:           "multiple domains",
			config:         Config{SSL: SSL{DomainList: []string{"yandex.ru", "google.com"}}},
			wantWithWWW:    []string{"yandex.ru", "www.yandex.ru", "google.com", "www.google.com"},
			wantWithoutWWW: []string{"yandex.ru", "google.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			server := NewServer(ctx, tt.config)

			got := server.getDomainsPlusWWWDomains()
			if !reflect.DeepEqual(got, tt.wantWithWWW) {
				t.Errorf("getDomainsPlusWWWDomains() = %v, want %v", got, tt.wantWithWWW)
			}

			if !reflect.DeepEqual(server.config.SSL.DomainList, tt.wantWithoutWWW) {
				t.Errorf("server.config.SSL.DomainList = %v, want %v", server.config.SSL.DomainList, tt.wantWithoutWWW)
			}
		})
	}
}

func TestServer_Launch(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		config := validConfig
		config.Port = freeTCPPort(t)

		ctx, cancel := context.WithCancel(context.Background())
		server := NewServer(ctx, config)
		launchDone := make(chan error, 1)

		go func() {
			launchDone <- server.Launch(func(r *chi.Mux) {
				r.Get("/", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				})
			})
		}()

		resp := waitForHTTPResponse(t, fmt.Sprintf("http://localhost:%d/", config.Port))

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status OK, got %v", resp.Status)
		}
		if err := resp.Body.Close(); err != nil {
			t.Errorf("failed to close response body: %v", err)
		}

		cancel()
		select {
		case err := <-launchDone:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Launch() error = %v, want context.Canceled", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Launch() did not return after context cancellation")
		}
	})
}

func TestServer_newHTTP1And2TLSConfig(t *testing.T) {
	server := NewServer(context.Background(), validConfig)
	certManager := &autocert.Manager{}

	tlsConfig := server.newHTTP1And2TLSConfig(certManager)

	if tlsConfig.MinVersion != server.minTLSVersion {
		t.Errorf("MinVersion = %d, want %d", tlsConfig.MinVersion, server.minTLSVersion)
	}
	for _, protocol := range []string{nextProtoH2, "http/1.1", acme.ALPNProto} {
		if !containsString(tlsConfig.NextProtos, protocol) {
			t.Errorf("NextProtos = %v, want protocol %q", tlsConfig.NextProtos, protocol)
		}
	}
}

func TestServer_newRouterProductionHeaders(t *testing.T) {
	tests := []struct {
		name            string
		productionMode  bool
		http3Enabled    bool
		wantHSTS        bool
		wantHTTP3Header bool
	}{
		{
			name:           "production without HTTP3",
			productionMode: true,
			wantHSTS:       true,
		},
		{
			name:            "production with HTTP3",
			productionMode:  true,
			http3Enabled:    true,
			wantHSTS:        true,
			wantHTTP3Header: true,
		},
		{
			name: "local HTTP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer(context.Background(), Config{ProductionMode: tt.productionMode})
			server.http3Enabled = tt.http3Enabled
			router := server.newRouter(func(r *chi.Mux) {
				r.Get("/", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				})
			})

			req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if got := rec.Header().Get("Strict-Transport-Security"); (got != "") != tt.wantHSTS {
				t.Errorf("Strict-Transport-Security = %q, want header present = %t", got, tt.wantHSTS)
			}
			if got := rec.Header().Get("Alt-Svc"); (got != "") != tt.wantHTTP3Header {
				t.Errorf("Alt-Svc = %q, want header present = %t", got, tt.wantHTTP3Header)
			}
		})
	}
}

func TestServer_newHTTP3Server(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		ctx := context.Background()
		server := NewServer(ctx, validConfig)
		router := chi.NewRouter()

		server.newHTTP3Server(router)

		if server.http3Server == nil {
			t.Error("HTTP3 server was not initialized")
		}

		if server.http3Server.Handler != router {
			t.Error("incorrect router set for HTTP3 server")
		}

		if server.http3Server.QUICConfig == nil {
			t.Error("QUIC config was not initialized")
		}

		// Check QUIC configuration
		config := server.http3Server.QUICConfig
		if config.MaxIncomingStreams != 1000 {
			t.Errorf("expected MaxIncomingStreams to be 1000, got %d", config.MaxIncomingStreams)
		}
		if config.MaxIncomingUniStreams != 1000 {
			t.Errorf("expected MaxIncomingUniStreams to be 1000, got %d", config.MaxIncomingUniStreams)
		}
		if config.MaxConnectionReceiveWindow != 15*1024*1024 {
			t.Errorf("expected MaxConnectionReceiveWindow to be 15MB, got %d", config.MaxConnectionReceiveWindow)
		}
		if config.MaxStreamReceiveWindow != 6*1024*1024 {
			t.Errorf("expected MaxStreamReceiveWindow to be 6MB, got %d", config.MaxStreamReceiveWindow)
		}
		if config.InitialStreamReceiveWindow != 512*1024 {
			t.Errorf("expected InitialStreamReceiveWindow to be 512KB, got %d", config.InitialStreamReceiveWindow)
		}
		if config.MaxIdleTimeout != 30*time.Second {
			t.Errorf("expected MaxIdleTimeout to be 30s, got %v", config.MaxIdleTimeout)
		}
		if config.HandshakeIdleTimeout != 10*time.Second {
			t.Errorf("expected HandshakeIdleTimeout to be 10s, got %v", config.HandshakeIdleTimeout)
		}
		if config.DisablePathMTUDiscovery {
			t.Error("expected DisablePathMTUDiscovery to be false")
		}
	})
}

func TestServer_shutdownClosesRedirectServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	listenerAddress := listener.Addr().String()

	redirectServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	server := NewServer(context.Background(), validConfig)
	server.httpRedirectServer = redirectServer

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- redirectServer.Serve(listener)
	}()

	resp := waitForHTTPResponse(t, "http://"+listenerAddress)
	if err := resp.Body.Close(); err != nil {
		t.Errorf("failed to close response body: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeOutDuration)
	defer cancel()
	if err := server.shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown() error = %v", err)
	}

	select {
	case err := <-serveDone:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve() error = %v, want http.ErrServerClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("redirect server did not stop")
	}

	reopenedListener, err := net.Listen("tcp", listenerAddress)
	if err != nil {
		t.Fatalf("redirect listener address was not released: %v", err)
	}
	if err := reopenedListener.Close(); err != nil {
		t.Errorf("failed to close reopened listener: %v", err)
	}
}

func TestServer_redirectToHTTPS(t *testing.T) {
	tests := []struct {
		name         string
		requestHost  string
		wantStatus   int
		wantLocation string
	}{
		{
			name:         "apex domain",
			requestHost:  "example.com",
			wantStatus:   http.StatusPermanentRedirect,
			wantLocation: "https://example.com/path?key=value",
		},
		{
			name:         "www uses apex domain",
			requestHost:  "www.example.com",
			wantStatus:   http.StatusPermanentRedirect,
			wantLocation: "https://example.com/path?key=value",
		},
		{
			name:         "host with port",
			requestHost:  "example.com:80",
			wantStatus:   http.StatusPermanentRedirect,
			wantLocation: "https://example.com/path?key=value",
		},
		{
			name:         "case insensitive host with trailing dot",
			requestHost:  "EXAMPLE.COM.:80",
			wantStatus:   http.StatusPermanentRedirect,
			wantLocation: "https://example.com/path?key=value",
		},
		{
			name:         "second configured domain",
			requestHost:  "test.com",
			wantStatus:   http.StatusPermanentRedirect,
			wantLocation: "https://test.com/path?key=value",
		},
		{
			name:        "unknown domain",
			requestHost: "unknown.example",
			wantStatus:  http.StatusMisdirectedRequest,
		},
		{
			name:        "substring domain",
			requestHost: "notexample.com",
			wantStatus:  http.StatusMisdirectedRequest,
		},
		{
			name:        "invalid port",
			requestHost: "example.com:http",
			wantStatus:  http.StatusMisdirectedRequest,
		},
		{
			name:        "malformed host",
			requestHost: "example.com/path",
			wantStatus:  http.StatusMisdirectedRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer(context.Background(), Config{
				SSL: SSL{
					DomainList: []string{"www.example.com", "example.com", "test.com"},
				},
			})
			handler := server.redirectToHTTPS()

			req := httptest.NewRequest(http.MethodGet, "/path?key=value", nil)
			req.Host = tt.requestHost
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if location := rec.Header().Get("Location"); location != tt.wantLocation {
				t.Errorf("Location = %q, want %q", location, tt.wantLocation)
			}
		})
	}
}

func freeTCPPort(t *testing.T) uint16 {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate TCP port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("failed to release allocated TCP port: %v", err)
	}

	return uint16(port)
}

func waitForHTTPResponse(t *testing.T, url string) *http.Response {
	t.Helper()

	client := &http.Client{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := client.Get(url)
		if err == nil {
			return resp
		}
		if time.Now().After(deadline) {
			t.Fatalf("server at %s did not become ready: %v", url, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
