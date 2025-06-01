package chissy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
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
		ctx := context.Background()
		server := NewServer(ctx, validConfig)

		// Start server in a goroutine
		go func() {
			err := server.Launch(func(r *chi.Mux) {
				r.Get("/", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				})
			})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		}()

		// Give server time to start
		time.Sleep(100 * time.Millisecond)

		// Test HTTP endpoint
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/", validConfig.Port))
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status OK, got %v", resp.Status)
		}
	})
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

func TestServer_Shutdown(t *testing.T) {
	t.Run("graceful shutdown", func(t *testing.T) {
		ctx := context.Background()
		server := NewServer(ctx, validConfig)
		router := chi.NewRouter()

		// Initialize servers
		server.newHTTP1And2Server(router)
		server.newHTTP3Server(router)

		// Create a context that will be cancelled immediately
		shutdownCtx, cancel := context.WithTimeout(context.Background(), timeOutDuration)
		defer cancel()

		// Start server in a goroutine
		go func() {
			_ = server.http1And2Server.ListenAndServe()
		}()

		// Give the server a moment to start
		time.Sleep(10 * time.Millisecond)

		// Attempt shutdown
		err := server.http1And2Server.Shutdown(shutdownCtx)
		if err != nil {
			t.Errorf("Shutdown() error = %v", err)
		}
	})
}

func TestServer_redirectToHTTPS(t *testing.T) {
	tests := []struct {
		name           string
		config         Config
		requestHost    string
		expectedDomain string
	}{
		{
			name: "single domain match",
			config: Config{
				SSL: SSL{
					DomainList: []string{"example.com"},
				},
			},
			requestHost:    "example.com",
			expectedDomain: "example.com",
		},
		{
			name: "www subdomain match",
			config: Config{
				SSL: SSL{
					DomainList: []string{"example.com"},
				},
			},
			requestHost:    "www.example.com",
			expectedDomain: "example.com",
		},
		{
			name: "multiple domains",
			config: Config{
				SSL: SSL{
					DomainList: []string{"example.com", "test.com"},
				},
			},
			requestHost:    "test.com",
			expectedDomain: "test.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			server := NewServer(ctx, tt.config)
			handler := server.redirectToHTTPS()

			req := httptest.NewRequest("GET", "/path", nil)
			req.Host = tt.requestHost
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusPermanentRedirect {
				t.Errorf("expected status %d, got %d", http.StatusPermanentRedirect, rec.Code)
			}

			expectedLocation := "https://" + tt.expectedDomain + "/path"
			if location := rec.Header().Get("Location"); location != expectedLocation {
				t.Errorf("expected location %s, got %s", expectedLocation, location)
			}
		})
	}
}
