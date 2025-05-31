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

		httpServer := server.http1And2Server
		if !strings.Contains(httpServer.Addr, fmt.Sprintf(":%d", validConfig.Port)) {
			t.Error("incorrect http port")
		}

		if httpServer.ReadTimeout != validConfig.ReadTimeout {
			t.Error("invalid read timeout")
		}

		if httpServer.WriteTimeout != validConfig.WriteTimeout {
			t.Error("invalid write timeout")
		}

		if httpServer.ReadHeaderTimeout != validConfig.ReadHeaderTimeout {
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
	tests := []struct {
		name          string
		config        Config
		setupHandlers SetUpHandlers
		ctx           context.Context
		expectedError bool
	}{
		{
			name:   "development mode",
			config: validConfig,
			setupHandlers: func(r *chi.Mux) {
				r.Get("/test", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				})
			},
			ctx:           context.Background(),
			expectedError: true, // Expect error due to context timeout
		},
		{
			name: "production mode with SSL",
			config: Config{
				ProductionMode: true,
				Port:           8089,
				SSL: SSL{
					Email:      "test@example.com",
					DomainList: []string{"example.com"},
				},
				ReadTimeout:       1 * time.Minute,
				ReadHeaderTimeout: 15 * time.Second,
				WriteTimeout:      1 * time.Minute,
			},
			setupHandlers: func(r *chi.Mux) {
				r.Get("/test", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				})
			},
			ctx:           context.Background(),
			expectedError: true, // Expect error due to context timeout
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer(tt.ctx, tt.config)

			// Create a context that will be cancelled after a short delay
			ctx, cancel := context.WithTimeout(tt.ctx, 100*time.Millisecond)
			defer cancel()

			err := server.Launch(ctx, tt.setupHandlers)
			if (err != nil) != tt.expectedError {
				t.Errorf("Launch() error = %v, expectedError %v", err, tt.expectedError)
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
