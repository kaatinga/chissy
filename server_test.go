package chissy

import (
	"context"
	"fmt"
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
