package chissy

import (
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

	// portTooSmall = Config{
	//	SSL: &SSL{Email: "info@yandex.ru",
	//		Domain: "yandex.ru",
	//	},
	//	ProductionMode: true,
	//	HTTP: HTTP{
	//		Port: 50,
	//	},
	// }
	//
	// portTooBig = Config{
	//	SSL: &SSL{Email: "info@yandex.ru",
	//		Domain: "yandex.ru",
	//	},
	//	ProductionMode: true,
	//	HTTP: HTTP{
	//		Port: 50000,
	//	},
	// }
	//
	// badEmail = Config{
	//	SSL: &SSL{Email: "info",
	//		Domain: "yandex.ru",
	//	},
	//	ProductionMode: true,
	//	HTTP: HTTP{
	//		Port: 8089,
	//	},
	// }
	//
	// badDomain = Config{
	//	SSL: &SSL{Email: "info@yandex.ru",
	//		Domain: "-",
	//	},
	//	ProductionMode: true,
	//	HTTP: HTTP{
	//		Port: 8089,
	//	},
	// }
	//
	// devMode = Config{
	//	HTTP: HTTP{
	//		Port: 8089,
	//	},
	// }
	//
	// sslForgotten = Config{
	//	ProductionMode: true,
	//	HTTP:           HTTP{Port: 8089},
	// }
	//
	// dbForgotten = Config{
	//	HTTP:  HTTP{Port: 8089},
	// }
)

func TestConfig_newWebService(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		router := chi.NewRouter()
		httpServer := validConfig.newHTTP1And2Server(router)
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

func TestConfig_getDomainsWithWWW(t *testing.T) {
	tests := []struct {
		config Config
		want   []string
	}{
		{config: Config{SSL: SSL{Domains: "yandex.ru"}}, want: []string{"yandex.ru", "www.yandex.ru"}},
		{config: Config{SSL: SSL{Domains: "yandex.ru,google.com"}}, want: []string{"yandex.ru", "www.yandex.ru", "google.com", "www.google.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.config.SSL.Domains, func(t *testing.T) {
			if got := tt.config.parseDomains(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseDomains() = %v, want %v", got, tt.want)
			}
		})
	}
}
