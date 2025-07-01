package chissy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	faststrconv "github.com/kaatinga/strconv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/errgroup"
)

const (
	timeOutDuration = 5 * time.Second
	nextProtoH3     = "h3"
	nextProtoH3_29  = "h3-29"
	nextProtoH2     = "h2"
)

// SetUpHandlers is a function type that defines how to configure HTTP routes and middleware
// for the server. It receives a chi.Mux router instance to set up the routing configuration.
type SetUpHandlers func(r *chi.Mux)

// Config represents the HTTP server configuration settings.
// It supports both production and development environments with SSL configuration.
// All fields can be configured through environment variables.
type Config struct {
	LocalhostDomain   string        `env:"LOCALHOST_DOMAIN" validate:"required_if=ProductionMode false"`
	SSL               SSL           `validate:"required_if=ProductionMode true"`
	ReadTimeout       time.Duration `env:"READ_TIMEOUT" default:"1m"`
	ReadHeaderTimeout time.Duration `env:"READ_HEADER_TIMEOUT" default:"15s"`
	WriteTimeout      time.Duration `env:"WRITE_TIMEOUT" default:"1m"`
	Port              uint16        `env:"PORT" validate:"min=80,max=65535"`
	ProductionMode    bool          `env:"PROD"`
}

// SSL contains the configuration for SSL/TLS certificates.
// It supports automatic certificate management through Let's Encrypt.
type SSL struct {
	Email      string `env:"EMAIL" validate:"email"`
	DomainList []string
}

// ServerOption defines a function that configures a server instance.
// It follows the functional options pattern for flexible server configuration.
type ServerOption func(*Server)

// WithMetricsServer enables Prometheus metrics server on the specified port.
// This allows monitoring of server metrics through the /metrics endpoint.
func WithMetricsServer(port uint16) ServerOption {
	return func(s *Server) {
		s.metricsEnabled = true
		s.metricsPort = port
	}
}

// WithHTTP3 enables HTTP/3 support for the server.
// HTTP/3 provides improved performance and reliability over HTTP/2.
func WithHTTP3() ServerOption {
	return func(s *Server) {
		s.http3Enabled = true
	}
}

func WithTLS12() ServerOption {
	return func(s *Server) {
		s.minTLSVersion = tls.VersionTLS12
	}
}

// NewServer creates a new HTTP server instance with the given configuration and options.
// It initializes the server with default settings and applies any provided options.
func NewServer(ctx context.Context, config Config, opts ...ServerOption) *Server {
	s := &Server{
		ctx:           ctx,
		config:        config,
		minTLSVersion: tls.VersionTLS13,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

type Server struct {
	ctx             context.Context
	http1And2Server *http.Server
	http3Server     *http3.Server
	metricsServer   *http.Server
	config          Config
	metricsPort     uint16
	metricsEnabled  bool
	http3Enabled    bool
	minTLSVersion   uint16 // minTLSVersion specifies the minimum supported TLS version for secure connections in the http/1.1 and http2 server.
}

// Launch starts the HTTP server with the provided route handlers.
// It supports both HTTP/1.1, HTTP/2, and optionally HTTP/3 protocols.
// In production mode, it also sets up SSL/TLS with automatic certificate management.
// Returns an error if the server fails to start or encounters a fatal error.
func (s *Server) Launch(setupHandlers SetUpHandlers) error {
	domainsPlusWWWDomains := s.getDomainsPlusWWWDomains()

	router := chi.NewRouter()
	if s.config.ProductionMode && s.http3Enabled {
		router.Use(advertiseHTTP3)
		router.Use(advertiseHSTS)
	}
	setupHandlers(router)

	s.newHTTP1And2Server(router)

	// Create a channel for server errors
	serverErrors := make(chan error, 3) // Buffer size 3 for HTTP1/2, HTTP3, and metrics servers

	// Start the servers based on the mode
	if s.config.ProductionMode {
		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domainsPlusWWWDomains...),
			Cache:      autocert.DirCache("certs"),
			Email:      s.config.SSL.Email,
		}

		tlsConfig1and2 := certManager.TLSConfig()
		tlsConfig1and2.MinVersion = s.minTLSVersion
		tlsConfig1and2.GetCertificate = certManager.GetCertificate
		tlsConfig1and2.NextProtos = []string{nextProtoH2, "http/1.1"}

		// HTTP redirect server (non-critical)
		go func() {
			redirectServer := &http.Server{
				Addr:    ":http",
				Handler: certManager.HTTPHandler(s.redirectToHTTPS()),
			}

			// Start the server, but don't report errors as critical
			_ = redirectServer.ListenAndServe()
		}()

		// Start metrics server if enabled
		if s.metricsEnabled {
			metricsMux := http.NewServeMux()
			metricsMux.Handle("/metrics", promhttp.Handler())

			s.metricsServer = &http.Server{
				Addr:              net.JoinHostPort("", faststrconv.Uint162String(s.metricsPort)),
				Handler:           metricsMux,
				ReadTimeout:       s.config.ReadTimeout,
				ReadHeaderTimeout: s.config.ReadHeaderTimeout,
				WriteTimeout:      s.config.WriteTimeout,
			}

			go func() {
				if err := s.metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					serverErrors <- fmt.Errorf("metrics server failed: %w", err)
				}
			}()
		}

		// HTTP 1.1 and HTTP/2 server
		go func() {
			s.http1And2Server.TLSConfig = tlsConfig1and2
			err := s.http1And2Server.ListenAndServeTLS("", "")
			serverErrors <- fmt.Errorf("HTTP1/2 server failed: %w", err)
		}()

		// HTTP/3 server if enabled
		if s.http3Enabled {
			s.newHTTP3Server(router)

			tlsConfig3 := certManager.TLSConfig()
			tlsConfig3.MinVersion = tls.VersionTLS13
			tlsConfig3.GetCertificate = certManager.GetCertificate
			tlsConfig3.NextProtos = []string{nextProtoH3, nextProtoH3_29}

			go func() {
				s.http3Server.TLSConfig = tlsConfig3
				err := s.http3Server.ListenAndServe()
				serverErrors <- fmt.Errorf("HTTP3 server failed: %w", err)
			}()
		}
	} else {
		go func() {
			err := s.http1And2Server.ListenAndServe()
			serverErrors <- fmt.Errorf("HTTP server failed: %w", err)
		}()
	}

	// Wait for shutdown signal or server errors
	var shutdownErr error
	select {
	case err := <-serverErrors:
		shutdownErr = err
	case <-s.ctx.Done():
		shutdownErr = s.ctx.Err()
	}

	// Create a timeout context for shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeOutDuration)
	defer cancel()

	// Use errgroup to manage shutdown of multiple servers
	g, gCtx := errgroup.WithContext(shutdownCtx)

	// Gracefully shutdown HTTP1/2 server
	g.Go(func() error {
		err := s.http1And2Server.Shutdown(gCtx)
		if err != nil {
			// If graceful shutdown fails, force close
			closeErr := s.http1And2Server.Close()
			if closeErr != nil {
				return fmt.Errorf("failed graceful shutdown (%w) and force close (%v) of HTTP1/2 server",
					err, closeErr)
			}
			return fmt.Errorf("failed graceful shutdown of HTTP1/2 server: %w", err)
		}
		return nil
	})

	// Gracefully shutdown HTTP3 server if enabled
	if s.http3Enabled {
		g.Go(func() error {
			if s.http3Server == nil {
				return nil
			}
			err := s.http3Server.Shutdown(gCtx)
			if err != nil {
				// If graceful shutdown fails, force close
				closeErr := s.http3Server.Close()
				if closeErr != nil {
					return fmt.Errorf("failed graceful shutdown (%w) and force close (%v) of HTTP3 server",
						err, closeErr)
				}
				return fmt.Errorf("failed graceful shutdown of HTTP3 server: %w", err)
			}
			return nil
		})
	}

	// Gracefully shutdown metrics server if enabled
	if s.metricsEnabled {
		g.Go(func() error {
			if s.metricsServer == nil {
				return nil
			}
			err := s.metricsServer.Shutdown(gCtx)
			if err != nil {
				// If graceful shutdown fails, force close
				closeErr := s.metricsServer.Close()
				if closeErr != nil {
					return fmt.Errorf("failed graceful shutdown (%w) and force close (%v) of metrics server",
						err, closeErr)
				}
				return fmt.Errorf("failed graceful shutdown of metrics server: %w", err)
			}
			return nil
		})
	}

	// Wait for all shutdowns to complete
	if err := g.Wait(); err != nil {
		// If there was an error during shutdown, combine it with the original error
		shutdownErr = fmt.Errorf("%v; additionally, shutdown error: %w", shutdownErr, err)
	}

	return shutdownErr
}

// getDomainsPlusWWWDomains generates a list of domains including their www subdomains
// for SSL certificate management. This ensures both apex and www domains are covered.
func (s *Server) getDomainsPlusWWWDomains() (domainsWithWWW []string) {
	domainsWithWWW = make([]string, len(s.config.SSL.DomainList)*2)
	for i := range s.config.SSL.DomainList {
		s.config.SSL.DomainList[i] = strings.TrimSpace(s.config.SSL.DomainList[i])
		domainsWithWWW[i*2] = s.config.SSL.DomainList[i]
		domainsWithWWW[i*2+1] = "www." + s.config.SSL.DomainList[i]
	}

	return domainsWithWWW
}

// redirectToHTTPS creates an HTTP handler that redirects all HTTP traffic to HTTPS.
// It preserves the original request path and query parameters during redirection.
func (s *Server) redirectToHTTPS() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// redirect to https
		var domainToRedirect string
		for _, domain := range s.config.SSL.DomainList {
			if strings.Contains(r.Host, domain) {
				domainToRedirect = domain
			}
		}
		http.Redirect(w, r, "https://"+domainToRedirect+r.RequestURI, http.StatusPermanentRedirect)
	}

	return http.HandlerFunc(fn)
}

// newHTTP1And2Server initializes an HTTP server for HTTP/1.1 and HTTP/2 protocols.
// It configures the server with the provided router and timeout settings.
func (s *Server) newHTTP1And2Server(router *chi.Mux) {
	s.http1And2Server = &http.Server{
		Addr:              net.JoinHostPort("", faststrconv.Uint162String(s.config.Port)),
		Handler:           router,
		ReadTimeout:       s.config.ReadTimeout,
		ReadHeaderTimeout: s.config.ReadHeaderTimeout,
		WriteTimeout:      s.config.WriteTimeout,
	}
}

// newHTTP3Server initializes an HTTP/3 server with optimized QUIC configuration.
// It sets up connection limits, performance parameters, and security settings
// for optimal HTTP/3 operation.
func (s *Server) newHTTP3Server(router *chi.Mux) {
	s.http3Server = &http3.Server{
		Handler: router,
		QUICConfig: &quic.Config{
			// Connection limits
			MaxIncomingStreams:    1000,
			MaxIncomingUniStreams: 1000,

			// Performance & resource management
			MaxConnectionReceiveWindow: 15 * 1024 * 1024, // 15MB per connection
			MaxStreamReceiveWindow:     6 * 1024 * 1024,  // 6MB per stream
			InitialStreamReceiveWindow: 512 * 1024,       // 512KB initial window
			MaxIdleTimeout:             30 * time.Second,
			HandshakeIdleTimeout:       10 * time.Second,

			// Security & stability
			DisablePathMTUDiscovery: false,
		},
	}
}
