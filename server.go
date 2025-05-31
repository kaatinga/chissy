package chissy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
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

// SetUpHandlers type to announce handlers.
type SetUpHandlers func(r *chi.Mux)

// Config - http service configuration compatible to settings package.
// https://github.com/kaatinga/settings
type Config struct {
	ProductionMode    bool          `env:"PROD"`
	LocalhostDomain   string        `env:"LOCALHOST_DOMAIN" validate:"required_if=ProductionMode false"`
	SSL               SSL           `validate:"required_if=ProductionMode true"`
	Port              uint16        `env:"PORT" validate:"min=80,max=65535"`
	ReadTimeout       time.Duration `env:"READ_TIMEOUT" default:"1m"`
	ReadHeaderTimeout time.Duration `env:"READ_HEADER_TIMEOUT" default:"15s"`
	WriteTimeout      time.Duration `env:"WRITE_TIMEOUT" default:"1m"`
}

type SSL struct {
	Email      string `env:"EMAIL" validate:"email"`
	DomainList []string
}

func NewServer(initCtx context.Context, config Config) *Server {
	return &Server{
		config: config,
		ctx:    initCtx,
	}
}

type Server struct {
	http1And2Server *http.Server
	http3Server     *http3.Server
	config          Config
	ctx             context.Context
}

// Launch enables the configured web server with the handlers that
// announced in a function matched with SetUpHandlers type.
func (c *Server) Launch(setupHandlers SetUpHandlers) error {
	domainsPlusWWWDomains := c.getDomainsPlusWWWDomains()

	router := chi.NewRouter()
	if c.config.ProductionMode {
		router.Use(advertiseHTTP3)
		router.Use(advertiseHSTS)
	}
	setupHandlers(router)

	c.newHTTP1And2Server(router)
	c.newHTTP3Server(router)

	// Create a channel for server errors
	serverErrors := make(chan error, 2) // Buffer size 2 for both servers

	// Start the servers based on the mode
	if c.config.ProductionMode {
		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domainsPlusWWWDomains...),
			Cache:      autocert.DirCache("certs"),
			Email:      c.config.SSL.Email,
		}

		tlsConfig1and2 := certManager.TLSConfig()
		tlsConfig1and2.MinVersion = tls.VersionTLS13
		tlsConfig1and2.GetCertificate = certManager.GetCertificate
		tlsConfig1and2.NextProtos = []string{nextProtoH2}

		tlsConfig3 := certManager.TLSConfig()
		tlsConfig3.MinVersion = tls.VersionTLS13
		tlsConfig3.GetCertificate = certManager.GetCertificate
		tlsConfig3.NextProtos = []string{nextProtoH3, nextProtoH3_29}

		// HTTP redirect server (non-critical)
		go func() {
			redirectServer := &http.Server{
				Addr:    ":http",
				Handler: certManager.HTTPHandler(c.redirectToHTTPS()),
			}

			// Start the server, but don't report errors as critical
			_ = redirectServer.ListenAndServe()
		}()

		// HTTP 1.1 and HTTP/2 server
		go func() {
			c.http1And2Server.TLSConfig = tlsConfig1and2
			err := c.http1And2Server.ListenAndServeTLS("", "")
			serverErrors <- fmt.Errorf("HTTP1/2 server failed: %w", err)
		}()

		// HTTP/3 server
		go func() {
			c.http3Server.TLSConfig = tlsConfig3
			err := c.http3Server.ListenAndServe()
			serverErrors <- fmt.Errorf("HTTP3 server failed: %w", err)
		}()
	} else {
		go func() {
			err := c.http1And2Server.ListenAndServe()
			serverErrors <- fmt.Errorf("HTTP server failed: %w", err)
		}()
	}

	// Wait for shutdown signal or server errors
	var shutdownErr error
	select {
	case err := <-serverErrors:
		shutdownErr = err
	case <-c.ctx.Done():
		shutdownErr = c.ctx.Err()
	}

	// Create a timeout context for shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeOutDuration)
	defer cancel()

	// Use errgroup to manage shutdown of multiple servers
	g, gCtx := errgroup.WithContext(shutdownCtx)

	// Gracefully shutdown HTTP1/2 server
	g.Go(func() error {
		err := c.http1And2Server.Shutdown(gCtx)
		if err != nil {
			// If graceful shutdown fails, force close
			closeErr := c.http1And2Server.Close()
			if closeErr != nil {
				return fmt.Errorf("failed graceful shutdown (%w) and force close (%v) of HTTP1/2 server",
					err, closeErr)
			}
			return fmt.Errorf("failed graceful shutdown of HTTP1/2 server: %w", err)
		}
		return nil
	})

	// Gracefully shutdown HTTP3 server if in production mode
	if c.config.ProductionMode {
		g.Go(func() error {
			err := c.http3Server.Shutdown(gCtx)
			if err != nil {
				// If graceful shutdown fails, force close
				closeErr := c.http3Server.Close()
				if closeErr != nil {
					return fmt.Errorf("failed graceful shutdown (%w) and force close (%v) of HTTP3 server",
						err, closeErr)
				}
				return fmt.Errorf("failed graceful shutdown of HTTP3 server: %w", err)
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

func (c *Server) getDomainsPlusWWWDomains() (domainsWithWWW []string) {
	domainsWithWWW = make([]string, len(c.config.SSL.DomainList)*2)
	for i := range c.config.SSL.DomainList {
		c.config.SSL.DomainList[i] = strings.TrimSpace(c.config.SSL.DomainList[i])
		domainsWithWWW[i*2] = c.config.SSL.DomainList[i]
		domainsWithWWW[i*2+1] = "www." + c.config.SSL.DomainList[i]
	}

	return domainsWithWWW
}

func (c *Server) redirectToHTTPS() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// redirect to https
		var domainToRedirect string
		for _, domain := range c.config.SSL.DomainList {
			if strings.Contains(r.Host, domain) {
				domainToRedirect = domain
			}
		}
		http.Redirect(w, r, "https://"+domainToRedirect+r.RequestURI, http.StatusPermanentRedirect)
	}

	return http.HandlerFunc(fn)
}

// newHTTP1And2Server creates http.Server.
func (c *Server) newHTTP1And2Server(router *chi.Mux) {
	c.http1And2Server = &http.Server{
		Addr:              net.JoinHostPort("", fmt.Sprintf("%d", c.config.Port)),
		Handler:           router,
		ReadTimeout:       c.config.ReadTimeout,
		ReadHeaderTimeout: c.config.ReadHeaderTimeout,
		WriteTimeout:      c.config.WriteTimeout,
	}
}

// newHTTP3Server creates http.Server.
func (c *Server) newHTTP3Server(router *chi.Mux) {
	c.http3Server = &http3.Server{
		Handler:    router,
		QUICConfig: &quic.Config{
			// MaxIncomingStreams: 1,
		},
		// StreamHijacker: func(frameType http3.FrameType, conn quic.ConnectionTracingID, stream quic.Stream, err error) (bool, error) {
		// 	// log.Println("stream frame type:", frameType)
		// 	return false, nil
		// },
	}
}
