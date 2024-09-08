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
	nextProtoH1     = "http/1.1"
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

	terminate  chan struct{}
	terminated chan struct{}
}

type SSL struct {
	Email      string `env:"EMAIL" validate:"email"`
	DomainList []string
}

// newHTTP1And2Server creates http.Server.
func (c *Config) newHTTP1And2Server(router *chi.Mux) *http.Server {
	return &http.Server{
		Addr:              net.JoinHostPort("", fmt.Sprintf("%d", c.Port)),
		Handler:           router,
		ReadTimeout:       c.ReadTimeout,
		ReadHeaderTimeout: c.ReadHeaderTimeout,
		WriteTimeout:      c.WriteTimeout,
	}
}

// newHTTP3Server creates http.Server.
func (c *Config) newHTTP3Server(router *chi.Mux) *http3.Server {
	return &http3.Server{
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

func (c *Config) Init() {
	c.terminate = make(chan struct{})
	c.terminated = make(chan struct{})
}

func (c *Config) Terminate() {
	c.terminate <- struct{}{}
	<-c.terminated
}

type ExtraFunc func() error

// Launch enables the configured web server with the handlers that
// announced in a function matched with SetUpHandlers type.
func (c *Config) Launch(setupHandlers SetUpHandlers) error {
	domainsWithWWW := c.getDomainsPlusWWWDomains()

	router := chi.NewRouter()
	setupHandlers(router)

	http1And2Server := c.newHTTP1And2Server(router)
	http3Server := c.newHTTP3Server(router)

	// shutdown is a special channel to handle errors
	shutdown := make(chan error)

	if c.ProductionMode {
		certManager := autocert.Manager{
			Prompt: autocert.AcceptTOS,

			// Domain,
			HostPolicy: autocert.HostWhitelist(domainsWithWWW...),

			// Folder to store certificates
			Cache: autocert.DirCache("certs"),
			Email: c.SSL.Email,
		}

		tlsConfig := certManager.TLSConfig()
		tlsConfig.MinVersion = tls.VersionTLS13
		tlsConfig.GetCertificate = certManager.GetCertificate
		tlsConfig.NextProtos = []string{nextProtoH3, nextProtoH3_29, nextProtoH2, nextProtoH1}

		// Config HTTP server to redirect from 80 to 443 port
		go func() {
			_ = http.ListenAndServe( //nolint:gosec
				":http",
				certManager.HTTPHandler(RedirectToHTTPS(c.SSL.DomainList)),
			)
		}()

		// HTTP 1.1 and HTTP/2 server to handle the service
		go func() {
			http1And2Server.TLSConfig = tlsConfig
			funcErr := http1And2Server.ListenAndServeTLS("", "")
			if funcErr != nil {
				shutdown <- funcErr
			}
		}()

		// HTTP/3 server to handle the service on UDP:443
		go func() {
			http3Server.TLSConfig = tlsConfig
			funcErr := http3Server.ListenAndServe()
			shutdown <- funcErr
		}()
	} else {
		go func() {
			funcErr := http1And2Server.ListenAndServe()
			if funcErr != nil {
				shutdown <- funcErr
			}
		}()
	}

	var outputError error
	select {
	case err := <-shutdown:
		outputError = fmt.Errorf("failed: %w", err)
	case <-c.terminate:
		outputError = errors.New("terminated")

		timeout, cancelFunc := context.WithTimeout(context.Background(), timeOutDuration)
		defer cancelFunc()

		errGroup, egCtx := errgroup.WithContext(timeout)
		errGroup.Go(func() error {
			if err := http1And2Server.Shutdown(egCtx); err != nil {
				err = fmt.Errorf("unable to terminate http1/2 service: %w", err)
				closeErr := http1And2Server.Close()
				if closeErr != nil {
					err = fmt.Errorf("%w: unable to close http1/2 service: %w", err, closeErr)
				}
				return err
			}

			return nil
		})

		errGroup.Go(func() error {
			if err := http3Server.CloseGracefully(timeOutDuration); err != nil {
				err = fmt.Errorf("unable to terminate http3 server: %w", err)
				closeErr := http3Server.Close()
				if closeErr != nil {
					err = fmt.Errorf("%w: unable to close http3 service: %w", err, closeErr)
				}
				return err
			}

			return nil
		})

		if err := errGroup.Wait(); err != nil {
			outputError = fmt.Errorf("unable to terminate the web services: %w", err)
		}

		cancelFunc()

		c.terminated <- struct{}{}
	}

	return outputError
}

func (c *Config) getDomainsPlusWWWDomains() (domainsWithWWW []string) {
	domainsWithWWW = make([]string, len(c.SSL.DomainList)*2)
	for i := range c.SSL.DomainList {
		c.SSL.DomainList[i] = strings.TrimSpace(c.SSL.DomainList[i])
		domainsWithWWW[i*2] = c.SSL.DomainList[i]
		domainsWithWWW[i*2+1] = "www." + c.SSL.DomainList[i]
	}

	return domainsWithWWW
}

func RedirectToHTTPS(domains []string) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// redirect to https
		var domainToRedirect string
		for _, domain := range domains {
			if strings.Contains(r.Host, domain) {
				domainToRedirect = domain
			}
		}
		http.Redirect(w, r, "https://"+domainToRedirect+r.RequestURI, http.StatusPermanentRedirect)
	}

	return http.HandlerFunc(fn)
}
