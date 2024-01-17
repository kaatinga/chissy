package chissy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
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
	SSL               SSL           `validate:"required_if=ProductionMode true"`
	Port              uint16        `env:"PORT" validate:"min=80,max=65535"`
	ReadTimeout       time.Duration `env:"READ_TIMEOUT" default:"1m"`
	ReadHeaderTimeout time.Duration `env:"READ_HEADER_TIMEOUT" default:"15s"`
	WriteTimeout      time.Duration `env:"WRITE_TIMEOUT" default:"1m"`

	terminate  chan struct{}
	terminated chan struct{}
}

type SSL struct {
	Domain string `env:"DOMAIN" validate:"fqdn"`
	Email  string `env:"EMAIL" validate:"email"`
}

// newHTTP1And2Server creates http.Server.
func (config *Config) newHTTP1And2Server(router *chi.Mux) *http.Server {
	return &http.Server{
		Addr:              net.JoinHostPort("", fmt.Sprintf("%d", config.Port)),
		Handler:           router,
		ReadTimeout:       config.ReadTimeout,
		ReadHeaderTimeout: config.ReadHeaderTimeout,
		WriteTimeout:      config.WriteTimeout,
	}
}

// newHTTP3Server creates http.Server.
func (config *Config) newHTTP3Server(router *chi.Mux) *http3.Server {
	return &http3.Server{
		Handler:    router,
		QuicConfig: &quic.Config{
			// MaxIncomingStreams: 1,
		},
		StreamHijacker: func(frameType http3.FrameType, conn quic.Connection, stream quic.Stream, err error) (bool, error) {
			// log.Println("stream frame type:", frameType)
			return false, nil
		},
	}
}

func (config *Config) Init() {
	config.terminate = make(chan struct{})
	config.terminated = make(chan struct{})
}

func (config *Config) Terminate() {
	config.terminate <- struct{}{}
	<-config.terminated
}

// Launch enables the configured web server with the handlers that
// announced in a function matched with SetUpHandlers type.
func (config *Config) Launch(setupHandlers SetUpHandlers) error {
	// enable handlers by setupHandlers() function
	router := chi.NewRouter()
	setupHandlers(router)

	http1And2Server := config.newHTTP1And2Server(router)
	http3Server := config.newHTTP3Server(router)

	// shutdown is a special channel to handle errors
	shutdown := make(chan error)

	switch config.ProductionMode {
	case true:
		certManager := autocert.Manager{
			Prompt: autocert.AcceptTOS,

			// Domain
			HostPolicy: autocert.HostWhitelist(config.SSL.Domain, "www."+config.SSL.Domain),

			// Folder to store certificates
			Cache: autocert.DirCache("certs"),
			Email: config.SSL.Email,
		}

		tlsConfig := certManager.TLSConfig()
		tlsConfig.MinVersion = tls.VersionTLS13
		tlsConfig.GetCertificate = certManager.GetCertificate
		tlsConfig.NextProtos = []string{nextProtoH3, nextProtoH3_29, nextProtoH2}

		// Config HTTP server to redirect from 80 to 443 port
		go func() {
			_ = http.ListenAndServe( //nolint:gosec
				":http",
				certManager.HTTPHandler(

					// Redirect from http to https
					http.RedirectHandler(
						"https://"+config.SSL.Domain,
						http.StatusPermanentRedirect),
				),
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
	default:
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
	case <-config.terminate:
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

		config.terminated <- struct{}{}
	}

	return outputError
}
