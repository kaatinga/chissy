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
)

var timeOutDuration = 5 * time.Second

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

// newHTTP1And2Service creates http.Server structure with router inside.
func (config *Config) newHTTP1And2Service() http.Server {
	return http.Server{
		Addr:              net.JoinHostPort("", fmt.Sprintf("%d", config.Port)),
		Handler:           chi.NewRouter(),
		ReadTimeout:       config.ReadTimeout,
		ReadHeaderTimeout: config.ReadHeaderTimeout,
		WriteTimeout:      config.WriteTimeout,
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

// Launch enables the configured web service with the handlers that
// announced in a function matched with SetUpHandlers type.
func (config *Config) Launch(handlers SetUpHandlers) error {
	http1And2Service := config.newHTTP1And2Service()
	var http3Service http3.Server

	// enable handlers inside SetUpHandlers function
	router, ok := http1And2Service.Handler.(*chi.Mux)
	if !ok {
		return errors.New("http1And2Service.Handler is not a *chi.Router")
	}
	handlers(router)

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

		// Config server to redirect
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
			http1And2Service.TLSConfig = tlsConfig
			funcErr := http1And2Service.ListenAndServeTLS("", "")
			if funcErr != nil {
				shutdown <- funcErr
			}
		}()

		// HTTP/3 server to handle the service
		go func() {
			streamHijacker := func(frameType http3.FrameType, conn quic.Connection, stream quic.Stream, err error) (bool, error) {
				// log.Println("stream frame type:", frameType)
				return false, nil
			}
			quicConf := &quic.Config{
				// MaxIncomingStreams: 1,
			}
			http3Service = http3.Server{
				Handler:        http1And2Service.Handler,
				QuicConfig:     quicConf,
				StreamHijacker: streamHijacker,
				TLSConfig:      tlsConfig,
			}
			funcErr := http3Service.ListenAndServeTLS("", "")
			shutdown <- funcErr
		}()
	default:
		go func() {
			funcErr := http1And2Service.ListenAndServe()
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

		if err := http1And2Service.Shutdown(timeout); err != nil {
			outputError = fmt.Errorf("unable to terminate http1/2 service: %w", err)
			err := http1And2Service.Close()
			if err != nil {
				outputError = fmt.Errorf("%w: unable to close http1/2 service: %w", outputError, err)
			}
		}

		if err := http3Service.CloseGracefully(timeOutDuration); err != nil {
			outputError = fmt.Errorf("unable to terminate http3 service: %w", err)
		}

		config.terminated <- struct{}{}
	}

	return outputError
}

func getCertificates(autoCertManager *autocert.Manager) (string, string) {
	if autoCertManager == nil {
		return "certs/cert.pem", "certs/key.pem"
	}

	return autoCertManager.Cache.Get(context.Background(), "certs/cert.pem"), autoCertManager.Cache.Get("certs/key.pem")

}
