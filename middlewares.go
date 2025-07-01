package chissy

import "net/http"

const (
	altSvcHeader = `h3=":443"; ma=2592000; h3-29=":443"; ma=2592000`
	hstsHeader   = `max-age=31536000; includeSubDomains; preload`
)

// advertiseHTTP3 is a middleware that sets the Alt-Svc header to advertise HTTP/3 (QUIC) support to clients.
// This header informs browsers and other clients that the server supports HTTP/3 (h3 and h3-29) on port 443,
// allowing them to upgrade future requests to use HTTP/3 for improved performance. The header is only set
// for requests that are not already using HTTP/3.
func advertiseHTTP3(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 3 {
			w.Header().Set("Alt-Svc", altSvcHeader)
		}
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

// advertiseHSTS is a middleware that sets the Strict-Transport-Security (HSTS) header for HTTPS requests.
// This header instructs browsers to only use HTTPS for the domain and all its subdomains for one year (31536000 seconds),
// and allows the domain to be included in browser preload lists. The header is only set for requests served over TLS.
func advertiseHSTS(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", hstsHeader)
		}
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
