package chissy

import "net/http"

const (
	altSvcHeader = `h3=":443"; ma=2592000; h3-29=":443"; ma=2592000`
	hstsHeader   = `max-age=31536000; includeSubDomains; preload`
)

func advertiseHTTP3(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 3 {
			w.Header().Set("Alt-Svc", altSvcHeader)
		}
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

func advertiseHSTS(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", hstsHeader)
		}
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
