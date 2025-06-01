# Chissy

A modern HTTP server implementation in Go that supports HTTP/1.1, HTTP/2, and HTTP/3 (QUIC) protocols with automatic SSL/TLS certificate management.

## Features

- HTTP/1.1 and HTTP/2 support
- HTTP/3 (QUIC) support
- Automatic SSL/TLS certificate management using Let's Encrypt
- Automatic HTTP to HTTPS redirection
- Configurable timeouts and server settings
- Production and development modes
- Graceful shutdown support
- Built with [Chi](https://github.com/go-chi/chi) router

## Installation

```bash
go get github.com/kaatinga/chissy/v2
```

## Usage

### Basic Example

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/kaatinga/chissy/v2"
    "github.com/go-chi/chi/v5"
)

func main() {
    config := chissy.Config{
        Port:              8080,
        ReadTimeout:       1 * time.Minute,
        ReadHeaderTimeout: 15 * time.Second,
        WriteTimeout:      1 * time.Minute,
    }

    server := chissy.NewServer(context.Background(), config)
    
    setupHandlers := func(r *chi.Mux) {
        r.Get("/", func(w http.ResponseWriter, r *http.Request) {
            w.Write([]byte("Hello, World!"))
        })
    }

    if err := server.Launch(context.Background(), setupHandlers); err != nil {
        log.Fatal(err)
    }
}
```

### Production Mode with SSL

```go
config := chissy.Config{
    ProductionMode: true,
    Port:          443,
    SSL: chissy.SSL{
        Email:      "your-email@example.com",
        DomainList: []string{"example.com", "www.example.com"},
    },
    ReadTimeout:       1 * time.Minute,
    ReadHeaderTimeout: 15 * time.Second,
    WriteTimeout:      1 * time.Minute,
}
```

## Configuration

The server can be configured using the following environment variables:

- `PROD`: Enable production mode (default: false)
- `PORT`: Server port (default: 8080)
- `LOCALHOST_DOMAIN`: Domain for localhost in development mode
- `EMAIL`: Email for Let's Encrypt certificate management
- `READ_TIMEOUT`: Read timeout duration (default: 1m)
- `READ_HEADER_TIMEOUT`: Read header timeout duration (default: 15s)
- `WRITE_TIMEOUT`: Write timeout duration (default: 1m)

## Development

### Running Tests

```bash
go test -v ./...
```

### Building

```bash
go build
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details on our code of conduct and the process for submitting pull requests.
