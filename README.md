# Chissy

A modern, production-ready HTTP server implementation in Go that supports HTTP/1.1, HTTP/2, and HTTP/3 (QUIC) protocols with automatic SSL/TLS certificate management.

## Features

- **Multi-Protocol Support**
  - HTTP/1.1 and HTTP/2 support
  - Optional HTTP/3 (QUIC) support with optimized configuration
  - Automatic protocol negotiation

- **Security**
  - Automatic SSL/TLS certificate management using Let's Encrypt
  - Automatic HTTP to HTTPS redirection
  - TLS 1.3 support
  - HSTS support in production mode

- **Performance & Reliability**
  - Configurable timeouts and server settings
  - Optimized QUIC configuration for HTTP/3
  - Graceful shutdown support
  - Connection and stream limits management

- **Monitoring**
  - Optional Prometheus metrics integration
  - Built-in metrics endpoint

- **Development**
  - Production and development modes
  - Built with [Chi](https://github.com/go-chi/chi) router
  - Environment-based configuration

## Installation

```bash
go get github.com/kaatinga/chissy/v2
```

## Quick Start

### Basic Example

```go
package main

import (
    "context"
    "log"
    "net/http"
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

    if err := server.Launch(setupHandlers); err != nil {
        log.Fatal(err)
    }
}
```

### Production Mode with SSL and HTTP/3

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

// Create server with HTTP/3 and metrics enabled
server := chissy.NewServer(
    context.Background(), 
    config,
    chissy.WithHTTP3(),
    chissy.WithMetricsServer(9090),
)
```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PROD` | Enable production mode | false | No |
| `PORT` | Server port | 8080 | No |
| `LOCALHOST_DOMAIN` | Domain for localhost in development mode | - | Yes (if PROD=false) |
| `EMAIL` | Email for Let's Encrypt certificate management | - | Yes (if PROD=true) |
| `READ_TIMEOUT` | Read timeout duration | 1m | No |
| `READ_HEADER_TIMEOUT` | Read header timeout duration | 15s | No |
| `WRITE_TIMEOUT` | Write timeout duration | 1m | No |

### Server Options

Chissy provides several server options for additional functionality:

- `WithHTTP3()`: Enables HTTP/3 support
- `WithMetricsServer(port uint16)`: Enables Prometheus metrics server

## HTTP/3 Configuration

When HTTP/3 is enabled, the server uses optimized QUIC settings:

- Max incoming streams: 1000
- Max incoming unidirectional streams: 1000
- Connection receive window: 15MB
- Stream receive window: 6MB
- Initial stream receive window: 512KB
- Max idle timeout: 30 seconds
- Handshake idle timeout: 10 seconds

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
