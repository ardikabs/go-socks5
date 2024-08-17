package socks5

import (
	"context"
	"log/slog"
	"net"
	"os"

	"github.com/ardikabs/socks5/pkg/auth"
	"github.com/ardikabs/socks5/pkg/auth/credentials"
	"github.com/ardikabs/socks5/pkg/request"
	"github.com/ardikabs/socks5/pkg/tool/contexts"
	"github.com/ardikabs/socks5/pkg/types"
	"github.com/go-logr/logr"
	"github.com/google/uuid"
)

type Server struct {
	cfg ServerConfig

	shutdownFn func()
}

func New(cfg ServerConfig) (*Server, error) {
	if cfg.Logger.IsZero() {
		cfg.Logger = logr.FromSlogHandler(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	}

	if len(cfg.EnabledAuthMethods) == 0 {
		cfg.EnabledAuthMethods = []types.AuthMethod{types.AuthNoAuthRequired, types.AuthUserPass}
	}

	if cfg.CredentialStore == nil {
		if cfg.UserPassFilename != "" {
			cs, err := credentials.NewFileStore(cfg.UserPassFilename)
			if err != nil {
				return nil, err
			}

			cfg.CredentialStore = cs
		} else if cfg.UserPassMaps != nil {
			cs, err := credentials.NewInMemoryStore(cfg.UserPassMaps)
			if err != nil {
				return nil, err
			}

			cfg.CredentialStore = cs
		}

	}

	return &Server{
		cfg: cfg,
	}, nil
}

func (s *Server) Shutdown() {
	if s.shutdownFn != nil {
		s.shutdownFn()
	}
}

func (s *Server) ListenAndServe(network, address string) error {
	s.cfg.Logger.Info("starting SOCKS5 proxy server", "address", address)

	listener, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	s.shutdownFn = func() {
		cancel()
		listener.Close()
	}

	return s.serve(ctx, listener)
}

func (s *Server) serve(ctx context.Context, l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(baseCtx context.Context, conn net.Conn) {
	defer conn.Close()

	connID := uuid.New().String()
	log := s.cfg.Logger.WithName("handleConn").WithValues("connID", connID)
	ctx := contexts.New(baseCtx, connID, log)

	version := []byte{0}
	if _, err := conn.Read(version); err != nil {
		log.Error(err, "failed to fetch SOCKS version, closing ...", "phase", "inititation")
		return
	}

	if version[0] != types.VERSION {
		log.Info("unsupported SOCKS version, closing ...", "phase", "inititation", "version", version[0])
		return
	}

	authHandler, err := auth.New(conn, s.cfg.EnabledAuthMethods, s.cfg.CredentialStore)
	if err != nil {
		log.Error(err, "failed to parse SOCKS authentication methods", "phase", "method selection")
		return
	}

	authCtx, err := authHandler.Handle(ctx)
	if err != nil {
		log.Error(err, "failed to authenticate SOCKS client", "phase", "authentication")
		return
	}

	// start processing client's request
	req, err := request.New(conn, SendReply, request.WithDialer(s.cfg.Dialer))
	if err != nil {
		log.Error(err, "failed to construct SOCKS request", "phase", "request parsing")
		return
	}

	reqCtx := contexts.WithAuth(ctx, authCtx)
	if err := req.Handle(reqCtx); err != nil {
		log.Error(err, "failed to handle SOCKS request", "phase", "request handling")
		return
	}

	log.Info("handling SOCKS request completed", "phase", "completion")
}
