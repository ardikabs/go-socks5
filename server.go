package socks5

import (
	"context"
	"errors"
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
			cfg.CredentialStore = credentials.MemoryStore(cfg.UserPassMaps)
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

func (s *Server) ListenAndServe(address string) error {
	s.cfg.Logger.Info("starting SOCKS5 proxy server", "address", address)

	listener, err := net.Listen("tcp", address)
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

	// initial check for SOCKS version
	if version[0] != types.VERSION {
		log.Info("unsupported SOCKS version, closing ...", "phase", "inititation", "version", version[0])
		return
	}

	// parsing SOCKS authentication
	authn, err := auth.Parse(conn, s.cfg.EnabledAuthMethods, s.cfg.CredentialStore)
	if err != nil {
		log.Error(err, "failed to parse SOCKS authentication methods", "phase", "method selection")
		return
	}

	// authenticate SOCKS client
	authCtx, err := authn.Authenticate(ctx, conn, conn)
	if err != nil {
		log.Error(err, "failed to authenticate SOCKS client", "phase", "authentication")
		return
	}

	// parsing SOCKS request
	req, err := request.Parse(conn, SendReply, request.WithDialer(s.cfg.Dialer))
	if err != nil {
		log = log.WithValues("phase", "request parsing")

		var repErr error
		switch errors.Unwrap(err) {
		case types.ErrUnsupportedCommand:
			repErr = SendReply(conn, types.ReplyCommandNotSupported, nil)
		case types.ErrUnsupportedAddressType:
			repErr = SendReply(conn, types.ReplyAddrNotSupported, nil)
		default:
			repErr = SendReply(conn, types.ReplyGeneralFailure, nil)
		}

		if repErr != nil {
			log.Error(repErr, "failed to send SOCKS reply")
		}

		log.Error(err, "failed to parse SOCKS request")
		return
	}

	// handling SOCKS request
	reqCtx := contexts.WithAuth(ctx, authCtx)
	if err := req.Handle(reqCtx, conn); err != nil {
		log.Error(err, "failed to handle SOCKS request", "phase", "request handling")
		return
	}

	log.Info("handling SOCKS request completed", "remote", req.GetAddress().String(), "phase", "completion")
}
