package auth

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/ardikabs/socks5/pkg/auth/credentials"
	"github.com/ardikabs/socks5/pkg/types"
)

var (
	ErrAuthNotSupported = fmt.Errorf("no authentication method supported")
)

type AuthPayload map[string]interface{}

type AuthContext struct {
	Method  types.AuthMethod
	Payload AuthPayload
}

type Authenticator interface {
	Authenticate(context.Context, net.Conn) (*AuthContext, error)
}

type Handler struct {
	conn  net.Conn
	authn Authenticator
}

func New(conn net.Conn, enabledAuthMethods []types.AuthMethod, cs credentials.Storer) (*Handler, error) {
	nMethods := []byte{0}

	if _, err := conn.Read(nMethods); err != nil {
		return nil, fmt.Errorf("failed to fetch SOCKS auth method options: %v", err)
	}

	numberMethods := int(nMethods[0])
	offeredMethods := make([]byte, numberMethods)
	if _, err := io.ReadAtLeast(conn, offeredMethods, numberMethods); err != nil {
		return nil, fmt.Errorf("failed to fetch SOCKS auth methods: %v", err)
	}

	return &Handler{
		conn:  conn,
		authn: authFactory(enabledAuthMethods, offeredMethods, cs),
	}, nil
}

func (h *Handler) Handle(ctx context.Context) (*AuthContext, error) {
	authCtx, err := h.authn.Authenticate(ctx, h.conn)
	if err != nil {
		return nil, err
	}

	return authCtx, nil
}
