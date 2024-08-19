package auth

import (
	"context"
	"fmt"
	"io"

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
	Authenticate(ctx context.Context, req io.Reader, rep io.Writer) (*AuthContext, error)
}

func Parse(rw io.ReadWriter, enabledAuthMethods []types.AuthMethod, cs credentials.Storer) (Authenticator, error) {
	nMethods := []byte{0}

	if _, err := rw.Read(nMethods); err != nil {
		return nil, fmt.Errorf("failed to fetch SOCKS auth method options: %v", err)
	}

	numberMethods := int(nMethods[0])
	offeredMethods := make([]byte, numberMethods)
	if _, err := io.ReadAtLeast(rw, offeredMethods, numberMethods); err != nil {
		return nil, fmt.Errorf("failed to fetch SOCKS auth methods: %v", err)
	}

	chosen, authn := factory(enabledAuthMethods, offeredMethods, cs)
	if _, err := rw.Write([]byte{types.VERSION, byte(chosen)}); err != nil {
		return nil, err
	}

	return authn, nil
}
