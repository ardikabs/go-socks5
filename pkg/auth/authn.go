package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ardikabs/socks5/pkg/auth/credentials"
	"github.com/ardikabs/socks5/pkg/types"
)

type notAcceptableAuthenticator struct {
	unsupportedMethods []byte
}

func (a *notAcceptableAuthenticator) Authenticate(_ context.Context, req io.Reader, rep io.Writer) (*AuthContext, error) {
	unsupportedInString := make([]string, 0, len(a.unsupportedMethods))
	for _, method := range a.unsupportedMethods {
		unsupportedInString = append(unsupportedInString, types.AuthMethod(method).String())
	}

	return nil, fmt.Errorf("%w: %v", ErrAuthNotSupported, strings.Join(unsupportedInString, ","))
}

type guestAuthenticator struct{}

func (a *guestAuthenticator) Authenticate(_ context.Context, req io.Reader, rep io.Writer) (*AuthContext, error) {
	return &AuthContext{Method: types.AuthNoAuthRequired}, nil
}

const userPassAuthVersion = uint8(1)

type userPassAuthenticator struct {
	cs credentials.Storer
}

func (a *userPassAuthenticator) Authenticate(_ context.Context, req io.Reader, rep io.Writer) (*AuthContext, error) {
	// Reference: https://datatracker.ietf.org/doc/html/rfc1929
	// USERNAME/PASSWORD Initial Negotiation
	// +----+------+----------+------+----------+
	// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	// +----+------+----------+------+----------+
	// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	// +----+------+----------+------+----------+

	version := []byte{0}
	if _, err := req.Read(version); err != nil {
		return nil, fmt.Errorf("failed to read user/pass header: %v", err)
	}

	if version[0] != userPassAuthVersion {
		return nil, fmt.Errorf("%w: %d", types.ErrUnsupportedVersion, version[0])
	}

	length := []byte{0}

	// Read username length
	if _, err := req.Read(length); err != nil {
		return nil, fmt.Errorf("failed to read username length: %v", err)
	}

	unameLength := int(length[0])
	uname := make([]byte, unameLength)
	if _, err := io.ReadAtLeast(req, uname, unameLength); err != nil {
		return nil, fmt.Errorf("failed to read username: %v", err)
	}

	// Read password length
	if _, err := req.Read(length); err != nil {
		return nil, fmt.Errorf("failed to read password length: %v", err)
	}

	passwdLength := int(length[0])
	passwd := make([]byte, passwdLength)
	if _, err := io.ReadAtLeast(req, passwd, passwdLength); err != nil {
		return nil, fmt.Errorf("failed to read password: %v", err)
	}

	// Authenticate
	// Reply:
	// +----+--------+
	// |VER | STATUS |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	// Status:
	// 		Success (0x00)
	// 		Failure (0x01)

	if err := a.cs.Validate(credentials.Parameters{
		Username: string(uname),
		Password: string(passwd),
	}); err != nil {
		if errors.Is(err, credentials.ErrInvalidCredentials) {
			// Send failure reply to indicate that the credentials are invalid
			if _, err := rep.Write([]byte{userPassAuthVersion, 0x01}); err != nil {
				return nil, fmt.Errorf("failed to send auth reply: %v", err)
			}
		}

		return nil, fmt.Errorf("failed to validate credentials: %v", err)
	}

	// Send success reply to indicate that the credentials are valid
	if _, err := rep.Write([]byte{userPassAuthVersion, 0x00}); err != nil {
		return nil, fmt.Errorf("failed to send auth reply: %v", err)
	}

	return &AuthContext{
		Method: types.AuthUserPass,
		Payload: AuthPayload{
			"username": string(uname),
		},
	}, nil
}
