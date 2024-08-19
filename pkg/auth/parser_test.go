package auth

import (
	"bytes"
	"testing"

	"github.com/ardikabs/socks5/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestAuthParser(t *testing.T) {

	t.Run("parse 'NO AUTHENTICATION REQUIRED' authenticator", func(t *testing.T) {
		rw := bytes.NewBuffer(nil)
		rw.Write([]byte{0x01, 0x00})

		authn, err := Parse(rw, []types.AuthMethod{types.AuthNoAuthRequired}, nil)
		require.NoError(t, err)
		require.IsType(t, new(guestAuthenticator), authn)
		require.Equal(t, []byte{types.VERSION, 0x00}, rw.Bytes())
	})

	t.Run("should return error if non-enabled methods are offered", func(t *testing.T) {
		rw := bytes.NewBuffer(nil)
		rw.Write([]byte{0x01, 0x01})

		authn, err := Parse(rw, []types.AuthMethod{types.AuthNoAuthRequired, types.AuthUserPass}, nil)
		require.NoError(t, err)
		require.IsType(t, new(notAcceptableAuthenticator), authn)
		require.Equal(t, []byte{types.VERSION, 0xFF}, rw.Bytes())
	})
}
