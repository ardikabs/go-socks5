package auth

import (
	"bytes"
	"context"
	"testing"

	"github.com/ardikabs/socks5/pkg/auth/credentials"
	"github.com/ardikabs/socks5/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestNotAcceptableAuthenticator(t *testing.T) {
	auth := &notAcceptableAuthenticator{[]byte{0x00, 0x02}}

	req := bytes.NewBuffer(nil)
	rep := bytes.NewBuffer(nil)

	authCtx, err := auth.Authenticate(context.TODO(), req, rep)
	require.ErrorIs(t, err, ErrAuthNotSupported)
	require.Nil(t, authCtx)
}

func TestGuestAuthenticator(t *testing.T) {
	auth := &guestAuthenticator{}

	req := bytes.NewBuffer(nil)
	rep := bytes.NewBuffer(nil)

	authCtx, err := auth.Authenticate(context.TODO(), req, rep)
	require.NoError(t, err)
	require.Equal(t, types.AuthNoAuthRequired, authCtx.Method)
}

func TestUserPassAuthenticator(t *testing.T) {
	uname := "test"
	passwd := "test"

	auth := &userPassAuthenticator{
		cs: credentials.MemoryStore{uname: passwd},
	}

	t.Run("valid credential", func(t *testing.T) {
		req := bytes.NewBuffer(nil)
		req.Write([]byte{userPassAuthVersion, byte(len(uname))})
		req.Write([]byte(uname))
		req.Write([]byte{byte(len(passwd))})
		req.Write([]byte(passwd))

		rep := bytes.NewBuffer(nil)
		authCtx, err := auth.Authenticate(context.TODO(), req, rep)
		require.NoError(t, err)
		require.Equal(t, []byte{userPassAuthVersion, 0x00}, rep.Bytes())
		require.Equal(t, types.AuthUserPass, authCtx.Method)
		p, exists := authCtx.Payload["username"]
		require.True(t, exists)
		require.Equal(t, passwd, p)
	})

	t.Run("username not exist", func(t *testing.T) {
		req := bytes.NewBuffer(nil)
		req.Write([]byte{userPassAuthVersion, byte(len("notexist"))})
		req.Write([]byte("notexist"))
		req.Write([]byte{byte(len(passwd))})
		req.Write([]byte(passwd))

		rep := bytes.NewBuffer(nil)
		authCtx, err := auth.Authenticate(context.TODO(), req, rep)
		require.Nil(t, authCtx)
		require.Error(t, err)
		require.Equal(t, []byte{userPassAuthVersion, 0x01}, rep.Bytes())
	})

	t.Run("password doesnt match", func(t *testing.T) {
		req := bytes.NewBuffer(nil)
		req.Write([]byte{userPassAuthVersion, byte(len(uname))})
		req.Write([]byte(uname))
		req.Write([]byte{byte(len("badpassword"))})
		req.Write([]byte("badpassword"))

		rep := bytes.NewBuffer(nil)
		authCtx, err := auth.Authenticate(context.TODO(), req, rep)
		require.Nil(t, authCtx)
		require.Error(t, err)
		require.Equal(t, []byte{userPassAuthVersion, 0x01}, rep.Bytes())
	})
}
