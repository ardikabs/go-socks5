package socks5

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ardikabs/socks5/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestServer_Connect(t *testing.T) {
	// Create dummy server
	dummyListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer dummyListener.Close()

	dummyAddr := dummyListener.Addr().(*net.TCPAddr)
	wantPayload := "dummy payload"

	go func() {
		conn, err := dummyListener.Accept()
		require.NoError(t, err)

		header := []byte{0}
		_, err = io.ReadAtLeast(conn, header, 1)
		require.NoError(t, err)

		payload := make([]byte, int(header[0]))
		_, err = io.ReadAtLeast(conn, payload, int(header[0]))
		require.NoError(t, err)

		require.Equal(t, wantPayload, string(payload))

		conn.Write([]byte{'o', 'k'})
		conn.Close()
	}()

	// Create SOCKS5 server
	srvAddr := "127.0.0.1:20080"
	srv, err := New(ServerConfig{
		EnabledAuthMethods: []types.AuthMethod{types.AuthUserPass},
		UserPassMaps:       map[string]string{"user": "password"},
	})
	require.NoError(t, err)

	go func() { require.NoError(t, srv.ListenAndServe(srvAddr)) }()

	time.Sleep(20 * time.Millisecond)

	// Act as client, to connect to the SOCKS5 server
	conn, err := net.Dial("tcp", srvAddr)
	require.NoError(t, err)

	req := bytes.NewBuffer(nil)
	// Initial negotiation
	req.Write([]byte{types.VERSION, 0x02, byte(types.AuthNoAuthRequired), byte(types.AuthUserPass)})
	// Authentication
	req.Write([]byte{0x01, 0x04, 'u', 's', 'e', 'r', 0x08, 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'})
	// Request
	req.Write([]byte{types.VERSION, byte(types.CommandConnect), 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, uint8(dummyAddr.Port >> 8), uint8(dummyAddr.Port & 0xFF)})

	// Actual traffic payload
	req.Write([]byte{byte(len(wantPayload))})
	req.Write([]byte(wantPayload))

	_, err = conn.Write(req.Bytes())
	require.NoError(t, err)

	wants := []byte{
		// Reply Auth Method Selection
		types.VERSION, byte(types.AuthUserPass),
		// Reply Auth Success
		0x01, 0x00,
		// Reply Request
		types.VERSION, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x00,
		// Reply the proxied payload
		'o', 'k',
	}

	out := make([]byte, len(wants))
	_, err = io.ReadAtLeast(conn, out, len(wants))
	require.NoError(t, err)

	// ignore bind port
	out[12] = 0
	out[13] = 0

	require.Equal(t, wants, out)
}
