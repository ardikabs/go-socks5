package socks5

import (
	"testing"

	"github.com/ardikabs/socks5/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestSendReply(t *testing.T) {
	fakeConn := &fakeConn{
		assertOnWrite: func(p []byte) {
			require.Equal(t, []byte{
				0x05,                   // SOCKS 5 Version
				0x00,                   // Reply Succeded
				0x00,                   // RSV
				0x01,                   // IPv4 Address Type
				0x00, 0x00, 0x00, 0x00, // IPv4 zero address
				0x00, 0x00, // IPv4
			}, p)
		},
	}

	require.NoError(t, SendReply(fakeConn, types.ReplySucceeded, nil))
}
