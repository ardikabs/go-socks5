package socks5

import (
	"io"

	"github.com/ardikabs/socks5/pkg/types"
)

func SendReply(w io.Writer, replyCode types.ReplyCode, addr *types.Address) error {
	if addr == nil {
		addr = types.NilAddress
	}

	addrBytes := addr.Bytes()

	msg := make([]byte, 3+len(addrBytes))
	msg[0] = types.VERSION
	msg[1] = uint8(replyCode)
	msg[2] = 0
	copy(msg[3:], addrBytes)
	_, err := w.Write(msg)
	return err
}
