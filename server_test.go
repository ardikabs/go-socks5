package socks5

import (
	"net"
)

type fakeConn struct {
	net.Conn

	assertOnWrite func(p []byte)
}

func (f *fakeConn) Write(p []byte) (n int, err error) {
	if f.assertOnWrite != nil {
		f.assertOnWrite(p)
	}

	return len(p), nil
}
