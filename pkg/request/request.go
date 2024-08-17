package request

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/ardikabs/socks5/pkg/resolver"
	"github.com/ardikabs/socks5/pkg/tool/contexts"
	"github.com/ardikabs/socks5/pkg/tool/proxy"
	"github.com/ardikabs/socks5/pkg/types"
)

var (
	DefaultResolver = resolver.BaseResolver{}
	DefaultDialer   = func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
)

// Cmder is a function that handles the SOCKS request command
type Cmder func(ctx context.Context, conn net.Conn) error

// Dialer is a function that dials the network
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// Replier is a function that sends the reply to the SOCKS client
type Replier func(conn net.Conn, rep types.ReplyCode, address *types.Address) error

// DomainResolver is an interface that resolves the domain name
type DomainResolver interface {
	Resolve(ctx context.Context, domain string) (net.IP, error)
}

// Request represents a SOCKS request.
type Request struct {
	conn net.Conn

	cmder    Cmder
	dialer   Dialer
	replier  Replier
	resolver DomainResolver

	cmdID   types.CommandID
	address *types.Address
}

func New(conn net.Conn, replier Replier, opts ...Option) (req *Request, err error) {
	defer func() {
		if err != nil {
			var repErr error
			switch errors.Unwrap(err) {
			case types.ErrUnsupportedCommand:
				repErr = replier(conn, types.ReplyCommandNotSupported, nil)
			case types.ErrUnsupportedAddressType:
				repErr = replier(conn, types.ReplyAddrNotSupported, nil)
			default:
				repErr = replier(conn, types.ReplyGeneralFailure, nil)
			}

			if repErr != nil {
				err = fmt.Errorf("failed to send reply: %v", repErr)
			}

			return
		}
	}()

	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(conn, header, 3); err != nil {
		return req, fmt.Errorf("%w: %v", types.ErrRequestHeaderParseFailed, err)
	}

	if header[0] != types.VERSION {
		return req, fmt.Errorf("%w: %d", types.ErrUnsupportedVersion, header[0])
	}

	req = &Request{
		conn:     conn,
		replier:  replier,
		dialer:   DefaultDialer,
		resolver: DefaultResolver,
	}

	for _, opt := range opts {
		if err = opt(req); err != nil {
			return
		}
	}

	if err = req.parseCommand(header[1]); err != nil {
		return
	}

	if err = req.parseAddress(conn); err != nil {
		return
	}

	return
}

func (req *Request) parseCommand(cmd byte) error {
	switch req.cmdID = types.CommandID(cmd); req.cmdID {
	case types.CommandConnect:
		req.cmder = req.handleConnect
	default:
		return fmt.Errorf("%w: %d", types.ErrUnsupportedCommand, cmd)
	}

	return nil
}

func (req *Request) parseAddress(r io.Reader) error {
	addr, err := types.NewAddress(r)
	if err != nil {
		return err
	}

	req.address = addr
	return nil
}

func (req *Request) GetCommand() types.CommandID {
	return req.cmdID
}

func (req *Request) GetAddress() types.Address {
	if req.address == nil {
		return *types.NilAddress
	}

	return *req.address
}

// Handle processes the SOCKS request.
func (req *Request) Handle(ctx context.Context) error {
	return req.cmder(ctx, req.conn)
}

func (req *Request) handleConnect(ctx context.Context, clientConn net.Conn) error {
	log := contexts.GetLogger(ctx).WithValues("command", "connect")

	// Attempt to connect to the target address
	if req.address.DomainName != "" {
		log = log.WithValues("domain", req.address.DomainName)
		log.V(1).Info("resolving domain name")

		ip, err := req.resolver.Resolve(ctx, req.address.DomainName)
		if err != nil {
			if err := req.replier(clientConn, types.ReplyHostUnreach, req.address); err != nil {
				return err
			}

			return fmt.Errorf("failed to resolve domain name: %s, %v", req.address.DomainName, err)
		}

		req.address.IP = ip
		log = log.WithValues("targetIP", ip.String())
	}

	dstAddress := req.address.Address()

	log.V(1).Info("dialing target address", "address", dstAddress)
	targetConn, err := req.dialer(ctx, "tcp", dstAddress)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "refused"):
			if err := req.replier(clientConn, types.ReplyConnRefused, req.address); err != nil {
				return fmt.Errorf("failed to send reply: %v", err)
			}

			return fmt.Errorf("%w: %s", err, dstAddress)
		case strings.Contains(err.Error(), "network is unreachable"):
			if err := req.replier(clientConn, types.ReplyNetworkUnreach, req.address); err != nil {
				return fmt.Errorf("failed to send reply: %v", err)
			}

			return fmt.Errorf("%w: %s", err, dstAddress)
		}

		return fmt.Errorf("failed to connect to target address: %s, %v", dstAddress, err)
	}
	defer targetConn.Close()

	localAddr := targetConn.LocalAddr().(*net.TCPAddr)
	bindAddr := &types.Address{
		IP:   localAddr.IP,
		Port: localAddr.Port,
	}

	log.V(2).Info("sending reply", "bindAddr", bindAddr, "replyCode", types.ReplySucceeded.String())
	if err := req.replier(clientConn, types.ReplySucceeded, bindAddr); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	log.Info("start proxying", "source", clientConn.RemoteAddr(), "destination", targetConn.RemoteAddr())

	// Start proxying connection between the client and the target host
	return proxy.Start(clientConn, targetConn)
}
