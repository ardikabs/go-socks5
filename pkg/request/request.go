package request

import (
	"context"
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
type Replier func(w io.Writer, rep types.ReplyCode, address *types.Address) error

// DomainResolver is an interface that resolves the domain name
type DomainResolver interface {
	Resolve(ctx context.Context, domain string) (net.IP, error)
}

// Request represents a SOCKS request.
type Request struct {
	cmder    Cmder
	dialer   Dialer
	replier  Replier
	resolver DomainResolver

	cmdID   types.CommandID
	address *types.Address
}

func Parse(r io.Reader, replier Replier, opts ...Option) (*Request, error) {
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(r, header, 3); err != nil {
		return nil, fmt.Errorf("%w: %v", types.ErrRequestHeaderParseFailed, err)
	}

	if header[0] != types.VERSION {
		return nil, fmt.Errorf("%w: %d", types.ErrUnsupportedVersion, header[0])
	}

	req := &Request{
		replier:  replier,
		dialer:   DefaultDialer,
		resolver: DefaultResolver,
	}

	for _, opt := range opts {
		if err := opt(req); err != nil {
			return nil, err
		}
	}

	if err := req.parseCommand(header[1]); err != nil {
		return nil, err
	}

	if err := req.parseAddress(r); err != nil {
		return nil, err
	}

	return req, nil
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
func (req *Request) Handle(ctx context.Context, clientConn net.Conn) error {
	return req.cmder(ctx, clientConn)
}

func (req *Request) handleConnect(ctx context.Context, clientConn net.Conn) error {
	log := contexts.GetLogger(ctx).WithValues("command", "connect")

	// Attempt to connect to the target address
	if req.address.DomainName != "" {
		log = log.WithValues("remoteDomain", req.address.DomainName)
		log.V(1).Info("resolving domain name")

		ip, err := req.resolver.Resolve(ctx, req.address.DomainName)
		if err != nil {
			if err := req.replier(clientConn, types.ReplyHostUnreach, req.address); err != nil {
				return err
			}

			return fmt.Errorf("failed to resolve domain name: %s, %v", req.address.DomainName, err)
		}

		req.address.IP = ip
		log = log.WithValues("remoteIP", ip.String())
	}

	dstAddress := req.address.Address()
	log = log.WithValues("remoteAddr", dstAddress)

	log.V(1).Info("dialing remote address")
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

	log.V(2).Info("sending reply", "bindAddr", bindAddr.String(), "replyCode", types.ReplySucceeded.String())
	if err := req.replier(clientConn, types.ReplySucceeded, bindAddr); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	log.Info("start proxying", "src", clientConn.RemoteAddr(), "dst", targetConn.RemoteAddr())

	// Start proxying connection between the client and the target host
	return proxy.Start(clientConn, targetConn)
}
