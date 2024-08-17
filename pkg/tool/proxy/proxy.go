package proxy

import (
	"io"

	"golang.org/x/sync/errgroup"
)

func Start(src, dst io.ReadWriter) error {
	g := errgroup.Group{}

	// Proxying from source (R) to destination (W)
	g.Go(func() error { return proxy(src, dst) })

	// Proxying from destination (R) to source (W)
	g.Go(func() error { return proxy(dst, src) })
	return g.Wait()
}

func proxy(src io.Reader, dst io.Writer) error {
	_, err := io.Copy(dst, src)
	return err
}
