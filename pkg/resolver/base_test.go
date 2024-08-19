package resolver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBase_Resolve(t *testing.T) {
	r := BaseResolver{}

	addr, err := r.Resolve(context.Background(), "localhost")
	require.NoError(t, err)
	require.True(t, addr.IsLoopback())
}
