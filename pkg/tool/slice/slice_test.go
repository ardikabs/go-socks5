package slice

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIn(t *testing.T) {
	intDatas := []int{1, 2, 3, 4, 5}
	require.True(t, In(3, intDatas))
	require.False(t, In(10, intDatas))
}
