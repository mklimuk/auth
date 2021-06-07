package auth

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScopeIs(t *testing.T) {
	tests := []struct {
		a      Scope
		b      Scope
		expect bool
	}{
		{7, 4, true},
		{4, 7, true},
		{4, 8, false},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%d_%d", test.a, test.b), func(t *testing.T) {
			assert.Equal(t, test.expect, test.a.Is(test.b))
		})
	}
}
