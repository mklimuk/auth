package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestGenerate(t *testing.T) {
	u, err := generateWithPassword([]string{"pkp", "okecie", "operator", "1", "m!ch4l_"})
	require.NoError(t, err)
	account, err := yaml.Marshal(u)
	if err != nil {
		fmt.Printf("[ERROR] could not marshal user: %v\n", err)
		return
	}
	fmt.Printf("%s", account)
}
