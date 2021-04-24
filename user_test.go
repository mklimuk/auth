package auth

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadUsers(t *testing.T) {
	fs := afero.NewMemMapFs()
	err := afero.WriteFile(fs, "/etc/users/conf", []byte(userFile), 0600)
	require.NoError(t, err)
	users, err := LoadUsersFromFile("/etc/users/conf", fs)
	assert.NoError(t, err)
	assert.Len(t, users, 2)
}

const userFile = `
-
  username: michal
  name: Michal Klimuk
  password: $2a$10$v9dAPJH9SD2pi2GGwcY1G.NCBGj83z.keXbZuLaIB47BWXQEDFXp6 #test123
  rights: 7
-
  username: pkp
  name: Operator
  password: $2a$10$IHyW1P2YF.WLCOHZjWcdRuTGsEpJF.zscwskYE0SIm24xvsyK3FyW #lomianki
  rights: 1
`
