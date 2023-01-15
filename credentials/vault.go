package credentials

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Gets the Vault token from the ENV or .vault_token file
func GetVaultToken() (string, error) {
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		return token, nil
	}

	homedir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	tokenFile := filepath.Join(homedir, ".vault-token")
	if _, err := os.Stat(tokenFile); os.IsNotExist(err) {
		return "", fmt.Errorf("No Vault token found. You must set a 'VAULT_TOKEN' env var or create a '.vault-token' file.")
	}

	if bytes, err := os.ReadFile(tokenFile); err != nil {
		return "", fmt.Errorf("Could not read Vault token")
	} else {
		return strings.TrimSpace(string(bytes)), nil
	}
}
