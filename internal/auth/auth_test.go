package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestJWT validates the creation and validation of JWT tokens.
func TestJWT(t *testing.T) {
	secret := "super-secret"
	userID := uuid.New()

	// Create a JWT that expires in 2 seconds
	token, err := MakeJWT(userID, secret, time.Second*2)
	require.NoError(t, err)

	// Validate the token and check if the user ID matches
	parsedID, err := ValidateJWT(token, secret)
	require.NoError(t, err)
	require.Equal(t, userID, parsedID)

	// === Expired token test ===

	// Create a JWT that is already expired
	expiredToken, err := MakeJWT(userID, secret, -1*time.Second)
	require.NoError(t, err)

	// Validation should fail due to expiration
	_, err = ValidateJWT(expiredToken, secret)
	require.Error(t, err)

	// === Invalid secret test ===

	// Validate the original token with the wrong secret
	_, err = ValidateJWT(token, "wrong-secret")
	require.Error(t, err)
}
