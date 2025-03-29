package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestJWT(t *testing.T) {
	secret := "super-secret"
	userID := uuid.New()
	token, err := MakeJWT(userID, secret, time.Second*2)
	require.NoError(t, err)

	parsedID, err := ValidateJWT(token, secret)
	require.NoError(t, err)
	require.Equal(t, userID, parsedID)

	// Expired token test
	expiredToken, err := MakeJWT(userID, secret, -1*time.Second)
	require.NoError(t, err)

	_, err = ValidateJWT(expiredToken, secret)
	require.Error(t, err)

	// Wrong secret test
	_, err = ValidateJWT(token, "wrong-secret")
	require.Error(t, err)
}
