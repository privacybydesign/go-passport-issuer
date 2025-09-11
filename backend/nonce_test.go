package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNonceGeneration(t *testing.T) {
	nonce1, err := GenerateNonce(8)
	require.NoError(t, err)
	// each byte is represented by 2 hex characters so length will be doubled
	require.Len(t, nonce1, 16)
}

func TestSessionIdGeneration(t *testing.T) {

	sessionId := GenerateSessionId()
	require.Len(t, sessionId, 32)
}
