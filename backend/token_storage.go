package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type InMemoryTokenStorage struct {
	TokenMap map[string]string
	mutex    sync.Mutex
}

func NewInMemoryTokenStorage() *InMemoryTokenStorage {
	return &InMemoryTokenStorage{
		TokenMap: make(map[string]string),
	}
}

type RedisTokenStorage struct {
	client    *redis.Client
	namespace string
}

func NewRedisTokenStorage(client *redis.Client, namespace string) *RedisTokenStorage {
	return &RedisTokenStorage{client: client, namespace: namespace}
}

// Should be safe to use in concurreny
type TokenStorage interface {
	// Store the sessionId for the given sessionId number
	// returns an error when it somehow fails to store the value.
	// Should not return an error when the value already exists,
	// it should just update in that case.
	StoreToken(sessionId string, nonce string) error

	// Should retrieve the token for the given sessionId number
	// and return an error in any case where it fails to do so.
	RetrieveToken(sessionId string) (string, error)

	// Should remove the token and return an error if it fails to do so.
	// The value not being there should also be considered an error.
	RemoveToken(sessionId string) error
}

// ------------------------------------------------------------------------------

func createKey(namespace, sessionId string) string {
	return fmt.Sprintf("%s:token:%s", namespace, sessionId)
}

const Timeout time.Duration = 24 * time.Hour

func (s *RedisTokenStorage) StoreToken(sessionId string, nonce string) error {
	ctx := context.Background()
	return s.client.Set(ctx, createKey(s.namespace, sessionId), nonce, Timeout).Err()
}

func (s *RedisTokenStorage) RetrieveToken(sessionId string) (string, error) {
	ctx := context.Background()
	return s.client.Get(ctx, createKey(s.namespace, sessionId)).Result()
}

func (s *RedisTokenStorage) RemoveToken(sessionId string) error {
	ctx := context.Background()
	return s.client.Del(ctx, createKey(s.namespace, sessionId)).Err()
}

// ------------------------------------------------------------------------------

func (s *InMemoryTokenStorage) StoreToken(sessionId, token string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.TokenMap[sessionId] = token
	return nil
}

func (s *InMemoryTokenStorage) RetrieveToken(sessionId string) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if token, ok := s.TokenMap[sessionId]; ok {
		return token, nil
	} else {
		return "", fmt.Errorf("failed to find token for %s", sessionId)
	}
}

func (s *InMemoryTokenStorage) RemoveToken(sessionId string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, ok := s.TokenMap[sessionId]; ok {
		delete(s.TokenMap, sessionId)
		return nil
	} else {
		return fmt.Errorf("failed to remove token for %s, because it wasn't there", sessionId)
	}
}
