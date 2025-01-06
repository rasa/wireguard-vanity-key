package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func BenchmarkGenerateKey(b *testing.B) {
	for range b.N {
		priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
		_ = priv.PublicKey().Bytes()
	}
}

func BenchmarkFindPublicKey(b *testing.B) {
	i := b.N

	findPublicKey(context.Background(), func(p []byte) bool {
		_ = p[0] + p[1] + p[2]
		i--
		return i == 0
	})
}
