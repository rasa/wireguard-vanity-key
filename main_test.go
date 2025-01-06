package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"testing"

	"filippo.io/edwards25519"
)

func BenchmarkGenerateKey(b *testing.B) {
	for range b.N {
		priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
		_ = priv.PublicKey().Bytes()
	}
}

func BenchmarkFindPublicKey(b *testing.B) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		b.Fatal(err)
	}

	s0, err := edwards25519.NewScalar().SetBytesWithClamping(key)
	if err != nil {
		b.Fatal(err)
	}

	i := 0
	findPublicKey(s0, func(p []byte) bool {
		_ = p[0] + p[1] + p[2]
		i++
		return i == b.N
	})
}
