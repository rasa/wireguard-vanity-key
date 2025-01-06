package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"runtime"
	"sync/atomic"
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

func BenchmarkFindPublicKeyParallel(b *testing.B) {
	var i atomic.Int64
	i.Store(int64(b.N))

	findPublicKeyParallel(context.Background(), runtime.NumCPU(), func(p []byte) bool {
		_ = p[0] + p[1] + p[2]
		return i.Add(-1) <= 0
	})
}
