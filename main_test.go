package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"runtime"
	"sync/atomic"
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
	i := b.N

	findPublicKey(context.Background(), func(p *edwards25519.Point) bool {
		pp := p.BytesMontgomery()
		i--
		return i == 0 || len(pp) == 0
	})
}

func BenchmarkFindPublicKeyParallel(b *testing.B) {
	var i atomic.Int64
	i.Store(int64(b.N))

	findPublicKeyParallel(context.Background(), runtime.NumCPU(), func(p *edwards25519.Point) bool {
		pp := p.BytesMontgomery()
		return i.Add(-1) <= 0 || len(pp) == 0
	})
}
