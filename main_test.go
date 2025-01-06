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
		match := hasBase64Prefix(p, []byte("GoodLuckWithThisPrefix"))
		i--
		return i == 0 || match
	})
}

func BenchmarkFindPublicKeyParallel(b *testing.B) {
	var i atomic.Int64
	i.Store(int64(b.N))

	findPublicKeyParallel(context.Background(), runtime.NumCPU(), func(p *edwards25519.Point) bool {
		match := hasBase64Prefix(p, []byte("GoodLuckWithThisPrefix"))
		return i.Add(-1) <= 0 || match
	})
}

func BenchmarkFindPoint(b *testing.B) {
	_, p := newPair()

	i := b.N

	findPoint(context.Background(), p, randUint64(), func(p *edwards25519.Point) bool {
		match := hasBase64Prefix(p, []byte("GoodLuckWithThisPrefix"))
		i--
		return i == 0 || match
	})
}
