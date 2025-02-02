package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/oasisprotocol/curve25519-voi/curve"
)

func BenchmarkGenerateKey(b *testing.B) {
	for range b.N {
		priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
		_ = priv.PublicKey().Bytes()
	}
}

func BenchmarkFindPoint(b *testing.B) {
	_, p0 := newPair()

	i := b.N

	findPoint(context.Background(), p0, randUint64(), func(p *curve.EdwardsPoint) bool {
		match := hasBase64Prefix(p, []byte("GoodLuckWithThisPrefix"))
		i--
		return i == 0 || match
	})
}

func BenchmarkFindPointParallel(b *testing.B) {
	_, p0 := newPair()

	var i atomic.Int64
	i.Store(int64(b.N))

	findPointParallel(context.Background(), runtime.NumCPU(), p0, func(p *curve.EdwardsPoint) bool {
		match := hasBase64Prefix(p, []byte("GoodLuckWithThisPrefix"))
		return i.Add(-1) <= 0 || match
	})
}
