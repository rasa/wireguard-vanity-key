package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/oasisprotocol/curve25519-voi/curve"
)

func BenchmarkNewPrivateKey(b *testing.B) {
	var key [32]byte
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()

	for range b.N {
		priv, _ := ecdh.X25519().NewPrivateKey(key[:])
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
