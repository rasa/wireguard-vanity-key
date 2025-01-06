// Package main searches for vanity X25519 key based on algorithm
// described here https://github.com/warner/wireguard-vanity-address/pull/15
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"runtime"
	"sync/atomic"
	"time"

	"filippo.io/edwards25519"
	"golang.org/x/sync/errgroup"
)

var (
	// l = 2^252 + 27742317777372353535851937790883648493 == 2^252 + smallScalar
	smallScalar = scalarFromBytes(decimalToLittleEndianBytes("27742317777372353535851937790883648493")...)
	// Ed25519 group's cofactor
	scalarOffset = scalarFromBytes(8)
	pointOffset  = new(edwards25519.Point).ScalarBaseMult(scalarOffset)
)

func main() {
	start := time.Now()

	prefix := flag.String("prefix", "AY/", "prefix of base64-encoded public key")
	flag.Parse()

	s0, p0 := newPair()

	test := func(p *edwards25519.Point) bool {
		return hasBase64Prefix(p, []byte(*prefix))
	}
	p, n, attempts := findPointParallel(context.Background(), runtime.NumCPU(), p0, test)
	s := adjustScalar(s0, n)

	fmt.Printf("%-44s %-44s %-10s %s\n", "private", "public", "attempts", "duration")
	fmt.Printf("%s %s %-10d %s\n",
		base64.StdEncoding.EncodeToString(scalarToKeyBytes(s)),
		base64.StdEncoding.EncodeToString(p.BytesMontgomery()),
		attempts, time.Now().Sub(start))
}

func newPair() (*edwards25519.Scalar, *edwards25519.Point) {
	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		panic(err)
	}

	s, err := edwards25519.NewScalar().SetBytesWithClamping(key[:])
	if err != nil {
		panic(err)
	}

	p := new(edwards25519.Point).ScalarBaseMult(s)

	return s, p
}

func findPointParallel(ctx context.Context, workers int, p0 *edwards25519.Point, test func(p *edwards25519.Point) bool) (*edwards25519.Point, uint64, uint64) {
	var (
		pr       *edwards25519.Point
		nr       uint64
		attempts atomic.Uint64
	)

	g, gtx := errgroup.WithContext(ctx)
	for range workers {
		g.Go(func() error {
			skip := randUint64()
			p, n := findPoint(gtx, p0, skip, test)

			attempts.Add(n - skip)
			if p != nil {
				pr, nr = p, n
				return fmt.Errorf("found")
			}
			return gtx.Err()
		})
	}
	g.Wait()

	return pr, nr, attempts.Load()
}

func findPoint(ctx context.Context, p0 *edwards25519.Point, skip uint64, test func(p *edwards25519.Point) bool) (*edwards25519.Point, uint64) {
	skipOffset := new(edwards25519.Point).ScalarMult(scalarFromUint64(skip), pointOffset)
	p := new(edwards25519.Point).Add(p0, skipOffset)

	i := skip
	for ; !test(p); i++ {
		select {
		case <-ctx.Done():
			return nil, i
		default:
			p.Add(p, pointOffset)
		}
	}
	return p, i
}

func adjustScalar(s *edwards25519.Scalar, n uint64) *edwards25519.Scalar {
	return edwards25519.NewScalar().MultiplyAdd(scalarOffset, scalarFromUint64(n), s)
}

func scalarToKeyBytes(s *edwards25519.Scalar) []byte {
	// We can't use Scalars to add "l" and produce the aliases: any addition
	// we do on the Scalar will be reduced immediately. But we can add
	// "small", and then manually adjust the high-end byte, to produce an
	// array of bytes whose value is s+kl
	//
	// The aliases (with high probability) have distinct
	// high-order bits: 0b0001, 0b0010, etc. We want one of the four aliases
	// whose high-order bits are 0b01xx: these bits will survive the high-end
	// clamping unchanged. These are where k=[4..7].
	//
	// The three low-order bits will be some number N. Each alias adds l%8 == 5 to
	// this low end:
	//
	// $ echo '(2^252 + 27742317777372353535851937790883648493) % 8' | bc
	// 5
	//
	// So the first alias (k=1) will end in N+5, the second
	// (k=2) will end in N+2 (since (5+5)%8 == 2). Our k=4..7 yields
	// N+4,N+1,N+6,N+3. One of these values might be all zeros. That alias
	// will survive the low-end clamping unchanged.

	lowBits := s.Bytes()[0] & 0b111
	// Solve (lowBits + k*5) % 8 == 0 for k:
	// k := [8]byte{0, 0, 6, 0, 4, 7, 0, 5}[lowBits]
	k := [8]byte{0, 3, 6, 1, 4, 7, 2, 5}[lowBits]
	if k < 4 { // TODO: prove k is one of 4, 5, 6, 7
		panic("invalid scalar first byte (lowBits)")
	}

	aliasBytes := edwards25519.NewScalar().MultiplyAdd(smallScalar, scalarFromBytes(k), s).Bytes()
	aliasBytes[31] += (k << 4)

	return aliasBytes
}

func scalarFromBytes(x ...byte) *edwards25519.Scalar {
	var xb [64]byte
	copy(xb[:], x)

	xs, err := edwards25519.NewScalar().SetUniformBytes(xb[:])
	if err != nil {
		panic(err)
	}
	return xs
}

func scalarFromUint64(n uint64) *edwards25519.Scalar {
	var nb [8]byte
	binary.LittleEndian.PutUint64(nb[:], n)
	return scalarFromBytes(nb[:]...)
}

func decimalToLittleEndianBytes(d string) []byte {
	i, ok := new(big.Int).SetString(d, 10)
	if !ok {
		panic("invalid decimal string " + d)
	}
	b := i.Bytes()
	// convert to little endian
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

func hasBase64Prefix(p *edwards25519.Point, prefix []byte) bool {
	var dst [44]byte
	base64.StdEncoding.Encode(dst[:], p.BytesMontgomery())
	return bytes.HasPrefix(dst[:], prefix)
}

func randUint64() uint64 {
	r, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		panic(err)
	}
	return r.Uint64()
}
