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
	"math/big"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/oasisprotocol/curve25519-voi/curve"
	"github.com/oasisprotocol/curve25519-voi/curve/scalar"
)

var (
	// l = 2^252 + 27742317777372353535851937790883648493 == 2^252 + smallScalar
	smallScalar = scalarFromBytes(decimalToBytes("27742317777372353535851937790883648493")...)
	// Ed25519 group's cofactor
	scalarOffset = scalarFromBytes(8)
	pointOffset  = new(curve.EdwardsPoint).MulBasepoint(curve.ED25519_BASEPOINT_TABLE, scalarOffset)
)

func main() {
	start := time.Now()

	prefix := flag.String("prefix", "AY/", "prefix of base64-encoded public key")
	timeout := flag.Duration("timeout", 0, "stop after specified timeout")
	flag.Parse()

	s0, p0 := newPair()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if *timeout != 0 {
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}

	test := func(p *curve.EdwardsPoint) bool {
		return hasBase64Prefix(p, []byte(*prefix))
	}

	p, n, attempts := findPointParallel(ctx, runtime.NumCPU(), p0, test)

	private := "-"
	public := *prefix + "..."
	if p != nil {
		s := adjustScalar(s0, n)
		private = base64.StdEncoding.EncodeToString(scalarToKeyBytes(s))
		public = base64.StdEncoding.EncodeToString(bytesMontgomery(p))
	}

	duration := time.Now().Sub(start)

	fmt.Printf("%-44s %-44s %-10s %-10s %s\n", "private", "public", "attempts", "duration", "attempts/s")
	fmt.Printf("%-44s %-44s %-10d %-10s %d\n", private, public, attempts, duration.Round(time.Second), time.Duration(attempts)*(time.Second)/duration)

	if p == nil {
		os.Exit(1)
	}
}

func newPair() (*scalar.Scalar, *curve.EdwardsPoint) {
	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		panic(err)
	}

	var wideBytes [64]byte
	copy(wideBytes[:], key[:])
	wideBytes[0] &= 248
	wideBytes[31] &= 63
	wideBytes[31] |= 64

	s, err := new(scalar.Scalar).SetBytesModOrderWide(wideBytes[:])
	if err != nil {
		panic(err)
	}

	p := new(curve.EdwardsPoint).MulBasepoint(curve.ED25519_BASEPOINT_TABLE, s)

	return s, p
}

func findPointParallel(ctx context.Context, workers int, p0 *curve.EdwardsPoint, test func(p *curve.EdwardsPoint) bool) (*curve.EdwardsPoint, uint64, uint64) {
	type point struct {
		p *curve.EdwardsPoint
		n uint64
	}

	result := make(chan point, workers)
	var attempts atomic.Uint64

	gctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()

			skip := randUint64()
			p, n := findPoint(gctx, p0, skip, test)

			attempts.Add(n - skip)
			if p != nil {
				result <- point{p, n}
				cancel()
			}
		}()
	}
	wg.Wait()

	select {
	case r := <-result:
		return r.p, r.n, attempts.Load()
	case <-ctx.Done():
		return nil, 0, attempts.Load()
	}
}

func findPoint(ctx context.Context, p0 *curve.EdwardsPoint, skip uint64, test func(p *curve.EdwardsPoint) bool) (*curve.EdwardsPoint, uint64) {
	skipOffset := new(curve.EdwardsPoint).Mul(pointOffset, scalarFromUint64(skip))
	p := new(curve.EdwardsPoint).Add(p0, skipOffset)

	n := skip
	for ; !test(p); n++ {
		select {
		case <-ctx.Done():
			return nil, n
		default:
			p.Add(p, pointOffset)
		}
	}
	return p, n
}

func adjustScalar(s *scalar.Scalar, n uint64) *scalar.Scalar {
	m := new(scalar.Scalar).Mul(scalarOffset, scalarFromUint64(n))
	return m.Add(m, s)
}

func scalarToKeyBytes(s *scalar.Scalar) []byte {
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

	var sBytes [32]byte
	s.ToBytes(sBytes[:])

	lowBits := sBytes[0] & 0b111
	// Solve (lowBits + k*5) % 8 == 0 for k:
	// k := [8]byte{0, 0, 6, 0, 4, 7, 0, 5}[lowBits]
	k := [8]byte{0, 3, 6, 1, 4, 7, 2, 5}[lowBits]
	if k < 4 { // TODO: why k is mostly one of 4, 5, 6, 7 when scalarOffset is Ed25519 group's cofactor?
		panic("invalid scalar first byte (lowBits)")
	}

	m := new(scalar.Scalar).Mul(smallScalar, scalarFromBytes(k))
	m.Add(m, s)

	aliasBytes := make([]byte, 32)
	m.ToBytes(aliasBytes)
	aliasBytes[31] += (k << 4)

	return aliasBytes
}

func scalarFromBytes(x ...byte) *scalar.Scalar {
	var xb [64]byte
	copy(xb[:], x)

	xs, err := new(scalar.Scalar).SetBytesModOrderWide(xb[:])
	if err != nil {
		panic(err)
	}
	return xs
}

func scalarFromUint64(n uint64) *scalar.Scalar {
	var nb [8]byte
	binary.LittleEndian.PutUint64(nb[:], n)
	return scalarFromBytes(nb[:]...)
}

func decimalToBytes(d string) []byte {
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

func hasBase64Prefix(p *curve.EdwardsPoint, prefix []byte) bool {
	var dst [44]byte
	base64.StdEncoding.Encode(dst[:], bytesMontgomery(p))
	return bytes.HasPrefix(dst[:], prefix)
}

func randUint64() uint64 {
	var num uint64
	err := binary.Read(rand.Reader, binary.NativeEndian, &num)
	if err != nil {
		panic(err)
	}
	return num
}

func bytesMontgomery(p *curve.EdwardsPoint) []byte {
	var mp curve.MontgomeryPoint
	mp.SetEdwards(p)
	return mp[:]
}
