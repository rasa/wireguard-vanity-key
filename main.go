// Package main searches for vanity X25519 key based on algorithm
// described here https://github.com/warner/wireguard-vanity-address/pull/15
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"

	"filippo.io/edwards25519"
)

var (
	// l = 2^252 + 27742317777372353535851937790883648493 == 2^252 + smallScalar
	smallScalar = scalarFromBytes(decimalToLittleEndianBytes("27742317777372353535851937790883648493")...)
	// Ed25519 group's cofactor
	scalarOffset = scalarFromBytes(8)

	pointOffset = new(edwards25519.Point).ScalarBaseMult(scalarOffset)
)

func main() {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}

	// priv, _ := ecdh.X25519().NewPrivateKey(key)
	// pub := priv.PublicKey()

	// fmt.Printf("private                                      public                                       attempts\n")
	// fmt.Printf("%s %s\n",
	// 	base64.StdEncoding.EncodeToString(priv.Bytes()),
	// 	base64.StdEncoding.EncodeToString(pub.Bytes()))

	s0, err := edwards25519.NewScalar().SetBytesWithClamping(key)
	if err != nil {
		panic(err)
	}

	check := func(p []byte) bool {
		// Search for 2025 prefix:
		// $ echo 2025 | base64 -d | hexdump -C
		// 00000000  db 4d b9                                          |.M.|
		// 00000003
		return p[0] == 0xdb && p[1] == 0x4d && p[2] == 0xb9
	}
	s, p, n := findPublicKey(s0, check)

	fmt.Printf("private                                      public                                       attempts\n")
	fmt.Printf("%s %s %d\n",
		base64.StdEncoding.EncodeToString(scalarToKeyBytes(s)),
		base64.StdEncoding.EncodeToString(p.BytesMontgomery()),
		n)

	// p0 := new(edwards25519.Point).ScalarBaseMult(s0)

	// fmt.Printf("%s %s\n",
	// 	base64.StdEncoding.EncodeToString(scalarToKeyBytes(s0)),
	// 	base64.StdEncoding.EncodeToString(p0.BytesMontgomery()))

	// s1 := s0.Add(s0, scalarOffset)
	// p1 := p0.Add(p0, pointOffset)

	// fmt.Printf("%s %s\n",
	// 	base64.StdEncoding.EncodeToString(scalarToKeyBytes(s1)),
	// 	base64.StdEncoding.EncodeToString(p1.BytesMontgomery()))
}

func findPublicKey(s *edwards25519.Scalar, check func(p []byte) bool) (*edwards25519.Scalar, *edwards25519.Point, int) {
	// set s to a randomly-selected scalar, clamped as usual
	// set scalar_offset to 8 (i.e. the Ed25519 group's cofactor)
	// set p to scalarmult(s, BASEPOINT)
	// set point_offset to scalarmult(scalar_offset, BASEPOINT)
	//
	// Then each step of the loop looks like:
	// If p passes the check, print the result and start over again from initialization
	// else, set s = s + scalar_offset and p = p + point_offset
	// repeat
	p := new(edwards25519.Point).ScalarBaseMult(s)
	i := 0
	for ; !check(p.BytesMontgomery()); i++ {
		s.Add(s, scalarOffset)
		p.Add(p, pointOffset)
	}
	return s, p, i
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
	//k := [8]byte{0, 0, 6, 0, 4, 7, 0, 5}[lowBits]
	k := [8]byte{0, 3, 6, 1, 4, 7, 2, 5}[lowBits]
	if k < 4 {
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
