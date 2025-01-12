# wireguard-vanity-key

Inspired by [wireguard-vanity-address "faster algorithm"](https://github.com/warner/wireguard-vanity-address/pull/15),
this tool searches for a [WireGuard](https://www.wireguard.com/) Curve25519 keypair
with a base64-encoded public key that has a specified prefix.

## Example

```console
$ go run . --prefix=2025
private                                      public                                       attempts   duration
IPmNWKPaN24CaVoC8IReswkgAzOapxIn2ZpbriGUVVM= 2025tLFHEKbyf2Jpsfzv83/cdh7vM1P5EapkNRXTVGE= 11111672   27.396459241s

# verify
$ echo IPmNWKPaN24CaVoC8IReswkgAzOapxIn2ZpbriGUVVM= | wg pubkey 
2025tLFHEKbyf2Jpsfzv83/cdh7vM1P5EapkNRXTVGE=
```

## Benchmark

The tool checks ~700'000 keys per second on a test machine:

```console
$ go test . -run=NONE -bench=BenchmarkFindPointParallel -benchmem -count=10
goos: linux
goarch: amd64
pkg: github.com/AlexanderYastrebov/wireguard-vanity-key
cpu: Intel(R) Core(TM) i5-8350U CPU @ 1.70GHz
BenchmarkFindPointParallel-8      655850              1602 ns/op               0 B/op          0 allocs/op
BenchmarkFindPointParallel-8      725287              1592 ns/op               0 B/op          0 allocs/op
BenchmarkFindPointParallel-8      713710              1591 ns/op               0 B/op          0 allocs/op
BenchmarkFindPointParallel-8      710394              1603 ns/op               0 B/op          0 allocs/op
BenchmarkFindPointParallel-8      676418              1596 ns/op               0 B/op          0 allocs/op
BenchmarkFindPointParallel-8      712020              1605 ns/op               0 B/op          0 allocs/op
BenchmarkFindPointParallel-8      694296              1627 ns/op               0 B/op          0 allocs/op
BenchmarkFindPointParallel-8      692424              1635 ns/op               0 B/op          0 allocs/op
BenchmarkFindPointParallel-8      678483              1664 ns/op               0 B/op          0 allocs/op
BenchmarkFindPointParallel-8      653674              1671 ns/op               0 B/op          0 allocs/op
PASS
ok      github.com/AlexanderYastrebov/wireguard-vanity-key      11.387s
```

## Similar projects

* [wireguard-vanity-address](https://github.com/warner/wireguard-vanity-address)
* [wireguard-vanity-keygen](https://github.com/axllent/wireguard-vanity-keygen)
* [Wireguard-Vanity-Key-Searcher](https://github.com/volleybus/Wireguard-Vanity-Key-Searcher)
* [wgmine](https://github.com/thatsed/wgmine)
* [Vanity](https://github.com/samuel-lucas6/Vanity)
