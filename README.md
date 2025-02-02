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

The tool checks ~1'500'000 keys per second on a test machine:

```console
$ go test . -run=NONE -bench=BenchmarkFindPointParallel -benchmem -count=10
goos: linux
goarch: amd64
pkg: github.com/AlexanderYastrebov/wireguard-vanity-key
cpu: Intel(R) Core(TM) i5-8350U CPU @ 1.70GHz
BenchmarkFindPointParallel-8     1610152               732.6 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8     1562487               728.7 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8     1645317               729.5 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8     1610070               731.9 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8     1534819               727.2 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8     1635752               739.1 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8     1621570               761.5 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8     1591744               755.0 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8     1557376               759.0 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8     1564669               876.1 ns/op             0 B/op          0 allocs/op
PASS
ok      github.com/AlexanderYastrebov/wireguard-vanity-key      20.799s
```

## Similar projects

* [wireguard-vanity-address](https://github.com/warner/wireguard-vanity-address)
* [wireguard-vanity-keygen](https://github.com/axllent/wireguard-vanity-keygen)
* [Wireguard-Vanity-Key-Searcher](https://github.com/volleybus/Wireguard-Vanity-Key-Searcher)
* [wgmine](https://github.com/thatsed/wgmine)
* [Vanity](https://github.com/samuel-lucas6/Vanity)
