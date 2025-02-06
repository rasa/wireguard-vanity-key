# wireguard-vanity-key

Inspired by [wireguard-vanity-address "faster algorithm"](https://github.com/warner/wireguard-vanity-address/pull/15),
this tool searches for a [WireGuard](https://www.wireguard.com/) Curve25519 keypair
with a base64-encoded public key that has a specified prefix.

## Example

Run the tool from the source repository:
```console
$ go run . --prefix=2025
private                                      public                                       attempts   duration   attempts/s
YEStzudoDL6fU0dnuS8OL7EjjoL4MbynRxntQJiLQXU= 2025C9iR7oZt/tJTg0nLt4diZfmdkkBR+2j9DnXC7jc= 11833889   1s         9335684

$ # verify
$ echo YEStzudoDL6fU0dnuS8OL7EjjoL4MbynRxntQJiLQXU= | wg pubkey
2025C9iR7oZt/tJTg0nLt4diZfmdkkBR+2j9DnXC7jc=
```

or use Docker image:
```console
$ docker run ghcr.io/alexanderyastrebov/wireguard-vanity-key:latest --prefix=2025
private                                      public                                       attempts   duration   attempts/s
KCMxR8XSy7rnIkm6jdCbjh7iWjLSKG6/Jf1VmZ2cj0Q= 2025E9Aze99TIlhSchsOOZZmgjIuReX0iu+l9gWsEBM= 2071199    0s         9788246

$ # verify
$ echo KCMxR8XSy7rnIkm6jdCbjh7iWjLSKG6/Jf1VmZ2cj0Q= | wg pubkey
2025E9Aze99TIlhSchsOOZZmgjIuReX0iu+l9gWsEBM=
```

## Benchmark

The tool checks ~10'000'000 keys per second on a test machine:

```console
$ go test . -run=NONE -bench=BenchmarkFindPointParallel -benchmem -count=10
goos: linux
goarch: amd64
pkg: github.com/AlexanderYastrebov/wireguard-vanity-key
cpu: Intel(R) Core(TM) i5-8350U CPU @ 1.70GHz
BenchmarkFindPointParallel-8    10849304               103.0 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8    11097517               102.7 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8    11212604               102.3 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8    11036245               102.7 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8    10965774               102.3 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8    11179293               106.1 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8     9909200               114.3 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8    10143001               113.3 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8    10122814               113.1 ns/op             0 B/op          0 allocs/op
BenchmarkFindPointParallel-8    10073284               112.5 ns/op             0 B/op          0 allocs/op
PASS
ok      github.com/AlexanderYastrebov/wireguard-vanity-key      21.154s
```

## Similar projects

* [wireguard-vanity-address](https://github.com/warner/wireguard-vanity-address)
* [wireguard-vanity-keygen](https://github.com/axllent/wireguard-vanity-keygen)
* [Wireguard-Vanity-Key-Searcher](https://github.com/volleybus/Wireguard-Vanity-Key-Searcher)
* [wgmine](https://github.com/thatsed/wgmine)
* [Vanity](https://github.com/samuel-lucas6/Vanity)
