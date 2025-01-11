# wireguard-vanity

Inspired by [wireguard-vanity-address "faster algorithm"](https://github.com/warner/wireguard-vanity-address/pull/15),
this tool searches for a [WireGuard](https://www.wireguard.com/) Curve25519 keypair
with a base64-encoded public key that has a specified prefix.

Example:

```console
$ go run . --prefix=2025
private                                      public                                       attempts   duration
IPmNWKPaN24CaVoC8IReswkgAzOapxIn2ZpbriGUVVM= 2025tLFHEKbyf2Jpsfzv83/cdh7vM1P5EapkNRXTVGE= 11111672   27.396459241s

# verify
$ echo IPmNWKPaN24CaVoC8IReswkgAzOapxIn2ZpbriGUVVM= | wg pubkey 
2025tLFHEKbyf2Jpsfzv83/cdh7vM1P5EapkNRXTVGE=
```
