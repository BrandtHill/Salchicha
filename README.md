# Salchicha

[![hex.pm](https://img.shields.io/hexpm/v/salchicha.svg)](https://hex.pm/packages/salchicha/)
[![Build Status](https://github.com/BrandtHill/Salchicha/workflows/Elixir%20CI/badge.svg)](https://github.com/BrandtHill/Salchicha/actions)

A pure-ish Elixir cryptography tool for the Salsa20 and ChaCha20 ciphers.

## Installation

The package can be installed by adding `salchicha` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:salchicha, "~> 0.4"}
  ]
end
```

## Usage

```elixir
iex()> key = Salchicha.generate_secret_key()
iex()> nonce = Salchicha.generate_nonce()
iex()> "Hello, World!"
       |> Salchicha.secretbox(nonce, key)
       |> Salchicha.secretbox_open(nonce, key) 
       |> IO.iodata_to_binary()
"Hello, World!"
```

## Background

The purpose of this library is to have a lightweight, NaCl/libsodium compatible tool
for symmetric key encryption/decryption that doesn't depend on any other packages or
NIFs. 

[KCl](https://github.com/mwmiller/kcl) is an impressive pure-elixir NaCl/libsodium
library we had previously used for Discord Voice encryption in [nostrum](https://github.com/Kraigie/nostrum). While adding support for newer encryption modes, I opted to remove
`:kcl` in favor of leveraging what was available via erlang's native `:crypto` module
and implementing the rest more adroitly. That code has since been migrated into this library,
and more of the NaCl/libsodium API has been added.

NaCl/libsodium (and Kcl) has functionality for public key cryptography, namely ECDH key exchange via
X25519 and EdDSA signatures via Ed25519. The `:crypto` module already supports these elliptic
curves, so I've added some sodium-flavored wrappers around those functions.
