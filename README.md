# Salchicha

[![hex.pm](https://img.shields.io/hexpm/v/salchicha.svg)](https://hex.pm/packages/salchicha/)
[![Build Status](https://github.com/BrandtHill/Salchicha/workflows/Elixir%20CI/badge.svg)](https://github.com/BrandtHill/Salchicha/actions)

A pure-ish Elixir cryptography tool for the Salsa20 and ChaCha20 ciphers.

## Installation

The package can be installed by adding `salchicha` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:salchicha, "~> 0.3"}
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
and implementing the rest more adroitly. In this library the functions have been made
more general-purpose and have analogues in the NaCl/libsodium API.

NaCl/libsodium (and KCl) has a lot of other functionality for public key cryptography
via EC25519, which erlang's `:crypto` module already supports. I may add some of that 
here in the future but in the meantime I've just brought over the XSalsa and XChaCha functions.
