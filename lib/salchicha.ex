defmodule Salchicha do
  @moduledoc """
  A pure-ish Elixir cryptography tool for the Salsa20 and ChaCha20 stream ciphers.

  This library has a handful of crypto functions that are compatible with NaCl/libsodium
  for encryption and decryption with shared secret keys. Some sodium-flavored public key
  cryptography functions are also available, and are primarily wrappers around `:crypto` functions.

  The Salsa20/XSalsa20 ciphers are implemented entirely in Elixir while the Poly1305 MAC
  function is done through the Erlang `:crypto` module, which is implemented as a NIF with
  OpenSSL bindings.

  The ChaCha20_Poly1305 AEAD cipher is already supported by the `:crypto` module, but XChaCha20
  is not. The HChaCha20 hash function, an intermediate step for generating an XChaCha20 sub-key,
  is implemented in Elixir so `:crypto.crypto_one_time_aead/7` can be leveraged for XChaCha20_Poly1305.

  The ChaCha20/XChaCha20 ciphers do also have pure Elixir implementations just like Salsa20/XSalsa20,
  but unless you are concerned with long-running NIFs blocking schedulers, you should prefer to use
  the versions that fully leverage `:crypto` NIFs, which is the behavior of functions in this module.
  If you wish to use the elixir implementations, you can call them directly with the functions
  available in `Salchicha.Chacha` ending in `_pure`.

  While this module contains everything you'll need to encrypt and decrypt with XSalsa20_Poly1305
  and XChaCha20_Poly1305, the internal modules `Salchicha.Salsa` and `Salchicha.Chacha` expose a
  few additional functions including some primitives and non-extended Salsa20 and ChaCha20 ciphers.

  ## Examples

  Assume we have a key, and an extended nonce, and a plaintext message
  ```elixir
  key = Salchicha.generate_secret_key()
  nonce = Salchicha.generate_nonce()
  message = "Hello, World!"
  ```

  ### XSalsa20 Poly1305 via `secretbox/3` and `secretbox_open/3`

  ```elixir
  encrypted_message =
    message
    |> Salchicha.secretbox(nonce, key)
    |> IO.iodata_to_binary()
  # <<211, 79, 12, ...>>

  decrypted_message =
    encrypted_message
    |> Salchicha.secretbox_open(nonce, key)
    |> IO.iodata_to_binary()
  # "Hello, World!"
  ```

  The secretbox'd message is in the format `| --- 16-byte tag --- | --- cipher text --- |`

  Note the `IO.iodata_to_binary/1` calls are optional. The input messages can be `t:iodata/0`.

  ### XChaCha20 Poly1305 in combined mode

  ```elixir
  encrypted_message =
    message
    |> Salchicha.xchacha20_poly1305_encrypt(nonce, key, _aad = "XCHACHA")
    |> IO.iodata_to_binary()
  # <<82, 26, 161, ...>>

  decrypted_message =
    encrypted_message
    |> Salchicha.xchacha20_poly1305_decrypt(nonce, key, _aad = "XCHACHA")
  # "Hello, World!"
  ```

  The combined mode encrypted message is in the format `| --- cipher text --- | --- 16-byte tag --- |`

  The AAD is optional and will default to `<<>>`, a zero-length binary.

  ### XChaCha20 Poly1305 in detached mode

  ```elixir
  {cipher_text, tag} =
    message
    |> Salchicha.xchacha20_poly1305_encrypt_detached(nonce, key, _aad = "XCHACHA")
  # {<<82, 26, 161, ...>>, <<1, 199, 251, ...>>}

  decrypted_message =
    cipher_text
    |> Salchicha.xchacha20_poly1305_decrypt_detached(nonce, key, _aad = "XCHACHA", tag)
  # "Hello, World!"
  ```

  Detached mode means the cipher text and tag are returned separately instead of being concatenated together.

  ### Curve25519 XSalsa20 Poly1305 via `box/4` and `box_open/4`

  ```elixir
  {alice_public, alice_private} = Salchicha.generate_box_keypair()
  {bob_public, bob_private} = Salchicha.generate_box_keypair()

  {shared_secret, encrypted_message} = Salchicha.box(message, nonce, bob_public, alice_private)
  # {<<192, 50, 31, ...>>, [<<89, 217, 187, ...>>, ...]}

  {^shared_secret, decrypted_message_by_keypair} =
    Salchicha.box_open(encrypted_message, nonce, alice_public, bob_private)

  IO.iodata_to_binary(decrypted_message_by_keypair)
  # "Hello, World!"

  decrypted_message_by_shared_secret =
    encrypted_message
    |> Salchicha.secretbox_open(nonce, shared_secret)
    |> IO.iodata_to_binary()
  # "Hello, World!"
  ```

  The `shared_secret` output key can be used with `secretbox/3` and `secretbox_open/3` for subsequent
  messages to avoid computing the shared secret from the public and private keys each time.

  ### Ed25519 Message Signatures

  ```elixir
  {public_key, private_key} = Salchicha.generate_sign_keypair()

  signature = Salchicha.sign(message, private_key)
  # <<51, 62, 180, ...>>

  Salchicha.signature_valid?(message, signature, public_key)
  # true

  Salchicha.signature_valid?(message <> "~~~", signature, public_key)
  # false
  ```
  """

  alias Salchicha.Chacha
  alias Salchicha.Salsa

  @nonce_size 24
  @key_size 32
  @tag_size 16

  @typedoc """
  24-byte extended nonce used by the XSalsa20 and XChaCha20 ciphers
  """
  @type extended_nonce() :: <<_::192>>

  @typedoc """
  8-byte nonce used by the Salsa20 cipher
  """
  @typedoc since: "0.2.0"
  @type salsa_nonce() :: <<_::64>>

  @typedoc """
  12-byte nonce used by the ChaCha20 (IETF) cipher
  """
  @typedoc since: "0.2.0"
  @type chacha_nonce() :: <<_::96>>

  @typedoc """
  32-byte shared secret key used by all variations of Salsa/ChaCha
  """
  @type secret_key() :: <<_::256>>

  @typedoc """
  Plaintext message to encrypt
  """
  @type message() :: iodata()

  @typedoc """
  Encrypted message to decrypt; `t:cipher_text/0` appended or prepended with `t:tag/0`
  """
  @type encrypted_message() :: iodata()

  @typedoc """
  Additional authenticated data
  """
  @type aad() :: iodata()

  @typedoc """
  Tag or MAC (message authentication code)
  """
  @type tag() :: <<_::128>>

  @typedoc """
  Encrypted plaintext
  """
  @type cipher_text() :: binary()

  @typedoc """
  32-byte public key of a Curve25519 (X25519 or Ed25519) key pair
  """
  @typedoc since: "0.4.0"
  @type public_key() :: <<_::256>>

  @typedoc """
  32-byte private key of a Curve25519 (X25519 or Ed25519) key pair
  """
  @typedoc since: "0.4.0"
  @type private_key() :: <<_::256>>

  @typedoc """
  64-byte Ed25519 message signature
  """
  @typedoc since: "0.4.0"
  @type signature() :: <<_::512>>

  @doc """
  Encrypts a message with a secret key using the XSalsa20_Poly1305 authenticated cipher.

  This function behaves like `crypto_secretbox()` does in NaCl.

  ## Parameters
    - `message` - Plaintext message to be encrypted
    - `nonce` - 24-byte extended nonce
    - `key` - 32-byte secret key

  The return value is the cipher text *prepended* by the 16-byte tag (MAC), compatible with NaCl.

  Returns an `t:iolist/0` to reduce binary copies. Call `IO.iodata_to_binary/1` if you need a single binary.

  _Calls `Salchicha.Salsa.xsalsa20_poly1305_encrypt/3` then concatenates the tag and cipher text_
  """
  @spec secretbox(message(), extended_nonce(), secret_key()) :: iolist()
  def secretbox(message, nonce, key) do
    {cipher_text, tag} = Salsa.xsalsa20_poly1305_encrypt(message, nonce, key)
    [tag, cipher_text]
  end

  @doc """
  Decrypts a message that was encrypted with `secretbox/3` using the XSalsa20_Poly1305 authenticated cipher.

  This function behaves like `crypto_secretbox_open()` does in NaCl.

  ## Parameters
    - `message` - The encrypted message (tag *prepended* to cipher text)
    - `nonce` - 24-byte extended nonce
    - `key` - 32-byte secret key

  The return value is the decrypted plaintext (as an iolist) or `:error` if authentication failed.

  Returns an `t:iolist/0` to reduce binary copies. Call `IO.iodata_to_binary/1` if you need the message as a binary.

  _Splits tag and cipher text then calls `Salchicha.Salsa.xsalsa20_poly1305_decrypt/4`_
  """
  @spec secretbox_open(encrypted_message(), extended_nonce(), secret_key()) :: iolist() | :error
  def secretbox_open(message, nonce, key) do
    <<tag::bytes-16, cipher_text::binary>> = IO.iodata_to_binary(message)
    Salsa.xsalsa20_poly1305_decrypt(cipher_text, nonce, key, tag)
  end

  @doc """
  Encrypts a message with your private key and the recipient's public key using Curve25519_XSalsa20_Poly1305.

  This function behaves like `crypto_box()` and `crypto_box_easy()` do in NaCl and libsodium.

  ## Parameters
    - `message` - Plaintext message to be encrypted
    - `nonce` - 24-byte extended nonce
    - `their_public` - Recipient's 32-byte public X25519 key
    - `your_private` - Your 32-byte private X25519 key

  Returns a tuple with the computed shared secret key and the encrypted message.

  The returned shared secret key can be used with `secretbox/3` for subsequent encrypted messages to the same recipient
  to avoid having to re-compute the key with `box/4` for each message. Doing this would be similar to using
  `crypto_box_afternm()` in NaCl, which uses the pre-computed shared secret for multiple messages.

  Calls `compute_shared_secret/2` then calls `secretbox/3` with the result.
  """
  @doc since: "0.4.0"
  @spec box(message(), extended_nonce(), public_key(), private_key()) :: {secret_key(), iolist()}
  def box(message, nonce, their_public, your_private) do
    with <<shared_secret_key::bytes-32>> <- compute_shared_secret(their_public, your_private) do
      {shared_secret_key, secretbox(message, nonce, shared_secret_key)}
    end
  end

  @doc """
  Decrypts a message with your private key and the sender's public key using Curve25519_XSalsa20_Poly1305.

  This function behaves like `crypto_box_open()` and `crypto_box_open_easy()` do in NaCl and libsodium.

  ## Parameters
    - `message` - The encrypted message
    - `nonce` - 24-byte extended nonce
    - `their_public` - Sender's 32-byte public X25519 key
    - `your_private` - Your 32-byte private X25519 key

  Returns a tuple with the computed shared secret key and the decrypted plaintext.

  The returned shared secret key can be used with `secretbox_open/3` for subsequent messages from the same sender
  to avoid having to re-compute the key with `box_open/4` for each message. Doing this would be similar to using
  `crypto_box_open_afternm()` in NaCl, which uses the pre-computed shared secret for multiple messages.

  Calls `compute_shared_secret/2` then calls `secretbox_open/3` with the result.
  """
  @doc since: "0.4.0"
  @spec box_open(encrypted_message(), extended_nonce(), public_key(), private_key()) ::
          {secret_key(), iolist()} | :error
  def box_open(message, nonce, their_public, your_private) do
    with <<shared_secret_key::bytes-32>> <- compute_shared_secret(their_public, your_private),
         plaintext when is_list(plaintext) <- secretbox_open(message, nonce, shared_secret_key) do
      {shared_secret_key, plaintext}
    end
  end

  @doc """
  Encrypts a message with a secret key using the XChaCha20_Poly1305 AEAD cipher in "combined mode".

  This function behaves like `crypto_aead_xchacha20poly1305_ietf_encrypt()` does in libsodium.

  ## Parameters
    - `message` - Plaintext message to be encrypted
    - `nonce` - 24-byte extended nonce
    - `key` - 32-byte secret key
    - `aad` - Additional authenticated data (defaults to `<<>>` i.e. no AAD)

  The return value is the cipher text *appended* by the 16-byte tag (MAC), i.e. "combined mode".

  Returns an `t:iolist/0` to reduce binary copies. Call `IO.iodata_to_binary/1` if you need a single binary.

  _Calls `Salchicha.Chacha.xchacha20_poly1305_encrypt/4` then concatenates the cipher text and tag_
  """
  @spec xchacha20_poly1305_encrypt(message(), extended_nonce(), secret_key(), aad()) :: iolist()
  def xchacha20_poly1305_encrypt(message, nonce, key, aad \\ <<>>) do
    {cipher_text, tag} = Chacha.xchacha20_poly1305_encrypt(message, nonce, key, aad)
    [cipher_text, tag]
  end

  @doc """
  Decrypts a message that was encrypted in "combined mode" using the XChaCha20_Poly1305 AEAD cipher.

  This function behaves like `crypto_aead_xchacha20poly1305_ietf_decrypt()` does in libsodium.

  ## Parameters
    - `message` - The encrypted message (tag *appended* to cipher text)
    - `nonce` - 24-byte extended nonce
    - `key` - 32-byte secret key
    - `aad` - Additional authenticated data (defaults to `<<>>` i.e. no AAD)

  The return value is the decrypted plaintext as a binary or `:error` if authentication failed.

  _Splits cipher text and tag then calls `Salchicha.Chacha.xchacha20_poly1305_decrypt/5`_
  """
  @spec xchacha20_poly1305_decrypt(encrypted_message(), extended_nonce(), secret_key(), aad()) ::
          binary() | :error
  def xchacha20_poly1305_decrypt(message, nonce, key, aad \\ <<>>) do
    message = IO.iodata_to_binary(message)
    cipher_text_length = byte_size(message) - @tag_size
    <<cipher_text::bytes-size(cipher_text_length), tag::bytes-size(@tag_size)>> = message
    Chacha.xchacha20_poly1305_decrypt(cipher_text, nonce, key, aad, tag)
  end

  @doc """
  Encrypts a message with a secret key using the XChaCha20_Poly1305 AEAD cipher in "detached mode".

  This function behaves like `crypto_aead_xchacha20poly1305_ietf_encrypt_detached()` does in libsodium.

  ## Parameters
    - See `xchacha20_poly1305_encrypt/4`

  This "detached mode" function differs from the "combined mode" `xchacha20_poly1305_encrypt/4`
  by returning the tag and cipher text separately in a tuple in the form `{cipher_text, tag}`.
  Both `cipher_text` and `tag` will already be binaries.

  _Calls `Salchicha.Chacha.xchacha20_poly1305_encrypt/4`_
  """
  @spec xchacha20_poly1305_encrypt_detached(message(), extended_nonce(), secret_key(), aad()) ::
          {cipher_text(), tag()}
  def xchacha20_poly1305_encrypt_detached(message, nonce, key, aad \\ <<>>) do
    Chacha.xchacha20_poly1305_encrypt(message, nonce, key, aad)
  end

  @doc """
  Decrypts a message that was encrypted in "detacheded mode" using the XChaCha20_Poly1305 AEAD cipher.

  This function behaves like `crypto_aead_xchacha20poly1305_ietf_decrypt_detached()` does in libsodium.

  ## Parameters
    - `cipher_text` - The encrypted message (only the cipher text, not appended with the tag)
    - `nonce` - 24-byte extended nonce
    - `key` - 32-byte secret key
    - `aad` - Additional authenticated data (defaults to `<<>>` i.e. no AAD)
    - `tag` - 16-byte Poly1305 authentication tag or MAC

  The return value is the decrypted plaintext as a binary or `:error` if authentication failed.

  This function differs from `xchacha20_poly1305_decrypt/4` by returning the tag and cipher text separately

  This "detached mode" function differs from the "combined mode" `xchacha20_poly1305_decrypt/4` in that
  the cipher text and tag are supplied as separate parameters, not combined as a single message.

  _Calls `Salchicha.Chacha.xchacha20_poly1305_decrypt/5`_
  """
  @spec xchacha20_poly1305_decrypt_detached(
          encrypted_message(),
          extended_nonce(),
          secret_key(),
          aad(),
          tag()
        ) :: binary() | :error
  def xchacha20_poly1305_decrypt_detached(cipher_text, nonce, key, aad \\ <<>>, tag) do
    Chacha.xchacha20_poly1305_decrypt(cipher_text, nonce, key, aad, tag)
  end

  @doc """
  Sign a message with an Ed25519 private key

  Behaves like NaCl/libsodium `crypto_sign()`. _Calls `:crypto.sign/4`_
  """
  @doc since: "0.4.0"
  @spec sign(message(), private_key()) :: signature()
  def sign(message, private_key) do
    :crypto.sign(:eddsa, :sha512, message, [private_key, :ed25519])
  end

  @doc """
  Verifies a message signature with the signer's Ed25519 public key

  Behaves like NaCl/libsodium `crypto_sign_open()`. _Calls `:crypto.sign/4`_
  """
  @doc since: "0.4.0"
  def signature_valid?(message, signature, public_key) do
    :crypto.verify(:eddsa, :sha512, message, signature, [public_key, :ed25519])
  end

  @doc """
  Generates a random 24-byte extended nonce

  XSalsa20 and XChaCha20 use a 24-byte nonce, up from the 8 and 8/12 byte nonces
  of the respective Salsa20 and ChaCha20 ciphers.

  You should never reuse the same nonce for a given secret key. 24 bytes are said to be large enough
  to generate nonces randomly - doing so would be ill-advised with 8-byte nonces since collision would
  be much more likely.
  """
  @spec generate_nonce() :: extended_nonce()
  def generate_nonce do
    :crypto.strong_rand_bytes(@nonce_size)
  end

  @doc """
  Generates a random 32-byte key
  """
  @spec generate_secret_key() :: secret_key()
  def generate_secret_key do
    :crypto.strong_rand_bytes(@key_size)
  end

  @doc """
  Generates a random X25519 key pair for public-key encryption (box/4 and box_open/4).

  If a private key is provided it will recover the public key instead of generating a random key pair.

  Behaves like NaCl/libsodium `crypto_box_keypair()`. _Calls `:crypto.generate_key/3`_
  """
  @doc since: "0.4.0"
  @spec generate_box_keypair(private_key() | nil) :: {public_key(), private_key()}
  def generate_box_keypair(private_key \\ nil) do
    :crypto.generate_key(:ecdh, :x25519, private_key || :undefined)
  end

  @doc """
  Generates a random Ed25519 key pair for message signing and signature verification.

  If a private key is provided it will recover the public key instead of generating a random key pair.

  Behaves like NaCl/libsodium `crypto_sign_keypair()`. _Calls `:crypto.generate_key/3`_
  """
  @doc since: "0.4.0"
  @spec generate_sign_keypair(private_key() | nil) :: {public_key(), private_key()}
  def generate_sign_keypair(private_key \\ nil) do
    :crypto.generate_key(:eddsa, :ed25519, private_key || :undefined)
  end

  @doc """
  Computes the shared secret key given a peer's X25519 public key and your X25519 private key.

  Similar to NaCl/libsodium `crypto_box_beforenm()`/`crypto_box_open_beforenm()`.

  _Calls `:crypto.compute_key/4` then calls `Salchicha.Salsa.hsalsa20/2` with the resultant key and 16 zeroes as the input vector._
  """
  @doc since: "0.4.0"
  @spec compute_shared_secret(public_key(), private_key()) :: secret_key()
  def compute_shared_secret(<<pk::bytes-32>> = _their_public, <<sk::bytes-32>> = _your_private) do
    with <<key::bytes-32>> <- :crypto.compute_key(:ecdh, pk, sk, :x25519) do
      <<_shared_secret::bytes-32>> = Salsa.hsalsa20(key, <<0::unit(8)-size(16)>>)
    end
  end
end
