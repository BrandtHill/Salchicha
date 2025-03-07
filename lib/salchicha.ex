defmodule Salchicha do
  @moduledoc """
  A pure-ish Elixir cryptography tool for the Salsa20 and ChaCha20 stream ciphers.

  This library has a handful of crypto functions that are compatible with NaCl/libsodium
  for encryption and decryption with shared secret keys.

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
  @type salsa_nonce() :: <<_::64>>

  @typedoc """
  12-byte nonce used by the ChaCha20 (IETF) cipher
  """
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
end
