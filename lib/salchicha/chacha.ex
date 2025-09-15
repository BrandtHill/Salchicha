defmodule Salchicha.Chacha do
  @moduledoc """
  Implementation of the ChaCha20 and XChaCha20 Ciphers

  > ### Internal module {: .info}
  >
  > This module is documented for completeness and for curious cryptographers.
  > It contains some ChaCha primitives that you likely won't need to use directly.

  ### Purpose

  Erlang's `:crypto` module supports the chacha20_poly1305 AEAD stream cipher,
  standardized by the IETF, as its underlying NIFs are bindings to OpenSSL, which implements it.

  Analogously to Salsa20 and XSalsa20, XChaCha20 is a way to use 192-bit nonces
  with ChaCha20 by hashing the key and part of the extended nonce to generate a
  sub-key, which is used as the input key for ChaCha20.

  To leverage the crypto module, we had to implement the HChaCha20 hash function
  in elixir to then pass the resulting sub-key and sub-nonce to `:crypto.crypto_one_time_aead/7`.

  ### Implementation

  The HChaCha20 function takes the first 16 bytes of the extended 24-byte XChaCha20 nonce,
  expands the key and the 16-byte nonce slice into a block in place of the block counter and
  usual smaller nonce. That block has 20 rounds of mutation, and instead of summing the block
  with its starting state as is done with keystream generation, 8 of the 16 32-bit words are taken
  and used as the sub-key, which is the input key for the chacha20 cipher. The sub-nonce is the latter
  8 bytes of the extended nonce prepended with 4 zero bytes for the 12-byte nonce that the IETF version
  of ChaCha20 specifies.

  After running HChaCha20, we have the inputs required use the `:crypto` module's `:chacha20_poly1305`
  functionality in the capacity of XChaCha20_Poly1305. This is all in service of leveraging the performance
  benefits of the crypto NIFs, which are necessarily going to be more performant than anything implemented
  in pure elixir/erlang like the `:kcl` package.

  For reference, I also implemented the ChaCha20/XChaCha20 functions in Elixir that don't use `crypto_one_time_aead/7`,
  only leveraging `:crypto.mac/3` for the Poly1305 MAC similarly to `Salchicha.Salsa`. The only reason you might prefer
  to use these functions (ending in `_pure`) over the NIF ones is that if you have an exceptionally large message
  the long-running NIF would not yield to the erlang scheduler and could block other processes. In most cases
  you should prefer the impure variants - the `Salchicha` functions will use them by default.

  *ChaCha20 is a variant of the Salsa20 cipher. I will discuss in greater detail the implementation
  in the `Salchicha.Salsa` module, where much is applicable here.*

  References for Salsa family of ciphers
  - https://cr.yp.to/snuffle/spec.pdf
  - https://cr.yp.to/chacha/chacha-20080128.pdf
  - https://cr.yp.to/snuffle/xsalsa-20110204.pdf
  - https://datatracker.ietf.org/doc/html/rfc7539
  - https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha

  ### Performance considerations

  After the XChaCha20 sub-key is generated in elixir, the crypto NIF function performs the
  heavy lifting. Performance should be speedy.
  """

  import Bitwise

  require Salchicha.Macros
  alias Salchicha.Macros

  import Salchicha.Salsa, only: [block_binary_to_tuple: 1, sum_blocks: 2, bxor_block: 2]

  @chacha_constant "expand 32-byte k"

  defp sum(a, b), do: a + b &&& 0xFFFFFFFF
  defp rotl(a, b), do: (a <<< b ||| a >>> (32 - b)) &&& 0xFFFFFFFF

  defp quarter_round(a, b, c, d) do
    a = a |> sum(b)
    d = d |> bxor(a) |> rotl(16)

    c = c |> sum(d)
    b = b |> bxor(c) |> rotl(12)

    a = a |> sum(b)
    d = d |> bxor(a) |> rotl(8)

    c = c |> sum(d)
    b = b |> bxor(c) |> rotl(7)

    {a, b, c, d}
  end

  defp quarter_round_on(tuple, {index_a, index_b, index_c, index_d} = indexes) do
    a = elem(tuple, index_a)
    b = elem(tuple, index_b)
    c = elem(tuple, index_c)
    d = elem(tuple, index_d)

    {_a, _b, _c, _d} = values = quarter_round(a, b, c, d)

    update_tuple(tuple, indexes, values)
  end

  # Define the four quarter rounds of a column round
  @column_quarter_round_1 {0, 4, 8, 12}
  @column_quarter_round_2 {1, 5, 9, 13}
  @column_quarter_round_3 {2, 6, 10, 14}
  @column_quarter_round_4 {3, 7, 11, 15}
  Macros.def_update_tuple(0, 4, 8, 12)
  Macros.def_update_tuple(1, 5, 9, 13)
  Macros.def_update_tuple(2, 6, 10, 14)
  Macros.def_update_tuple(3, 7, 11, 15)

  # Define the four quarter rounds of a diagonal round
  @diagonal_quarter_round_1 {0, 5, 10, 15}
  @diagonal_quarter_round_2 {1, 6, 11, 12}
  @diagonal_quarter_round_3 {2, 7, 8, 13}
  @diagonal_quarter_round_4 {3, 4, 9, 14}
  Macros.def_update_tuple(0, 5, 10, 15)
  Macros.def_update_tuple(1, 6, 11, 12)
  Macros.def_update_tuple(2, 7, 8, 13)
  Macros.def_update_tuple(3, 4, 9, 14)

  # Column round followed by diagonal round
  defp double_round(tuple) do
    tuple
    |> quarter_round_on(@column_quarter_round_1)
    |> quarter_round_on(@column_quarter_round_2)
    |> quarter_round_on(@column_quarter_round_3)
    |> quarter_round_on(@column_quarter_round_4)
    |> quarter_round_on(@diagonal_quarter_round_1)
    |> quarter_round_on(@diagonal_quarter_round_2)
    |> quarter_round_on(@diagonal_quarter_round_3)
    |> quarter_round_on(@diagonal_quarter_round_4)
  end

  defp twenty_rounds(block) do
    Enum.reduce(1..10, block, fn _, t -> double_round(t) end)
  end

  defp expand(<<key::bytes-32>>, <<nonce::bytes-12>>, block_counter)
       when is_integer(block_counter) do
    # Full input is 32-bit little-endian block counter concatenated with 96-bit nonce
    input = <<block_counter::little-32>> <> nonce
    expand(key, input)
  end

  defp expand(<<key::bytes-32>> = _k, <<input::bytes-16>> = _i) do
    @chacha_constant <> key <> input
  end

  @doc """
  HChaCha20 hash function for deriving a sub-key for XChaCha20. Crypto primitive.

  Second arg can be extended nonce (first 16 bytes of the nonce will be used) or 16 bytes.
  """
  @spec hchacha20(Salchicha.secret_key(), Salchicha.extended_nonce()) :: Salchicha.secret_key()
  @spec hchacha20(Salchicha.secret_key(), input_vector :: <<_::128>>) :: Salchicha.secret_key()
  def hchacha20(<<key::bytes-32>> = _key, <<first_sixteen::bytes-16, _last::bytes-8>> = _nonce) do
    hchacha20(key, first_sixteen)
  end

  def hchacha20(<<key::bytes-32>> = _key, <<vector::bytes-16>> = _input_vector) do
    key
    |> expand(vector)
    |> block_binary_to_tuple()
    |> twenty_rounds()
    |> hchacha20_block_tuple_to_binary()
  end

  @spec xchacha20_key_and_nonce(Salchicha.secret_key(), Salchicha.extended_nonce()) ::
          {Salchicha.secret_key(), Salchicha.chacha_nonce()}
  defp xchacha20_key_and_nonce(<<key::bytes-32>> = _k, <<nonce::bytes-24>> = _n) do
    xchacha20_key = hchacha20(key, nonce)
    <<_first_sixteen::bytes-16, last_eight::bytes-8>> = nonce
    # The IETF version of ChaCha20_Poly1305 specifies a 12-byte nonce, so prepend 4 zeros.
    xchacha20_nonce = <<0, 0, 0, 0>> <> last_eight
    {xchacha20_key, xchacha20_nonce}
  end

  defp hchacha20_block_tuple_to_binary(
         {x0, x1, x2, x3, _, _, _, _, _, _, _, _, x12, x13, x14, x15}
       ) do
    <<x0::little-32, x1::little-32, x2::little-32, x3::little-32, x12::little-32, x13::little-32,
      x14::little-32, x15::little-32>>
  end

  defp keystream_block(key, nonce, block_counter) do
    block =
      key
      |> expand(nonce, block_counter)
      |> block_binary_to_tuple()

    block
    |> twenty_rounds()
    |> sum_blocks(block)
  end

  defp crypt(key, nonce, message, block_counter, outputs \\ [])

  defp crypt(key, nonce, <<message::bytes-64, rest::binary>>, block_counter, outputs)
       when byte_size(rest) > 0 do
    output_block = crypt_block(key, nonce, message, block_counter)
    crypt(key, nonce, rest, block_counter + 1, [output_block | outputs])
  end

  defp crypt(key, nonce, <<message::binary>>, block_counter, outputs) do
    output_block = crypt_block(key, nonce, message, block_counter)
    _final_outputs = Enum.reverse([output_block | outputs])
  end

  defp crypt_block(_key, _nonce, <<>>, _block_counter), do: <<>>

  defp crypt_block(key, nonce, message, block_counter) do
    keystream = keystream_block(key, nonce, block_counter)
    bxor_block(keystream, message)
  end

  defp zeros(size), do: <<0::unit(8)-size(size)>>
  defp padding_length(data_length), do: rem(16 - rem(data_length, 16), 16)

  defp mac_input(aad, cipher_text) do
    aad_length = IO.iodata_length(aad)
    cipher_text_length = IO.iodata_length(cipher_text)
    padding_1_length = padding_length(aad_length)
    padding_2_length = padding_length(cipher_text_length)

    [
      aad,
      zeros(padding_1_length),
      cipher_text,
      zeros(padding_2_length),
      <<aad_length::little-64>>,
      <<cipher_text_length::little-64>>
    ]
  end

  @doc since: "0.2.0"
  @spec xchacha20_poly1305_encrypt_pure(
          Salchicha.message(),
          Salchicha.extended_nonce(),
          Salchicha.secret_key(),
          Salchicha.aad()
        ) ::
          {cipher_text :: iolist(), Salchicha.tag()}
  def xchacha20_poly1305_encrypt_pure(
        plain_text,
        <<nonce::bytes-24>> = _nonce,
        <<key::bytes-32>> = _key,
        aad
      ) do
    {xchacha_key, xchacha_nonce} = xchacha20_key_and_nonce(key, nonce)
    chacha20_poly1305_encrypt_pure(plain_text, xchacha_nonce, xchacha_key, aad)
  end

  @doc since: "0.2.0"
  @spec xchacha20_poly1305_decrypt_pure(
          cipher_text :: iodata(),
          Salchicha.extended_nonce(),
          Salchicha.secret_key(),
          Salchicha.aad(),
          Salchicha.tag()
        ) ::
          plain_text :: iolist() | :error
  def xchacha20_poly1305_decrypt_pure(
        plain_text,
        <<nonce::bytes-24>> = _nonce,
        <<key::bytes-32>> = _key,
        aad,
        <<tag::bytes-16>> = _tag
      ) do
    {xchacha_key, xchacha_nonce} = xchacha20_key_and_nonce(key, nonce)
    chacha20_poly1305_decrypt_pure(plain_text, xchacha_nonce, xchacha_key, aad, tag)
  end

  @doc since: "0.2.0"
  @spec chacha20_poly1305_encrypt_pure(
          Salchicha.message(),
          Salchicha.chacha_nonce(),
          Salchicha.secret_key(),
          Salchicha.aad()
        ) ::
          {cipher_text :: iolist(), Salchicha.tag()}
  def chacha20_poly1305_encrypt_pure(
        plain_text,
        <<nonce::bytes-12>> = _nonce,
        <<key::bytes-32>> = _key,
        aad
      ) do
    plain_text = IO.iodata_to_binary(plain_text)
    [<<mac_otp::bytes-32, _discard::bytes-32>>] = crypt(key, nonce, zeros(64), _block_counter = 0)
    cipher_text = crypt(key, nonce, plain_text, _block_counter = 1)
    mac_input = mac_input(aad, cipher_text)

    tag = :crypto.mac(:poly1305, mac_otp, mac_input)

    {cipher_text, tag}
  end

  @doc since: "0.2.0"
  @spec chacha20_poly1305_decrypt_pure(
          cipher_text :: iodata(),
          Salchicha.chacha_nonce(),
          Salchicha.secret_key(),
          Salchicha.aad(),
          Salchicha.tag()
        ) ::
          plain_text :: iolist() | :error
  def chacha20_poly1305_decrypt_pure(
        cipher_text,
        <<nonce::bytes-12>> = _nonce,
        <<key::bytes-32>> = _key,
        aad,
        <<tag::bytes-16>> = _tag
      ) do
    cipher_text = IO.iodata_to_binary(cipher_text)
    [<<mac_otp::bytes-32, _discard::bytes-32>>] = crypt(key, nonce, zeros(64), _block_counter = 0)

    mac_input = mac_input(aad, cipher_text)

    case :crypto.mac(:poly1305, mac_otp, mac_input) do
      ^tag -> crypt(key, nonce, cipher_text, _block_counter = 1)
      _error -> :error
    end
  end

  @spec xchacha20_poly1305_encrypt(
          Salchicha.message(),
          Salchicha.extended_nonce(),
          Salchicha.secret_key(),
          Salchicha.aad()
        ) ::
          {cipher_text :: binary(), Salchicha.tag()}
  def xchacha20_poly1305_encrypt(
        plain_text,
        <<nonce::bytes-24>> = _nonce,
        <<key::bytes-32>> = _key,
        aad
      ) do
    {xchacha_key, xchacha_nonce} = xchacha20_key_and_nonce(key, nonce)

    {_cipher_text, _tag} =
      :crypto.crypto_one_time_aead(
        :chacha20_poly1305,
        xchacha_key,
        xchacha_nonce,
        plain_text,
        aad,
        _encrypt = true
      )
  end

  @spec xchacha20_poly1305_decrypt(
          cipher_text :: iodata(),
          Salchicha.extended_nonce(),
          Salchicha.secret_key(),
          Salchicha.aad(),
          Salchicha.tag()
        ) ::
          plain_text :: binary() | :error
  def xchacha20_poly1305_decrypt(
        cipher_text,
        <<nonce::bytes-24>> = _nonce,
        <<key::bytes-32>> = _key,
        aad,
        <<tag::bytes-16>> = _tag
      ) do
    {xchacha_key, xchacha_nonce} = xchacha20_key_and_nonce(key, nonce)

    :crypto.crypto_one_time_aead(
      :chacha20_poly1305,
      xchacha_key,
      xchacha_nonce,
      cipher_text,
      aad,
      tag,
      _encrypt = false
    )
  end

  @doc """
  Plain ChaCha20 Cipher. Crypto primitive.

  XOR a message (encrypt or decrypt) with ChaCha20.
  This uses 12 byte nonces and isn't authenticated with Poly1305 MAC.

  The IETF standardized version of ChaCha20 uses 12 byte nonces and a 4 byte block
  counter instead of 8 byte nonces and an 8 byte block counter.
  The IETF standard's 4 byte (32 bit) block counter means messages are limited to 256GB:
  2^32 blocks (4 GigaBlocks) * 64 bytes per block = 256GB.

  Because of how the block state is arranged in the cipher, if you take an 8-byte nonce
  and prepend it with 4 zeros to form a 12 byte nonce, this is equivalent to
  the pre-IETF-standardized version of ChaCha20 that uses 8 byte nonces. In fact,
  the XChaCha20 sub-nonce derived from the 24-byte extended nonce is simply the last 8 byte
  prepended with 4 zeros.

  Block counter starts at 0 by default.

  Implemented in Elixir.

  Equivalent NIF-powered version of this would be
  ```elixir
  # Encrypt
  :crypto.crypto_one_time(:chacha20, key, iv, plaintext, _encrypt = true)

  # Decrypt
  :crypto.crypto_one_time(:chacha20, key, iv, ciphertext, _encrypt = false)
  ```

  Some things worth noting from the above usage of the `:crypto` module function:
    - The initialization vector (iv) arg is NOT simply the nonce - it the full 16-byte user-controlled input.
      - For an 8 or 12 byte nonce, you'd have to prepend your initial block counter in little-endian.
        - `iv = <<_block_counter=0::little-32>> <> my_twelve_byte_nonce`
        - `iv = <<_block_counter=0::little-64>> <> my_eight_byte_nonce`
      - How annoying!
    - The fifth argument, the boolean `encrypt` flag, is irrelevant.
      - This is an unauthenticated stream cipher where the input message is XOR'd with the keystream.
        - Encryption and decryption are fundamentally the same operation.
        - While the flag is required, whether it's `true` or `false` makes no difference.
      - How annoying!
  """
  @doc since: "0.2.0"
  @spec chacha20_xor(
          message :: iodata(),
          Salchicha.chacha_nonce(),
          Salchicha.secret_key(),
          non_neg_integer()
        ) :: iolist()
  def chacha20_xor(
        message,
        <<nonce::bytes-12>> = _nonce,
        <<key::bytes-32>> = _key,
        initial_block_counter \\ 0
      ) do
    message = IO.iodata_to_binary(message)
    crypt(key, nonce, message, initial_block_counter)
  end
end
