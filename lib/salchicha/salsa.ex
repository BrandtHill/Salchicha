defmodule Salchicha.Salsa do
  @moduledoc """
  Implementation of the Salsa20 and XSalsa20 Ciphers

  > ### Internal module {: .info}
  >
  > This module is documented for completeness and for curious cryptographers.
  > It contains some Salsa primitives that you likely won't need to use directly.

  ### Purpose

  To support xsalsa20_poly1305 without a NIF, we have to implement the
  Salsa20 cipher and HSalsa20 hash function to use 192-bit nonces in the capacity
  of XSalsa20.

  Along with leveraging the `:crypto` module to perform the poly1305 MAC function
  and xor'ing arbitrary-length binaries, by being more thoughtful and explicit
  with our implementation we should be able to eek out better performance
  than the `:kcl` package provides.

  ### Implementation

  The `:kcl` package is an impressive pure-elixir NaCl/libsodium compatible library I've used
  in the past for xsalsa20_poly1305 encryption.

  Some of the key differences in our implementation compared to Kcl
  - Heavy use of explicit binary pattern matching instead of more traditional implicit enumeration
  - Intermediate block state stored in a 16-element tuple that is mutated during the 20-round hot loop instead of lists
  - Minimized the number binary copies, returning iolists when appropriate, instead of concatenating binaries
  - XOR whole keystream and message blocks instead of XOR'ing one byte at a time
  - Poly1305 MAC handled by `:crypto` module instead of implemented in elixir
  - Only supporting Salsa/ChaCha family ciphers, not full NaCl/libsodium API

  Additionally there appears to be a bug in how Kcl serializes the 16-byte block counter during key expansion:
  According to the spec it's supposed to be little endian, and it happens to be for blocks 0-255, but for larger
  block counts, Kcl would be incompatible with NaCl/libsodium-type libraries.

  The XOR'ing of the keystream and message occurs one block (64 bytes) at a time using `:crypto.exor/2`, which
  is implemented as a NIF, but this could have just as easily been done in elixir by casting the
  keystream and message block binaries into 512-bit integers, passing them to `Bitwise.bxor/2`, and casting the result
  into a binary.

  The cipher functions were implemented in the order they're defined in the original Salsa specification,
  and though it's using a lot of explicit binary pattern matching, it turned out to be quite legible.
  In a single statement of binary pattern matching, the 512-bit initial block state is cast into 16
  little-endian 32-bit words. Standard elixir patterns might have you iterate through the binary until the
  end was reached, but matching and casting all sixteen block elements in a single statement then returning
  a tuple is explicit, clear, and simple to understand when referencing the spec.

  Readers interested in cryptography are encouraged to read more about the Salsa20/ChaCha20 ciphers.

  References for Salsa family of ciphers
  - https://cr.yp.to/snuffle/spec.pdf
  - https://cr.yp.to/chacha/chacha-20080128.pdf
  - https://cr.yp.to/snuffle/xsalsa-20110204.pdf
  - https://datatracker.ietf.org/doc/html/rfc7539
  - https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha

  ### Performance considerations

  The entire keystream generation and xor'ing the message with the stream is done in elixir,
  only performing the Poly1305 MAC function through the `:crypto` module. Although it was implemented
  as thoughtfully and explicitly as possible with memory usage and performance in mind, using any
  of the Salsa modes will likely be less performant than ChaCha.
  """

  import Bitwise

  @salsa_constant ~c"expand 32-byte k"
                  |> Enum.chunk_every(4)
                  |> Enum.map(&to_string/1)

  defp sum(a, b), do: a + b &&& 0xFFFFFFFF
  defp rotl(a, b), do: (a <<< b ||| a >>> (32 - b)) &&& 0xFFFFFFFF

  defp quarter_round(a, b, c, d) do
    b = a |> sum(d) |> rotl(7) |> bxor(b)
    c = b |> sum(a) |> rotl(9) |> bxor(c)
    d = c |> sum(b) |> rotl(13) |> bxor(d)
    a = d |> sum(c) |> rotl(18) |> bxor(a)

    {a, b, c, d}
  end

  defp quarter_round_on(tuple, index_a, index_b, index_c, index_d) do
    a = elem(tuple, index_a)
    b = elem(tuple, index_b)
    c = elem(tuple, index_c)
    d = elem(tuple, index_d)

    {a, b, c, d} = quarter_round(a, b, c, d)

    tuple
    |> put_elem(index_a, a)
    |> put_elem(index_b, b)
    |> put_elem(index_c, c)
    |> put_elem(index_d, d)
  end

  # Column round followed by row round
  defp double_round(tuple) do
    tuple
    |> quarter_round_on(0, 4, 8, 12)
    |> quarter_round_on(5, 9, 13, 1)
    |> quarter_round_on(10, 14, 2, 6)
    |> quarter_round_on(15, 3, 7, 11)
    |> quarter_round_on(0, 1, 2, 3)
    |> quarter_round_on(5, 6, 7, 4)
    |> quarter_round_on(10, 11, 8, 9)
    |> quarter_round_on(15, 12, 13, 14)
  end

  defp twenty_rounds(block) do
    Enum.reduce(1..10, block, fn _, t -> double_round(t) end)
  end

  defp expand(<<key::bytes-32>>, <<nonce::bytes-8>>, block_counter)
       when is_integer(block_counter) do
    # Full input is 64-bit nonce concatenated with little endian block counter
    input = nonce <> <<block_counter::little-64>>
    expand(key, input)
  end

  defp expand(<<k0::bytes-16, k1::bytes-16>> = _key, <<input::bytes-16>>) do
    [c0, c1, c2, c3] = @salsa_constant

    c0 <> k0 <> c1 <> input <> c2 <> k1 <> c3
  end

  @doc """
  HSalsa20 hash function for deriving a sub-key for XSalsa20. Crypto primitive.
  """
  @spec hsalsa20(Salchicha.secret_key(), Salchicha.extended_nonce()) :: Salchicha.secret_key()
  def hsalsa20(<<key::bytes-32>> = _key, <<first_sixteen::bytes-16, _last::bytes-8>> = _nonce) do
    key
    |> expand(first_sixteen)
    |> block_binary_to_tuple()
    |> twenty_rounds()
    |> hsalsa20_block_tuple_to_binary()
  end

  @spec xsalsa20_key_and_nonce(Salchicha.secret_key(), Salchicha.extended_nonce()) ::
          {Salchicha.secret_key(), Salchicha.salsa_nonce()}
  defp xsalsa20_key_and_nonce(<<key::bytes-32>> = _k, <<nonce::bytes-24>> = _n) do
    xsalsa20_key = hsalsa20(key, nonce)
    <<_first_sixteen::bytes-16, xsalsa20_nonce::bytes-8>> = nonce
    {xsalsa20_key, xsalsa20_nonce}
  end

  # Shared with ChaCha
  @doc false
  def block_binary_to_tuple(
        <<x0::little-32, x1::little-32, x2::little-32, x3::little-32, x4::little-32,
          x5::little-32, x6::little-32, x7::little-32, x8::little-32, x9::little-32,
          x10::little-32, x11::little-32, x12::little-32, x13::little-32, x14::little-32,
          x15::little-32>>
      ) do
    {x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15}
  end

  defp hsalsa20_block_tuple_to_binary({x0, _, _, _, _, x5, x6, x7, x8, x9, x10, _, _, _, _, x15}) do
    <<x0::little-32, x5::little-32, x10::little-32, x15::little-32, x6::little-32, x7::little-32,
      x8::little-32, x9::little-32>>
  end

  # Shared with ChaCha
  @doc false
  def sum_blocks(
        {x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15},
        {y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15}
      ) do
    <<sum(x0, y0)::little-32, sum(x1, y1)::little-32, sum(x2, y2)::little-32,
      sum(x3, y3)::little-32, sum(x4, y4)::little-32, sum(x5, y5)::little-32,
      sum(x6, y6)::little-32, sum(x7, y7)::little-32, sum(x8, y8)::little-32,
      sum(x9, y9)::little-32, sum(x10, y10)::little-32, sum(x11, y11)::little-32,
      sum(x12, y12)::little-32, sum(x13, y13)::little-32, sum(x14, y14)::little-32,
      sum(x15, y15)::little-32>>
  end

  # Shared with ChaCha
  @doc false
  def bxor_block(<<keystream::bytes-64>>, <<message::bytes-64>>) do
    :crypto.exor(keystream, message)
  end

  def bxor_block(<<keystream::bytes-64>>, message) when byte_size(message) < 64 do
    keystream
    |> binary_part(0, byte_size(message))
    |> :crypto.exor(message)
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

  # NaCl/libsodium use the first 32-bytes of the first Salsa20 keystream block as the OTP
  # for the Poly1305 MAC function. This is accomplished by prepending the messages with 32
  # zeros, so the XOR'ing yields just the keystream for those bytes. Only concatenate the
  # zeros with the first half block of the message to avoid copying entire message binary.
  defp prepare_message(<<first_thirty_two::bytes-32, rest::binary>>) when byte_size(rest) > 0 do
    {<<0::unit(8)-size(32), first_thirty_two::bytes-32>>, rest}
  end

  defp prepare_message(<<whole_message::binary>>) do
    {<<0::unit(8)-size(32), whole_message::binary>>, _rest = <<>>}
  end

  defp prepare_message(message) when not is_binary(message) do
    message |> IO.iodata_to_binary() |> prepare_message()
  end

  @spec xsalsa20_poly1305_encrypt(
          Salchicha.message(),
          Salchicha.extended_nonce(),
          Salchicha.secret_key()
        ) ::
          {cipher_text :: iolist(), Salchicha.tag()}
  def xsalsa20_poly1305_encrypt(
        plain_text,
        <<nonce::bytes-24>> = _nonce,
        <<key::bytes-32>> = _key
      ) do
    {xsalsa_key, xsalsa_nonce} = xsalsa20_key_and_nonce(key, nonce)
    salsa20_poly1305_encrypt(plain_text, xsalsa_nonce, xsalsa_key)
  end

  @spec xsalsa20_poly1305_decrypt(
          Salchicha.cipher_text(),
          Salchicha.extended_nonce(),
          Salchicha.secret_key(),
          Salchicha.tag()
        ) ::
          plain_text :: iolist() | :error
  def xsalsa20_poly1305_decrypt(
        cipher_text,
        <<nonce::bytes-24>> = _nonce,
        <<key::bytes-32>> = _key,
        <<tag::bytes-16>> = _tag
      ) do
    {xsalsa_key, xsalsa_nonce} = xsalsa20_key_and_nonce(key, nonce)
    salsa20_poly1305_decrypt(cipher_text, xsalsa_nonce, xsalsa_key, tag)
  end

  @spec salsa20_poly1305_encrypt(
          Salchicha.message(),
          Salchicha.salsa_nonce(),
          Salchicha.secret_key()
        ) ::
          {cipher_text :: iolist(), Salchicha.tag()}
  def salsa20_poly1305_encrypt(
        plain_text,
        <<nonce::bytes-8>> = _nonce,
        <<key::bytes-32>> = _key
      ) do
    {message_head, message_tail} = prepare_message(plain_text)

    # This returns exactly 1 block
    [<<mac_otp::bytes-32, cipher_text_head::binary>>] =
      crypt(key, nonce, message_head, _block_counter = 0)

    cipher_text = [
      cipher_text_head
      | _cipher_text_tail = crypt(key, nonce, message_tail, _block_counter = 1)
    ]

    tag = :crypto.mac(:poly1305, mac_otp, cipher_text)

    {cipher_text, tag}
  end

  @spec salsa20_poly1305_decrypt(
          Salchicha.cipher_text(),
          Salchicha.salsa_nonce(),
          Salchicha.secret_key(),
          Salchicha.tag()
        ) ::
          plain_text :: iolist() | :error
  def salsa20_poly1305_decrypt(
        cipher_text,
        <<nonce::bytes-8>> = _nonce,
        <<key::bytes-32>> = _key,
        <<tag::bytes-16>> = _tag
      ) do
    {message_head, message_tail} = prepare_message(cipher_text)

    [<<mac_otp::bytes-32, plain_text_head::binary>>] =
      crypt(key, nonce, message_head, _block_counter = 0)

    case :crypto.mac(:poly1305, mac_otp, cipher_text) do
      ^tag ->
        [
          plain_text_head
          | _plain_text_tail = crypt(key, nonce, message_tail, _block_counter = 1)
        ]

      _error ->
        :error
    end
  end

  @doc """
  Plain Salsa20 Cipher. Crypto primitive.

  XOR a message (encrypt or decrypt) with Salsa20.
  This uses 8 byte nonces and isn't authenticated with Poly1305 MAC.
  Block counter starts at 0 by default.
  """
  @spec salsa20_xor(
          message :: iodata(),
          Salchicha.salsa_nonce(),
          Salchicha.secret_key(),
          non_neg_integer()
        ) ::
          iolist()
  def salsa20_xor(
        message,
        <<nonce::bytes-8>> = _nonce,
        <<key::bytes-32>> = _key,
        initial_block_counter \\ 0
      ) do
    message = IO.iodata_to_binary(message)
    crypt(key, nonce, message, initial_block_counter)
  end
end
