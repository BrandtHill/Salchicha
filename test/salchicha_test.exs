defmodule SalchichaTest do
  use ExUnit.Case

  alias Salchicha.Chacha

  setup do
    key = Salchicha.generate_secret_key()
    nonce = Salchicha.generate_nonce()
    aad = "dnarberyf"

    plaintext =
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."

    %{
      key: key,
      nonce: nonce,
      aad: aad,
      plaintext: plaintext
    }
  end

  def zeros(size), do: <<0::unit(8)-size(size)>>

  describe "ChaCha" do
    test "encryption and decryption, combined mode", %{key: key, nonce: nonce, aad: aad} do
      plain_text = "Hello, World!"

      cipher_message = Salchicha.xchacha20_poly1305_encrypt(plain_text, nonce, key, aad)
      ^plain_text = Salchicha.xchacha20_poly1305_decrypt(cipher_message, nonce, key, aad)
    end

    test "encryption and decryption, detached mode", %{key: key, nonce: nonce, aad: aad} do
      plain_text = "Hello, World!"

      {cipher_text, tag} =
        Salchicha.xchacha20_poly1305_encrypt_detached(plain_text, nonce, key, aad)

      ^plain_text =
        Salchicha.xchacha20_poly1305_decrypt_detached(cipher_text, nonce, key, aad, tag)
    end

    test "decryption fails with altered input, combined mode", %{key: key, nonce: nonce, aad: aad} do
      plain_text = "Hello, World!"

      cipher_message = Salchicha.xchacha20_poly1305_encrypt(plain_text, nonce, key, aad)
      :error = Salchicha.xchacha20_poly1305_decrypt(cipher_message, nonce, key, aad <> "!")
    end

    test "decryption fails with altered input, detached mode", %{key: key, nonce: nonce, aad: aad} do
      plain_text = "Hello, World!"

      {cipher_text, tag} =
        Salchicha.xchacha20_poly1305_encrypt_detached(plain_text, nonce, key, aad)

      <<first_byte, rest::binary>> = tag
      altered_tag = <<Bitwise.bxor(first_byte, 0xFF), rest::binary>>

      :error =
        Salchicha.xchacha20_poly1305_decrypt_detached(cipher_text, nonce, key, aad <> "!", tag)

      :error =
        Salchicha.xchacha20_poly1305_decrypt_detached(cipher_text, nonce, key, aad, altered_tag)
    end

    test "IETF ChaCha20 encryption test vector #1" do
      # https://datatracker.ietf.org/doc/html/rfc7539#appendix-A.2
      key = zeros(32)
      nonce = zeros(12)
      initial_block_count = 0
      plain_text = zeros(64)

      expected =
        <<118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189, 210, 25,
          184, 160, 141, 237, 26, 168, 54, 239, 204, 139, 119, 13, 199, 218, 65, 89, 124, 81, 87,
          72, 141, 119, 36, 224, 63, 184, 216, 74, 55, 106, 67, 184, 244, 21, 24, 161, 28, 195,
          135, 182, 105, 178, 238, 101, 134>>

      result = Chacha.chacha20_xor(plain_text, nonce, key, initial_block_count)
      assert IO.iodata_to_binary(result) == expected
    end

    test "IETF ChaCha20 encryption test vector #2" do
      # https://datatracker.ietf.org/doc/html/rfc7539#appendix-A.2
      key = <<1::unit(8)-size(32)>>
      nonce = <<2::unit(8)-size(12)>>
      initial_block_count = 1

      plain_text =
        "Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to"

      expected =
        <<163, 251, 240, 125, 243, 250, 47, 222, 79, 55, 108, 162, 62, 130, 115, 112, 65, 96, 93,
          159, 79, 79, 87, 189, 140, 255, 44, 29, 75, 121, 85, 236, 42, 151, 148, 139, 211, 114,
          41, 21, 200, 243, 211, 55, 247, 211, 112, 5, 14, 158, 150, 214, 71, 183, 195, 159, 86,
          224, 49, 202, 94, 182, 37, 13, 64, 66, 224, 39, 133, 236, 236, 250, 75, 75, 181, 232,
          234, 208, 68, 14, 32, 182, 232, 219, 9, 216, 129, 167, 198, 19, 47, 66, 14, 82, 121, 80,
          66, 189, 250, 119, 115, 216, 169, 5, 20, 71, 179, 41, 28, 225, 65, 28, 104, 4, 101, 85,
          42, 166, 196, 5, 183, 118, 77, 94, 135, 190, 168, 90, 208, 15, 132, 73, 237, 143, 114,
          208, 214, 98, 171, 5, 38, 145, 202, 102, 66, 75, 200, 109, 45, 248, 14, 164, 31, 67,
          171, 249, 55, 211, 37, 157, 196, 178, 208, 223, 180, 138, 108, 145, 57, 221, 215, 247,
          105, 102, 233, 40, 230, 53, 85, 59, 167, 108, 92, 135, 157, 123, 53, 212, 158, 178, 230,
          43, 8, 113, 205, 172, 99, 137, 57, 226, 94, 138, 30, 14, 249, 213, 40, 15, 168, 202, 50,
          139, 53, 28, 60, 118, 89, 137, 203, 207, 61, 170, 139, 108, 204, 58, 175, 159, 57, 121,
          201, 43, 55, 32, 252, 136, 220, 149, 237, 132, 161, 190, 5, 156, 100, 153, 185, 253,
          162, 54, 231, 232, 24, 176, 75, 11, 195, 156, 30, 135, 107, 25, 59, 254, 85, 105, 117,
          63, 136, 18, 140, 192, 138, 170, 155, 99, 209, 161, 111, 128, 239, 37, 84, 215, 24, 156,
          65, 31, 88, 105, 202, 82, 197, 184, 63, 163, 111, 242, 22, 185, 193, 211, 0, 98, 190,
          188, 253, 45, 197, 188, 224, 145, 25, 52, 253, 167, 154, 134, 246, 230, 152, 206, 215,
          89, 195, 255, 155, 100, 119, 51, 143, 61, 164, 249, 205, 133, 20, 234, 153, 130, 204,
          175, 179, 65, 178, 56, 77, 217, 2, 243, 209, 171, 122, 198, 29, 210, 156, 111, 33, 186,
          91, 134, 47, 55, 48, 227, 124, 253, 196, 253, 128, 108, 34, 242, 33>>

      result = Chacha.chacha20_xor(plain_text, nonce, key, initial_block_count)
      assert IO.iodata_to_binary(result) == expected
    end

    test "pure returns the same values as nif functions", %{
      key: key,
      nonce: nonce,
      aad: aad,
      plaintext: plaintext
    } do
      {cipher_text_pure, tag_pure} =
        Chacha.xchacha20_poly1305_encrypt_pure(plaintext, nonce, key, aad)

      {cipher_text_nif, tag_nif} = Chacha.xchacha20_poly1305_encrypt(plaintext, nonce, key, aad)

      assert IO.iodata_to_binary(cipher_text_pure) == cipher_text_nif
      assert tag_pure == tag_nif

      plaintext_pure =
        Chacha.xchacha20_poly1305_decrypt_pure(cipher_text_nif, nonce, key, aad, tag_nif)
        |> IO.iodata_to_binary()

      plaintext_nif = Chacha.xchacha20_poly1305_decrypt(cipher_text_nif, nonce, key, aad, tag_nif)

      assert plaintext_pure == plaintext_nif

      twelve_byte_nonce = <<0, 0, 0, 0>> <> binary_part(nonce, 16, 8)

      chacha20_xor_nif =
        :crypto.crypto_one_time(
          :chacha20,
          key,
          <<_block_count = 0::little-32>> <> twelve_byte_nonce,
          plaintext,
          true
        )

      chacha20_xor_pure =
        Chacha.chacha20_xor(plaintext, twelve_byte_nonce, key) |> IO.iodata_to_binary()

      assert chacha20_xor_pure == chacha20_xor_nif
    end
  end

  describe "Salsa" do
    test "encryption and decryption", %{key: key, nonce: nonce} do
      plain_text = "Hello, World!"

      cipher_message = Salchicha.secretbox(plain_text, nonce, key)
      message = Salchicha.secretbox_open(cipher_message, nonce, key)
      ^plain_text = IO.iodata_to_binary(message)
    end

    test "decryption fails with altered input", %{key: key, nonce: nonce} do
      plain_text = "Hello, World!"

      cipher_text = Salchicha.secretbox(plain_text, nonce, key)
      <<first_byte, rest::binary>> = IO.iodata_to_binary(cipher_text)
      altered_cipher_text = <<Bitwise.bxor(first_byte, 0xFF), rest::binary>>

      :error = Salchicha.secretbox_open(altered_cipher_text, nonce, key)
    end
  end
end
