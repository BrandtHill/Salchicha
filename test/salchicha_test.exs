defmodule SalchichaTest do
  use ExUnit.Case

  setup do
    key = Salchicha.generate_secret_key()
    nonce = Salchicha.generate_nonce()
    aad = "dnarberyf"

    %{
      key: key,
      nonce: nonce,
      aad: aad
    }
  end

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
