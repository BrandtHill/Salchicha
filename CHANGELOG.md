# Changelog

## v0.4.0 (2025-03-12)
  * Add Changelog
  * Add NaCl public-key encryption via X25519 ECDH
    * `Salchicha.box/4`
    * `Salchicha.box_open/4`
    * `Salchicha.generate_box_keypair/0`
    * `Salchicha.compute_shared_secret/2`
  * Add NaCl public-key message signing via Ed25519 EdDSA
    * `Salchicha.sign/2`
    * `Salchicha.signature_valid?/3`
    * `Salchicha.generate_sign_keypair/0`
  * Add examples of public key crypto usage

## v0.3.0 (2025-03-07)
  * Improve docs
    * Add examples for XSalsa20/XChaCha20 encryption/decryption
    * Add additional type docs
    * Change references of "block count" to "block counter" for clarity
    * Fix typos
  * Internal function `Salchicha.Salsa.xsalsa20_poly1305_decrypt/4` takes `cipher_text` and `tag` as arguments instead of combined message. `Salchicha.secretbox_open/3` remains unchanged.
  * Expose Salsa20 Poly1305 functions
    * `Salchicha.Salsa.salsa20_poly1305_encrypt/3`
    * `Salchicha.Salsa.salsa20_poly1305_decrypt/4`

## v0.2.0 (2025-03-06)
  * Improve docs and typespecs
  * Add pure elixir implementations of ChaCha20/XChaCha20 Poly1305 functions in `Salchicha.Chacha`
    * `Salchicha.Chacha.chacha20_poly1305_encrypt_pure/4`
    * `Salchicha.Chacha.chacha20_poly1305_decrypt_pure/5`
    * `Salchicha.Chacha.xchacha20_poly1305_encrypt_pure/4`
    * `Salchicha.Chacha.xchacha20_poly1305_decrypt_pure/5`
    * Add `Salchicha.Chacha.chacha20_xor/4` stream cipher primitive
  * Internal `Salchicha.Salsa` improvements
    * Verify MAC before decrypting remaining ciphertext

## v0.1.0 (2025-02-19)
  * Initial release
  * Support XSalsa20 Poly1305
    * `Salchicha.secretbox/3`
    * `Salchicha.secretbox_open/3`
    * Internal functions and primitives in `Salchicha.Salsa`
  * Support XChaCha20 Poly1305 in combined and detached modes
    * `Salchicha.xchacha20_poly1305_encrypt/4`
    * `Salchicha.xchacha20_poly1305_decrypt/4`
    * `Salchicha.xchacha20_poly1305_encrypt_detached/4`
    * `Salchicha.xchacha20_poly1305_decrypt_detached/5`
    * Internal functions and primitives in `Salchicha.Chacha`

