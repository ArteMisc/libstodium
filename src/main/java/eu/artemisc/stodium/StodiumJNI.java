package eu.artemisc.stodium;

import java.nio.ByteBuffer;

/**
 * StodiumJNI implements the java definitions of native methods for wrappers
 * around Libsodium functions.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class StodiumJNI {
    //
    // Library methods
    //
    static native int stodium_init();
    static native int sodium_init();

    //
    // Utility methods
    //
    static native int randombytes_random();
    static native int randombytes_uniform(int upper_bound);
    static native void randombytes_buf(ByteBuffer dst);

    //
    // Core
    //
    static native int crypto_core_hsalsa20_outputbytes();
    static native int crypto_core_hsalsa20_inputbytes();
    static native int crypto_core_hsalsa20_keybytes();
    static native int crypto_core_hsalsa20_constbytes();
    static native int crypto_core_hsalsa20(
            ByteBuffer dst, ByteBuffer src, ByteBuffer key, ByteBuffer constant);

    //
    // AEAD
    //
    static native int crypto_aead_chacha20poly1305_keybytes();
    static native int crypto_aead_chacha20poly1305_nsecbytes();
    static native int crypto_aead_chacha20poly1305_npubbytes();
    static native int crypto_aead_chacha20poly1305_abytes();

    static native int crypto_aead_chacha20poly1305_encrypt_detached(
            ByteBuffer dstCipher, ByteBuffer srcPlain, ByteBuffer ad, ByteBuffer nonce, ByteBuffer key);
    static native int crypto_aead_chacha20poly1305_decrypt_detached(
            ByteBuffer dstPlain, ByteBuffer srcCipher, ByteBuffer ad, ByteBuffer nonce, ByteBuffer key);

    static native int crypto_aead_xchacha20poly1305_encrypt_detached(
            ByteBuffer dstCipher, ByteBuffer srcPlain, ByteBuffer ad, ByteBuffer nonce, ByteBuffer key);
    static native int crypto_aead_xchacha20poly1305_decrypt_detached(
            ByteBuffer dstPlain, ByteBuffer srcCipher, ByteBuffer ad, ByteBuffer nonce, ByteBuffer key);

    static native int crypto_aead_xsalsa20poly1305_encrypt_detached(
            ByteBuffer dstCipher, ByteBuffer srcPlain, ByteBuffer ad, ByteBuffer nonce, ByteBuffer key);
    static native int crypto_aead_xsalsa20poly1305_decrypt_detached(
            ByteBuffer dstPlain, ByteBuffer srcCipher, ByteBuffer ad, ByteBuffer nonce, ByteBuffer key);

    //
    // ScalarMult
    //
    static native String crypto_scalarmult_primitive();

    static native int crypto_scalarmult_curve25519_bytes();
    static native int crypto_scalarmult_curve25519_scalarbytes();
    static native int crypto_scalarmult_curve25519(
            ByteBuffer dst, ByteBuffer src, ByteBuffer elm);
    static native int crypto_scalarmult_curve25519_base(
            ByteBuffer dst, ByteBuffer src);
}
