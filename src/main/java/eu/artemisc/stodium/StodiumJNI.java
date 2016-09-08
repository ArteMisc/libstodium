package eu.artemisc.stodium;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.ByteBuffer;

/**
 * StodiumJNI implements the java definitions of native methods for wrappers
 *
 * around Libsodium functions.
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
            @NotNull ByteBuffer dst,
            @NotNull ByteBuffer src,
            @NotNull ByteBuffer key,
            @NotNull ByteBuffer constant);

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
    // Box
    //
    static native String crypto_box_primitive();

    static native int crypto_box_seedbytes();
    static native int crypto_box_publickeybytes();
    static native int crypto_box_secretkeybytes();
    static native int crypto_box_noncebytes();
    static native int crypto_box_macbytes();
    static native int crypto_box_beforenmbytes();
    static native int crypto_box_sealbytes();

    static native int crypto_box_keypair(
            ByteBuffer publicKey, ByteBuffer privateKey);
    static native int crypto_box_seed_keypair(
            ByteBuffer publicKey, ByteBuffer privateKey, ByteBuffer seed);

    static native int crypto_box_seal(
            ByteBuffer dstCipher, ByteBuffer srcPlain, ByteBuffer publicKey);
    static native int crypto_box_seal_open(
            ByteBuffer dstPlain, ByteBuffer srcCipher, ByteBuffer publicKey, ByteBuffer privateKey);

    //
    // GenericHash Blake2b
    //
    static native int crypto_generichash_blake2b_bytes();
    static native int crypto_generichash_blake2b_bytes_min();
    static native int crypto_generichash_blake2b_bytes_max();
    static native int crypto_generichash_blake2b_keybytes();
    static native int crypto_generichash_blake2b_keybytes_min();
    static native int crypto_generichash_blake2b_keybytes_max();
    static native int crypto_generichash_blake2b_personalbytes();
    static native int crypto_generichash_blake2b_saltbytes();
    static native int crypto_generichash_blake2b_statebytes();

    static native int crypto_generichash_blake2b(
            @NotNull  ByteBuffer dst,
            @NotNull  ByteBuffer src,
            @Nullable ByteBuffer key);

    static native int crypto_generichash_blake2b_salt_personal(
            @NotNull ByteBuffer dst,
            @NotNull ByteBuffer src,
            @NotNull ByteBuffer key,
            @NotNull ByteBuffer salt,
            @NotNull ByteBuffer personal);

    static native int crypto_generichash_blake2b_init(
            @NotNull ByteBuffer state,
            @NotNull ByteBuffer key,
                     int        outlen);
    static native int crypto_generichash_blake2b_update(
            @NotNull ByteBuffer state,
            @NotNull ByteBuffer in);
    static native int crypto_generichash_blake2b_final(
            @NotNull ByteBuffer state,
            @NotNull ByteBuffer out);

    //
    // PwHash
    //
    static native String crypto_pwhash_primitive();

    static native int crypto_pwhash_alg_default();
    static native int crypto_pwhash_saltbytes();
    static native int crypto_pwhash_strbytes();
    static native int crypto_pwhash_opslimit_interactive();
    static native int crypto_pwhash_memlimit_interactive();
    static native int crypto_pwhash_opslimit_moderate();
    static native int crypto_pwhash_memlimit_moderate();
    static native int crypto_pwhash_opslimit_sensitive();
    static native int crypto_pwhash_memlimit_sensitive();

    static native int crypto_pwhash(
            ByteBuffer dst, ByteBuffer password, ByteBuffer salt, int opslimit, int memlimit);

    //
    // PwHash Scrypt
    //
    static native int crypto_pwhash_scryptsalsa208sha256_saltbytes();
    static native int crypto_pwhash_scryptsalsa208sha256_strbytes();
    static native int crypto_pwhash_scryptsalsa208sha256_opslimit_interactive();
    static native int crypto_pwhash_scryptsalsa208sha256_memlimit_interactive();
    static native int crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive();
    static native int crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive();

    static native int crypto_pwhash_scryptsalsa208sha256(
            ByteBuffer dst, ByteBuffer password, ByteBuffer salt, int opslimit, int memlimit);

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

    //
    // SecretBox
    //
    static native String crypto_secretbox_primitive();

    static native int crypto_secretbox_keybytes();
    static native int crypto_secretbox_macbytes();
    static native int crypto_secretbox_noncebytes();
    static native int crypto_secretbox_easy(
            ByteBuffer dst, ByteBuffer src, ByteBuffer nonce, ByteBuffer key);
    static native int crypto_secretbox_open_easy(
            ByteBuffer dst, ByteBuffer src, ByteBuffer nonce, ByteBuffer key);
    static native int crypto_secretbox_detached(
            ByteBuffer dst, ByteBuffer mac, ByteBuffer src, ByteBuffer nonce, ByteBuffer key);
    static native int crypto_secretbox_open_detached(
            ByteBuffer dst, ByteBuffer src, ByteBuffer mac, ByteBuffer nonce, ByteBuffer key);
}
