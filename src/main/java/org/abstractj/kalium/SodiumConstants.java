package org.abstractj.kalium;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class SodiumConstants {
    /*
     * secretbox_xsalsa20poly1305_* constants
     */
    public static final int secretbox_xsalsa20poly1305_KEYBYTES = 32;
    public static final int secretbox_xsalsa20poly1305_MACBYTES = 16;
    public static final int secretbox_xsalsa20poly1305_NONCEBYTES = 24;

    /*
     * secretbox_default_* constants
     */
    public static final int secretbox_KEYBYTES = secretbox_xsalsa20poly1305_KEYBYTES;
    public static final int secretbox_MACBYTES = secretbox_xsalsa20poly1305_MACBYTES;
    public static final int secretbox_NONCEBYTES = secretbox_xsalsa20poly1305_NONCEBYTES;


    // Robosodium leftovers, will probably be removed later
    public static final int SHA256BYTES = 32;
    public static final int SHA512BYTES = 64;
    public static final int BLAKE2B_OUTBYTES = 64;
    public static final int PUBLICKEY_BYTES = 32;
    public static final int SECRETKEY_BYTES = 32;
    public static final int NONCE_BYTES = 24;
    public static final int ZERO_BYTES = 32;
    public static final int BOXZERO_BYTES = 16;
    public static final int SCALAR_BYTES = 32;
    public static final int XSALSA20_POLY1305_SECRETBOX_KEYBYTES = 32;
    public static final int XSALSA20_POLY1305_SECRETBOX_NONCEBYTES = 24;
    public static final int OPSLIMIT_INTERACTIVE = 524288;
    public static final int MEMLIMIT_INTERACTIVE = 16777216;
    public static final int OPSLIMIT_SENSITIVE = 33554432;
    public static final int MEMLIMIT_SENSITIVE = 1073741824;
    public static final int SIGNATURE_BYTES = 64;
    public static final int AEAD_CHACHA20_POLY1305_KEYBYTES = 32;
    public static final int AEAD_CHACHA20_POLY1305_NPUBBYTES = 8;
    public static final int AEAD_CHACHA20_POLY1305_ABYTES = 8;
}
