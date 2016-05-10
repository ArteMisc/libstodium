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
    // randombyte() etc...

    //
    // Core
    //
    static native int crypto_core_hsalsa20_outputbytes();
    static native int crypto_core_hsalsa20_inputbytes();
    static native int crypto_core_hsalsa20_keybytes();
    static native int crypto_core_hsalsa20_constbytes();
    static native int crypto_core_hsalsa20(
            ByteBuffer dst, ByteBuffer src, ByteBuffer key, ByteBuffer constant);
}
