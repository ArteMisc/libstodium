package eu.artemisc.stodium;

import android.support.annotation.NonNull;

import java.nio.ByteBuffer;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class Argon2i {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private Argon2i() {}

    // constants

//  public static final String PRIMITIVE            = StodiumJNI.crypto_pwhash_primitive();
//  public static final String STRPREFIX            = StodiumJNI.crypto_pwhash_strprefix();
    public static final int    STRBYTES             = StodiumJNI.crypto_pwhash_strbytes();
    public static final int    SALTBYTES            = 16;//StodiumJNI.crypto_pwhash_saltbytes();
    public static final int    OPSLIMIT_INTERACTIVE = StodiumJNI.crypto_pwhash_opslimit_interactive();
    public static final int    MEMLIMIT_INTERACTIVE = StodiumJNI.crypto_pwhash_memlimit_interactive();
    public static final int    OPSLIMIT_MODERATE    = StodiumJNI.crypto_pwhash_opslimit_moderate();
    public static final int    MEMLIMIT_MODERATE    = StodiumJNI.crypto_pwhash_memlimit_moderate();
    public static final int    OPSLIMIT_SENSITIVE   = StodiumJNI.crypto_pwhash_opslimit_sensitive();
    public static final int    MEMLIMIT_SENSITIVE   = StodiumJNI.crypto_pwhash_memlimit_sensitive();

    // wrappers

    //
    // Key derivation API
    //

    /**
     * pwhashArgon2i with default (INTERACTIVE) memlimit and opslimit. Equivalent
     * to calling {@link #pwhashArgon2i(ByteBuffer, ByteBuffer, ByteBuffer, int, int)}
     * with {@code opslimit = OPSLIMIT_INTERACTIVE} and {@code memlimit =
     * MEMLIMIT_INTERACTIVE}.
     *
     * @param dstKey
     * @param srcPwd
     * @param srcSalt
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void pwhashArgon2i(@NonNull final ByteBuffer dstKey,
                                     @NonNull final ByteBuffer srcPwd,
                                     @NonNull final ByteBuffer srcSalt)
            throws StodiumException {
        pwhashArgon2i(dstKey, srcPwd, srcSalt, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);
    }

    /**
     *
     * @param dstKey
     * @param srcPwd
     * @param srcSalt
     * @param opsLimit
     * @param memLimit
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void pwhashArgon2i(@NonNull final ByteBuffer dstKey,
                                     @NonNull final ByteBuffer srcPwd,
                                     @NonNull final ByteBuffer srcSalt,
                                              final int        opsLimit,
                                              final int        memLimit)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstKey, "Stodium.Argon2i#pwhashScrypt(dstKey)");

        Stodium.checkSize(srcSalt.remaining(), SALTBYTES, "Argon2i.SALTBYTES");
        Stodium.checkPow2(memLimit,                       "Argon2i.pwhashArgon2i(memLimit)");

        Stodium.checkStatus(StodiumJNI.crypto_pwhash(
                Stodium.ensureUsableByteBuffer(dstKey),
                Stodium.ensureUsableByteBuffer(srcPwd),
                Stodium.ensureUsableByteBuffer(srcSalt),
                opsLimit, memLimit));
    }

    //
    // TODO: 26-6-16 String based API
    //
}
