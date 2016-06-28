package eu.artemisc.stodium;

import android.support.annotation.NonNull;

import java.nio.ByteBuffer;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class Scrypt {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private Scrypt() {}

    // constants
//  public static final String STRPREFIX            = StodiumJNI.crypto_pwhash_scryptsalsa208sha256_strprefix();
    public static final int    STRBYTES             = StodiumJNI.crypto_pwhash_scryptsalsa208sha256_strbytes();

    public static final int    SALTBYTES            = StodiumJNI.crypto_pwhash_scryptsalsa208sha256_saltbytes();
    public static final int    OPSLIMIT_INTERACTIVE = StodiumJNI.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive();
    public static final int    MEMLIMIT_INTERACTIVE = StodiumJNI.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive();
    public static final int    OPSLIMIT_SENSITIVE   = StodiumJNI.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive();
    public static final int    MEMLIMIT_SENSITIVE   = StodiumJNI.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive();

    // wrappers

    //
    // Key derivation API
    //

    /**
     * pwhashScrypt with default (INTERACTIVE) memlimit and opslimit. Equivalent
     * to calling {@link #pwhashScrypt(ByteBuffer, ByteBuffer, ByteBuffer, int, int)}
     * with {@code opslimit = OPSLIMIT_INTERACTIVE} and {@code memlimit =
     * MEMLIMIT_INTERACTIVE}.
     *
     * @param dstKey
     * @param srcPwd
     * @param srcSalt
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void pwhashScrypt(@NonNull final ByteBuffer dstKey,
                                    @NonNull final ByteBuffer srcPwd,
                                    @NonNull final ByteBuffer srcSalt)
            throws StodiumException {
        pwhashScrypt(dstKey, srcPwd, srcSalt, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);
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
    public static void pwhashScrypt(@NonNull final ByteBuffer dstKey,
                                    @NonNull final ByteBuffer srcPwd,
                                    @NonNull final ByteBuffer srcSalt,
                                             final int        opsLimit,
                                             final int        memLimit)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstKey, "Stodium.Scrypt#pwhashScrypt(dstKey)");

        Stodium.checkSize(srcSalt.remaining(), SALTBYTES, "SCrypt.SALTBYTES");
        Stodium.checkPow2(memLimit,                       "SCrypt.pwhashScrypt(memLimit)");

        Stodium.checkStatus(StodiumJNI.crypto_pwhash_scryptsalsa208sha256(
                Stodium.ensureUsableByteBuffer(dstKey),
                Stodium.ensureUsableByteBuffer(srcPwd),
                Stodium.ensureUsableByteBuffer(srcSalt),
                opsLimit, memLimit));
    }

    //
    // TODO: 26-6-16 String based API
    //
}
