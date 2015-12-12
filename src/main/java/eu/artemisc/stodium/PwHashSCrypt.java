package eu.artemisc.stodium;

import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

import eu.artemisc.stodium.Stodium;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class PwHashSCrypt {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private PwHashSCrypt() {}

    // constants
    public static final int SALTBYTES = 32;

    public static final int STRBYTES = 102;
    public static final String STRPREFIX = "$7$";

    public static final int OPSLIMIT_INTERACTIVE = 524288;
    public static final int MEMLIMIT_INTERACTIVE = 16777216;
    public static final int OPSLIMIT_SENSITIVE = 33554432;
    public static final int MEMLIMIT_SENSITIVE = 1073741824;

    // wrappers

    //
    // Key derivation API
    //

    /**
     * pwhashScrypt with default (INTERACTIVE) memlimit and opslimit. Equivalent
     * to calling {@link #pwhashScrypt(byte[], byte[], byte[], int, int)} with
     * {@code opslimit = OPSLIMIT_INTERACTIVE} and {@code memlimit =
     * MEMLIMIT_INTERACTIVE}.
     *
     * @param dstKey
     * @param srcPwd
     * @param srcSalt
     * @throws SecurityException
     */
    public static void pwhashScrypt(@NonNull final byte[] dstKey,
                                    @NonNull final byte[] srcPwd,
                                    @NonNull final byte[] srcSalt)
            throws SecurityException {
        pwhashScrypt(dstKey, srcPwd, srcSalt, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);
    }
    /**
     *
     * @param dstKey
     * @param srcPwd
     * @param srcSalt
     * @param opsLimit
     * @param memLimit
     * @throws SecurityException
     */
    public static void pwhashScrypt(@NonNull final byte[] dstKey,
                                    @NonNull final byte[] srcPwd,
                                    @NonNull final byte[] srcSalt,
                                    final int opsLimit,
                                    final int memLimit)
            throws SecurityException {
        Stodium.checkSize(srcSalt.length, SALTBYTES, "PwHashSCrypt.SALTBYTES");
        Stodium.checkPow2(memLimit, "PwHashSCrypt.pwhashScrypt(memLimit)");
        Stodium.checkStatus(Sodium.crypto_pwhash_scryptsalsa208sha256(
                dstKey, dstKey.length, srcPwd, srcPwd.length, srcSalt,
                opsLimit, memLimit));
    }

    //
    // String based API
    //

    public static void pwhashScryptStr() {}

    public static boolean pwhashScryptStrVerify() {
        return false;
    }
}
