package eu.artemisc.stodium;

import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

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
    public static final int SALTBYTES = Sodium.crypto_pwhash_scryptsalsa208sha256_saltbytes();

    public static final int STRBYTES = Sodium.crypto_pwhash_scryptsalsa208sha256_strbytes();
    public static final String STRPREFIX = Sodium.crypto_pwhash_scryptsalsa208sha256_strprefix();

    public static final int OPSLIMIT_INTERACTIVE = Sodium.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive();
    public static final int MEMLIMIT_INTERACTIVE = Sodium.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive();
    public static final int OPSLIMIT_SENSITIVE = Sodium.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive();
    public static final int MEMLIMIT_SENSITIVE = Sodium.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive();

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
