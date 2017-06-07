package eu.artemisc.stodium.pwhash;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
final class Scrypt
        extends PwHash {

    Scrypt() {
        super(StodiumJNI.crypto_pwhash_scryptsalsa208sha256_bytes_min(),
                StodiumJNI.crypto_pwhash_scryptsalsa208sha256_bytes_max(),
                StodiumJNI.crypto_pwhash_scryptsalsa208sha256_passwd_min(),
                StodiumJNI.crypto_pwhash_scryptsalsa208sha256_passwd_max(),
                StodiumJNI.crypto_pwhash_scryptsalsa208sha256_saltbytes(),
                StodiumJNI.crypto_pwhash_scryptsalsa208sha256_strbytes(),
                StodiumJNI.crypto_pwhash_scryptsalsa208sha256_strprefix(),
                StodiumJNI.crypto_pwhash_scryptsalsa208sha256_opslimit_min(),
                StodiumJNI.crypto_pwhash_scryptsalsa208sha256_opslimit_max(),
                StodiumJNI.crypto_pwhash_scryptsalsa208sha256_memlimit_min(),
                StodiumJNI.crypto_pwhash_scryptsalsa208sha256_memlimit_max(),
                StodiumJNI.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive(),
                StodiumJNI.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive(),
                StodiumJNI.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive(),
                StodiumJNI.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive(),
                StodiumJNI.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive(),
                StodiumJNI.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive());
    }

    @Override
    public void hash(final @NotNull ByteBuffer dstKey,
                     final @NotNull ByteBuffer srcPw,
                     final @NotNull ByteBuffer srcSalt,
                     final          long       opsLimit,
                     final          long       memLimit)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstKey);

        Stodium.checkSize(dstKey.remaining(), BYTES_MIN, BYTES_MAX);
        Stodium.checkSize(srcPw.remaining(), PASSWD_MIN, PASSWD_MAX);
        Stodium.checkSize(srcSalt.remaining(), SALTBYTES);
        Stodium.checkPow2(memLimit);
        Stodium.checkSize(memLimit, MEMLIMIT_MIN, MEMLIMIT_MAX);
        Stodium.checkSize(opsLimit, OPSLIMIT_MIN, OPSLIMIT_MAX);

        Stodium.checkStatus(StodiumJNI.crypto_pwhash_scryptsalsa208sha256(
                Stodium.ensureUsableByteBuffer(dstKey),
                Stodium.ensureUsableByteBuffer(srcPw),
                Stodium.ensureUsableByteBuffer(srcSalt),
                opsLimit, memLimit));
    }

    @Override
    public void strHash(final @NotNull ByteBuffer dstString,
                        final @NotNull ByteBuffer srcPw,
                        final          long       opsLimit,
                        final          long       memLimit)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstString);

        Stodium.checkSize(dstString.remaining(), STRBYTES);
        Stodium.checkSize(srcPw.remaining(), PASSWD_MIN, PASSWD_MAX);
        Stodium.checkPow2(memLimit);
        Stodium.checkSize(memLimit, MEMLIMIT_MIN, MEMLIMIT_MAX);
        Stodium.checkSize(opsLimit, OPSLIMIT_MIN, OPSLIMIT_MAX);

        Stodium.checkStatus(StodiumJNI.crypto_pwhash_scryptsalsa208sha256_str(
                Stodium.ensureUsableByteBuffer(dstString),
                Stodium.ensureUsableByteBuffer(srcPw),
                opsLimit, memLimit));
    }

    @Override
    public boolean strVerify(final @NotNull ByteBuffer str,
                             final @NotNull ByteBuffer pw)
            throws StodiumException {
        Stodium.checkSize(str.remaining(), STRBYTES);
        Stodium.checkSize(pw.remaining(), PASSWD_MIN, PASSWD_MAX);

        // FIXME: 7-6-17 determine whether this is a missmatch or the OS refusing to alloc memory
        return StodiumJNI.NOERR == StodiumJNI.crypto_pwhash_scryptsalsa208sha256_str_verify(
                Stodium.ensureUsableByteBuffer(str),
                Stodium.ensureUsableByteBuffer(pw));
    }
}
