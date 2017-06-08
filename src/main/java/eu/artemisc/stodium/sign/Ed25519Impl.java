package eu.artemisc.stodium.sign;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
final class Ed25519Impl
        extends Sign
        implements MultipartSign.Spec {

    Ed25519Impl() {
        super(StodiumJNI.crypto_sign_ed25519_publickeybytes(),
                StodiumJNI.crypto_sign_ed25519_secretkeybytes(),
                StodiumJNI.crypto_sign_ed25519_bytes(),
                StodiumJNI.crypto_sign_ed25519_seedbytes(),
                StodiumJNI.crypto_sign_ed25519ph_statebytes());
    }

    @Override
    public void keypair(final @NotNull ByteBuffer dstPub,
                        final @NotNull ByteBuffer dstPriv)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstPub);
        Stodium.checkDestinationWritable(dstPriv);

        Stodium.checkSizeMin(dstPub.remaining(), PUBLICKEYBYTES);
        Stodium.checkSize(dstPriv.remaining(), SECRETKEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_sign_ed25519_keypair(
                Stodium.ensureUsableByteBuffer(dstPub),
                Stodium.ensureUsableByteBuffer(dstPriv)));
    }

    @Override
    public void keypair(final @NotNull ByteBuffer dstPub,
                        final @NotNull ByteBuffer dstPriv,
                        final @NotNull ByteBuffer seed)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstPub);
        Stodium.checkDestinationWritable(dstPriv);

        Stodium.checkSizeMin(dstPub.remaining(), PUBLICKEYBYTES);
        Stodium.checkSize(dstPriv.remaining(), SECRETKEYBYTES);
        Stodium.checkSize(seed.remaining(), SEEDBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_sign_ed25519_seed_keypair(
                Stodium.ensureUsableByteBuffer(dstPub),
                Stodium.ensureUsableByteBuffer(dstPriv),
                Stodium.ensureUsableByteBuffer(seed)));
    }

    @Override
    public void sign(final @NotNull ByteBuffer dstSigned,
                     final @NotNull ByteBuffer srcMsg,
                     final @NotNull ByteBuffer priv)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstSigned);

        Stodium.checkSizeMin(dstSigned.remaining(), srcMsg.remaining() + BYTES);
        Stodium.checkSize(priv.remaining(), SECRETKEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_sign_ed25519(
                Stodium.ensureUsableByteBuffer(dstSigned),
                Stodium.ensureUsableByteBuffer(srcMsg),
                Stodium.ensureUsableByteBuffer(priv)));
    }

    @Override
    public boolean open(final @NotNull ByteBuffer dstMsg,
                        final @NotNull ByteBuffer srcSigned,
                        final @NotNull ByteBuffer priv)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstMsg);

        Stodium.checkSizeMin(srcSigned.remaining(), dstMsg.remaining() + BYTES);
        Stodium.checkSize(priv.remaining(), SECRETKEYBYTES);

        return StodiumJNI.NOERR == StodiumJNI.crypto_sign_ed25519_open(
                Stodium.ensureUsableByteBuffer(dstMsg),
                Stodium.ensureUsableByteBuffer(srcSigned),
                Stodium.ensureUsableByteBuffer(priv));
    }

    @Override
    public void signDetached(final @NotNull ByteBuffer dstSig,
                             final @NotNull ByteBuffer srcMsg,
                             final @NotNull ByteBuffer priv)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstSig);

        Stodium.checkSizeMin(dstSig.remaining(), BYTES);
        Stodium.checkSize(priv.remaining(), SECRETKEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_sign_ed25519_detached(
                Stodium.ensureUsableByteBuffer(dstSig),
                Stodium.ensureUsableByteBuffer(srcMsg),
                Stodium.ensureUsableByteBuffer(priv)));
    }

    @Override
    public boolean verifyDetached(final @NotNull ByteBuffer srcSig,
                                  final @NotNull ByteBuffer srcMsg,
                                  final @NotNull ByteBuffer priv)
            throws StodiumException {
        Stodium.checkSizeMin(srcSig.remaining(), BYTES);
        Stodium.checkSize(priv.remaining(), SECRETKEYBYTES);

        return StodiumJNI.NOERR == StodiumJNI.crypto_sign_ed25519_verify_detached(
                Stodium.ensureUsableByteBuffer(srcSig),
                Stodium.ensureUsableByteBuffer(srcMsg),
                Stodium.ensureUsableByteBuffer(priv));
    }

    @NotNull
    @Override
    public MultipartSign init()
            throws StodiumException {
        final ByteBuffer state;

        state = ByteBuffer.allocateDirect(STATEBYTES);
        Stodium.checkStatus(StodiumJNI.crypto_sign_ed25519ph_init(state));

        return new MultipartSign(this, state);
    }

    @Override
    public void update(final @NotNull ByteBuffer state,
                       final @NotNull ByteBuffer in)
            throws StodiumException {
        Stodium.checkDestinationWritable(state);

        Stodium.checkSize(state.remaining(), STATEBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_sign_ed25519ph_update(
                Stodium.ensureUsableByteBuffer(state),
                Stodium.ensureUsableByteBuffer(in)));
    }

    @Override
    public void doFinal(final @NotNull ByteBuffer state,
                        final @NotNull ByteBuffer dst,
                        final @NotNull ByteBuffer priv)
            throws StodiumException {
        Stodium.checkDestinationWritable(state);
        Stodium.checkDestinationWritable(dst);

        Stodium.checkSizeMin(dst.remaining(), BYTES);
        Stodium.checkSize(state.remaining(), STATEBYTES);
        Stodium.checkSize(priv.remaining(), SECRETKEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_sign_ed25519ph_final_create(
                Stodium.ensureUsableByteBuffer(state),
                Stodium.ensureUsableByteBuffer(dst),
                Stodium.ensureUsableByteBuffer(priv)));
    }

    @Override
    public boolean doFinalVerify(final @NotNull ByteBuffer state,
                                 final @NotNull ByteBuffer sig,
                                 final @NotNull ByteBuffer priv)
            throws StodiumException {
        Stodium.checkDestinationWritable(state);

        Stodium.checkSizeMin(sig.remaining(), BYTES);
        Stodium.checkSize(state.remaining(), STATEBYTES);
        Stodium.checkSize(priv.remaining(), SECRETKEYBYTES);

        return StodiumJNI.NOERR == StodiumJNI.crypto_sign_ed25519ph_final_verify(
                Stodium.ensureUsableByteBuffer(state),
                Stodium.ensureUsableByteBuffer(sig),
                Stodium.ensureUsableByteBuffer(priv));
    }
}
