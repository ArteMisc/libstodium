package eu.artemisc.stodium.aead;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Singleton;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class AEAD {

    private static final @NotNull Singleton<AEAD> AES = new Singleton<AEAD>() {
        @NotNull
        @Override
        protected AEAD initialize() {
            return new Aes256Gcm();
        }
    };

    private static final @NotNull Singleton<AEAD> CHACHA = new Singleton<AEAD>() {
        @NotNull
        @Override
        protected AEAD initialize() {
            return new Chacha20Poly1305();
        }
    };

    private static final @NotNull Singleton<AEAD> CHACHA_IETF = new Singleton<AEAD>() {
        @NotNull
        @Override
        protected AEAD initialize() {
            return new Chacha20Poly1305Ietf();
        }
    };

    private static final @NotNull Singleton<AEAD> XCHACHA_IETF = new Singleton<AEAD>() {
        @NotNull
        @Override
        protected AEAD initialize() {
            return new XChacha20Poly1305Ietf();
        }
    };

    @NotNull
    public static AEAD instance() {
        return chachaInstance();
    }

    @Nullable
    public static AEAD aesInstance() {
        return Aes256Gcm.isAvailable() ? AES.get() : null;
    }

    @NotNull
    public static AEAD chachaInstance() {
        return CHACHA.get();
    }

    @NotNull
    public static AEAD chachaIetfInstance() {
        return CHACHA_IETF.get();
    }

    @NotNull
    public static AEAD xchachaIetfInstance() {
        return XCHACHA_IETF.get();
    }

    // constants
    final int KEYBYTES;
    final int NSECBYTES;
    final int NPUBBYTES;
    final int ABYTES;

    /**
     *
     * @param key
     * @param nsec
     * @param npub
     * @param a
     */
    AEAD(final int key,
         final int nsec,
         final int npub,
         final int a) {
        KEYBYTES  = key;
        NSECBYTES = nsec;
        NPUBBYTES = npub;
        ABYTES    = a;
    }

    /**
     *
     * @return
     */
    public final int keyBytes() {
        return KEYBYTES;
    }

    /**
     *
     * @return
     */
    public final int nsecBytes() {
        return NSECBYTES;
    }

    /**
     *
     * @return
     */
    public final int npubBytes() {
        return NPUBBYTES;
    }

    /**
     *
     * @return
     */
    public final int aBytes() {
        return ABYTES;
    }

    /**
     *
     * @param dstCipher
     * @param dstMac
     * @param srcPlain
     * @param ad
     * @param nonce
     * @param key
     * @throws StodiumException
     */
    public abstract void encryptDetached(final @NotNull ByteBuffer dstCipher,
                                         final @NotNull ByteBuffer dstMac,
                                         final @NotNull ByteBuffer srcPlain,
                                         final @NotNull ByteBuffer ad,
                                         final @NotNull ByteBuffer nonce,
                                         final @NotNull ByteBuffer key)
            throws StodiumException;

    /**
     *
     * @param dstCipher
     * @param srcPlain
     * @param ad
     * @param nonce
     * @param key
     * @throws StodiumException
     */
    public abstract void encrypt(final @NotNull ByteBuffer dstCipher,
                                 final @NotNull ByteBuffer srcPlain,
                                 final @NotNull ByteBuffer ad,
                                 final @NotNull ByteBuffer nonce,
                                 final @NotNull ByteBuffer key)
            throws StodiumException;

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param srcMac
     * @param ad
     * @param nonce
     * @param key
     * @return
     * @throws StodiumException
     */
    public abstract boolean decryptDetached(final @NotNull ByteBuffer dstPlain,
                                            final @NotNull ByteBuffer srcCipher,
                                            final @NotNull ByteBuffer srcMac,
                                            final @NotNull ByteBuffer ad,
                                            final @NotNull ByteBuffer nonce,
                                            final @NotNull ByteBuffer key)
            throws StodiumException;

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param ad
     * @param nonce
     * @param key
     * @return
     * @throws StodiumException
     */
    public abstract boolean decrypt(final @NotNull ByteBuffer dstPlain,
                                    final @NotNull ByteBuffer srcCipher,
                                    final @NotNull ByteBuffer ad,
                                    final @NotNull ByteBuffer nonce,
                                    final @NotNull ByteBuffer key)
            throws StodiumException;
}
