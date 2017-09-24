package eu.artemisc.stodium.codecs;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Singleton;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class Codec {

    private static final @NotNull Singleton<Codec> HEX = new Singleton<Codec>() {
        @NotNull
        @Override
        protected Codec initialize() {
            return new Hex();
        }
    };

    private static final @NotNull Singleton<Codec> BASE64_ORIG = new Singleton<Codec>() {
        @NotNull
        @Override
        protected Codec initialize() {
            return new Base64(StodiumJNI.sodium_base64_variant_original());
        }
    };

    private static final @NotNull Singleton<Codec> BASE64_ORIG_NOPAD = new Singleton<Codec>() {
        @NotNull
        @Override
        protected Codec initialize() {
            return new Base64(StodiumJNI.sodium_base64_variant_original_no_padding());
        }
    };

    private static final @NotNull Singleton<Codec> BASE64_URL = new Singleton<Codec>() {
        @NotNull
        @Override
        protected Codec initialize() {
            return new Base64(StodiumJNI.sodium_base64_variant_urlsafe());
        }
    };

    private static final @NotNull Singleton<Codec> BASE64_URL_NOPAD = new Singleton<Codec>() {
        @NotNull
        @Override
        protected Codec initialize() {
            return new Base64(StodiumJNI.sodium_base64_variant_urlsafe_no_padding());
        }
    };

    @NotNull
    public static Codec hex() {
        return HEX.get();
    }

    @NotNull
    public static Codec base64Original() {
        return BASE64_ORIG.get();
    }

    @NotNull
    public static Codec base64OriginalNoPadding() {
        return BASE64_ORIG_NOPAD.get();
    }

    @NotNull
    public static Codec base64UrlSafe() {
        return BASE64_URL.get();
    }

    @NotNull
    public static Codec base64UrlSafeNoPadding() {
        return BASE64_URL_NOPAD.get();
    }

    /**
     *
     * @param input
     * @return
     */
    public abstract int encodedLength(final int input);

    /**
     *
     * @param dst
     * @param src
     * @throws StodiumException
     */
    public abstract void encode(final @NotNull ByteBuffer dst,
                                final @NotNull ByteBuffer src)
            throws StodiumException;

    /**
     *
     * @param src
     * @return
     * @throws StodiumException
     */
    @NotNull
    public final String encode(final @NotNull ByteBuffer src)
            throws StodiumException {
        final byte[] dst;
        dst = new byte[encodedLength(src.remaining())];
        encode(ByteBuffer.wrap(dst), src);
        return new String(dst);
    }

    /**
     *
     * @param dst
     * @param src
     * @throws StodiumException
     */
    public abstract void decode(final @NotNull ByteBuffer dst,
                                final @NotNull ByteBuffer src)
            throws StodiumException;

    /**
     *
     * @param dst
     * @param src
     * @throws StodiumException
     */
    public final void decode(final @NotNull ByteBuffer dst,
                             final @NotNull String     src)
            throws StodiumException {
        decode(dst, ByteBuffer.wrap(src.getBytes()));
    }
}
