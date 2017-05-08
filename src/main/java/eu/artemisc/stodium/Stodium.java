/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium;

import org.abstractj.kalium.Sodium;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Locale;

import eu.artemisc.stodium.exceptions.ConstraintViolationException;
import eu.artemisc.stodium.exceptions.OperationFailedException;
import eu.artemisc.stodium.exceptions.ReadOnlyBufferException;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * Stodium is an abstract class with static methods. It is an attempt to
 * simplify the API generated by SWIG to a more Java-ish version, as well as add
 * some proper JavaDocs to the methods.
 *
 * All method calls are wrappers around calls to JNI implemented methods. The
 * library is aimed specifically at the android platform.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class Stodium {
    // Block constructor
    private Stodium() { throw new IllegalAccessError(); }

    /**
     *
     */
    private static final @NotNull byte[] EMPTY_BUFFER = new byte[1024];

    /**
     *
     * @param status
     * @throws StodiumException
     */
    public static void checkStatus(final int status)
            throws StodiumException {
        if (status == StodiumJNI.NOERR) {
            return;
        }
        throw new OperationFailedException("operation returned non-zero status " + status);
    }

    /**
     *
     * @param src
     * @param expected
     * @throws ConstraintViolationException
     */
    public static void checkSize(final int src,
                                 final int expected)
            throws ConstraintViolationException {
        if (src == expected) {
            return;
        }
        throw new ConstraintViolationException(
                String.format(Locale.ENGLISH, "Check size failed [expected: %d, real: %d]",
                        expected, src));
    }

    /**
     *
     * @param src
     * @param lower
     * @param upper
     * @throws ConstraintViolationException
     */
    public static void checkSize(final int src,
                                 final int lower,
                                 final int upper)
            throws ConstraintViolationException {
        if (src <= upper && src >= lower) {
            return;
        }
        throw new ConstraintViolationException(
                String.format(Locale.ENGLISH, "CheckSize failed [lower: %d, upper: %d, real: %d]",
                        lower, upper, src));
    }

    /**
     *
     * @param src
     * @param lower
     * @throws ConstraintViolationException
     */
    public static void checkSizeMin(final int src,
                                    final int lower)
            throws ConstraintViolationException {
        checkSize(src, lower, Integer.MAX_VALUE);
    }

    /**
     *
     * @param src
     * @throws ConstraintViolationException
     */
    public static void checkPositive(final int src)
            throws ConstraintViolationException {
        if (src >= 0) {
            return;
        }
        throw new ConstraintViolationException(
                String.format(Locale.ENGLISH, "checkPositive failed [real: %d]", src));
    }

    /**
     * checkOffsetParams is a shorthand for the combined verification calls
     * required when using an API based on the (in, offset, len) format.
     *
     * @param dataLen
     * @param offset
     * @param len
     */
    public static void checkOffsetParams(final int dataLen,
                                         final int offset,
                                         final int len)
            throws ConstraintViolationException {
        Stodium.checkSize(offset, 0, dataLen);
        Stodium.checkSize(offset + len, 0, dataLen);
        Stodium.checkPositive(len);
    }

    /**
     * checkPow2 checks whether the given integer src is a power of 2, and
     * throws an exception otherwise.
     *
     * @param src
     * @throws ConstraintViolationException
     */
    public static void checkPow2(final int src)
            throws ConstraintViolationException {
        if ((src > 0) && ((src & (~src + 1)) == src)) {
            return;
        }
        throw new ConstraintViolationException("checkPow2 failed [" + src + "]");
    }

    /**
     *
     * @param src
     * @throws ConstraintViolationException
     */
    public static void checkPow2(final long src)
            throws ConstraintViolationException {
        if ((src > 0) && ((src & (~src + 1)) == src)) {
            return;
        }
        throw new ConstraintViolationException("checkPow2 failed [" + src + "]");
    }

    /**
     * isEqual implements a Java-implementation of constant-time,
     * length-independent equality checking for sensitive values.
     *
     * @return true iff a == b
     */
    public static boolean isEqual(final @NotNull byte[] a,
                                  final @NotNull byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    /**
     *
     * @param a
     * @param b
     * @return
     */
    public static boolean isEqual(final @NotNull ByteBuffer a,
                                  final @NotNull ByteBuffer b) {
        if (a.remaining() != b.remaining()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.remaining(); i++) {
            result |= a.get(i) ^ b.get(i);
        }
        return result == 0;
    }

    /**
     *
     * @param a
     */
    public static void wipeBytes(final @NotNull byte[] a) {
        Arrays.fill(a, (byte) 0x00);
    }

    /**
     *
     * @param a
     */
    public static void wipeBytes(final @Nullable ByteBuffer a) {
        if (a == null) {
            return;
        }

        if (a.hasArray()) {
            wipeBytes(a.array());
            return;
        }

        if (a.isReadOnly()) {
            return; // ignore
        }

        while (a.hasRemaining()) {
            a.put(EMPTY_BUFFER, 0, a.remaining() < 1024 ? a.remaining() : 1024);
        }
    }

    /**
     * ensureUsableByteBuffer returns a ByteBuffer instance that is guaranteed
     * to work correctly with the implementation of stodium_buffers in the
     * native code.
     * <p>
     * If the passed buff argument represents a JNI usable ByteBuffer, it is
     * directly returned. Otherwise, the method allocates a direct buffer with
     * the size of {@code buff.remaining()}, and copies the contents of buff.
     * This copy is guaranteed to work with the native code (as it is a direct
     * buffer) and therefore is returned.
     *
     * @param buff the original buffer
     * @return a ByteBuffer that is guaranteed to function correctly in the
     *         native code.
     */
    @NotNull
    public static ByteBuffer ensureUsableByteBuffer(final @NotNull ByteBuffer buff) {
        if (buff.isDirect() || !buff.isReadOnly()) {
            return buff;
        }

        final ByteBuffer direct = ByteBuffer.allocateDirect(buff.remaining());
        direct.mark();
        direct.put(buff.slice());
        direct.reset();
        return direct;
    }

    /**
     * checkDestinationWritable throws an exception if the ByteBuffer passed to
     * it is backed by an array and is read-only. If this is the case, the
     * native code would not have a way to operate on the buffer's contents, and
     * copying to it from Java's side would also be impossible.
     *
     * @param buff The ByteBuffer that needs to be verified
     * @throws ReadOnlyBufferException if the buffer is incorrectly passed as a
     *         read-only buffer, even while being the output for an operation.
     */
    public static void checkDestinationWritable(final @NotNull ByteBuffer buff) {
        if (buff.isDirect() || !buff.isReadOnly()) {
            return;
        }
        throw new ReadOnlyBufferException("Stodium: output buffer is readonly");
    }

    /**
     * version returns the value of sodium_version_string().
     *
     * @return libsodium's version string
     */
    @NotNull
    public static String version() {
        return Sodium.sodium_version_string();
    }
}

