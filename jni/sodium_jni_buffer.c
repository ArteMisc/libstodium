/**
 * This file wraps calls to methods in libsodium using ByteBuffer instances to
 * provide access to the data for the operations.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */

// Required headers
#include <jni.h>
#include <stdbool.h>
#include "sodium.h"

#define STODIUM_JNI(type, method) JNIEXPORT type JNICALL Java_eu_artemisc_stodium_StodiumJNI_##method

/**
 * STODIUM_CONSTANT is a utility macro for crypto_primitive_sthsize() methods.
 * It can be used for every method that takes 0 arguments and returns a jint
 * value.
 *
 * @group:     the group the primitive belongs to (e.g. core, stream, aead)
 * @primitive: the name of the primitive (e.g. ed25519, blake2b)
 * @constant:  the name of the constant in lower case (e.g. inputbytes, constbytes)
 */
#define STODIUM_CONSTANT(group, primitive, constant) \
    STODIUM_JNI(jint, crypto_1##group##_1##primitive##_1##constant) (JNIEnv *jenv, jclass jcls) { \
        return (jint) crypto_##group##_##primitive##_##constant (); }

/**
 * STODIUM_CONSTANT_STR does the same as STODIUM_CONSTANT, except it returns a
 * Java String instead of a jint. Used for crypto_*_primitive() wrappers.
 */
#define STODIUM_CONSTANT_STR(group) \
    STODIUM_JNI(jstring, crypto_1##group##_1primitive) (JNIEnv *jenv, jclass jcls) { \
        return (*jenv)->NewStringUTF(jenv, crypto_##group##_primitive ()); }

/**
 * STODIUM_CONSTANT_HL does the same as STODIUM_CONSTANT, except it works for
 * High Level API's (without explicit implementation identifiers), excluding the
 * primitive from the argument list.
 */
#define STODIUM_CONSTANT_HL(group, constant) \
    STODIUM_JNI(jint, crypto_1##group##_1##constant) (JNIEnv *jenv, jclass jcls) { \
        return (jint) crypto_##group##_##constant (); }

/**
 * AS_INPUT, AS_OUTPUT, AS_INPUT_LEN and AS_OUTPUT_LEN are utility macros to
 * reduce the effort of writing casting code and buffer references in every
 * wrapper function.
 */
#define AS_INPUT(type, buffer)      ((const type *) (buffer.content + buffer.offset))
#define AS_OUTPUT(type, buffer)     ((type *)       (buffer.content + buffer.offset))

#define AS_INPUT_LEN(type, buffer)  ((type)   (buffer.capacity))
#define AS_OUTPUT_LEN(type, buffer) ((type *) (buffer.capacity))

/**
 * Beginning of the real C code.
 */
#ifdef __cplusplus
extern "C" {
#endif

/**
 * These static variables are used to hold cached references to Java values in
 * order to reduce the amount of calls made to the JVM from the native code.
 */
static jclass    stodium_g_byte_buffer_class;
static jmethodID stodium_g_byte_buffer_method_array;
static jmethodID stodium_g_byte_buffer_method_array_offset;
static jmethodID stodium_g_byte_buffer_method_remaining;

/**
 * JNI_OnLoad caches the methods called on indirect (backing array) versions of
 * ByteBuffers passed to Stodium methods, to avoid repreated calls to
 * GetMethodID.
 */
jint JNI_OnLoad(JavaVM* jvm, void* reserved) {
    JNIEnv *jenv;
    if ((*jvm)->GetEnv(jvm, (void**)(&jenv), JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }

    stodium_g_byte_buffer_class = (*jenv)->FindClass(jenv, "java/nio/ByteBuffer");
    if ((*jenv)->ExceptionCheck(jenv)) {
        return -1;
    }

    stodium_g_byte_buffer_method_array = (*jenv)->GetMethodID(jenv, stodium_g_byte_buffer_class, "array", "()[B");
    if ((*jenv)->ExceptionCheck(jenv)) {
        return -1;
    }

    stodium_g_byte_buffer_method_array_offset = (*jenv)->GetMethodID(jenv, stodium_g_byte_buffer_class, "arrayOffset", "()I");
    if ((*jenv)->ExceptionCheck(jenv)) {
        return -1;
    }

    stodium_g_byte_buffer_method_remaining = (*jenv)->GetMethodID(jenv, stodium_g_byte_buffer_class, "remaining", "()I");
    if ((*jenv)->ExceptionCheck(jenv)) {
        return -1;
    }

    return JNI_VERSION_1_6;
}

/**
 * stodium_buffers represent a C-accessible link to the array held by a
 * ByteBuffer instance. The methods working with stodium_buffers use the fields
 * of the struct to determine whether the JNI methods should be used to manage a
 * Direct buffer, or whether an underling jbyteArray should be addressed.
 */
typedef struct stodium_buffers {
    unsigned char *content;
    size_t         offset;
    size_t         capacity;
    bool           is_direct;
    jbyteArray     backing_array; // Only defined if the buffer was not direct
} stodium_buffer;

/**
 *
 */
void stodium_get_buffer(JNIEnv *jenv, stodium_buffer *dst, jobject jbuffer) {
    if (jbuffer == NULL) {
        dst->content   = 0;
        dst->offset    = 0;
        dst->capacity  = 0;
        dst->is_direct = true; // A null buffer can be treated as direct
        return;
    }

    // FIXME can byte[] arrays be passed as jobjects? if so, we could support them as well

    dst->content = (unsigned char *) (*jenv)->GetDirectBufferAddress(jenv, jbuffer);
    if (dst->content != NULL) {
        dst->offset    = 0;
        dst->capacity  = (size_t) (*jenv)->GetDirectBufferCapacity(jenv, jbuffer);
        dst->is_direct = true;
        return;
    }

    // indirect (backing array). HALP
    // FIXME is isCopy is stored, we can explicitely call sodium_memzero on the
    // FIXME copied data to avoid leaking sensitive data even in the event of a
    // FIXME copied key value
    dst->backing_array = (jbyteArray) (*jenv)->CallObjectMethod(jenv, jbuffer, stodium_g_byte_buffer_method_array);
    dst->content       = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, dst->backing_array, NULL);
    dst->offset        = (size_t) (*jenv)->CallIntMethod(jenv, jbuffer, stodium_g_byte_buffer_method_array_offset);
    dst->capacity      = (size_t) (*jenv)->CallIntMethod(jenv, jbuffer, stodium_g_byte_buffer_method_remaining);
    dst->is_direct     = false;
    return;
}

/**
 *
 */
void stodium_release_output(JNIEnv *jenv, jobject output, stodium_buffer *buffer) {
    if (buffer->is_direct) {
        return; // No need for copying
    }
    
    // Release with copying of the native buffer
    (*jenv)->ReleaseByteArrayElements(jenv, buffer->backing_array, (jbyte *) (buffer->content), 0);
}

/**
 *
 */
void stodium_release_input(JNIEnv *jenv, jobject output, stodium_buffer *buffer) {
    if (buffer->is_direct || buffer->content == 0) {
        return; // No need for copying or releasing
    }

    // Release without copying the native buffer
    (*jenv)->ReleaseByteArrayElements(jenv, buffer->backing_array, (jbyte *) (buffer->content), JNI_ABORT);
}

/**
 * Libstodium init method
 */
STODIUM_JNI(jint, stodium_1init) (JNIEnv *jenv, jclass jcls) {
    if (sodium_init() == -1) {
        return -1;
    }

    return 0;
}

/** ****************************************************************************
 *
 * Libsodium library methods
 *
 **************************************************************************** */

STODIUM_JNI(jint, sodium_1init) (JNIEnv *jenv, jclass jcls) {
    return (jint) sodium_init();
}

STODIUM_JNI(jint, randombytes_1random) (JNIEnv *jenv, jclass jcls) {
    return (jint) randombytes_random();
}

STODIUM_JNI(jint, randombytes_1uniform) (JNIEnv *jenv, jclass jcls, jint upper_bound) {
    return (jint) randombytes_uniform((const uint32_t) upper_bound);
}

STODIUM_JNI(void, randombytes_1buf) (JNIEnv *jenv, jclass jcls,
        jobject dst) {
    stodium_buffer dst_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);

    randombytes_buf(
            AS_OUTPUT(void, dst_buffer),
            AS_INPUT_LEN(const size_t, dst_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
}

/** ****************************************************************************
 *
 * AEAD - AES-256-GCM
 *
 **************************************************************************** */

STODIUM_CONSTANT(aead, aes256gcm, keybytes)
STODIUM_CONSTANT(aead, aes256gcm, nsecbytes)
STODIUM_CONSTANT(aead, aes256gcm, npubbytes)
STODIUM_CONSTANT(aead, aes256gcm, abytes)

STODIUM_JNI(jint, crypto_1aead_1aes256gcm_1is_1available) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_aead_aes256gcm_is_available();
}

STODIUM_JNI(jint, crypto_1aead_1aes256gcm_1encrypt_1detached) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject mac,
        jobject src,
        jobject ad,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, mac_buffer, src_buffer, ad_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &mac_buffer,   mac);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &ad_buffer,    ad);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer,   key);
 
    jint result = (jint) crypto_aead_aes256gcm_encrypt_detached(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_OUTPUT_LEN(unsigned long long, mac_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, ad_buffer),
            AS_INPUT_LEN(unsigned long long, ad_buffer),
            NULL, // nsec
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst,   &dst_buffer);
    stodium_release_output(jenv, mac,   &mac_buffer);
    stodium_release_input(jenv,  src,   &src_buffer);
    stodium_release_input(jenv,  ad,    &ad_buffer);
    stodium_release_input(jenv,  nonce, &nonce_buffer);
    stodium_release_input(jenv,  key,   &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1aead_1aes256gcm_1encrypt) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject ad,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, src_buffer, ad_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &ad_buffer,    ad);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer,   key);
 
    jint result = (jint) crypto_aead_aes256gcm_encrypt(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_OUTPUT_LEN(unsigned long long, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, ad_buffer),
            AS_INPUT_LEN(unsigned long long, ad_buffer),
            NULL, // nsec
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst,   &dst_buffer);
    stodium_release_input(jenv,  src,   &src_buffer);
    stodium_release_input(jenv,  ad,    &ad_buffer);
    stodium_release_input(jenv,  nonce, &nonce_buffer);
    stodium_release_input(jenv,  key,   &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1aead_1aes256gcm_1decrypt_1detached) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject mac,
        jobject ad,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, mac_buffer, src_buffer, ad_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &mac_buffer,   mac);
    stodium_get_buffer(jenv, &ad_buffer,    ad);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer,   key);
 
    jint result = (jint) crypto_aead_aes256gcm_decrypt_detached(
            AS_OUTPUT(unsigned char, dst_buffer),
            NULL, // nsec
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_INPUT(unsigned char, ad_buffer),
            AS_INPUT_LEN(unsigned long long, ad_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst,   &dst_buffer);
    stodium_release_input(jenv,  mac,   &mac_buffer);
    stodium_release_input(jenv,  src,   &src_buffer);
    stodium_release_input(jenv,  ad,    &ad_buffer);
    stodium_release_input(jenv,  nonce, &nonce_buffer);
    stodium_release_input(jenv,  key,   &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1aead_1aes256gcm_1decrypt) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject ad,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, src_buffer, ad_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &ad_buffer,    ad);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer,   key);
 
    jint result = (jint) crypto_aead_aes256gcm_decrypt(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_OUTPUT_LEN(unsigned long long, dst_buffer),
            NULL, // nsec
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, ad_buffer),
            AS_INPUT_LEN(unsigned long long, ad_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst,   &dst_buffer);
    stodium_release_input(jenv,  src,   &src_buffer);
    stodium_release_input(jenv,  ad,    &ad_buffer);
    stodium_release_input(jenv,  nonce, &nonce_buffer);
    stodium_release_input(jenv,  key,   &key_buffer);

    return result;
}

/** ****************************************************************************
 *
 * AEAD - Chacha20Poly1305
 *
 **************************************************************************** */

STODIUM_CONSTANT(aead, chacha20poly1305, keybytes)
STODIUM_CONSTANT(aead, chacha20poly1305, nsecbytes)
STODIUM_CONSTANT(aead, chacha20poly1305, npubbytes)
STODIUM_CONSTANT(aead, chacha20poly1305, abytes)

STODIUM_JNI(jint, crypto_1aead_1chacha20poly1305_1encrypt_1detached) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject mac,
        jobject src,
        jobject ad,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, mac_buffer, src_buffer, ad_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &mac_buffer,   mac);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &ad_buffer,    ad);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer,   key);
 
    jint result = (jint) crypto_aead_chacha20poly1305_encrypt_detached(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_OUTPUT_LEN(unsigned long long, mac_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, ad_buffer),
            AS_INPUT_LEN(unsigned long long, ad_buffer),
            NULL, // nsec
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst,   &dst_buffer);
    stodium_release_output(jenv, mac,   &mac_buffer);
    stodium_release_input(jenv,  src,   &src_buffer);
    stodium_release_input(jenv,  ad,    &ad_buffer);
    stodium_release_input(jenv,  nonce, &nonce_buffer);
    stodium_release_input(jenv,  key,   &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1aead_1chacha20poly1305_1encrypt) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject ad,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, src_buffer, ad_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &ad_buffer,    ad);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer,   key);
 
    jint result = (jint) crypto_aead_chacha20poly1305_encrypt(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_OUTPUT_LEN(unsigned long long, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, ad_buffer),
            AS_INPUT_LEN(unsigned long long, ad_buffer),
            NULL, // nsec
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst,   &dst_buffer);
    stodium_release_input(jenv,  src,   &src_buffer);
    stodium_release_input(jenv,  ad,    &ad_buffer);
    stodium_release_input(jenv,  nonce, &nonce_buffer);
    stodium_release_input(jenv,  key,   &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1aead_1chacha20poly1305_1decrypt_1detached) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject mac,
        jobject ad,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, mac_buffer, src_buffer, ad_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &mac_buffer,   mac);
    stodium_get_buffer(jenv, &ad_buffer,    ad);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer,   key);
 
    jint result = (jint) crypto_aead_chacha20poly1305_decrypt_detached(
            AS_OUTPUT(unsigned char, dst_buffer),
            NULL, // nsec
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_INPUT(unsigned char, ad_buffer),
            AS_INPUT_LEN(unsigned long long, ad_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst,   &dst_buffer);
    stodium_release_input(jenv,  mac,   &mac_buffer);
    stodium_release_input(jenv,  src,   &src_buffer);
    stodium_release_input(jenv,  ad,    &ad_buffer);
    stodium_release_input(jenv,  nonce, &nonce_buffer);
    stodium_release_input(jenv,  key,   &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1aead_1chacha20poly1305_1decrypt) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject ad,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, src_buffer, ad_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &ad_buffer,    ad);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer,   key);
 
    jint result = (jint) crypto_aead_chacha20poly1305_decrypt(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_OUTPUT_LEN(unsigned long long, dst_buffer),
            NULL, // nsec
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, ad_buffer),
            AS_INPUT_LEN(unsigned long long, ad_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst,   &dst_buffer);
    stodium_release_input(jenv,  src,   &src_buffer);
    stodium_release_input(jenv,  ad,    &ad_buffer);
    stodium_release_input(jenv,  nonce, &nonce_buffer);
    stodium_release_input(jenv,  key,   &key_buffer);

    return result;
}

/** ****************************************************************************
 *
 * AEAD - Chacha20Poly1305 (ietf)
 *
 **************************************************************************** */

STODIUM_JNI(jint, crypto_1aead_1chacha20poly1305_1ietf_1keybytes) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_aead_chacha20poly1305_ietf_keybytes();
}
STODIUM_JNI(jint, crypto_1aead_1chacha20poly1305_1ietf_1nsecbytes) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_aead_chacha20poly1305_ietf_nsecbytes();
}
STODIUM_JNI(jint, crypto_1aead_1chacha20poly1305_1ietf_1npubbytes) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_aead_chacha20poly1305_ietf_npubbytes();
}
STODIUM_JNI(jint, crypto_1aead_1chacha20poly1305_1ietf_1abytes) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_aead_chacha20poly1305_ietf_abytes();
}

STODIUM_JNI(jint, crypto_1aead_1chacha20poly1305_1ietf_1encrypt_1detached) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject mac,
        jobject src,
        jobject ad,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, mac_buffer, src_buffer, ad_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &mac_buffer,   mac);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &ad_buffer,    ad);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer,   key);
 
    jint result = (jint) crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_OUTPUT_LEN(unsigned long long, mac_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, ad_buffer),
            AS_INPUT_LEN(unsigned long long, ad_buffer),
            NULL, // nsec
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst,   &dst_buffer);
    stodium_release_output(jenv, mac,   &mac_buffer);
    stodium_release_input(jenv,  src,   &src_buffer);
    stodium_release_input(jenv,  ad,    &ad_buffer);
    stodium_release_input(jenv,  nonce, &nonce_buffer);
    stodium_release_input(jenv,  key,   &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1aead_1chacha20poly1305_1ietf_1encrypt) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject ad,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, src_buffer, ad_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &ad_buffer,    ad);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer,   key);
 
    jint result = (jint) crypto_aead_chacha20poly1305_ietf_encrypt(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_OUTPUT_LEN(unsigned long long, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, ad_buffer),
            AS_INPUT_LEN(unsigned long long, ad_buffer),
            NULL, // nsec
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst,   &dst_buffer);
    stodium_release_input(jenv,  src,   &src_buffer);
    stodium_release_input(jenv,  ad,    &ad_buffer);
    stodium_release_input(jenv,  nonce, &nonce_buffer);
    stodium_release_input(jenv,  key,   &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1aead_1chacha20poly1305_1ietf_1decrypt_1detached) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject mac,
        jobject ad,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, mac_buffer, src_buffer, ad_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &mac_buffer,   mac);
    stodium_get_buffer(jenv, &ad_buffer,    ad);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer,   key);
 
    jint result = (jint) crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            AS_OUTPUT(unsigned char, dst_buffer),
            NULL, // nsec
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_INPUT(unsigned char, ad_buffer),
            AS_INPUT_LEN(unsigned long long, ad_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst,   &dst_buffer);
    stodium_release_input(jenv,  mac,   &mac_buffer);
    stodium_release_input(jenv,  src,   &src_buffer);
    stodium_release_input(jenv,  ad,    &ad_buffer);
    stodium_release_input(jenv,  nonce, &nonce_buffer);
    stodium_release_input(jenv,  key,   &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1aead_1chacha20poly1305_1ietf_1decrypt) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject ad,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, src_buffer, ad_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &ad_buffer,    ad);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer,   key);
 
    jint result = (jint) crypto_aead_chacha20poly1305_ietf_decrypt(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_OUTPUT_LEN(unsigned long long, dst_buffer),
            NULL, // nsec
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, ad_buffer),
            AS_INPUT_LEN(unsigned long long, ad_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst,   &dst_buffer);
    stodium_release_input(jenv,  src,   &src_buffer);
    stodium_release_input(jenv,  ad,    &ad_buffer);
    stodium_release_input(jenv,  nonce, &nonce_buffer);
    stodium_release_input(jenv,  key,   &key_buffer);

    return result;
}


/** ****************************************************************************
 *
 * AEAD - XChacha20Poly1305 (ietf)
 *
 **************************************************************************** */

STODIUM_JNI(jint, crypto_1aead_1xchacha20poly1305_1ietf_1keybytes) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_aead_xchacha20poly1305_ietf_keybytes();
}
STODIUM_JNI(jint, crypto_1aead_1xchacha20poly1305_1ietf_1nsecbytes) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_aead_xchacha20poly1305_ietf_nsecbytes();
}
STODIUM_JNI(jint, crypto_1aead_1xchacha20poly1305_1ietf_1npubbytes) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_aead_xchacha20poly1305_ietf_npubbytes();
}
STODIUM_JNI(jint, crypto_1aead_1xchacha20poly1305_1ietf_1abytes) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_aead_xchacha20poly1305_ietf_abytes();
}

STODIUM_JNI(jint, crypto_1aead_1xchacha20poly1305_1ietf_1encrypt_1detached) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject mac,
        jobject src,
        jobject ad,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, mac_buffer, src_buffer, ad_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &mac_buffer,   mac);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &ad_buffer,    ad);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer,   key);
 
    jint result = (jint) crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_OUTPUT_LEN(unsigned long long, mac_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, ad_buffer),
            AS_INPUT_LEN(unsigned long long, ad_buffer),
            NULL, // nsec
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst,   &dst_buffer);
    stodium_release_output(jenv, mac,   &mac_buffer);
    stodium_release_input(jenv,  src,   &src_buffer);
    stodium_release_input(jenv,  ad,    &ad_buffer);
    stodium_release_input(jenv,  nonce, &nonce_buffer);
    stodium_release_input(jenv,  key,   &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1aead_1xchacha20poly1305_1ietf_1encrypt) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject ad,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, src_buffer, ad_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &ad_buffer,    ad);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer,   key);
 
    jint result = (jint) crypto_aead_xchacha20poly1305_ietf_encrypt(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_OUTPUT_LEN(unsigned long long, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, ad_buffer),
            AS_INPUT_LEN(unsigned long long, ad_buffer),
            NULL, // nsec
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst,   &dst_buffer);
    stodium_release_input(jenv,  src,   &src_buffer);
    stodium_release_input(jenv,  ad,    &ad_buffer);
    stodium_release_input(jenv,  nonce, &nonce_buffer);
    stodium_release_input(jenv,  key,   &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1aead_1xchacha20poly1305_1ietf_1decrypt_1detached) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject mac,
        jobject ad,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, mac_buffer, src_buffer, ad_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &mac_buffer,   mac);
    stodium_get_buffer(jenv, &ad_buffer,    ad);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer,   key);
 
    jint result = (jint) crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            AS_OUTPUT(unsigned char, dst_buffer),
            NULL, // nsec
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_INPUT(unsigned char, ad_buffer),
            AS_INPUT_LEN(unsigned long long, ad_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst,   &dst_buffer);
    stodium_release_input(jenv,  mac,   &mac_buffer);
    stodium_release_input(jenv,  src,   &src_buffer);
    stodium_release_input(jenv,  ad,    &ad_buffer);
    stodium_release_input(jenv,  nonce, &nonce_buffer);
    stodium_release_input(jenv,  key,   &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1aead_1xchacha20poly1305_1ietf_1decrypt) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject ad,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, src_buffer, ad_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &ad_buffer,    ad);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer,   key);
 
    jint result = (jint) crypto_aead_xchacha20poly1305_ietf_decrypt(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_OUTPUT_LEN(unsigned long long, dst_buffer),
            NULL, // nsec
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, ad_buffer),
            AS_INPUT_LEN(unsigned long long, ad_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst,   &dst_buffer);
    stodium_release_input(jenv,  src,   &src_buffer);
    stodium_release_input(jenv,  ad,    &ad_buffer);
    stodium_release_input(jenv,  nonce, &nonce_buffer);
    stodium_release_input(jenv,  key,   &key_buffer);

    return result;
}

/** ****************************************************************************
 *
 * AUTH
 *
 **************************************************************************** */

STODIUM_CONSTANT_STR(auth)

/** ****************************************************************************
 *
 * AUTH - HMAC-256
 *
 **************************************************************************** */

STODIUM_CONSTANT(auth, hmacsha256, bytes)
STODIUM_CONSTANT(auth, hmacsha256, keybytes)
STODIUM_CONSTANT(auth, hmacsha256, statebytes)

STODIUM_JNI(jint, crypto_1auth_1hmacsha256) (JNIEnv *jenv, jclass jcls,
        jobject mac,
        jobject src,
        jobject key) {
    stodium_buffer mac_buffer, src_buffer, key_buffer;
    stodium_get_buffer(jenv, &mac_buffer, mac);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_auth_hmacsha256(
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, mac, &mac_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1auth_1hmacsha256_1verify) (JNIEnv *jenv, jclass jcls,
        jobject mac,
        jobject src,
        jobject key) {
    stodium_buffer mac_buffer, src_buffer, key_buffer;
    stodium_get_buffer(jenv, &mac_buffer, mac);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_auth_hmacsha256_verify(
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_input(jenv, mac, &mac_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1auth_1hmacsha256_1init) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject key) {
    stodium_buffer dst_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_auth_hmacsha256_init(
            AS_OUTPUT(crypto_auth_hmacsha256_state, dst_buffer),
            AS_INPUT(unsigned char, key_buffer),
            AS_INPUT_LEN(size_t, key_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1auth_1hmacsha256_1update) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src) {
    stodium_buffer dst_buffer, src_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);

    jint result = (jint) crypto_auth_hmacsha256_update(
            AS_OUTPUT(crypto_auth_hmacsha256_state, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1auth_1hmacsha256_1final) (JNIEnv *jenv, jclass jcls,
        jobject state,
        jobject dst) {
    stodium_buffer state_buffer, dst_buffer;
    stodium_get_buffer(jenv, &state_buffer, state);
    stodium_get_buffer(jenv, &dst_buffer, dst);

    jint result = (jint) crypto_auth_hmacsha256_final(
            AS_OUTPUT(crypto_auth_hmacsha256_state, state_buffer),
            AS_OUTPUT(unsigned char, dst_buffer));

    stodium_release_output(jenv, state, &state_buffer);
    stodium_release_output(jenv, dst, &dst_buffer);

    return result;
}

/** ****************************************************************************
 *
 * AUTH - HMAC-512
 *
 **************************************************************************** */

STODIUM_CONSTANT(auth, hmacsha512, bytes)
STODIUM_CONSTANT(auth, hmacsha512, keybytes)
STODIUM_CONSTANT(auth, hmacsha512, statebytes)

STODIUM_JNI(jint, crypto_1auth_1hmacsha512) (JNIEnv *jenv, jclass jcls,
        jobject mac,
        jobject src,
        jobject key) {
    stodium_buffer mac_buffer, src_buffer, key_buffer;
    stodium_get_buffer(jenv, &mac_buffer, mac);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_auth_hmacsha512(
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, mac, &mac_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1auth_1hmacsha512_1verify) (JNIEnv *jenv, jclass jcls,
        jobject mac,
        jobject src,
        jobject key) {
    stodium_buffer mac_buffer, src_buffer, key_buffer;
    stodium_get_buffer(jenv, &mac_buffer, mac);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_auth_hmacsha512_verify(
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_input(jenv, mac, &mac_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1auth_1hmacsha512_1init) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject key) {
    stodium_buffer dst_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_auth_hmacsha512_init(
            AS_OUTPUT(crypto_auth_hmacsha512_state, dst_buffer),
            AS_INPUT(unsigned char, key_buffer),
            AS_INPUT_LEN(size_t, key_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1auth_1hmacsha512_1update) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src) {
    stodium_buffer dst_buffer, src_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);

    jint result = (jint) crypto_auth_hmacsha512_update(
            AS_OUTPUT(crypto_auth_hmacsha512_state, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1auth_1hmacsha512_1final) (JNIEnv *jenv, jclass jcls,
        jobject state,
        jobject dst) {
    stodium_buffer state_buffer, dst_buffer;
    stodium_get_buffer(jenv, &state_buffer, state);
    stodium_get_buffer(jenv, &dst_buffer, dst);

    jint result = (jint) crypto_auth_hmacsha512_final(
            AS_OUTPUT(crypto_auth_hmacsha512_state, state_buffer),
            AS_OUTPUT(unsigned char, dst_buffer));

    stodium_release_output(jenv, state, &state_buffer);
    stodium_release_output(jenv, dst, &dst_buffer);

    return result;
}

/** ****************************************************************************
 *
 * AUTH - HMAC-512/256
 *
 **************************************************************************** */

STODIUM_CONSTANT(auth, hmacsha512256, bytes)
STODIUM_CONSTANT(auth, hmacsha512256, keybytes)
STODIUM_CONSTANT(auth, hmacsha512256, statebytes)

STODIUM_JNI(jint, crypto_1auth_1hmacsha512256) (JNIEnv *jenv, jclass jcls,
        jobject mac,
        jobject src,
        jobject key) {
    stodium_buffer mac_buffer, src_buffer, key_buffer;
    stodium_get_buffer(jenv, &mac_buffer, mac);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_auth_hmacsha512256(
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, mac, &mac_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1auth_1hmacsha512256_1verify) (JNIEnv *jenv, jclass jcls,
        jobject mac,
        jobject src,
        jobject key) {
    stodium_buffer mac_buffer, src_buffer, key_buffer;
    stodium_get_buffer(jenv, &mac_buffer, mac);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_auth_hmacsha512256_verify(
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_input(jenv, mac, &mac_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1auth_1hmacsha512256_1init) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject key) {
    stodium_buffer dst_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_auth_hmacsha512256_init(
            AS_OUTPUT(crypto_auth_hmacsha512256_state, dst_buffer),
            AS_INPUT(unsigned char, key_buffer),
            AS_INPUT_LEN(size_t, key_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1auth_1hmacsha512256_1update) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src) {
    stodium_buffer dst_buffer, src_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);

    jint result = (jint) crypto_auth_hmacsha512256_update(
            AS_OUTPUT(crypto_auth_hmacsha512256_state, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1auth_1hmacsha512256_1final) (JNIEnv *jenv, jclass jcls,
        jobject state,
        jobject dst) {
    stodium_buffer state_buffer, dst_buffer;
    stodium_get_buffer(jenv, &state_buffer, state);
    stodium_get_buffer(jenv, &dst_buffer, dst);

    jint result = (jint) crypto_auth_hmacsha512256_final(
            AS_OUTPUT(crypto_auth_hmacsha512256_state, state_buffer),
            AS_OUTPUT(unsigned char, dst_buffer));

    stodium_release_output(jenv, state, &state_buffer);
    stodium_release_output(jenv, dst, &dst_buffer);

    return result;
}

/** ****************************************************************************
 *
 * BOX
 *
 **************************************************************************** */

STODIUM_CONSTANT_STR(box)
STODIUM_CONSTANT_HL(box, sealbytes)

STODIUM_JNI(jint, crypto_1box_1seal) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject pub) {
    stodium_buffer dst_buffer, src_buffer, pub_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &pub_buffer, pub);

    jint result = (jint) crypto_box_seal(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, pub_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, pub, &pub_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1box_1seal_1open) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject pub,
        jobject priv) {
    stodium_buffer dst_buffer, src_buffer, pub_buffer, priv_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &pub_buffer, pub);
    stodium_get_buffer(jenv, &priv_buffer, priv);

    jint result = (jint) crypto_box_seal_open(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, pub_buffer),
            AS_INPUT(unsigned char, priv_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, pub, &pub_buffer);
    stodium_release_input(jenv, priv, &priv_buffer);

    return result;
}

/** ****************************************************************************
 *
 * BOX - X25519XSalsa20Poly1305
 *
 **************************************************************************** */

STODIUM_CONSTANT(box, curve25519xsalsa20poly1305, seedbytes)
STODIUM_CONSTANT(box, curve25519xsalsa20poly1305, publickeybytes)
STODIUM_CONSTANT(box, curve25519xsalsa20poly1305, secretkeybytes)
STODIUM_CONSTANT(box, curve25519xsalsa20poly1305, beforenmbytes)
STODIUM_CONSTANT(box, curve25519xsalsa20poly1305, noncebytes)
STODIUM_CONSTANT(box, curve25519xsalsa20poly1305, zerobytes)
STODIUM_CONSTANT(box, curve25519xsalsa20poly1305, boxzerobytes)
STODIUM_CONSTANT(box, curve25519xsalsa20poly1305, macbytes)

STODIUM_JNI(jint, crypto_1box_1curve25519xsalsa20poly1305_1seed_1keypair) (JNIEnv *jenv, jclass jcls,
        jobject pk,
        jobject sk,
        jobject seed) {
    stodium_buffer pk_buffer, sk_buffer, seed_buffer;
    stodium_get_buffer(jenv, &pk_buffer, pk);
    stodium_get_buffer(jenv, &sk_buffer, sk);
    stodium_get_buffer(jenv, &seed_buffer, seed);

    jint result = (jint) crypto_box_curve25519xsalsa20poly1305_seed_keypair(
            AS_OUTPUT(unsigned char, pk_buffer),
            AS_OUTPUT(unsigned char, sk_buffer),
            AS_INPUT(unsigned char, seed_buffer));

    stodium_release_output(jenv, pk, &pk_buffer);
    stodium_release_output(jenv, sk, &sk_buffer);
    stodium_release_input(jenv, seed, &seed_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1box_1curve25519xsalsa20poly1305_1keypair) (JNIEnv *jenv, jclass jcls,
        jobject pk,
        jobject sk) {
    stodium_buffer pk_buffer, sk_buffer;
    stodium_get_buffer(jenv, &pk_buffer, pk);
    stodium_get_buffer(jenv, &sk_buffer, sk);

    jint result = (jint) crypto_box_curve25519xsalsa20poly1305_keypair(
            AS_OUTPUT(unsigned char, pk_buffer),
            AS_OUTPUT(unsigned char, sk_buffer));

    stodium_release_output(jenv, pk, &pk_buffer);
    stodium_release_output(jenv, sk, &sk_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1box_1curve25519xsalsa20poly1305_1beforenm) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject pub,
        jobject priv) {
    stodium_buffer dst_buffer, pub_buffer, priv_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &pub_buffer, pub);
    stodium_get_buffer(jenv, &priv_buffer, priv);

    jint result = (jint) crypto_box_curve25519xsalsa20poly1305_beforenm(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, pub_buffer),
            AS_INPUT(unsigned char, priv_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, pub, &pub_buffer);
    stodium_release_input(jenv, priv, &priv_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1box_1curve25519xsalsa20poly1305_1afternm) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, src_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_box_curve25519xsalsa20poly1305_afternm(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, nonce, &nonce_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1box_1curve25519xsalsa20poly1305_1open_1afternm) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, src_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_box_curve25519xsalsa20poly1305_open_afternm(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, nonce, &nonce_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1box_1curve25519xsalsa20poly1305) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject nonce,
        jobject pub,
        jobject priv) {
    stodium_buffer dst_buffer, src_buffer, nonce_buffer, pub_buffer, priv_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &pub_buffer, pub);
    stodium_get_buffer(jenv, &priv_buffer, priv);

    jint result = (jint) crypto_box_curve25519xsalsa20poly1305(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, pub_buffer),
            AS_INPUT(unsigned char, priv_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, nonce, &nonce_buffer);
    stodium_release_input(jenv, pub, &pub_buffer);
    stodium_release_input(jenv, priv, &priv_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1box_1curve25519xsalsa20poly1305_1open) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject nonce,
        jobject pub,
        jobject priv) {
    stodium_buffer dst_buffer, src_buffer, nonce_buffer, pub_buffer, priv_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &pub_buffer, pub);
    stodium_get_buffer(jenv, &priv_buffer, priv);

    jint result = (jint) crypto_box_curve25519xsalsa20poly1305_open(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, pub_buffer),
            AS_INPUT(unsigned char, priv_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, nonce, &nonce_buffer);
    stodium_release_input(jenv, pub, &pub_buffer);
    stodium_release_input(jenv, priv, &priv_buffer);

    return result;
}

/** ****************************************************************************
 *
 * BOX - X25519XChacha20Poly1305
 *
 **************************************************************************** */

STODIUM_CONSTANT(box, curve25519xchacha20poly1305, seedbytes)
STODIUM_CONSTANT(box, curve25519xchacha20poly1305, publickeybytes)
STODIUM_CONSTANT(box, curve25519xchacha20poly1305, secretkeybytes)
STODIUM_CONSTANT(box, curve25519xchacha20poly1305, beforenmbytes)
STODIUM_CONSTANT(box, curve25519xchacha20poly1305, noncebytes)
STODIUM_CONSTANT(box, curve25519xchacha20poly1305, macbytes)

STODIUM_JNI(jint, crypto_1box_1curve25519xchacha20poly1305_1seed_1keypair) (JNIEnv *jenv, jclass jcls,
        jobject pk,
        jobject sk,
        jobject seed) {
    stodium_buffer pk_buffer, sk_buffer, seed_buffer;
    stodium_get_buffer(jenv, &pk_buffer, pk);
    stodium_get_buffer(jenv, &sk_buffer, sk);
    stodium_get_buffer(jenv, &seed_buffer, seed);

    jint result = (jint) crypto_box_curve25519xchacha20poly1305_seed_keypair(
            AS_OUTPUT(unsigned char, pk_buffer),
            AS_OUTPUT(unsigned char, sk_buffer),
            AS_INPUT(unsigned char, seed_buffer));

    stodium_release_output(jenv, pk, &pk_buffer);
    stodium_release_output(jenv, sk, &sk_buffer);
    stodium_release_input(jenv, seed, &seed_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1box_1curve25519xchacha20poly1305_1keypair) (JNIEnv *jenv, jclass jcls,
        jobject pk,
        jobject sk) {
    stodium_buffer pk_buffer, sk_buffer;
    stodium_get_buffer(jenv, &pk_buffer, pk);
    stodium_get_buffer(jenv, &sk_buffer, sk);

    jint result = (jint) crypto_box_curve25519xchacha20poly1305_keypair(
            AS_OUTPUT(unsigned char, pk_buffer),
            AS_OUTPUT(unsigned char, sk_buffer));

    stodium_release_output(jenv, pk, &pk_buffer);
    stodium_release_output(jenv, sk, &sk_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1box_1curve25519xchacha20poly1305_1beforenm) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject pub,
        jobject priv) {
    stodium_buffer dst_buffer, pub_buffer, priv_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &pub_buffer, pub);
    stodium_get_buffer(jenv, &priv_buffer, priv);

    jint result = (jint) crypto_box_curve25519xchacha20poly1305_beforenm(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, pub_buffer),
            AS_INPUT(unsigned char, priv_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, pub, &pub_buffer);
    stodium_release_input(jenv, priv, &priv_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1box_1curve25519xchacha20poly1305_1easy_1afternm) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, src_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_box_curve25519xchacha20poly1305_easy_afternm(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, nonce, &nonce_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1box_1curve25519xchacha20poly1305_1open_1easy_1afternm) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, src_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_box_curve25519xchacha20poly1305_open_easy_afternm(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, nonce, &nonce_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1box_1curve25519xchacha20poly1305_1easy) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject nonce,
        jobject pub,
        jobject priv) {
    stodium_buffer dst_buffer, src_buffer, nonce_buffer, pub_buffer, priv_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &pub_buffer, pub);
    stodium_get_buffer(jenv, &priv_buffer, priv);

    jint result = (jint) crypto_box_curve25519xchacha20poly1305_easy(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, pub_buffer),
            AS_INPUT(unsigned char, priv_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, nonce, &nonce_buffer);
    stodium_release_input(jenv, pub, &pub_buffer);
    stodium_release_input(jenv, priv, &priv_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1box_1curve25519xchacha20poly1305_1open_1easy) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject nonce,
        jobject pub,
        jobject priv) {
    stodium_buffer dst_buffer, src_buffer, nonce_buffer, pub_buffer, priv_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &pub_buffer, pub);
    stodium_get_buffer(jenv, &priv_buffer, priv);

    jint result = (jint) crypto_box_curve25519xchacha20poly1305_open_easy(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, pub_buffer),
            AS_INPUT(unsigned char, priv_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, nonce, &nonce_buffer);
    stodium_release_input(jenv, pub, &pub_buffer);
    stodium_release_input(jenv, priv, &priv_buffer);

    return result;
}

/** ****************************************************************************
 *
 * CORE - HCHACHA
 *
 **************************************************************************** */

STODIUM_CONSTANT(core, hchacha20, outputbytes)
STODIUM_CONSTANT(core, hchacha20, inputbytes)
STODIUM_CONSTANT(core, hchacha20, keybytes)
STODIUM_CONSTANT(core, hchacha20, constbytes)

STODIUM_JNI(jint, crypto_1core_1hchacha20) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject key,
        jobject constant) {
    stodium_buffer dst_buffer, src_buffer, key_buffer, const_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &key_buffer,   key);
    stodium_get_buffer(jenv, &const_buffer, constant);

    jint result = (jint) crypto_core_hchacha20(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT(unsigned char, key_buffer),
            AS_INPUT(unsigned char, const_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, key, &key_buffer);
    stodium_release_input(jenv, constant, &const_buffer);
    
    return result;
}

/** ****************************************************************************
 *
 * CORE - HSALSA20
 *
 **************************************************************************** */

STODIUM_CONSTANT(core, hsalsa20, outputbytes)
STODIUM_CONSTANT(core, hsalsa20, inputbytes)
STODIUM_CONSTANT(core, hsalsa20, keybytes)
STODIUM_CONSTANT(core, hsalsa20, constbytes)

STODIUM_JNI(jint, crypto_1core_1hsalsa20) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject key,
        jobject constant) {
    stodium_buffer dst_buffer, src_buffer, key_buffer, const_buffer;
    stodium_get_buffer(jenv, &dst_buffer,   dst);
    stodium_get_buffer(jenv, &src_buffer,   src);
    stodium_get_buffer(jenv, &key_buffer,   key);
    stodium_get_buffer(jenv, &const_buffer, constant);

    jint result = (jint) crypto_core_hsalsa20(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT(unsigned char, key_buffer),
            AS_INPUT(unsigned char, const_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, key, &key_buffer);
    stodium_release_input(jenv, constant, &const_buffer);
    
    return result;
}

/** ****************************************************************************
 *
 * GENERICHASH
 *
 **************************************************************************** */

STODIUM_CONSTANT_STR(generichash)

/** ****************************************************************************
 *
 * GENERICHASH - Blake2b
 *
 **************************************************************************** */
STODIUM_CONSTANT(generichash, blake2b, bytes)
STODIUM_CONSTANT(generichash, blake2b, keybytes)
STODIUM_CONSTANT(generichash, blake2b, saltbytes)
STODIUM_CONSTANT(generichash, blake2b, personalbytes)
STODIUM_CONSTANT(generichash, blake2b, statebytes)
STODIUM_JNI(jint, crypto_1generichash_1blake2b_1bytes_1min) (JNIEnv *jenv, jclass jcls) {
    return (jint) crypto_generichash_blake2b_bytes_min();
}
STODIUM_JNI(jint, crypto_1generichash_1blake2b_1bytes_1max) (JNIEnv *jenv, jclass jcls) {
    return (jint) crypto_generichash_blake2b_bytes_max();
}
STODIUM_JNI(jint, crypto_1generichash_1blake2b_1keybytes_1min) (JNIEnv *jenv, jclass jcls) {
    return (jint) crypto_generichash_blake2b_keybytes_min();
}
STODIUM_JNI(jint, crypto_1generichash_1blake2b_1keybytes_1max) (JNIEnv *jenv, jclass jcls) {
    return (jint) crypto_generichash_blake2b_keybytes_max();
}

STODIUM_JNI(jint, crypto_1generichash_1blake2b) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject key) {
    stodium_buffer dst_buffer, src_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_generichash_blake2b(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT_LEN(size_t, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, key_buffer),
            AS_INPUT_LEN(size_t, key_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1generichash_1blake2b_1salt_1personal) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject key,
        jobject salt,
        jobject personal) {
    stodium_buffer dst_buffer, src_buffer, key_buffer, salt_buffer, pers_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &key_buffer, key);
    stodium_get_buffer(jenv, &salt_buffer, salt);
    stodium_get_buffer(jenv, &pers_buffer, personal);

    jint result = (jint) crypto_generichash_blake2b_salt_personal(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT_LEN(size_t, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, key_buffer),
            AS_INPUT_LEN(size_t, key_buffer),
            AS_INPUT(unsigned char, salt_buffer),
            AS_INPUT(unsigned char, pers_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, key, &key_buffer);
    stodium_release_input(jenv, salt, &salt_buffer);
    stodium_release_input(jenv, personal, &pers_buffer);

    return result;
}


STODIUM_JNI(jint, crypto_1generichash_1blake2b_1init) (JNIEnv *jenv, jclass jcls,
        jobject state,
        jobject key,
        jint    outlen) {
    stodium_buffer dst_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer, state);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_generichash_blake2b_init(
            AS_OUTPUT(crypto_generichash_blake2b_state, dst_buffer),
            AS_INPUT(unsigned char, key_buffer),
            AS_INPUT_LEN(size_t, key_buffer),
            (size_t) outlen);

    stodium_release_output(jenv, state, &dst_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1generichash_1blake2b_1update) (JNIEnv *jenv, jclass jcls,
        jobject state,
        jobject src) {
    stodium_buffer dst_buffer, src_buffer;
    stodium_get_buffer(jenv, &dst_buffer, state);
    stodium_get_buffer(jenv, &src_buffer, src);

    jint result = (jint) crypto_generichash_blake2b_update(
            AS_OUTPUT(crypto_generichash_blake2b_state, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer));

    stodium_release_output(jenv, state, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    return result;
}

STODIUM_JNI(jint, crypto_1generichash_1blake2b_1final) (JNIEnv *jenv, jclass jcls,
        jobject state,
        jobject dst) {
    stodium_buffer state_buffer, dst_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &state_buffer, state);

    jint result = (jint) crypto_generichash_blake2b_final(
            AS_OUTPUT(crypto_generichash_blake2b_state, state_buffer),
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT_LEN(size_t, dst_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_output(jenv, state, &state_buffer);

    return result;
}

/** ****************************************************************************
 *
 * HASH
 *
 **************************************************************************** */

STODIUM_CONSTANT_STR(hash)

/** ****************************************************************************
 *
 * HASH - SHA-256
 *
 **************************************************************************** */

STODIUM_CONSTANT(hash, sha256, bytes)
STODIUM_CONSTANT(hash, sha256, statebytes)

STODIUM_JNI(jint, crypto_1hash_1sha256) (JNIEnv *jenv, jclass jcls,
        jobject mac,
        jobject src) {
    stodium_buffer mac_buffer, src_buffer;
    stodium_get_buffer(jenv, &mac_buffer, mac);
    stodium_get_buffer(jenv, &src_buffer, src);

    jint result = (jint) crypto_hash_sha256(
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer));

    stodium_release_output(jenv, mac, &mac_buffer);
    stodium_release_input(jenv, src, &src_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1hash_1sha256_1init) (JNIEnv *jenv, jclass jcls,
        jobject dst) {
    stodium_buffer dst_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);

    jint result = (jint) crypto_hash_sha256_init(
            AS_OUTPUT(crypto_hash_sha256_state, dst_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1hash_1sha256_1update) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src) {
    stodium_buffer dst_buffer, src_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);

    jint result = (jint) crypto_hash_sha256_update(
            AS_OUTPUT(crypto_hash_sha256_state, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1hash_1sha256_1final) (JNIEnv *jenv, jclass jcls,
        jobject state,
        jobject dst) {
    stodium_buffer state_buffer, dst_buffer;
    stodium_get_buffer(jenv, &state_buffer, state);
    stodium_get_buffer(jenv, &dst_buffer, dst);

    jint result = (jint) crypto_hash_sha256_final(
            AS_OUTPUT(crypto_hash_sha256_state, state_buffer),
            AS_OUTPUT(unsigned char, dst_buffer));

    stodium_release_output(jenv, state, &state_buffer);
    stodium_release_output(jenv, dst, &dst_buffer);

    return result;
}

/** ****************************************************************************
 *
 * HASH - SHA-512
 *
 **************************************************************************** */

STODIUM_CONSTANT(hash, sha512, bytes)
STODIUM_CONSTANT(hash, sha512, statebytes)

STODIUM_JNI(jint, crypto_1hash_1sha512) (JNIEnv *jenv, jclass jcls,
        jobject mac,
        jobject src) {
    stodium_buffer mac_buffer, src_buffer;
    stodium_get_buffer(jenv, &mac_buffer, mac);
    stodium_get_buffer(jenv, &src_buffer, src);

    jint result = (jint) crypto_hash_sha512(
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer));

    stodium_release_output(jenv, mac, &mac_buffer);
    stodium_release_input(jenv, src, &src_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1hash_1sha512_1init) (JNIEnv *jenv, jclass jcls,
        jobject dst) {
    stodium_buffer dst_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);

    jint result = (jint) crypto_hash_sha512_init(
            AS_OUTPUT(crypto_hash_sha512_state, dst_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1hash_1sha512_1update) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src) {
    stodium_buffer dst_buffer, src_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);

    jint result = (jint) crypto_hash_sha512_update(
            AS_OUTPUT(crypto_hash_sha512_state, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1hash_1sha512_1final) (JNIEnv *jenv, jclass jcls,
        jobject state,
        jobject dst) {
    stodium_buffer state_buffer, dst_buffer;
    stodium_get_buffer(jenv, &state_buffer, state);
    stodium_get_buffer(jenv, &dst_buffer, dst);

    jint result = (jint) crypto_hash_sha512_final(
            AS_OUTPUT(crypto_hash_sha512_state, state_buffer),
            AS_OUTPUT(unsigned char, dst_buffer));

    stodium_release_output(jenv, state, &state_buffer);
    stodium_release_output(jenv, dst, &dst_buffer);

    return result;
}

/** ****************************************************************************
 *
 * ONETIMEAUTH
 *
 **************************************************************************** */

STODIUM_CONSTANT_STR(onetimeauth)

/** ****************************************************************************
 *
 * ONETIMEAUTH - Poly1305
 *
 **************************************************************************** */

STODIUM_CONSTANT(onetimeauth, poly1305, bytes)
STODIUM_CONSTANT(onetimeauth, poly1305, keybytes)
STODIUM_CONSTANT(onetimeauth, poly1305, statebytes)

STODIUM_JNI(jint, crypto_1onetimeauth_1poly1305) (JNIEnv *jenv, jclass jcls,
        jobject mac,
        jobject src,
        jobject key) {
    stodium_buffer mac_buffer, src_buffer, key_buffer;
    stodium_get_buffer(jenv, &mac_buffer, mac);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_onetimeauth_poly1305(
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, mac, &mac_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1onetimeauth_1poly1305_1verify) (JNIEnv *jenv, jclass jcls,
        jobject mac,
        jobject src,
        jobject key) {
    stodium_buffer mac_buffer, src_buffer, key_buffer;
    stodium_get_buffer(jenv, &mac_buffer, mac);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_onetimeauth_poly1305_verify(
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_input(jenv, mac, &mac_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1onetimeauth_1poly1305_1init) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject key) {
    stodium_buffer dst_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_onetimeauth_poly1305_init(
            AS_OUTPUT(crypto_onetimeauth_poly1305_state, dst_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1onetimeauth_1poly1305_1update) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src) {
    stodium_buffer dst_buffer, src_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);

    jint result = (jint) crypto_onetimeauth_poly1305_update(
            AS_OUTPUT(crypto_onetimeauth_poly1305_state, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1onetimeauth_1poly1305_1final) (JNIEnv *jenv, jclass jcls,
        jobject state,
        jobject dst) {
    stodium_buffer state_buffer, dst_buffer;
    stodium_get_buffer(jenv, &state_buffer, state);
    stodium_get_buffer(jenv, &dst_buffer, dst);

    jint result = (jint) crypto_onetimeauth_poly1305_final(
            AS_OUTPUT(crypto_onetimeauth_poly1305_state, state_buffer),
            AS_OUTPUT(unsigned char, dst_buffer));

    stodium_release_output(jenv, state, &state_buffer);
    stodium_release_output(jenv, dst, &dst_buffer);

    return result;
}

/** ****************************************************************************
 *
 * SECRETBOX - XSalsa20Poly1305
 *
 **************************************************************************** */

STODIUM_CONSTANT_STR(secretbox)

STODIUM_CONSTANT_HL(secretbox, keybytes)
STODIUM_CONSTANT_HL(secretbox, macbytes)
STODIUM_CONSTANT_HL(secretbox, noncebytes)

STODIUM_JNI(jint, crypto_1secretbox_1easy) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, src_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_secretbox_easy(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, nonce, &nonce_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1secretbox_1open_1easy) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, src_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_secretbox_open_easy(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, nonce, &nonce_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1secretbox_1detached) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject dst_mac,
        jobject src,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, mac_buffer, src_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &mac_buffer, dst_mac);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_secretbox_detached(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_OUTPUT(unsigned char, mac_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_output(jenv, dst_mac, &mac_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, nonce, &nonce_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

STODIUM_JNI(jint, crypto_1secretbox_1open_1detached) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src,
        jobject src_mac,
        jobject nonce,
        jobject key) {
    stodium_buffer dst_buffer, mac_buffer, src_buffer, nonce_buffer, key_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &mac_buffer, src_mac);
    stodium_get_buffer(jenv, &src_buffer, src);
    stodium_get_buffer(jenv, &nonce_buffer, nonce);
    stodium_get_buffer(jenv, &key_buffer, key);

    jint result = (jint) crypto_secretbox_open_detached(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, src_buffer),
            AS_INPUT(unsigned char, mac_buffer),
            AS_INPUT_LEN(unsigned long long, src_buffer),
            AS_INPUT(unsigned char, nonce_buffer),
            AS_INPUT(unsigned char, key_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    stodium_release_input(jenv, src_mac, &mac_buffer);
    stodium_release_input(jenv, nonce, &nonce_buffer);
    stodium_release_input(jenv, key, &key_buffer);

    return result;
}

/** ****************************************************************************
 *
 * PWHASH
 *
 **************************************************************************** */

STODIUM_CONSTANT_STR(pwhash)

STODIUM_CONSTANT_HL(pwhash, saltbytes)
STODIUM_CONSTANT_HL(pwhash, strbytes)
//STODIUM_CONSTANT_HL(pwhash, strprefix)
STODIUM_JNI(jint, crypto_1pwhash_1alg_1default) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_pwhash_alg_default();
}
STODIUM_JNI(jint, crypto_1pwhash_1memlimit_1interactive) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_pwhash_memlimit_interactive();
}
STODIUM_JNI(jint, crypto_1pwhash_1opslimit_1interactive) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_pwhash_opslimit_interactive();
}
STODIUM_JNI(jint, crypto_1pwhash_1memlimit_1moderate) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_pwhash_memlimit_moderate();
}
STODIUM_JNI(jint, crypto_1pwhash_1opslimit_1moderate) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_pwhash_opslimit_moderate();
}
STODIUM_JNI(jint, crypto_1pwhash_1memlimit_1sensitive) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_pwhash_memlimit_sensitive();
}
STODIUM_JNI(jint, crypto_1pwhash_1opslimit_1sensitive) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_pwhash_opslimit_sensitive();
}

STODIUM_JNI(jint, crypto_1pwhash) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject password,
        jobject salt,
        jint opslimit,
        jint memlimit) {
    stodium_buffer dst_buffer, pw_buffer, salt_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &pw_buffer, password);
    stodium_get_buffer(jenv, &salt_buffer, salt);

    jint result = (jint) crypto_pwhash(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT_LEN(unsigned long long, dst_buffer),
            AS_INPUT(char, pw_buffer),
            AS_INPUT_LEN(unsigned long long, pw_buffer),
            AS_INPUT(unsigned char, salt_buffer),
            (unsigned long long) opslimit,
            (size_t) memlimit,
            crypto_pwhash_ALG_DEFAULT);

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, password, &pw_buffer);
    stodium_release_input(jenv, salt, &salt_buffer);

    return result;
}

/** ****************************************************************************
 *
 * PWHASH - Scrypt
 *
 **************************************************************************** */

STODIUM_CONSTANT(pwhash, scryptsalsa208sha256, saltbytes)
STODIUM_CONSTANT(pwhash, scryptsalsa208sha256, strbytes)
//STODIUM_CONSTANT(pwhash, scryptsalsa208sha256, strprefix)

STODIUM_JNI(jint, crypto_1pwhash_1scryptsalsa208sha256_1memlimit_1interactive) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_pwhash_scryptsalsa208sha256_memlimit_interactive();
}
STODIUM_JNI(jint, crypto_1pwhash_1scryptsalsa208sha256_1opslimit_1interactive) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_pwhash_scryptsalsa208sha256_opslimit_interactive();
}
STODIUM_JNI(jint, crypto_1pwhash_1scryptsalsa208sha256_1memlimit_1sensitive) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive();
}
STODIUM_JNI(jint, crypto_1pwhash_1scryptsalsa208sha256_1opslimit_1sensitive) (JNIEnv *jenv, jclass jcls) {
       return (jint) crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive();
}

STODIUM_JNI(jint, crypto_1pwhash_1scryptsalsa208sha256) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject password,
        jobject salt,
        jint opslimit,
        jint memlimit) {
    stodium_buffer dst_buffer, pw_buffer, salt_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &pw_buffer, password);
    stodium_get_buffer(jenv, &salt_buffer, salt);

    jint result = (jint) crypto_pwhash_scryptsalsa208sha256(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT_LEN(unsigned long long, dst_buffer),
            AS_INPUT(char, pw_buffer),
            AS_INPUT_LEN(unsigned long long, pw_buffer),
            AS_INPUT(unsigned char, salt_buffer),
            (unsigned long long) opslimit,
            (size_t) memlimit);

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, password, &pw_buffer);
    stodium_release_input(jenv, salt, &salt_buffer);

    return result;
}

/** ****************************************************************************
 *
 * SCALARMULT - Curve25519
 *
 **************************************************************************** */
STODIUM_CONSTANT_STR(scalarmult)

STODIUM_CONSTANT(scalarmult, curve25519, bytes)
STODIUM_CONSTANT(scalarmult, curve25519, scalarbytes)

STODIUM_JNI(jint, crypto_1scalarmult_1curve25519) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject priv,
        jobject pub) {
    stodium_buffer dst_buffer, priv_buffer, pub_buffer;
    stodium_get_buffer(jenv, &dst_buffer,  dst);
    stodium_get_buffer(jenv, &priv_buffer, priv);
    stodium_get_buffer(jenv, &pub_buffer,  pub);

    jint result = (jint) crypto_scalarmult_curve25519(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char,  priv_buffer),
            AS_INPUT(unsigned char,  pub_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, priv, &priv_buffer);
    stodium_release_input(jenv, pub, &pub_buffer);
    
    return result;
}

STODIUM_JNI(jint, crypto_1scalarmult_1curve25519_1base) (JNIEnv *jenv, jclass jcls,
        jobject dst,
        jobject src) {
    stodium_buffer dst_buffer, src_buffer;
    stodium_get_buffer(jenv, &dst_buffer, dst);
    stodium_get_buffer(jenv, &src_buffer, src);
    
    jint result = (jint) crypto_scalarmult_curve25519_base(
            AS_OUTPUT(unsigned char, dst_buffer),
            AS_INPUT(unsigned char, src_buffer));

    stodium_release_output(jenv, dst, &dst_buffer);
    stodium_release_input(jenv, src, &src_buffer);
    
    return result;
}

#ifdef __cplusplus
}
#endif
