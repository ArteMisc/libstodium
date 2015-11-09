/* sodium.i */
%module Sodium

%include "typemaps.i"
%include "stdint.i"
%include "arrays_java.i"
%include "carrays.i"
%include "various.i"

%apply int {unsigned long long};
%apply long[] {unsigned long long *};
%apply long {size_t};

/* TODO map void* to byteArray */

%typemap(jni) unsigned char *"jbyteArray"
%typemap(jtype) unsigned char *"byte[]"
%typemap(jstype) unsigned char *"byte[]"
%typemap(in) unsigned char *{
    $1 = (unsigned char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}

%typemap(argout) unsigned char *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}

%typemap(javain) unsigned char *"$javainput"

/* Prevent default freearg typemap from being used */
%typemap(freearg) unsigned char *""



/* char types */
%typemap(jni) char *BYTE "jbyteArray"
%typemap(jtype) char *BYTE "byte[]"
%typemap(jstype) char *BYTE "byte[]"
%typemap(in) char *BYTE {
    $1 = (char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}

%typemap(argout) char *BYTE {
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}

%typemap(javain) char *BYTE "$javainput"

/* Prevent default freearg typemap from being used */
%typemap(freearg) char *BYTE ""





/* ***************************** */


/*
%typemap(jni) unsigned char*        "jbyteArray"
%typemap(jtype) unsigned char*      "byte[]"
%typemap(jstype) unsigned char*     "byte[]"
*/
 
%{
 /* Put header files here or function declarations like below */
#include "sodium.h"

%}

/*
    Runtime API
*/
int sodium_init(void);

const char *sodium_version_string(void);

/* void randombytes(unsigned char * const buf, const unsigned long long buf_len); */
void randombytes(unsigned char *dst_buf,
                 unsigned long long buf_len);

/*
    randombytes API
*/

/*void randombytes_buf(void * const buf, const size_t size);*/
void randombytes_buf(unsigned char * const buff,
                     const unsigned long long buff_len);

int randombytes_close(void);

void randombytes_stir(void);

/*
    helpers API
*/
/*int sodium_memcmp(const void * const b1_,
                  const void * const b2_,
                  size_t len);*/

void sodium_increment(unsigned char *src_dst_number,
                      const size_t number_len);

/*
    crypto_secretbox API
*/
int crypto_secretbox_easy(unsigned char *dst_cipher,
                          const unsigned char *src_plain,
                          unsigned long long plain_len,
                          const unsigned char *nonce,
                          const unsigned char *secret_key);

int crypto_secretbox_open_easy(unsigned char *dst_plain,
                               const unsigned char *src_cipher,
                               unsigned long long cipher_len,
                               const unsigned char *nonce,
                               const unsigned char *secret_key);

/*
    crypto_secretbox_detached API
*/
int crypto_secretbox_detached(unsigned char *dst_cipher,
                              unsigned char *mac,
                              const unsigned char *src_plain,
                              unsigned long long plain_len,
                              const unsigned char *nonce,
                              const unsigned char *secretkey);

int crypto_secretbox_open_detached(unsigned char *dst_plain,
                                   const unsigned char *src_cipher,
                                   const unsigned char *mac,
                                   unsigned long long cipher_len,
                                   const unsigned char *nonce,
                                   const unsigned char *secretkey);

/*
    crypto_box API
*/

int crypto_box_keypair(unsigned char *dst_public_Key,
                       unsigned char *dst_private_key);

int crypto_box_seed_keypair(unsigned char *dst_public_key,
                            unsigned char *dst_private_key,
                            const unsigned char *src_seed);

int crypto_scalarmult_base(unsigned char *dst_group_element,
                           const unsigned char *src_n_multiplier);

int crypto_box_easy(unsigned char *dst_cipher,
                    const unsigned char *src_plain,
                    unsigned long long plain_len,
                    const unsigned char *nonce,
                    const unsigned char *remote_public_key,
                    const unsigned char *local_private_key);

int crypto_box_open_easy(unsigned char *dst_plain,
                         const unsigned char *src_cipher,
                         unsigned long long cipher_len,
                         const unsigned char *nonce,
                         const unsigned char *remote_public_key,
                         const unsigned char *local_private_key);

int crypto_box_detached(unsigned char *dst_cipher,
                        unsigned char *dst_mac,
                        const unsigned char *src_plain,
                        unsigned long long plain_len,
                        const unsigned char *nonces,
                        const unsigned char *remote_public_key,
                        const unsigned char *local_private_key);

int crypto_box_open_detached(unsigned char *dst_plain,
                             const unsigned char *src_cipher,
                             const unsigned char *src_mac,
                             unsigned long long cipher_len,
                             const unsigned char *nonce,
                             const unsigned char *remote_public_key,
                             const unsigned char *local_private_key);

int crypto_box_beforenm(unsigned char *dst_shared_key,
                        const unsigned char *remote_public_key,
                        const unsigned char *local_private_key);

int crypto_box_easy_afternm(unsigned char *dst_cipher,
                            const unsigned char *src_plain,
                            unsigned long long plain_len,
                            const unsigned char *nonce,
                            const unsigned char *shared_key);

int crypto_box_open_easy_afternm(unsigned char *dst_plain,
                                 const unsigned char *src_cipher,
                                 unsigned long long cipher_len,
                                 const unsigned char *nonce,
                                 const unsigned char *shared_key);

int crypto_box_detached_afternm(unsigned char *dst_cipher,
                                unsigned char *dst_mac,
                                const unsigned char *src_plain,
                                unsigned long long plain_len,
                                const unsigned char *nonce,
                                const unsigned char *shared_key);

int crypto_box_open_detached_afternm(unsigned char *dst_plain,
                                     const unsigned char *src_cipher,
                                     const unsigned char *src_mac,
                                     unsigned long long cipher_len,
                                     const unsigned char *nonce,
                                     const unsigned char *shared_key);

/*
    crypto_box_seal API
*/
int crypto_box_seal(unsigned char *dst_cipher,
                    const unsigned char *src_plain,
                    unsigned long long plain_len,
                    const unsigned char *remote_public_key);

int crypto_box_seal_open(unsigned char *dst_plain,
                         const unsigned char *src_cipher,
                         unsigned long long cipher_len,
                         const unsigned char *local_public_key,
                         const unsigned char *local_private_key);

/*
    crypto_sign API
*/

int crypto_sign_keypair(unsigned char *dst_public_Key,
                        unsigned char *dst_private_key);

int crypto_sign_seed_keypair(unsigned char *dst_public_Key,
                             unsigned char *dst_private_key,
                             const unsigned char *src_seed);

int crypto_sign(unsigned char *dst_signed_msg,
                unsigned long long *signed_msg_len,
                const unsigned char *src_msg,
                unsigned long long msg_len,
                const unsigned char *local_private_key);

int crypto_sign_open(unsigned char *dst_msg,
                     unsigned long long *msg_len,
                     const unsigned char *src_signed_msg,
                     unsigned long long signed_msg_len,
                     const unsigned char *remote_public_key);

int crypto_sign_detached(unsigned char *dst_signature,
                         unsigned long long *signature_len,
                         const unsigned char *src_msg,
                         unsigned long long msg_len,
                         const unsigned char *local_private_key);

int crypto_sign_verify_detached(const unsigned char *src_signature,
                                const unsigned char *src_msg,
                                unsigned long long msg_len,
                                const unsigned char *remote_public_key);

int crypto_sign_ed25519_sk_to_seed(unsigned char *dst_seed,
                                   const unsigned char *src_private_key);

int crypto_sign_ed25519_sk_to_pk(unsigned char *dst_public_key,
                                 const unsigned char *src_private_key);

/*
    crypto_hash API
*/
int crypto_generichash(unsigned char *dst_hash,
                       unsigned long long dst_len,
                       const unsigned char *src_input,
                       unsigned long long input_len,
                       const unsigned char *src_key,
                       unsigned long long key_len);

/*
    crypto_auth API
*/
int crypto_auth(unsigned char *out,
                const unsigned char *in,
                unsigned long long inlen,
                const unsigned char *k);

int crypto_auth_verify(const unsigned char *h,
                       const unsigned char *in,
                       unsigned long long inlen,
                       const unsigned char *k);

/*
    crypto_onetimeauth API
    TODO streaming interface
*/
int crypto_onetimeauth(unsigned char *out,
                       const unsigned char *in,
                       unsigned long long inlen,
                       const unsigned char *k);

int crypto_onetimeauth_verify(const unsigned char *h,
                              const unsigned char *in,
                              unsigned long long inlen,
                              const unsigned char *k);

/*

the crypto_generichash_* methods require the existence of a
crypto_generichash_state type. TODO

Note: Some instances of size_t have been replaced by unsigned long long.

int crypto_generichash_init(crypto_generichash_state *state,
                            const unsigned char *key,
                            const unsigned long long keylen,
                            const unsigned long long outlen);

int crypto_generichash_update(crypto_generichash_state *state,
                              const unsigned char *in,
                              unsigned long long inlen);

int crypto_generichash_final(crypto_generichash_state *state,
                             unsigned char *out,
                             const unsigned long long outlen);
*/

/* TODO update these methods */

int crypto_aead_chacha20poly1305_encrypt(unsigned char *c,
                                         unsigned long long *clen,
                                         const unsigned char *m,
                                         unsigned long long mlen,
                                         const unsigned char *ad,
                                         unsigned long long adlen,
                                         const unsigned char *nsec,
                                         const unsigned char *npub,
                                         const unsigned char *k);

int crypto_aead_chacha20poly1305_decrypt(unsigned char *m,
                                         unsigned long long *mlen,
                                         unsigned char *nsec,
                                         const unsigned char *c,
                                         unsigned long long clen,
                                         const unsigned char *ad,
                                         unsigned long long adlen,
                                         const unsigned char *npub,
                                         const unsigned char *k);

int crypto_hash_sha256(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen);

int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen);

int crypto_generichash_blake2b(unsigned char *out, size_t outlen,
                               const unsigned char *in,
                               unsigned long long inlen,
                               const unsigned char *key, size_t keylen);
                           
int crypto_pwhash_scryptsalsa208sha256(unsigned char * const out,
                                    unsigned long long outlen,
                                    const char * const passwd,
                                    unsigned long long passwdlen,
                                    const unsigned char * const salt,
                                    unsigned long long opslimit,
                                    size_t memlimit);

int crypto_box_curve25519xsalsa20poly1305_keypair(unsigned char *pk,
                                                  unsigned char *sk);

int crypto_box_curve25519xsalsa20poly1305_seed_keypair(unsigned char *pk, unsigned char *sk,
                        const unsigned char *seed);


int crypto_box_curve25519xsalsa20poly1305(unsigned char *c,
                                          const unsigned char *m,
                                          unsigned long long mlen,
                                          const unsigned char *n,
                                          const unsigned char *pk,
                                          const unsigned char *sk);


int crypto_box_curve25519xsalsa20poly1305_open(unsigned char *m,
                                               const unsigned char *c,
                                               unsigned long long clen,
                                               const unsigned char *n,
                                               const unsigned char *pk,
                                               const unsigned char *sk);


int crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
                                 const unsigned char *p);

int crypto_secretbox_xsalsa20poly1305(unsigned char *c,
                                      const unsigned char *m,
                                      unsigned long long mlen,
                                      const unsigned char *n,
                                      const unsigned char *k);

int crypto_secretbox_xsalsa20poly1305_open(unsigned char *m,
                                           const unsigned char *c,
                                           unsigned long long clen,
                                           const unsigned char *n,
                                           const unsigned char *k);

int crypto_sign_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
                                     const unsigned char *seed);

int crypto_sign_ed25519(unsigned char *sm, unsigned long long *smlen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *sk);

int crypto_sign_ed25519_open(unsigned char *m, unsigned long long *mlen,
                             const unsigned char *sm, unsigned long long smlen,
                             const unsigned char *pk);
                             
                             
int crypto_stream_xsalsa20(unsigned char *c, unsigned long long clen,
              const unsigned char *n, const unsigned char *k);


int crypto_stream_xsalsa20_xor(unsigned char *c, const unsigned char *m,
                  unsigned long long mlen, const unsigned char *n,
                  const unsigned char *k);

int crypto_core_hsalsa20(unsigned char *out, const unsigned char *in,
                         const unsigned char *k, const unsigned char *c);
