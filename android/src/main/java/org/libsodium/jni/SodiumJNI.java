package org.libsodium.jni;

public class SodiumJNI {
  public final static native int sodium_init();
  public final static native String sodium_version_string();

  public final static native long randombytes_random();
  public final static native long randombytes_uniform(long upper_bound);
  public final static native void randombytes_buf(byte[] buf, int size);
  public final static native int  randombytes_close();
  public final static native void randombytes_stir();

  public final static native int crypto_secretbox_keybytes();
  public final static native int crypto_secretbox_noncebytes();
  public final static native int crypto_secretbox_macbytes();
  public final static native void crypto_secretbox_keygen(byte[] key);
  public final static native int crypto_secretbox_easy(byte[] c, final byte[] m, final long mlen, final byte[] n, final byte[] k);
  public final static native int crypto_secretbox_open_easy(byte[] m, final byte[] c, final long clen,  final byte[] n, final byte[] k);

  public final static native int crypto_auth_keybytes();
  public final static native int crypto_auth_bytes();
  public final static native void crypto_auth_keygen(byte[] key);
  public final static native int crypto_auth(byte[] out, final byte[] in, final long inlen,  final byte[] k);
  public final static native int crypto_auth_verify(final byte[] h, final byte[] in, final long inlen, final byte[] k);

  public final static native int crypto_box_publickeybytes();
  public final static native int crypto_box_secretkeybytes();
  public final static native int crypto_box_beforenmbytes();
  public final static native int crypto_box_seedbytes();
  public final static native int crypto_box_noncebytes();
  public final static native int crypto_box_macbytes();
  public final static native int crypto_box_zerobytes();
  public final static native int crypto_box_boxzerobytes();
  public final static native int crypto_box_sealbytes();
  public final static native int crypto_box_keypair(byte[] pk, byte[] sk);
  public final static native int crypto_box_easy(byte[] c, final byte[] m, final long mlen, final byte[] n, final byte[] pk, final byte[] sk);
  public final static native int crypto_box_open_easy(byte[] m, final byte[] c, final long clen,  final byte[] n, final byte[] pk, final byte[] sk);

  public final static native int crypto_box_beforenm(byte[] s, final byte[] pk, final byte[] sk);
  public final static native int crypto_box_easy_afternm(byte[] c, byte[] m, long mlen, byte [] n, byte[] k);
  public final static native int crypto_box_open_easy_afternm(byte[] m, byte[] c, long clen, byte[] n, byte[] k);

  public final static native int crypto_box_seal(byte[] c, byte[] m, long mlen, byte[] pk);
  public final static native int crypto_box_seal_open(byte[] m, byte[] c, long clen, byte[] pk, byte[] sk);

  public final static native int crypto_pwhash(byte[] out, final long olen, final byte[] password, final long plen, byte[] salt, long opslimit, long memlimit, int algo);
  public final static native int crypto_pwhash_salt_bytes();
  public final static native int crypto_pwhash_opslimit_moderate();
  public final static native int crypto_pwhash_opslimit_min();
  public final static native int crypto_pwhash_opslimit_max();
  public final static native int crypto_pwhash_memlimit_moderate();
  public final static native int crypto_pwhash_memlimit_min();
  public final static native int crypto_pwhash_memlimit_max();
  public final static native int crypto_pwhash_algo_default();
  public final static native int crypto_pwhash_algo_argon2i13();
  public final static native int crypto_pwhash_algo_argon2id13();

  public final static native int crypto_scalarmult_bytes();
  public final static native int crypto_scalarmult_scalarbytes();
  public final static native int crypto_scalarmult_base(byte[] q, final byte[] n);
  public final static native int crypto_scalarmult(byte[] q, final byte[] n, final byte[] p);

  public final static native int crypto_sign_publickeybytes();
  public final static native int crypto_sign_secretkeybytes();
  public final static native int crypto_sign_seedbytes();
  public final static native int crypto_sign_bytes();
  public final static native int crypto_sign_detached(byte[] sig, final byte[] msg, final int msg_len, final byte[] sk);
  public final static native int crypto_sign_verify_detached(byte[] sig, byte[] msg, long msg_len, final byte[] pk);
  public final static native int crypto_sign_keypair(byte[] pk, byte[] sk);
  public final static native int crypto_sign_seed_keypair(byte[] pk, byte[] sk, final byte[] seed);
  public final static native int crypto_sign_ed25519_sk_to_seed(byte[] seed, final byte[] sk);
  public final static native int crypto_sign_ed25519_pk_to_curve25519(byte[] curve25519_pk, final byte[] ed25519_pk);
  public final static native int crypto_sign_ed25519_sk_to_curve25519(byte[] curve25519_sk, final byte[] ed25519_sk);
  public final static native int crypto_sign_ed25519_sk_to_pk(byte[] sk, byte[] pk);

  public final static native int crypto_core_ed25519_bytes();
  public final static native int crypto_core_ed25519_uniformbytes();
  public final static native int crypto_core_ed25519_scalarbytes();
  public final static native int crypto_core_ed25519_nonreducedscalarbytes();
  public final static native int crypto_aead_xchacha20poly1305_ietf_keybytes();
  public final static native int crypto_aead_xchacha20poly1305_ietf_npubbytes();

  public final static native void crypto_core_ed25519_random(byte[] p);
  public final static native int crypto_core_ed25519_from_uniform(byte[] p, final byte[] r);
  public final static native int crypto_core_ed25519_add(byte[] r, final byte[] p, final byte[] q);
  public final static native int crypto_core_ed25519_sub(byte[] r, final byte[] p, final byte[] q);
  public final static native int crypto_core_ed25519_is_valid_point(final byte[] p);

  public final static native void crypto_core_ed25519_scalar_random(byte[] r);
  public final static native void crypto_core_ed25519_scalar_add(byte[] z, final byte[] x, final byte[] y);
  public final static native void crypto_core_ed25519_scalar_sub(byte[] z, final byte[] x, final byte[] y);
  public final static native void crypto_core_ed25519_scalar_mul(byte[] z, final byte[] x, final byte[] y);
  public final static native void crypto_core_ed25519_scalar_negate(byte[] neg, final byte[] s);
  public final static native void crypto_core_ed25519_scalar_complement(byte[] comp, final byte[] s);
  public final static native int crypto_core_ed25519_scalar_invert(byte[] recip, final byte[] s);
  public final static native void crypto_core_ed25519_scalar_reduce(byte[] r, final byte[] s);

  public final static native int crypto_scalarmult_ed25519(byte[] q, final byte[] n, final byte[] p);
  public final static native int crypto_scalarmult_ed25519_noclamp(byte[] q, final byte[] n, final byte[] p);
  public final static native int crypto_scalarmult_ed25519_base(byte[] q, final byte[] n);
  public final static native int crypto_scalarmult_ed25519_base_noclamp(byte[] q, final byte[] n);

  public final static native int crypto_generichash(
          byte[] out,
          final long outlen,
          final byte[] in,
          final long inlen,
          final byte[] key,
          final long keylen);

  public final static native void crypto_aead_chacha20poly1305_ietf_keygen(byte[] k);
  public final static native int crypto_aead_xchacha20poly1305_ietf_encrypt(
          byte[] c,
          final byte[] m,
          final long mlen,
          final byte[] ad,
          final long adlen,
          final byte[] nsec,
          final long nseclen,
          final byte[] npub,
          final byte[] k);

  public final static native int crypto_aead_xchacha20poly1305_ietf_decrypt(
          byte[] m,
          byte[] nsec,
          final long nseclen,
          final byte[] c,
          final long clen,
          final byte[] ad,
          final long adlen,
          final byte[] npub,
          final byte[] k);
}
