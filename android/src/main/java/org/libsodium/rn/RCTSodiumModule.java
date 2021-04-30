package org.libsodium.rn;

/**
* Created by Lyubomir Ivanov on 21/09/16.
*/

import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import android.util.Base64;
import android.util.Log;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.common.MapBuilder;

import org.libsodium.jni.Sodium;

public class RCTSodiumModule extends ReactContextBaseJavaModule {

  private static final ExecutorService executor = Executors.newSingleThreadExecutor();

  private void runOnExecutor(Runnable runnable) {
    executor.execute(runnable);
  }

  static final String ESODIUM = "ESODIUM";
  static final String ERR_BAD_KEY = "BAD_KEY";
  static final String ERR_BAD_MAC = "BAD_MAC";
  static final String ERR_BAD_MSG = "BAD_MSG";
  static final String ERR_BAD_NONCE = "BAD_NONCE";
  static final String ERR_BAD_SEED = "BAD_SEED";
  static final String ERR_BAD_SIG = "BAD_SIG";
  static final String ERR_FAILURE = "FAILURE";

  static final String ERR_CODE_FAILURE = "FAILURE";
  static final String RES_CODE_SUCCESS = "SUCCESS";

  public RCTSodiumModule(ReactApplicationContext reactContext) {
    super(reactContext);
    Sodium.loadLibrary();
  }

  @Override
  public String getName() {
    return "Sodium";
  }

  @Override
  public Map<String, Object> getConstants() {
     final Map<String, Object> constants = new HashMap<>();
     constants.put("crypto_secretbox_KEYBYTES", Sodium.crypto_secretbox_keybytes());
     constants.put("crypto_secretbox_NONCEBYTES", Sodium.crypto_secretbox_noncebytes());
     constants.put("crypto_secretbox_MACBYTES", Sodium.crypto_secretbox_macbytes());
     constants.put("crypto_auth_KEYBYTES", Sodium.crypto_auth_keybytes());
     constants.put("crypto_auth_BYTES", Sodium.crypto_auth_bytes());
     constants.put("crypto_box_PUBLICKEYBYTES", Sodium.crypto_box_publickeybytes());
     constants.put("crypto_box_SECRETKEYBYTES", Sodium.crypto_box_secretkeybytes());
     constants.put("crypto_box_BEFORENMBYTES", Sodium.crypto_box_beforenmbytes());
     constants.put("crypto_box_SEEDBYTES", Sodium.crypto_box_seedbytes());
     constants.put("crypto_box_NONCEBYTES", Sodium.crypto_box_noncebytes());
     constants.put("crypto_box_MACBYTES", Sodium.crypto_box_macbytes());
     constants.put("crypto_box_ZEROBYTES", Sodium.crypto_box_zerobytes());
     constants.put("crypto_box_BOXZEROBYTES", Sodium.crypto_box_boxzerobytes());
     constants.put("crypto_box_SEALBYTES", Sodium.crypto_box_sealbytes());
     constants.put("crypto_sign_PUBLICKEYBYTES", Sodium.crypto_sign_publickeybytes());
     constants.put("crypto_sign_SECRETKEYBYTES", Sodium.crypto_sign_secretkeybytes());
     constants.put("crypto_sign_SEEDBYTES", Sodium.crypto_sign_seedbytes());
     constants.put("crypto_sign_BYTES", Sodium.crypto_sign_bytes());
     constants.put("crypto_pwhash_SALTBYTES", Sodium.crypto_pwhash_salt_bytes());
     constants.put("crypto_pwhash_OPSLIMIT_MODERATE", Sodium.crypto_pwhash_opslimit_moderate());
     constants.put("crypto_pwhash_OPSLIMIT_MIN", Sodium.crypto_pwhash_opslimit_min());
     constants.put("crypto_pwhash_OPSLIMIT_MAX", Sodium.crypto_pwhash_opslimit_max());
     constants.put("crypto_pwhash_MEMLIMIT_MODERATE", Sodium.crypto_pwhash_memlimit_moderate());
     constants.put("crypto_pwhash_MEMLIMIT_MIN", Sodium.crypto_pwhash_memlimit_min());
     constants.put("crypto_pwhash_MEMLIMIT_MAX", Sodium.crypto_pwhash_memlimit_max());
     constants.put("crypto_pwhash_ALG_DEFAULT", Sodium.crypto_pwhash_algo_default());
     constants.put("crypto_pwhash_ALG_ARGON2I13", Sodium.crypto_pwhash_algo_argon2i13());
     constants.put("crypto_pwhash_ALG_ARGON2ID13", Sodium.crypto_pwhash_algo_argon2id13());
     constants.put("crypto_scalarmult_BYTES", Sodium.crypto_scalarmult_bytes());
     constants.put("crypto_scalarmult_SCALARBYTES", Sodium.crypto_scalarmult_scalarbytes());

     constants.put("crypto_core_ed25519_BYTES", Sodium.crypto_core_ed25519_bytes());
     constants.put("crypto_core_ed25519_UNIFORMBYTES", Sodium.crypto_core_ed25519_uniformbytes());
     constants.put("crypto_core_ed25519_SCALARBYTES", Sodium.crypto_core_ed25519_scalarbytes());
     constants.put("crypto_core_ed25519_NONREDUCEDSCALARBYTES", Sodium.crypto_core_ed25519_nonreducedscalarbytes());
     constants.put("crypto_aead_xchacha20poly1305_ietf_KEYBYTES", Sodium.crypto_aead_xchacha20poly1305_ietf_keybytes());
     constants.put("crypto_aead_xchacha20poly1305_ietf_NPUBBYTES", Sodium.crypto_aead_xchacha20poly1305_ietf_npubbytes());
     return constants;
  }

  // ***************************************************************************
  // * Sodium-specific functions
  // ***************************************************************************
  @ReactMethod
  public void sodium_version_string(final Promise p) {
    p.resolve(Sodium.sodium_version_string());
  }

  // ***************************************************************************
  // * Random data generation
  // ***************************************************************************
  @ReactMethod
  public void randombytes_random(final Promise p) {
    // RN0.34: Long can't be passed through the bridge (int and double only)
    p.resolve(Long.valueOf(Sodium.randombytes_random()).doubleValue());
  }

  @ReactMethod
  public void randombytes_uniform(Double upper_bound, final Promise p) {
    // RN0.34: Long can't be passed through the bridge (int and double only)
    p.resolve(Long.valueOf(Sodium.randombytes_uniform(upper_bound.longValue())).doubleValue());
  }

  @ReactMethod
  public void randombytes_buf(int size, final Promise p) {
    try {
      byte[] buf = new byte[size];
      Sodium.randombytes_buf(buf, size);
      p.resolve(Base64.encodeToString(buf,Base64.NO_WRAP));
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void randombytes_close(final Promise p) {
    int result = Sodium.randombytes_close();
    if (result == 0) p.resolve(0); else p.reject(ESODIUM,ERR_FAILURE);
  }

  @ReactMethod
  public void randombytes_stir(final Promise p) {
    Sodium.randombytes_stir();
    p.resolve(0);
  }


  // ***************************************************************************
  // * Secret-key cryptography - authenticated encryption
  // ***************************************************************************
  @ReactMethod
  public void crypto_secretbox_keygen(final Promise p){
    try {
      byte[] key = new byte[Sodium.crypto_secretbox_keybytes()];
      Sodium.crypto_secretbox_keygen(key);

      p.resolve(Base64.encodeToString(key,Base64.NO_WRAP));
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_secretbox_easy(final String m, final String n, final String k, final Promise p) {
    try {
      byte[] mb = Base64.decode(m, Base64.NO_WRAP);
      byte[] nb = Base64.decode(n, Base64.NO_WRAP);
      byte[] kb = Base64.decode(k, Base64.NO_WRAP);
      if (kb.length != Sodium.crypto_secretbox_keybytes())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else if (nb.length != Sodium.crypto_secretbox_noncebytes())
        p.reject(ESODIUM,ERR_BAD_NONCE);
      else {
        byte[] cb = new byte[mb.length + Sodium.crypto_secretbox_macbytes()];
        int result = Sodium.crypto_secretbox_easy(cb, mb, mb.length, nb, kb);
        if (result != 0)
          p.reject(ESODIUM,ERR_FAILURE);
        else
          p.resolve(Base64.encodeToString(cb,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_secretbox_open_easy(final String c, final String n, final String k, final Promise p) {
    try {
      byte[] cb = Base64.decode(c, Base64.NO_WRAP);
      byte[] nb = Base64.decode(n, Base64.NO_WRAP);
      byte[] kb = Base64.decode(k, Base64.NO_WRAP);
      if (kb.length != Sodium.crypto_secretbox_keybytes())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else if (nb.length != Sodium.crypto_secretbox_noncebytes())
        p.reject(ESODIUM,ERR_BAD_NONCE);
      else if (cb.length <=  Sodium.crypto_secretbox_macbytes())
        p.reject(ESODIUM,ERR_BAD_MSG);
      else {
        byte[] mb = new byte[cb.length - Sodium.crypto_secretbox_macbytes()];
        int result = Sodium.crypto_secretbox_open_easy(mb, cb, cb.length, nb, kb);
        if (result != 0)
          p.reject(ESODIUM,ERR_FAILURE);
        else
          p.resolve(Base64.encodeToString(mb,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  // ***************************************************************************
  // * Secret-key cryptography - authentication
  // ***************************************************************************
  @ReactMethod
  public void crypto_auth_keygen(final Promise p){
    try {
      byte[] key = new byte[Sodium.crypto_auth_keybytes()];
      Sodium.crypto_auth_keygen(key);

      p.resolve(Base64.encodeToString(key,Base64.NO_WRAP));
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_auth(String in, String k, final Promise p){
    try {
      byte[] out = new byte[Sodium.crypto_auth_bytes()];
      byte[] inb = Base64.decode(in, Base64.NO_WRAP);
      byte[] kb = Base64.decode(k, Base64.NO_WRAP);
      if (kb.length != Sodium.crypto_auth_keybytes())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else {
        int result = Sodium.crypto_auth(out, inb, inb.length, kb);
        if (result != 0)
          p.reject(ESODIUM,ERR_FAILURE);
        else
          p.resolve(Base64.encodeToString(out,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_auth_verify(String h, String in, String k, final Promise p){
    try {
      byte[] inb = Base64.decode(in, Base64.NO_WRAP);
      byte[] hb = Base64.decode(h, Base64.NO_WRAP);
      byte[] kb = Base64.decode(k, Base64.NO_WRAP);
      if (kb.length != Sodium.crypto_auth_keybytes())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else if (hb.length != Sodium.crypto_auth_bytes())
        p.reject(ESODIUM,ERR_BAD_MAC);
      else {
        int result = Sodium.crypto_auth_verify(hb, inb, inb.length, kb);
        p.resolve(result);
      }
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  // ***************************************************************************
  // * Public-key cryptography - authenticated encryption
  // ***************************************************************************
  @ReactMethod
  public void crypto_box_keypair(final Promise p){
    try {
      byte[] pk = new byte[Sodium.crypto_box_publickeybytes()];
      byte[] sk = new byte[Sodium.crypto_box_secretkeybytes()];

      if (Sodium.crypto_box_keypair(pk, sk) != 0)
        p.reject(ESODIUM,ERR_FAILURE);
      else {
        WritableNativeMap result = new WritableNativeMap();
        result.putString("pk",Base64.encodeToString(pk,Base64.NO_WRAP));
        result.putString("sk",Base64.encodeToString(sk,Base64.NO_WRAP));
        p.resolve(result);
      }
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_box_easy(final String m, final String n, final String pk, final String sk, final Promise p) {
    try {
      byte[] mb = Base64.decode(m, Base64.NO_WRAP);
      byte[] nb = Base64.decode(n, Base64.NO_WRAP);
      byte[] pkb = Base64.decode(pk, Base64.NO_WRAP);
      byte[] skb = Base64.decode(sk, Base64.NO_WRAP);
      if (pkb.length != Sodium.crypto_box_publickeybytes())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else if (skb.length != Sodium.crypto_box_secretkeybytes())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else if (nb.length != Sodium.crypto_box_noncebytes())
        p.reject(ESODIUM,ERR_BAD_NONCE);
      else {
        byte[] cb = new byte[mb.length + Sodium.crypto_box_macbytes()];
        int result = Sodium.crypto_box_easy(cb, mb, mb.length, nb, pkb, skb);
        if (result != 0)
          p.reject(ESODIUM,ERR_FAILURE);
        else
          p.resolve(Base64.encodeToString(cb,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_box_easy_afternm(final String m, final String n, final String k, final Promise p) {
    try {
      byte[] mb = Base64.decode(m, Base64.NO_WRAP);
      byte[] nb = Base64.decode(n, Base64.NO_WRAP);
      byte[] kb = Base64.decode(k, Base64.NO_WRAP);
      if (kb.length != Sodium.crypto_box_secretkeybytes())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else if (nb.length != Sodium.crypto_box_noncebytes())
        p.reject(ESODIUM,ERR_BAD_NONCE);
      else {
        byte[] cb = new byte[mb.length + Sodium.crypto_box_macbytes()];
        int result = Sodium.crypto_box_easy_afternm(cb, mb, mb.length, nb, kb);
        if (result != 0)
          p.reject(ESODIUM,ERR_FAILURE);
        else
          p.resolve(Base64.encodeToString(cb,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_box_open_easy(final String c, final String n, final String pk, final String sk, final Promise p) {
    try {
      byte[] cb = Base64.decode(c, Base64.NO_WRAP);
      byte[] nb = Base64.decode(n, Base64.NO_WRAP);
      byte[] pkb = Base64.decode(pk, Base64.NO_WRAP);
      byte[] skb = Base64.decode(sk, Base64.NO_WRAP);
      if (pkb.length != Sodium.crypto_box_publickeybytes())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else if (skb.length != Sodium.crypto_box_secretkeybytes())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else if (nb.length != Sodium.crypto_box_noncebytes())
        p.reject(ESODIUM,ERR_BAD_NONCE);
      else if (cb.length < Sodium.crypto_box_macbytes())
        p.reject(ESODIUM,ERR_BAD_MSG);
      else {
        byte[] mb = new byte[cb.length - Sodium.crypto_box_macbytes()];
        int result = Sodium.crypto_box_open_easy(mb, cb, cb.length, nb, pkb, skb);
        if (result != 0)
          p.reject(ESODIUM,ERR_FAILURE);
        else
          p.resolve(Base64.encodeToString(mb,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_box_open_easy_afternm(final String c, final String n, final String k, final Promise p) {
    try {
      byte[] cb = Base64.decode(c, Base64.NO_WRAP);
      byte[] nb = Base64.decode(n, Base64.NO_WRAP);
      byte[] kb = Base64.decode(k, Base64.NO_WRAP);
      if (kb.length != Sodium.crypto_box_secretkeybytes())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else if (nb.length != Sodium.crypto_box_noncebytes())
        p.reject(ESODIUM,ERR_BAD_NONCE);
      else if (cb.length < Sodium.crypto_box_macbytes())
        p.reject(ESODIUM,ERR_BAD_MSG);
      else {
        byte[] mb = new byte[cb.length - Sodium.crypto_box_macbytes()];
        int result = Sodium.crypto_box_open_easy_afternm(mb, cb, cb.length, nb, kb);
        if (result != 0)
          p.reject(ESODIUM,ERR_FAILURE);
        else
          p.resolve(Base64.encodeToString(mb,Base64.NO_WRAP));
      }
    }
    catch(Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_box_beforenm(final String pk, final String sk, final Promise p) {
    try {
      byte[] pkb = Base64.decode(pk, Base64.NO_WRAP);
      byte[] skb = Base64.decode(sk, Base64.NO_WRAP);
      if (pkb.length != Sodium.crypto_box_publickeybytes())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else if (skb.length != Sodium.crypto_box_secretkeybytes())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] s = new byte[Sodium.crypto_box_secretkeybytes()];
        int result = Sodium.crypto_box_beforenm(s, pkb, skb);
        if (result != 0)
          p.reject(ESODIUM,ERR_FAILURE);
        else
          p.resolve(Base64.encodeToString(s,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_pwhash(final Integer keylen, final String password, final String salt, final Integer opslimit, final Integer memlimit, final Integer algo , final Promise p) {
    runOnExecutor(() -> {
      try {
        byte[] saltb = Base64.decode(salt, Base64.NO_WRAP);
        byte[] passwordb = Base64.decode(password, Base64.NO_WRAP);
        byte[] out = new byte[keylen];

        int result = Sodium.crypto_pwhash(out, out.length, passwordb, passwordb.length, saltb, opslimit, memlimit, algo);
        if (result != 0)
          p.reject(ESODIUM,ERR_FAILURE);
        else
          p.resolve(Base64.encodeToString(out, Base64.NO_WRAP));
      }
      catch (Throwable t) {
        p.reject(ESODIUM,ERR_FAILURE,t);
      }
    });
  }

  @ReactMethod
  public void crypto_box_seal(final String m, final String pk, final Promise p) {
    try {
      byte[] pkb = Base64.decode(pk, Base64.NO_WRAP);
      byte[] mb = Base64.decode(m, Base64.NO_WRAP);
      if (pkb.length != Sodium.crypto_box_publickeybytes())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] c = new byte[Sodium.crypto_box_sealbytes() + mb.length];
        int result = Sodium.crypto_box_seal(c, mb, mb.length, pkb);
        if (result != 0)
          p.reject(ESODIUM,ERR_FAILURE);
        else
          p.resolve(Base64.encodeToString(c, Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_box_seal_open(final String c, final String pk, final String sk, final Promise p) {
    try {
      byte[] pkb = Base64.decode(pk, Base64.NO_WRAP);
      byte[] skb = Base64.decode(sk, Base64.NO_WRAP);
      byte[] cb = Base64.decode(c, Base64.NO_WRAP);
      if (pkb.length != Sodium.crypto_box_publickeybytes())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else if (skb.length != Sodium.crypto_box_secretkeybytes())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] m = new byte[cb.length - Sodium.crypto_box_sealbytes()];
        int result = Sodium.crypto_box_seal_open(m, cb, cb.length, pkb, skb);
        if (result != 0)
          p.reject(ESODIUM,ERR_FAILURE);
        else
          p.resolve(Base64.encodeToString(m, Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_scalarmult_base(final String n, final Promise p) {
    try {
      byte[] nb = Base64.decode(n, Base64.NO_WRAP);
      if (nb.length != Sodium.crypto_scalarmult_scalarbytes())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] q = new byte[Sodium.crypto_scalarmult_bytes()];
        int result = Sodium.crypto_scalarmult_base(q, nb);
        if (result != 0)
          p.reject(ESODIUM,ERR_BAD_KEY);
        else
          p.resolve(Base64.encodeToString(q,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_scalarmult(final String n, final String p, final Promise pp) {
    try {
      byte[] nb = Base64.decode(n, Base64.NO_WRAP);
      byte[] pb = Base64.decode(p, Base64.NO_WRAP);
      if (nb.length != Sodium.crypto_scalarmult_scalarbytes() || pb.length != Sodium.crypto_scalarmult_bytes())
        pp.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] q = new byte[Sodium.crypto_scalarmult_bytes()];
        int result = Sodium.crypto_scalarmult(q, nb, pb);
        if (result != 0)
          pp.reject(ESODIUM,ERR_BAD_KEY);
        else{
          pp.resolve(Base64.encodeToString(q,Base64.NO_WRAP));}
      }
    }
    catch (Throwable t) {
      pp.reject(ESODIUM,t);
    }
  }

  // ***************************************************************************
  // * Public-key cryptography - signatures
  // ***************************************************************************
  @ReactMethod
  public void crypto_sign_detached(final String msg, final String sk, final Promise p) {
    try {
      byte[] msgb = Base64.decode(msg, Base64.NO_WRAP);
      byte[] skb  = Base64.decode(sk, Base64.NO_WRAP);
      if (skb.length != Sodium.crypto_sign_secretkeybytes()){
        p.reject(ESODIUM,ERR_BAD_KEY);
      }
      else {
        byte[] sig = new byte[Sodium.crypto_sign_bytes()];
        int result = Sodium.crypto_sign_detached(sig, msgb, msgb.length, skb);
        if (result != 0)
          p.reject(ESODIUM, ERR_FAILURE);
        else {
          p.resolve(Base64.encodeToString(sig, Base64.NO_WRAP));
        }
      }
    }
    catch(Throwable t) {
      p.reject(ESODIUM, ERR_FAILURE, t);
    }
  }

  @ReactMethod
  public void crypto_sign_verify_detached(final String sig, final String msg, final String pk, final Promise p) {
    try {
      byte[] sigb = Base64.decode(sig, Base64.NO_WRAP);
      byte[] msgb = Base64.decode(msg, Base64.NO_WRAP);
      byte[] pkb  = Base64.decode(pk, Base64.NO_WRAP);
      if (pkb.length != Sodium.crypto_sign_publickeybytes()){
        p.reject(ESODIUM,ERR_BAD_KEY);
      }
      if (sigb.length != Sodium.crypto_sign_bytes()){
        p.reject(ESODIUM,ERR_BAD_SIG);
      }
      else {
        int result = Sodium.crypto_sign_verify_detached(sigb, msgb, msgb.length, pkb);
        if (result != 0)
          p.reject(ESODIUM, ERR_FAILURE);
        else
          p.resolve(true);
      }
    }
    catch(Throwable t) {
      p.reject(ESODIUM, ERR_FAILURE, t);
    }
  }

  @ReactMethod
  public void crypto_sign_keypair(final Promise p) {
    try {
      byte[] pk = new byte[Sodium.crypto_sign_publickeybytes()];
      byte[] sk = new byte[Sodium.crypto_sign_secretkeybytes()];

      int result = Sodium.crypto_sign_keypair(pk, sk);
      if (result != 0)
        p.reject(ESODIUM, ERR_FAILURE);
      else {
        WritableNativeMap map = new WritableNativeMap();
        map.putString("pk",Base64.encodeToString(pk,Base64.NO_WRAP));
        map.putString("sk",Base64.encodeToString(sk,Base64.NO_WRAP));
        p.resolve(map);
      }
    }
    catch(Throwable t) {
      p.reject(ESODIUM, ERR_FAILURE, t);
    }
  }

  @ReactMethod
  public void crypto_sign_seed_keypair(final String seed, final Promise p) {
    try {
      byte[] seedb = Base64.decode(seed, Base64.NO_WRAP);
      byte[] pk = new byte[Sodium.crypto_sign_publickeybytes()];
      byte[] sk = new byte[Sodium.crypto_sign_secretkeybytes()];

      if (seedb.length != Sodium.crypto_sign_seedbytes()) {
        p.reject(ESODIUM,ERR_BAD_SEED);
      }
      else {
        int result = Sodium.crypto_sign_seed_keypair(pk, sk, seedb);
        if (result != 0)
          p.reject(ESODIUM, ERR_FAILURE);
        else {
          WritableNativeMap map = new WritableNativeMap();
          map.putString("pk",Base64.encodeToString(pk,Base64.NO_WRAP));
          map.putString("sk",Base64.encodeToString(sk,Base64.NO_WRAP));
          p.resolve(map);
        }
      }
    }
    catch(Throwable t) {
      p.reject(ESODIUM, ERR_FAILURE, t);
    }
  }

  @ReactMethod
  public void crypto_sign_ed25519_sk_to_seed(final String sk, final Promise p) {
    try {
      byte[] skb = Base64.decode(sk, Base64.NO_WRAP);
      if(skb.length != Sodium.crypto_sign_secretkeybytes()){
        p.reject(ESODIUM,ERR_BAD_KEY);
      }
      else {
        byte[] seed = new byte[Sodium.crypto_box_secretkeybytes()];
        int result = Sodium.crypto_sign_ed25519_sk_to_seed(seed, skb);
        if (result != 0)
          p.reject(ESODIUM, ERR_FAILURE);
        else
          p.resolve(Base64.encodeToString(seed, Base64.NO_WRAP));
      }
    }
    catch(Throwable t) {
      p.reject(ESODIUM, ERR_FAILURE, t);
    }
  }

  @ReactMethod
  public void crypto_sign_ed25519_pk_to_curve25519(final String pk, final Promise p) {
    try {
      byte[] pkb = Base64.decode(pk, Base64.NO_WRAP);
      if(pkb.length != Sodium.crypto_sign_publickeybytes()){
        p.reject(ESODIUM,ERR_BAD_KEY);
      }
      else {
        byte[] curve_pk = new byte[Sodium.crypto_sign_publickeybytes()];
        int result = Sodium.crypto_sign_ed25519_pk_to_curve25519(curve_pk, pkb);
        if (result != 0)
          p.reject(ESODIUM, ERR_FAILURE);
        else
          p.resolve(Base64.encodeToString(curve_pk, Base64.NO_WRAP));
      }
    }
    catch(Throwable t) {
      p.reject(ESODIUM, ERR_FAILURE, t);
    }
  }

  @ReactMethod
  public void crypto_sign_ed25519_sk_to_curve25519(final String sk, final Promise p) {
    try {
      byte[] skb = Base64.decode(sk, Base64.NO_WRAP);
      if(skb.length != Sodium.crypto_sign_secretkeybytes()){
        p.reject(ESODIUM,ERR_BAD_KEY);
      }
      else {
        byte[] curve_sk = new byte[Sodium.crypto_box_secretkeybytes()];
        int result = Sodium.crypto_sign_ed25519_sk_to_curve25519(curve_sk, skb);
        if (result != 0)
          p.reject(ESODIUM, ERR_FAILURE);
        else
          p.resolve(Base64.encodeToString(curve_sk, Base64.NO_WRAP));
      }
    }
    catch(Throwable t) {
      p.reject(ESODIUM, ERR_FAILURE, t);
    }
  }

  @ReactMethod
  public void crypto_sign_ed25519_sk_to_pk(final String sk, final Promise p) {
    try {
      byte[] skb = Base64.decode(sk, Base64.NO_WRAP);
      if(skb.length != Sodium.crypto_sign_secretkeybytes()){
        p.reject(ESODIUM,ERR_BAD_KEY);
      }
      else {
        byte[] pk = new byte[Sodium.crypto_sign_publickeybytes()];
        int result = Sodium.crypto_sign_ed25519_sk_to_pk(skb, pk);
        if (result != 0) {
          p.reject(ESODIUM, ERR_FAILURE);
        }
        else {
          p.resolve(Base64.encodeToString(pk, Base64.NO_WRAP));
        }
      }
    }
    catch(Throwable t) {
      p.reject(ESODIUM, ERR_FAILURE, t);
    }
  }

  @ReactMethod
  public void crypto_core_ed25519_random(final Promise promise) {
    try {
      byte[] p = new byte[Sodium.crypto_core_ed25519_bytes()];
      Sodium.crypto_core_ed25519_random(p);
      promise.resolve(Base64.encodeToString(p,Base64.NO_WRAP));
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_core_ed25519_from_uniform(final String r, final Promise promise) {
    try {
      byte[] rb = Base64.decode(r, Base64.NO_WRAP);
      if (rb.length != Sodium.crypto_core_ed25519_bytes())
        promise.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] p = new byte[Sodium.crypto_core_ed25519_bytes()];
        int result = Sodium.crypto_core_ed25519_from_uniform(p, rb);
        if (result != 0)
          promise.reject(ESODIUM,ERR_BAD_KEY);
        else
          promise.resolve(Base64.encodeToString(p,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_core_ed25519_add(final String p, final String q, final Promise promise) {
    try {
      byte[] pb = Base64.decode(p, Base64.NO_WRAP);
      byte[] qb = Base64.decode(q, Base64.NO_WRAP);
      if ((pb.length != Sodium.crypto_core_ed25519_bytes()) || (qb.length != Sodium.crypto_core_ed25519_bytes()))
        promise.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] r = new byte[Sodium.crypto_core_ed25519_bytes()];
        int result = Sodium.crypto_core_ed25519_add(r, pb, qb);
        if (result != 0)
          promise.reject(ESODIUM,ERR_BAD_KEY);
        else
          promise.resolve(Base64.encodeToString(r,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_core_ed25519_sub(final String p, final String q, final Promise promise) {
    try {
      byte[] pb = Base64.decode(p, Base64.NO_WRAP);
      byte[] qb = Base64.decode(q, Base64.NO_WRAP);
      if ((pb.length != Sodium.crypto_core_ed25519_bytes()) || (qb.length != Sodium.crypto_core_ed25519_bytes()))
        promise.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] r = new byte[Sodium.crypto_core_ed25519_bytes()];
        int result = Sodium.crypto_core_ed25519_sub(r, pb, qb);
        if (result != 0)
          promise.reject(ESODIUM,ERR_BAD_KEY);
        else
          promise.resolve(Base64.encodeToString(r,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_core_ed25519_is_valid_point(final String p, final Promise promise) {
    try {
      byte[] pb = Base64.decode(p, Base64.NO_WRAP);
      if (pb.length != Sodium.crypto_core_ed25519_bytes())
        promise.reject(ESODIUM,ERR_BAD_KEY);
      else {
        int result = Sodium.crypto_core_ed25519_is_valid_point(pb);
        promise.resolve(result);
      }
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_core_ed25519_scalar_random(final Promise promise) {
    try {
      byte[] r = new byte[Sodium.crypto_core_ed25519_scalarbytes()];
      Sodium.crypto_core_ed25519_scalar_random(r);
      promise.resolve(Base64.encodeToString(r,Base64.NO_WRAP));
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_core_ed25519_scalar_add(final String x, final String y, final Promise promise) {
    try {
      byte[] xb = Base64.decode(x, Base64.NO_WRAP);
      byte[] yb = Base64.decode(y, Base64.NO_WRAP);
      if ((xb.length != Sodium.crypto_core_ed25519_scalarbytes()) || (yb.length != Sodium.crypto_core_ed25519_scalarbytes()))
        promise.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] z = new byte[Sodium.crypto_core_ed25519_scalarbytes()];
        Sodium.crypto_core_ed25519_scalar_add(z, xb, yb);
        promise.resolve(Base64.encodeToString(z,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_core_ed25519_scalar_sub(final String x, final String y, final Promise promise) {
    try {
      byte[] xb = Base64.decode(x, Base64.NO_WRAP);
      byte[] yb = Base64.decode(y, Base64.NO_WRAP);
      if ((xb.length != Sodium.crypto_core_ed25519_scalarbytes()) || (yb.length != Sodium.crypto_core_ed25519_scalarbytes()))
        promise.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] z = new byte[Sodium.crypto_core_ed25519_scalarbytes()];
        Sodium.crypto_core_ed25519_scalar_sub(z, xb, yb);
        promise.resolve(Base64.encodeToString(z,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_core_ed25519_scalar_mul(final String x, final String y, final Promise promise) {
    try {
      byte[] xb = Base64.decode(x, Base64.NO_WRAP);
      byte[] yb = Base64.decode(y, Base64.NO_WRAP);
      if ((xb.length != Sodium.crypto_core_ed25519_scalarbytes()) || (yb.length != Sodium.crypto_core_ed25519_scalarbytes()))
        promise.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] z = new byte[Sodium.crypto_core_ed25519_scalarbytes()];
        Sodium.crypto_core_ed25519_scalar_mul(z, xb, yb);
        promise.resolve(Base64.encodeToString(z,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_core_ed25519_scalar_negate(final String s, final Promise promise) {
    try {
      byte[] sb = Base64.decode(s, Base64.NO_WRAP);
      if (sb.length != Sodium.crypto_core_ed25519_scalarbytes())
        promise.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] z = new byte[Sodium.crypto_core_ed25519_scalarbytes()];
        Sodium.crypto_core_ed25519_scalar_negate(z, sb);
        promise.resolve(Base64.encodeToString(z,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_core_ed25519_scalar_complement(final String s, final Promise promise) {
    try {
      byte[] sb = Base64.decode(s, Base64.NO_WRAP);
      if (sb.length != Sodium.crypto_core_ed25519_scalarbytes())
        promise.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] z = new byte[Sodium.crypto_core_ed25519_scalarbytes()];
        Sodium.crypto_core_ed25519_scalar_complement(z, sb);
        promise.resolve(Base64.encodeToString(z,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_core_ed25519_scalar_invert(final String s, final Promise promise) {
    try {
      byte[] sb = Base64.decode(s, Base64.NO_WRAP);
      if (sb.length != Sodium.crypto_core_ed25519_scalarbytes())
        promise.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] z = new byte[Sodium.crypto_core_ed25519_scalarbytes()];
        int result = Sodium.crypto_core_ed25519_scalar_invert(z, sb);
        if (result != 0)
          promise.reject(ESODIUM,ERR_BAD_KEY);
        else
          promise.resolve(Base64.encodeToString(z,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_core_ed25519_scalar_reduce(final String s, final Promise promise) {
    try {
      byte[] sb = Base64.decode(s, Base64.NO_WRAP);
      if (sb.length != Sodium.crypto_core_ed25519_nonreducedscalarbytes())
        promise.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] z = new byte[Sodium.crypto_core_ed25519_scalarbytes()];
        Sodium.crypto_core_ed25519_scalar_reduce(z, sb);
        promise.resolve(Base64.encodeToString(z,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_scalarmult_ed25519(final String n, final String p, final Promise promise) {
    try {
      byte[] nb = Base64.decode(n, Base64.NO_WRAP);
      byte[] pb = Base64.decode(p, Base64.NO_WRAP);
      if ((nb.length != Sodium.crypto_core_ed25519_scalarbytes()) || (pb.length != Sodium.crypto_core_ed25519_bytes()))
        promise.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] q = new byte[Sodium.crypto_core_ed25519_bytes()];
        int result = Sodium.crypto_scalarmult_ed25519(q, nb, pb);
        if (result != 0)
          promise.reject(ESODIUM,ERR_BAD_KEY);
        else
          promise.resolve(Base64.encodeToString(q,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_scalarmult_ed25519_noclamp(final String n, final String p, final Promise promise) {
    try {
      byte[] nb = Base64.decode(n, Base64.NO_WRAP);
      byte[] pb = Base64.decode(p, Base64.NO_WRAP);
      if ((nb.length != Sodium.crypto_core_ed25519_scalarbytes()) || (pb.length != Sodium.crypto_core_ed25519_bytes()))
        promise.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] q = new byte[Sodium.crypto_core_ed25519_bytes()];
        int result = Sodium.crypto_scalarmult_ed25519_noclamp(q, nb, pb);
        if (result != 0)
          promise.reject(ESODIUM,ERR_BAD_KEY);
        else
          promise.resolve(Base64.encodeToString(q,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_scalarmult_ed25519_base(final String n, final Promise promise) {
    try {
      byte[] nb = Base64.decode(n, Base64.NO_WRAP);
      if (nb.length != Sodium.crypto_core_ed25519_scalarbytes())
        promise.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] q = new byte[Sodium.crypto_core_ed25519_bytes()];
        int result = Sodium.crypto_scalarmult_ed25519_base(q, nb);
        if (result != 0)
          promise.reject(ESODIUM,ERR_BAD_KEY);
        else
          promise.resolve(Base64.encodeToString(q,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_scalarmult_ed25519_base_noclamp(final String n, final Promise promise) {
    try {
      byte[] nb = Base64.decode(n, Base64.NO_WRAP);
      if (nb.length != Sodium.crypto_core_ed25519_scalarbytes())
        promise.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] q = new byte[Sodium.crypto_core_ed25519_bytes()];
        int result = Sodium.crypto_scalarmult_ed25519_base_noclamp(q, nb);
        if (result != 0)
          promise.reject(ESODIUM,ERR_BAD_KEY);
        else
          promise.resolve(Base64.encodeToString(q,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_generichash(final int hash_length, final String msg, final String key, final Promise promise) {
    try {
      byte[] msgb = Base64.decode(msg, Base64.NO_WRAP);
      byte[] keyb = Base64.decode(key, Base64.NO_WRAP);

      if (msgb.length == 0)
        promise.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] q = new byte[hash_length];
        int result = Sodium.crypto_generichash(q, hash_length, msgb, msgb.length, keyb, keyb.length);
        if (result != 0)
          promise.reject(ESODIUM,ERR_BAD_KEY);
        else
          promise.resolve(Base64.encodeToString(q,Base64.NO_WRAP));
      }
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_aead_chacha20poly1305_ietf_keygen(final Promise promise) {
    try {
      byte[] p = new byte[Sodium.crypto_aead_xchacha20poly1305_ietf_keybytes()];
      Sodium.crypto_aead_chacha20poly1305_ietf_keygen(p);
      promise.resolve(Base64.encodeToString(p,Base64.NO_WRAP));
    }
    catch (Throwable t) {
      promise.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_aead_xchacha20poly1305_ietf_encrypt(
          final String message,
          final String additional_data,
          final String secret_nonce,
          final String public_nonce,
          final String key,
          final Promise promise) {

    try {
      byte[] b_message = Base64.decode(message, Base64.NO_WRAP);
      byte[] b_additional_data = Base64.decode(additional_data, Base64.NO_WRAP);
      byte[] b_secret_nonce = Base64.decode(secret_nonce, Base64.NO_WRAP);
      byte[] b_public_nonce = Base64.decode(public_nonce, Base64.NO_WRAP);
      byte[] b_key = Base64.decode(key, Base64.NO_WRAP);

      byte[] q = new byte[b_message.length + 16];
      int result = Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
              q,
              b_message,
              b_message.length,
              b_additional_data,
              b_additional_data.length,
              b_secret_nonce,
              b_secret_nonce.length,
              b_public_nonce,
              b_key);
      if (result < 0)
        promise.reject(ESODIUM, ERR_BAD_KEY);
      else
        promise.resolve(Base64.encodeToString(q, 0, result, Base64.NO_WRAP));
    } catch (Throwable t) {
      promise.reject(ESODIUM, ERR_FAILURE, t);
    }
  }

  @ReactMethod
  public void crypto_aead_xchacha20poly1305_ietf_decrypt(
          final String secret_nonce,
          final String ciphertext,
          final String additional_data,
          final String public_nonce,
          final String key,
          final Promise promise){
    try {
      byte[] b_secret_nonce = Base64.decode(secret_nonce, Base64.NO_WRAP);
      byte[] b_ciphertext = Base64.decode(ciphertext, Base64.NO_WRAP);
      byte[] b_additional_data = Base64.decode(additional_data, Base64.NO_WRAP);
      byte[] b_public_nonce = Base64.decode(public_nonce, Base64.NO_WRAP);
      byte[] b_key = Base64.decode(key, Base64.NO_WRAP);

      byte[] q = new byte[b_ciphertext.length];
      int result = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
              q,
              b_secret_nonce,
              b_secret_nonce.length,
              b_ciphertext,
              b_ciphertext.length,
              b_additional_data,
              b_additional_data.length,
              b_public_nonce,
              b_key);

      if (result < 0)
        promise.reject(ESODIUM, ERR_BAD_KEY);
      else
        promise.resolve(Base64.encodeToString(q, 0, result, Base64.NO_WRAP));
    } catch (Throwable t) {
      promise.reject(ESODIUM, ERR_FAILURE, t);
    }
  }


  ///// SynchronousMethod
  @ReactMethod(isBlockingSynchronousMethod = true)
  public String randombytes_buf_sync(int size) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] buf = new byte[size];
      Sodium.randombytes_buf(buf, size);
      res_data = Base64.encodeToString(buf,Base64.NO_WRAP);
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_core_ed25519_random_sync() {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] p = new byte[Sodium.crypto_core_ed25519_bytes()];
      Sodium.crypto_core_ed25519_random(p);
      res_data = Base64.encodeToString(p,Base64.NO_WRAP);
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_core_ed25519_from_uniform_sync(final String r) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] rb = Base64.decode(r, Base64.NO_WRAP);
      if (rb.length != Sodium.crypto_core_ed25519_bytes())
        res_code = ERR_CODE_FAILURE;
      else {
        byte[] p = new byte[Sodium.crypto_core_ed25519_bytes()];
        int result = Sodium.crypto_core_ed25519_from_uniform(p, rb);
        if (result != 0)
          res_code = ERR_CODE_FAILURE;
        else
          res_data = Base64.encodeToString(p,Base64.NO_WRAP);
      }
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_core_ed25519_add_sync(final String p, final String q) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] pb = Base64.decode(p, Base64.NO_WRAP);
      byte[] qb = Base64.decode(q, Base64.NO_WRAP);
      if ((pb.length != Sodium.crypto_core_ed25519_bytes()) || (qb.length != Sodium.crypto_core_ed25519_bytes()))
        res_code = ERR_CODE_FAILURE;
      else {
        byte[] r = new byte[Sodium.crypto_core_ed25519_bytes()];
        int result = Sodium.crypto_core_ed25519_add(r, pb, qb);
        if (result != 0)
          res_code = ERR_CODE_FAILURE;
        else
          res_data = Base64.encodeToString(r,Base64.NO_WRAP);
      }
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_core_ed25519_sub_sync(final String p, final String q) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] pb = Base64.decode(p, Base64.NO_WRAP);
      byte[] qb = Base64.decode(q, Base64.NO_WRAP);
      if ((pb.length != Sodium.crypto_core_ed25519_bytes()) || (qb.length != Sodium.crypto_core_ed25519_bytes()))
        res_code = ERR_CODE_FAILURE;
      else {
        byte[] r = new byte[Sodium.crypto_core_ed25519_bytes()];
        int result = Sodium.crypto_core_ed25519_sub(r, pb, qb);
        if (result != 0)
          res_code = ERR_CODE_FAILURE;
        else
          res_data = Base64.encodeToString(r,Base64.NO_WRAP);
      }
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_core_ed25519_is_valid_point_sync(final String p) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] pb = Base64.decode(p, Base64.NO_WRAP);
      if (pb.length != Sodium.crypto_core_ed25519_bytes())
        res_code = ERR_CODE_FAILURE;
      else {
        int result = Sodium.crypto_core_ed25519_is_valid_point(pb);
        res_data = Integer.toString(result);
      }
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_core_ed25519_scalar_random_sync() {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] r = new byte[Sodium.crypto_core_ed25519_scalarbytes()];
      Sodium.crypto_core_ed25519_scalar_random(r);
      res_data = Base64.encodeToString(r,Base64.NO_WRAP);
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_core_ed25519_scalar_add_sync(final String x, final String y) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] xb = Base64.decode(x, Base64.NO_WRAP);
      byte[] yb = Base64.decode(y, Base64.NO_WRAP);
      if ((xb.length != Sodium.crypto_core_ed25519_scalarbytes()) || (yb.length != Sodium.crypto_core_ed25519_scalarbytes()))
        res_code = ERR_CODE_FAILURE;
      else {
        byte[] z = new byte[Sodium.crypto_core_ed25519_scalarbytes()];
        Sodium.crypto_core_ed25519_scalar_add(z, xb, yb);
        res_data = Base64.encodeToString(z,Base64.NO_WRAP);
      }
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_core_ed25519_scalar_sub_sync(final String x, final String y) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] xb = Base64.decode(x, Base64.NO_WRAP);
      byte[] yb = Base64.decode(y, Base64.NO_WRAP);
      if ((xb.length != Sodium.crypto_core_ed25519_scalarbytes()) || (yb.length != Sodium.crypto_core_ed25519_scalarbytes()))
        res_code = ERR_CODE_FAILURE;
      else {
        byte[] z = new byte[Sodium.crypto_core_ed25519_scalarbytes()];
        Sodium.crypto_core_ed25519_scalar_sub(z, xb, yb);
        res_data = Base64.encodeToString(z,Base64.NO_WRAP);
      }
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_core_ed25519_scalar_mul_sync(final String x, final String y) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] xb = Base64.decode(x, Base64.NO_WRAP);
      byte[] yb = Base64.decode(y, Base64.NO_WRAP);
      if ((xb.length != Sodium.crypto_core_ed25519_scalarbytes()) || (yb.length != Sodium.crypto_core_ed25519_scalarbytes()))
        res_code = ERR_CODE_FAILURE;
      else {
        byte[] z = new byte[Sodium.crypto_core_ed25519_scalarbytes()];
        Sodium.crypto_core_ed25519_scalar_mul(z, xb, yb);
        res_data = Base64.encodeToString(z,Base64.NO_WRAP);
      }
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_core_ed25519_scalar_negate_sync(final String s) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] sb = Base64.decode(s, Base64.NO_WRAP);
      if (sb.length != Sodium.crypto_core_ed25519_scalarbytes())
        res_code = ERR_CODE_FAILURE;
      else {
        byte[] z = new byte[Sodium.crypto_core_ed25519_scalarbytes()];
        Sodium.crypto_core_ed25519_scalar_negate(z, sb);
        res_data = Base64.encodeToString(z,Base64.NO_WRAP);
      }
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_core_ed25519_scalar_complement_sync(final String s) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] sb = Base64.decode(s, Base64.NO_WRAP);
      if (sb.length != Sodium.crypto_core_ed25519_scalarbytes())
        res_code = ERR_CODE_FAILURE;
      else {
        byte[] z = new byte[Sodium.crypto_core_ed25519_scalarbytes()];
        Sodium.crypto_core_ed25519_scalar_complement(z, sb);
        res_data = Base64.encodeToString(z,Base64.NO_WRAP);
      }
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_core_ed25519_scalar_invert_sync(final String s) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] sb = Base64.decode(s, Base64.NO_WRAP);
      if (sb.length != Sodium.crypto_core_ed25519_scalarbytes())
        res_code = ERR_CODE_FAILURE;
      else {
        byte[] z = new byte[Sodium.crypto_core_ed25519_scalarbytes()];
        int result = Sodium.crypto_core_ed25519_scalar_invert(z, sb);
        if (result != 0)
          res_code = ERR_CODE_FAILURE;
        else
          res_data = Base64.encodeToString(z,Base64.NO_WRAP);
      }
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_core_ed25519_scalar_reduce_sync(final String s) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] sb = Base64.decode(s, Base64.NO_WRAP);
      if (sb.length != Sodium.crypto_core_ed25519_nonreducedscalarbytes())
        res_code = ERR_CODE_FAILURE;
      else {
        byte[] z = new byte[Sodium.crypto_core_ed25519_scalarbytes()];
        Sodium.crypto_core_ed25519_scalar_reduce(z, sb);
        res_data = Base64.encodeToString(z,Base64.NO_WRAP);
      }
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_scalarmult_ed25519_sync(final String n, final String p) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] nb = Base64.decode(n, Base64.NO_WRAP);
      byte[] pb = Base64.decode(p, Base64.NO_WRAP);
      if ((nb.length != Sodium.crypto_core_ed25519_scalarbytes()) || (pb.length != Sodium.crypto_core_ed25519_bytes()))
        res_code = ERR_CODE_FAILURE;
      else {
        byte[] q = new byte[Sodium.crypto_core_ed25519_bytes()];
        int result = Sodium.crypto_scalarmult_ed25519(q, nb, pb);
        if (result != 0)
          res_code = ERR_CODE_FAILURE;
        else
          res_data = Base64.encodeToString(q,Base64.NO_WRAP);
      }
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_scalarmult_ed25519_noclamp_sync(final String n, final String p) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] nb = Base64.decode(n, Base64.NO_WRAP);
      byte[] pb = Base64.decode(p, Base64.NO_WRAP);
      if ((nb.length != Sodium.crypto_core_ed25519_scalarbytes()) || (pb.length != Sodium.crypto_core_ed25519_bytes()))
        res_code = ERR_CODE_FAILURE;
      else {
        byte[] q = new byte[Sodium.crypto_core_ed25519_bytes()];
        int result = Sodium.crypto_scalarmult_ed25519_noclamp(q, nb, pb);
        if (result != 0)
          res_code = ERR_CODE_FAILURE;
        else
          res_data = Base64.encodeToString(q,Base64.NO_WRAP);
      }
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_scalarmult_ed25519_base_sync(final String n) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] nb = Base64.decode(n, Base64.NO_WRAP);
      if (nb.length != Sodium.crypto_core_ed25519_scalarbytes())
        res_code = ERR_CODE_FAILURE;
      else {
        byte[] q = new byte[Sodium.crypto_core_ed25519_bytes()];
        int result = Sodium.crypto_scalarmult_ed25519_base(q, nb);
        if (result != 0)
          res_code = ERR_CODE_FAILURE;
        else
          res_data = Base64.encodeToString(q,Base64.NO_WRAP);
      }
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_scalarmult_ed25519_base_noclamp_sync(final String n) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] nb = Base64.decode(n, Base64.NO_WRAP);
      if (nb.length != Sodium.crypto_core_ed25519_scalarbytes())
        res_code = ERR_CODE_FAILURE;
      else {
        byte[] q = new byte[Sodium.crypto_core_ed25519_bytes()];
        int result = Sodium.crypto_scalarmult_ed25519_base_noclamp(q, nb);
        if (result != 0)
          res_code = ERR_CODE_FAILURE;
        else
          res_data = Base64.encodeToString(q,Base64.NO_WRAP);
      }
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_generichash_sync(final int hash_length, final String msg, final String key) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] msgb = Base64.decode(msg, Base64.NO_WRAP);
      byte[] keyb = Base64.decode(key, Base64.NO_WRAP);

      if (msgb.length == 0)
        res_code = ERR_CODE_FAILURE;
      else {
        byte[] q = new byte[hash_length];
        int result = Sodium.crypto_generichash(q, hash_length, msgb, msgb.length, keyb, keyb.length);
        if (result != 0)
          res_code = ERR_CODE_FAILURE;
        else
          res_data = Base64.encodeToString(q,Base64.NO_WRAP);
      }
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_aead_chacha20poly1305_ietf_keygen_sync() {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] p = new byte[Sodium.crypto_aead_xchacha20poly1305_ietf_keybytes()];
      Sodium.crypto_aead_chacha20poly1305_ietf_keygen(p);
      res_data = Base64.encodeToString(p,Base64.NO_WRAP);
    }
    catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_aead_xchacha20poly1305_ietf_encrypt_sync(
          final String message,
          final String additional_data,
          final String secret_nonce,
          final String public_nonce,
          final String key
          ) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";

    try {
      byte[] b_message = Base64.decode(message, Base64.NO_WRAP);
      byte[] b_additional_data = Base64.decode(additional_data, Base64.NO_WRAP);
      byte[] b_secret_nonce = Base64.decode(secret_nonce, Base64.NO_WRAP);
      byte[] b_public_nonce = Base64.decode(public_nonce, Base64.NO_WRAP);
      byte[] b_key = Base64.decode(key, Base64.NO_WRAP);

      byte[] q = new byte[b_message.length + 16];
      int result = Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
              q,
              b_message,
              b_message.length,
              b_additional_data,
              b_additional_data.length,
              b_secret_nonce,
              b_secret_nonce.length,
              b_public_nonce,
              b_key);
      if (result < 0)
        res_code = ERR_CODE_FAILURE;
      else
        res_data = Base64.encodeToString(q, 0, result, Base64.NO_WRAP);
    } catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String crypto_aead_xchacha20poly1305_ietf_decrypt_sync(
          final String secret_nonce,
          final String ciphertext,
          final String additional_data,
          final String public_nonce,
          final String key
          ) {
    String res_code = RES_CODE_SUCCESS;
    String res_data = "";
    try {
      byte[] b_secret_nonce = Base64.decode(secret_nonce, Base64.NO_WRAP);
      byte[] b_ciphertext = Base64.decode(ciphertext, Base64.NO_WRAP);
      byte[] b_additional_data = Base64.decode(additional_data, Base64.NO_WRAP);
      byte[] b_public_nonce = Base64.decode(public_nonce, Base64.NO_WRAP);
      byte[] b_key = Base64.decode(key, Base64.NO_WRAP);

      byte[] q = new byte[b_ciphertext.length];
      int result = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
              q,
              b_secret_nonce,
              b_secret_nonce.length,
              b_ciphertext,
              b_ciphertext.length,
              b_additional_data,
              b_additional_data.length,
              b_public_nonce,
              b_key);

      if (result < 0)
        res_code = ERR_CODE_FAILURE;
      else
        res_data = Base64.encodeToString(q, 0, result, Base64.NO_WRAP);
    } catch (Throwable t) {
      res_code = ERR_CODE_FAILURE;
    }
    return "{\"code\":\"" + res_code + "\", \"data\":\"" + res_data +"\"}";
  }
}
