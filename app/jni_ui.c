/***************************************************************************
 *  _____
 * |\    | >                   VESmail
 * | \   | >  ___       ___    Email Encryption made Convenient and Reliable
 * |  \  | > /   \     /   \                               https://vesmail.email
 * |  /  | > \__ /     \ __/
 * | /   | >    \\     //        - RFC5322 MIME Stream Encryption & Decryption
 * |/____| >     \\   //         - IMAP4rev1 Transparent Proxy Server
 *       ___      \\_//          - ESMTP Transparent Proxy Server
 *      /   \     /   \          - VES Encryption Key Exchange & Recovery
 *      \__ /     \ __/
 *         \\     //    _____                     ______________by______________
 *          \\   //  > |\    |
 *           \\_//   > | \   |                    VESvault
 *           /   \   > |  \  |                    Encrypt Everything
 *           \___/   > |  /  |                    without fear of losing the Key
 *                   > | /   |                              https://vesvault.com
 *                   > |/____|                                  https://ves.host
 *
 * (c) 2026 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * Apache License, Version 2.0
 * You may use, copy, modify, merge, publish, distribute and/or sell copies
 * of the Software under the terms of the Apache License, Version 2.0, a copy
 * of which is provided in the COPYING file, or http://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.
 *
 ***************************************************************************/

#include <stdint.h>
#include <jni.h>
#include <VESlocker.h>
#include "../srv/tls.h"

#ifndef VESMAIL_JNI_SESS
#define	VESMAIL_JNI_SESS(_n)	Java_com_vesvault_vesmail_VESSession_ ## _n
#endif

/* All the VESFlow / VESlocker / Vault / Item / ItemCipher / session-token
 * JNI shims that used to live here moved to libves-jvm (com.vesvault.libves.*).
 * Vesmail-android consumes them via gradle composite build; see vesmail-android
 * /app/src/main/java/com/vesvault/vesmail/{VESFlow,VESLocker,VESSession}.kt
 * for the Kotlin wrappers.
 *
 * What's left here is the bridge that lets the Kotlin side wire VESmail's
 * libcurl/TLS setup onto every libVES that libves-jvm creates. */

/* Set the API + WWW URLs that VESmail_tls_initVES applies to every libVES,
 * then return the address of VESmail_tls_initVES (cast to jlong) so the
 * Kotlin side can install it via Vault.initFn(). The two operations are
 * combined so the URLs are always set before any caller can grab the
 * pointer — eliminates the race with the Proxy service's own URL setup.
 *
 * NULLs leave the libVES built-in defaults in place (production:
 * api.ves.host / www.vesvault.com). Strings are persisted for the app
 * lifetime; pass static BuildConfig values. */
JNIEXPORT jlong JNICALL VESMAIL_JNI_SESS(tlsInitFnPtr)(JNIEnv *env, jclass cls, jstring japi, jstring jwww) {
    (void) cls;
    const char *api = japi ? (*env)->GetStringUTFChars(env, japi, NULL) : NULL;
    const char *www = jwww ? (*env)->GetStringUTFChars(env, jwww, NULL) : NULL;
    VESmail_tls_setVESurls(api, www);   /* setVESurls owns the duplication */
    if (api) (*env)->ReleaseStringUTFChars(env, japi, api);
    if (www) (*env)->ReleaseStringUTFChars(env, jwww, www);
    return (jlong) (intptr_t) &VESmail_tls_initVES;
}

/* httpInitFn for VESlocker — VESlocker keeps its own libcurl handle
 * independent of any libVES, so the TLS context doesn't get applied via
 * VESmail_tls_initVES. Without this hook, the handshake to the locker
 * server fails on Android and decrypt() surfaces VESLOCKER_E_LIB
 * ("Network error"). Mirrors the prior in-tree fix (78b72c7) that was
 * lost when VESLocker moved to libves-jvm. */
static void VESmail_tls_initVL(struct VESlocker *vl) {
    VESmail_tls_setcurlctx(vl->curl);
}

/* Address of VESmail_tls_initVL (cast to jlong) for VESLocker.initFn().
 * Mirrors tlsInitFnPtr's role for Vault — once installed, libcurl gets the
 * Android SSL_CTX setup on first VESlocker request. */
JNIEXPORT jlong JNICALL VESMAIL_JNI_SESS(tlsVlInitFnPtr)(JNIEnv *env, jclass cls) {
    (void) env; (void) cls;
    return (jlong) (intptr_t) &VESmail_tls_initVL;
}
