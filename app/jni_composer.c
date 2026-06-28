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
 *
 * Android JNI wrapper for lib/composer.* — thin glue, no logic.
 ***************************************************************************/

#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <jni.h>
#include "../VESmail.h"
#include "../lib/composer.h"

#ifndef VESMAIL_JNI_COMPOSER
#define	VESMAIL_JNI_COMPOSER(_n)	Java_com_vesvault_vesmail_Composer_ ## _n
#endif

JNIEXPORT jlong JNICALL VESMAIL_JNI_COMPOSER(create)(JNIEnv *env, jclass cls) {
    return (jlong) (intptr_t) VESmail_composer_new();
}

JNIEXPORT void JNICALL VESMAIL_JNI_COMPOSER(destroy)(JNIEnv *env, jclass cls, jlong handle) {
    VESmail_composer_free((VESmail_composer *) (intptr_t) handle);
}

JNIEXPORT jint JNICALL VESMAIL_JNI_COMPOSER(input)(JNIEnv *env, jclass cls,
						   jlong handle,
						   jbyteArray buf, jint offset, jint len,
						   jboolean final) {
    VESmail_composer *c = (VESmail_composer *) (intptr_t) handle;
    if (!c) return VESMAIL_E_PARAM;
    if (!buf && len > 0) return VESMAIL_E_PARAM;
    jbyte *bbuf = NULL;
    if (buf) {
	jsize bsz = (*env)->GetArrayLength(env, buf);
	if (offset < 0 || len < 0 || offset + len > bsz) return VESMAIL_E_PARAM;
	bbuf = (*env)->GetByteArrayElements(env, buf, NULL);
    }
    int r = VESmail_composer_input(c,
				   bbuf ? (const unsigned char *) bbuf + offset : NULL,
				   (size_t) len, final ? 1 : 0);
    if (bbuf) (*env)->ReleaseByteArrayElements(env, buf, bbuf, JNI_ABORT);
    return r;
}

JNIEXPORT jbyteArray JNICALL VESMAIL_JNI_COMPOSER(drain)(JNIEnv *env, jclass cls, jlong handle) {
    VESmail_composer *c = (VESmail_composer *) (intptr_t) handle;
    if (!c) return NULL;
    char *buf = NULL;
    int n = VESmail_composer_drain(c, &buf);
    if (n <= 0) {
	free(buf);
	return NULL;
    }
    jbyteArray arr = (*env)->NewByteArray(env, n);
    if (arr) (*env)->SetByteArrayRegion(env, arr, 0, n, (const jbyte *) buf);
    free(buf);
    return arr;
}

JNIEXPORT jint JNICALL VESMAIL_JNI_COMPOSER(pending)(JNIEnv *env, jclass cls, jlong handle) {
    VESmail_composer *c = (VESmail_composer *) (intptr_t) handle;
    return c ? (jint) VESmail_composer_pending(c) : 0;
}

JNIEXPORT jint JNICALL VESMAIL_JNI_COMPOSER(lastError)(JNIEnv *env, jclass cls, jlong handle) {
    VESmail_composer *c = (VESmail_composer *) (intptr_t) handle;
    return c ? VESmail_composer_lasterror(c) : VESMAIL_E_PARAM;
}

JNIEXPORT jbyteArray JNICALL VESMAIL_JNI_COMPOSER(boundary)(JNIEnv *env, jclass cls) {
    char *b = VESmail_composer_boundary();
    if (!b) return NULL;
    jsize n = (jsize) strlen(b);
    jbyteArray arr = (*env)->NewByteArray(env, n);
    if (arr) (*env)->SetByteArrayRegion(env, arr, 0, n, (const jbyte *) b);
    free(b);
    return arr;
}
