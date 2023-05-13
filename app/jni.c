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
 * (c) 2020 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <jni.h>
#include "../VESmail.h"
#include "../srv/daemon.h"
#include "../srv/local.h"
#include "../srv/x509store.h"

#ifndef VESMAIL_JNI
#define	VESMAIL_JNI(_name)	Java_com_vesvault_vesmail_Proxy_ ## _name
#endif


JNIEXPORT void JNICALL VESMAIL_JNI(init)(JNIEnv *env, jobject obj) {
    VESmail_local_init(NULL);
}

JNIEXPORT jint JNICALL VESMAIL_JNI(addcert)(JNIEnv *env, jobject obj, jbyteArray array) {
    jbyte *buf = (*env)->GetByteArrayElements(env, array, NULL);
    jsize len = (*env)->GetArrayLength(env, array);
    int r = VESmail_x509store_addcert((unsigned char *) buf, len);
    (*env)->ReleaseByteArrayElements(env, array, buf, 0);
    return r;
}

JNIEXPORT jint JNICALL VESMAIL_JNI(start)(JNIEnv *env, jobject obj) {
    VESmail_local_init(NULL);
    if (!VESmail_local_start()) return 0;
    return 1;
}

JNIEXPORT jintArray JNICALL VESMAIL_JNI(watch)(JNIEnv *env, jobject obj) {
    VESmail_local_watch();
    VESmail_daemon **dp = VESmail_local_daemons;
    jint st[64];
    int len = 0;
    if (dp) while (*dp++ && len < sizeof(st) / sizeof(*st)) {
	st[len] = VESmail_local_getstat(len);
	len++;
    }
    jintArray rs = (*env)->NewIntArray(env, len);
    if (!rs) return NULL;
    (*env)->SetIntArrayRegion(env, rs, 0, len, st);
    return rs;
}

JNIEXPORT void JNICALL VESMAIL_JNI(signal)(JNIEnv *env, jobject obj, jint sig) {
    VESmail_daemon_SIG = sig;
}

JNIEXPORT jint JNICALL VESMAIL_JNI(getdaemons)(JNIEnv *env, jobject obj, jobject dst) {
    VESmail_daemon **dp = VESmail_local_daemons;
    if (!dp) return VESMAIL_E_PARAM;
    int n = 0;
    jclass cls = (*env)->GetObjectClass(env, dst);
    jmethodID meth = (*env)->GetMethodID(env, cls, "setdaemon", "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
    for (; *dp; dp++, n++) {
	jstring jsrv = (*env)->NewStringUTF(env, (*dp)->type);
	jstring jhost = (*env)->NewStringUTF(env, VESmail_local_gethost(*dp));
	jstring jport = (*env)->NewStringUTF(env, VESmail_local_getport(*dp));
	(*env)->CallVoidMethod(env, dst, meth, n, jsrv, jhost, jport);
    }
    return n;
}

JNIEXPORT jintArray JNICALL VESMAIL_JNI(getusers)(JNIEnv *env, jobject obj, jobject dst, jint last) {
    jint *ubuf = malloc(VESmail_local_ulen * sizeof(*ubuf));
    const char *ulogin = NULL;
    int st, i;
    jclass cls;
    jmethodID meth;
    for (i = 0; i < VESmail_local_ulen; i++) {
	VESmail_local_getuser(&ulogin, &st);
	if (!ulogin) break;
	if ((st & VESMAIL_LCST_LSTNERR) && VESmail_local_getusererror(ulogin, NULL)) st |= VESMAIL_LCSF_UERR;
	ubuf[i] = st;
	if (i == last) {
	    cls = (*env)->GetObjectClass(env, dst);
	    meth = (*env)->GetMethodID(env, cls, "setuser", "(ILjava/lang/String;)V");
	}
	if (i >= (unsigned) last) {
	    jstring juser = (*env)->NewStringUTF(env, ulogin);
	    (*env)->CallVoidMethod(env, dst, meth, i, juser);
	}
    }
    jintArray rs = (*env)->NewIntArray(env, i);
    if (rs) {
	(*env)->SetIntArrayRegion(env, rs, 0, i, ubuf);
    }
    free(ubuf);
    return rs;
}

JNIEXPORT jstring JNICALL VESMAIL_JNI(getuser)(JNIEnv *env, jobject obj, jint idx) {
    if (idx < 0) return NULL;
    const char *ulogin = NULL;
    int i;
    for (i = 0; i <= idx; i++) {
	VESmail_local_getuser(&ulogin, NULL);
	if (!ulogin) break;
    }
    if (!ulogin) return NULL;
    return (*env)->NewStringUTF(env, ulogin);
}

JNIEXPORT jstring JNICALL VESMAIL_JNI(getuserprofileurl)(JNIEnv *env, jobject obj, jint idx) {
    if (idx < 0) return NULL;
    const char *ulogin = NULL;
    int i;
    for (i = 0; i <= idx; i++) {
	VESmail_local_getuser(&ulogin, NULL);
	if (!ulogin) return NULL;
    }
    const char *prof = VESmail_local_getuserprofileurl(ulogin);
    if (!prof) return NULL;
    return (*env)->NewStringUTF(env, prof);
}

JNIEXPORT jstring JNICALL VESMAIL_JNI(getusererror)(JNIEnv *env, jobject obj, jint idx) {
    if (idx < 0) return NULL;
    const char *ulogin = NULL;
    int i;
    for (i = 0; i <= idx; i++) {
	VESmail_local_getuser(&ulogin, NULL);
	if (!ulogin) return NULL;
    }
    char err[32];
    if (!VESmail_local_getusererror(ulogin, err)) return NULL;
    return (*env)->NewStringUTF(env, err);
}


struct VESmail_jni_wake {
    JavaVM *jvm;
    jobject obj;
    jmethodID meth;
};

void VESmail_jni_wakefn(void *arg) {
    struct VESmail_jni_wake *wake = arg;
    JNIEnv *env;
    (*wake->jvm)->AttachCurrentThread(wake->jvm, &env, NULL);
    (*env)->CallVoidMethod(env, wake->obj, wake->meth);
    (*env)->DeleteGlobalRef(env, wake->obj);
    (*wake->jvm)->DetachCurrentThread(wake->jvm);
    free(wake);
}

JNIEXPORT void JNICALL VESMAIL_JNI(sleep)(JNIEnv *env, jobject obj, jobject dst) {
    struct VESmail_jni_wake *wake = malloc(sizeof(struct VESmail_jni_wake));
    (*env)->GetJavaVM(env, &wake->jvm);
    jclass cls = (*env)->GetObjectClass(env, dst);
    wake->obj = (*env)->NewGlobalRef(env, dst);
    wake->meth = (*env)->GetMethodID(env, cls, "wakeup", "()V");
    VESmail_local_sleep(&VESmail_jni_wakefn, wake);
}

JNIEXPORT jboolean JNICALL VESMAIL_JNI(snif)(JNIEnv *env, jobject obj, jstring cert, jstring pkey, jstring passphrase, jstring initurl) {
    const char *c = (*env)->GetStringUTFChars(env, cert, NULL);
    const char *k = (*env)->GetStringUTFChars(env, pkey, NULL);
    const char *p = passphrase ? (*env)->GetStringUTFChars(env, passphrase, NULL) : NULL;
    const char *u = initurl ? (*env)->GetStringUTFChars(env, initurl, NULL) : NULL;
    jboolean rs = !!VESmail_local_snif(c, k, p, u);
    (*env)->ReleaseStringUTFChars(env, cert, c);
    (*env)->ReleaseStringUTFChars(env, pkey, k);
    if (p) (*env)->ReleaseStringUTFChars(env, passphrase, p);
    if (u) (*env)->ReleaseStringUTFChars(env, initurl, u);
    return rs;
}

#ifdef VESMAIL_NOW_OAUTH
JNIEXPORT jboolean JNICALL VESMAIL_JNI(setoauth)(JNIEnv *env, jobject obj, jstring pkey, jstring passphrase) {
    const char *k = (*env)->GetStringUTFChars(env, pkey, NULL);
    const char *p = passphrase ? (*env)->GetStringUTFChars(env, passphrase, NULL) : NULL;
    jboolean rs = !!VESmail_local_setoauth(k, p);
    (*env)->ReleaseStringUTFChars(env, pkey, k);
    if (p) (*env)->ReleaseStringUTFChars(env, passphrase, p);
    return rs;
}
#endif

JNIEXPORT jint JNICALL VESMAIL_JNI(snifstat)(JNIEnv *env, jobject obj) {
    return VESmail_local_snifstat();
}

JNIEXPORT jstring JNICALL VESMAIL_JNI(snifhost)(JNIEnv *env, jobject obj) {
    return (*env)->NewStringUTF(env, VESmail_local_snifhost());
}

JNIEXPORT jstring JNICALL VESMAIL_JNI(snifauthurl)(JNIEnv *env, jobject obj) {
    return (*env)->NewStringUTF(env, VESmail_local_snifauthurl());
}

JNIEXPORT void JNICALL VESMAIL_JNI(snifawake)(JNIEnv *env, jobject obj, jboolean awake) {
    VESmail_local_snifawake(awake);
}

JNIEXPORT jstring JNICALL VESMAIL_JNI(feedback)(JNIEnv *env, jobject obj) {
    VESmail_local_setfeedback(NULL);
    return (*env)->NewStringUTF(env, VESmail_local_feedback);
}
