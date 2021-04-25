# Set the correct paths to libs and headers

INC_CURL := /src/android/curl/$(TARGET_ARCH_ABI)/include
LIB_CURL := /src/android/curl/$(TARGET_ARCH_ABI)/lib/libcurl.a
INC_OPENSSL := /src/android/openssl/$(TARGET_ARCH_ABI)/include
LIB_CRYPTO := /src/android/openssl/$(TARGET_ARCH_ABI)/lib/libcrypto.a
LIB_SSL := /src/android/openssl/$(TARGET_ARCH_ABI)/lib/libssl.a
INC_VES := $(call my-dir)/../libVES-c/lib
LIB_VES := $(call my-dir)/../../AndroidStudioProjects/libVES/app/build/intermediates/ndkBuild/debug/obj/local/$(TARGET_ARCH_ABI)/libVES.so


LOCAL_PATH := $(call my-dir)

LOCAL_MODULE := libvesmail
LOCAL_MODULE_FILENAME := libvesmail

LOCAL_CFLAGS += -I$(INC_OPENSSL) \
    -I$(INC_CURL) \
    -I$(INC_VES) \
    -DVESMAIL_LOCAL \
    -DVESMAIL_X509STORE \
    -DVESMAIL_LOG_FACILITY=LOG_USER \
    -DVESMAIL_APP_BUILD=android \
    -DVESMAIL_CURLSH \
    -DVESMAIL_POLL_TMOUT=45 \
    -DHAVE_POLL_H \
    -DHAVE_CURL_CURL_H

LOCAL_ALLOW_UNDEFINED_SYMBOLS := true

LOCAL_SHARED_LIBRARIES += libVES
LOCAL_STATIC_LIBRARIES += libcurl libcrypto libssl

LOCAL_SRC_FILES := lib/mail.c lib/optns.c lib/parse.c lib/header.c \
    lib/xform.c lib/multi.c lib/cte.c lib/ves.c lib/encrypt.c \
    lib/decrypt.c lib/banner.c lib/util.c \
    srv/server.c srv/arch.c srv/tls.c srv/sasl.c srv/proc.c srv/daemon.c \
    srv/conf.c srv/override.c srv/curlsh.c srv/local.c srv/x509store.c \
    imap/imap.c imap/imap_xform.c imap/imap_token.c imap/imap_track.c \
    imap/imap_start.c imap/imap_proxy.c imap/imap_msg.c \
    imap/imap_fetch.c imap/imap_result.c imap/imap_result_proc.c \
    imap/imap_sect.c imap/imap_append.c imap/imap_xves.c \
    smtp/smtp.c smtp/smtp_cmd.c smtp/smtp_reply.c smtp/smtp_track.c \
    smtp/smtp_start.c smtp/smtp_proxy.c smtp/smtp_xves.c \
    now/now.c now/now_store.c now/now_probe.c \
    util/jTree.c \
    app/jni.c

include $(BUILD_SHARED_LIBRARY)


include $(CLEAR_VARS)
LOCAL_PATH := $(call my-dir)
LOCAL_MODULE := libVES
LOCAL_SRC_FILES := $(LIB_VES)
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libcrypto
LOCAL_MODULE_FILENAME := libcrypto
LOCAL_SRC_FILES := $(LIB_CRYPTO)
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libssl
LOCAL_MODULE_FILENAME := libssl
LOCAL_SRC_FILES := $(LIB_SSL)
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libcurl
LOCAL_MODULE_FILENAME := libcurl
LOCAL_SRC_FILES := $(LIB_CURL)
include $(PREBUILT_STATIC_LIBRARY)
