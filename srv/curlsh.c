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
 * (c) 2020-2026 VESvault Corp
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include "../VESmail.h"
#include "arch.h"
#include "curlsh.h"


void *VESmail_curlsh = NULL;
void *VESmail_curlsh_mutex = NULL;


void VESmail_curlsh_lockfn(CURL *handle, curl_lock_data data, curl_lock_access access, void *userptr) {
    VESmail_arch_mutex_lock(&VESmail_curlsh_mutex);
}

void VESmail_curlsh_unlockfn(CURL *handle, curl_lock_data data, void *userptr) {
    VESmail_arch_mutex_unlock(&VESmail_curlsh_mutex);
}

void VESmail_curlsh_init() {
    if (VESmail_curlsh) return;
    VESmail_curlsh = curl_share_init();
    curl_share_setopt(VESmail_curlsh, CURLSHOPT_LOCKFUNC, &VESmail_curlsh_lockfn);
    curl_share_setopt(VESmail_curlsh, CURLSHOPT_UNLOCKFUNC, &VESmail_curlsh_unlockfn);
    curl_share_setopt(VESmail_curlsh, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
    curl_share_setopt(VESmail_curlsh, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
}

void VESmail_curlsh_apply(void *curl) {
    if (VESmail_curlsh) curl_easy_setopt(curl, CURLOPT_SHARE, VESmail_curlsh);
}

void VESmail_curlsh_done() {
    if (VESmail_curlsh) curl_share_cleanup(VESmail_curlsh);
    VESmail_curlsh = NULL;
    VESmail_arch_mutex_done(VESmail_curlsh_mutex);
    VESmail_curlsh_mutex = NULL;
}
