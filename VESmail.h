/***************************************************************************
 *  _____
 * |\    | >                   VESmail Project
 * | \   | >  ___       ___    Email Encryption made Convenient and Reliable
 * |  \  | > /   \     /   \                              https://mail.ves.world
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

struct VESmail;
struct libVES;

#ifdef HAVE_CONFIG_H
#ifndef PACKAGE_VERSION
#include "config.h"
#endif
#endif

#ifdef	PACKAGE_VERSION
#define	VESMAIL_VERSION		PACKAGE_VERSION
#else
#define	VESMAIL_VERSION		"0.85a"
#endif

#define	VESMAIL_SHORT_NAME	"VESmail"

#define	VESMAIL_VES_DOMAIN	"vesmail"

#define	VESMAIL_E_OK		0
#define	VESMAIL_E_PARAM		-1
#define	VESMAIL_E_BUF		-2
#define	VESMAIL_E_VES		-3
#define	VESMAIL_E_IO		-4
#define	VESMAIL_E_UNKNOWN	-5
#define	VESMAIL_E_AUTH		-6
#define	VESMAIL_E_CONF		-7
#define	VESMAIL_E_RESOLV	-16
#define	VESMAIL_E_CONN		-17
#define	VESMAIL_E_TLS		-18
#define	VESMAIL_E_SASL		-19
#define	VESMAIL_E_INTERNAL	-32
#define	VESMAIL_E_HOLD		-100

#define VESMAIL_DEBUG_LIBVES	4

/*
libVESmail interface calls to be defined here
*/
