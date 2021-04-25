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

extern struct VESmail_daemon **VESmail_local_daemons;
extern int VESmail_local_ulen;

void VESmail_local_init();
struct VESmail_daemon **VESmail_local_start();
int VESmail_local_watch();
int VESmail_local_getstat(int idx);
void VESmail_local_getuser(const char **usr, int *st);
const char *VESmail_local_getuserprofileurl(const char *ulogin);
int VESmail_local_run(long udelay);
const char *VESmail_local_gethost(struct VESmail_daemon *daemon);
const char *VESmail_local_getport(struct VESmail_daemon *daemon);

#define	VESMAIL_LCST_LSTN	0x0001
#define	VESMAIL_LCST_LSTNERR	0x0002
#define	VESMAIL_LCST_TRFREQ	0x0004
#define	VESMAIL_LCST_TRFRSP	0x0008
#define	VESMAIL_LCST_PROC	0x0010
#define	VESMAIL_LCST_PROCERR	0x0020
#define	VESMAIL_LCST_PROCNEW	0x0040
#define	VESMAIL_LCST_PROCDONE	0x0080
#define	VESMAIL_LCST_LOGINOK	0x00010000
#define	VESMAIL_LCST_LOGINERR	0x00020000

#ifndef VESMAIL_APP_BUILD
#define	VESMAIL_APP_BUILD	local
#endif
#define	VESMAIL_APP_BUILDSTR2(_build)	#_build
#define	VESMAIL_APP_BUILDSTR(_build)	VESMAIL_APP_BUILDSTR2(_build)
#define VESMAIL_VERSION_SHORT	"vesmail-" VESMAIL_APP_BUILDSTR(VESMAIL_APP_BUILD) "/" VESMAIL_VERSION

