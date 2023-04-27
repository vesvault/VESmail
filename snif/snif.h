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
 *
 *     _________
 *    /````````_\                  S N I F ~ e2e TLS trust for IoT
 *   /\     , / O\      ___
 *  | |     | \__|_____/  o\       e2e TLS SNI Forwarder
 *  | |     |  ``/`````\___/       e2e TLS CA Proxy
 *  | |     | . | <"""""""~~
 *  |  \___/ ``  \________/        https://snif.host
 *   \  '''  ``` /````````         (C) 2021 VESvault Corp
 *    \_________/                  Jim Zubov <jz@vesvault.com>
 *
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


typedef struct VESmail_snif {
    struct snif_cert *cert;
    struct VESmail_snif_port {
	const char *port;
	struct VESmail_daemon_sock *sock;
	int tls;
    } *ports;
    struct VESmail_tls_server *tls;
    void *thread;
    struct VESmail_conf *mftconf;
    char *msgout;
    void *mutex;
    struct VESmail_daemon **daemons;
    unsigned long backoff;
    char running;
    char waiting;
    char hold;
} VESmail_snif;

struct VESmail_daemon;

#define	VESMAIL_SNIFST_INIT	0
#define	VESMAIL_SNIFST_OK	1
#define	VESMAIL_SNIFST_RETRY	2
#define	VESMAIL_SNIFST_AUTH	3

#ifndef VESMAIL_SNIF_INITURL
#define	VESMAIL_SNIF_INITURL	"https://snif.vesmail.xyz:4443"
#endif
#ifndef VESMAIL_SNIF_RPORT
#define	VESMAIL_SNIF_RPORT	"7123"
#endif
#ifndef VESMAIL_SNIF_REKEY
#define	VESMAIL_SNIF_REKEY	10
#endif

#ifndef VESMAIL_SNIF_ALIVE
#define	VESMAIL_SNIF_ALIVE	240
#endif
#ifndef VESMAIL_SNIF_STALE
#define	VESMAIL_SNIF_STALE	1440
#endif
#ifndef VESMAIL_SNIF_TMOUT
#define	VESMAIL_SNIF_TMOUT	15
#endif
#ifndef VESMAIL_SNIF_BACKOFF
#define	VESMAIL_SNIF_BACKOFF	10
#endif
#ifndef VESMAIL_SNIF_ABUSE
#define	VESMAIL_SNIF_ABUSE	1
#endif

struct VESmail_server *VESmail_snif_new(struct snif_cert *cert, struct VESmail_snif_port *ports, struct VESmail_daemon **daemons);
struct VESmail_daemon_sock *VESmail_snif_daemonsock(struct VESmail_daemon *daemon);
void VESmail_snif_initcert(struct snif_cert *cert);
int VESmail_snif_stat(struct VESmail_server *srv);
int VESmail_snif_awake(struct VESmail_server *srv, int awake);
int VESmail_snif_msg(struct VESmail_server *srv, const char *msg);

struct VESmail_conf *VESmail_snif_mftconf(struct VESmail_snif *snif, struct VESmail_conf *conf);
void *VESmail_snif_tlsctx(struct VESmail_snif *snif);
