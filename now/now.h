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

struct VESmail_optns;
struct VESmail_xform;

typedef struct VESmail_now_req {
    struct VESmail_xform *xform;
    char method[16];
    struct {
	const char *start;
	const char *path;
	const char *search;
	const char *hash;
	const char *end;
    } uri;
    struct {
	const char *start;
	const char *end;
    } hdr;
    struct VESmail_now_hdr {
	struct VESmail_now_hdr *chain;
	const char *val;
	const char *end;
	const char *lcval;
	const char *next;
	char key[0];
    } *headers;
} VESmail_now_req;

struct VESmail_server *VESmail_server_new_now(struct VESmail_optns *optns);
int VESmail_now_error(struct VESmail_server *srv, int code, const char *msg);
void VESmail_now_log(struct VESmail_server *srv, const char *meth, int code, ...);
int VESmail_now_send(struct VESmail_server *srv, int final, const char *str);
int VESmail_now_send_status(struct VESmail_server *srv, int code);
int VESmail_now_sendhdrs(struct VESmail_server *srv);
int VESmail_now_sendcl(struct VESmail_server *srv, const char *body);
int VESmail_now_req_cont(struct VESmail_now_req *req);

#define VESmail_now_errorlog(srv, code, msg, meth, ...) (VESmail_now_log(srv, meth, code, __VA_ARGS__), VESmail_now_error(srv, code, msg))
#define VESmail_now_CONF(srv, key)	((srv)->optns->ref ? ((VESmail_conf *) srv->optns->ref)->key : NULL)
#define VESmail_now_PCONF(srv, key)	((srv)->optns->ref ? &((VESmail_conf *) srv->optns->ref)->key : NULL)

struct VESmail_now_hdr *VESmail_now_req_header(struct VESmail_now_req *req, struct VESmail_now_hdr *prev);
void VESmail_now_req_cleanup(struct VESmail_now_req *req);


#define	VESMAIL_MERR_NOW	0x0100

#ifndef VESMAIL_NOW_REQ_SAFEBYTES
#define	VESMAIL_NOW_REQ_SAFEBYTES	32767
#endif

#ifndef VESMAIL_NOW_TMOUT
#define	VESMAIL_NOW_TMOUT	20
#endif
