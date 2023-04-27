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

extern const char *VESmail_arch_NAME;

#ifndef VESMAIL_POLL_TMOUT
#define VESMAIL_POLL_TMOUT 5
#endif

void VESmail_arch_init();
void VESmail_arch_done();
int VESmail_arch_sigaction(int sig, void (* sigfn)(int));
int VESmail_arch_set_nb(int fd, int nb);
int VESmail_arch_thread(void *arg, void *(* threadfn)(void *), void **pth);
void VESmail_arch_thread_done(void *th);
int VESmail_arch_thread_kill(void *th);
int VESmail_arch_mutex_lock(void **pmutex);
int VESmail_arch_mutex_unlock(void **pmutex);
void VESmail_arch_mutex_done(void *mutex);
int VESmail_arch_polltm(long tmout, int len, ...);
#define	VESmail_arch_poll(...)		VESmail_arch_polltm(VESMAIL_POLL_TMOUT, __VA_ARGS__)
char *VESmail_arch_gethostname();
int VESmail_arch_getpid();
int VESmail_arch_creat(const char *path);
int VESmail_arch_openr(const char *path);
int VESmail_arch_read(int fd, char *buf, int len);
int VESmail_arch_write(int fd, const char *src, int len);
int VESmail_arch_setlinebuf(void *file);
int VESmail_arch_keepalive(int fd);
int VESmail_arch_close(int fd);
int VESmail_arch_shutdown(int fd);
int VESmail_arch_log(const char *fmt, ...);
#ifdef va_arg
int VESmail_arch_vlog(const char *fmt, va_list va);
#endif
int VESmail_arch_usleep(unsigned long int t);
unsigned long VESmail_arch_mtime(const char *path);
int VESmail_arch_getuid();
int VESmail_arch_mkdir(const char *path, short mod);

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

#ifndef VESMAIL_CONF_PATH
#define VESMAIL_CONF_PATH	""
#endif

#ifndef VESMAIL_LOG_MUTEX
#define VESMAIL_LOG_MUTEX	1
#endif

#else

#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip.h>

#ifndef VESMAIL_CONF_PATH
#define VESMAIL_CONF_PATH	"/etc/vesmail/"
#endif

#ifndef VESMAIL_LOG_MUTEX
#define VESMAIL_LOG_MUTEX	0
#endif

#endif
