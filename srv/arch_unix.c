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

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/time.h>
#include <stdarg.h>
#include <syslog.h>

const char *VESmail_arch_NAME = "Unix";

void VESmail_arch_sa_h_alrm(int sig) {
}

void VESmail_arch_init() {
    static struct sigaction sa_alrm;
    sigaction(SIGALRM, NULL, &sa_alrm);
    sa_alrm.sa_handler = &VESmail_arch_sa_h_alrm;
    sigaction(SIGALRM, &sa_alrm, NULL);
}

int VESmail_arch_set_nb(int fd, int nb) {
    alarm(5);
    int flgs = fcntl(fd, F_GETFL, 0);
    if (flgs == -1) return VESMAIL_E_IO;
    flgs &= ~O_NONBLOCK;
    if (nb) flgs |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flgs);
}

int VESmail_arch_thread(VESmail_server *srv, void (* threadfn)(void *)) {
    return VESMAIL_E_PARAM;
}

int VESmail_arch_poll(int len, ...) {
    fd_set rd;
    struct timeval tmout = {
	.tv_sec = 5,
	.tv_usec = 0
    };
    FD_ZERO(&rd);
    int nfds = 1;
    va_list va;
    va_start(va, len);
    int i;
    for (i = 0; i < len; i++) {
	int fd = va_arg(va, int);
	if (fd >= FD_SETSIZE) return VESMAIL_E_PARAM;
	if (fd >= nfds) nfds = fd + 1;
	FD_SET(fd, &rd);
    }
    va_end(va);
    alarm(0);
    int r = select(nfds, &rd, NULL, NULL, &tmout);
    if (r < 0) switch (errno) {
	case EINTR:
	case EAGAIN:
	    break;
	default:
	    return VESMAIL_E_IO;
    }
    return 0;
}

char *VESmail_arch_gethostname() {
    char *h = malloc(256);
    if (gethostname(h, 256) >= 0) {
	return realloc(h, strlen(h) + 1);
    } else {
	free(h);
	return NULL;
    }
}

int VESmail_arch_creat(const char *path) {
    return open(path, O_CREAT | O_EXCL | O_WRONLY, 0666);
}

int VESmail_arch_openr(const char *path) {
    return open(path, O_RDONLY);
}

int VESmail_arch_read(int fd, char *buf, int len) {
    return read(fd, buf, len);
}

int VESmail_arch_write(int fd, const char *src, int len) {
    return write(fd, src, len);
}

int VESmail_arch_close(int fd) {
    return close(fd);
}

int VESmail_arch_log(const char *fmt, ...) {
    static char started = 0;
    if (!started) {
	openlog("vesmail", LOG_PID, LOG_MAIL);
	started = 1;
    }
    va_list va;
    va_start(va, fmt);
    vsyslog(LOG_NOTICE, fmt, va);
    va_end(va);
    return 0;
}
