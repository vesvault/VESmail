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

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <syslog.h>
#include <pthread.h>
#include <stdio.h>

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

const char *VESmail_arch_NAME = "Unix";

void VESmail_arch_sa_h_alrm(int sig) {
}

void VESmail_arch_init() {
    signal(SIGPIPE, SIG_IGN);
    VESmail_arch_sigaction(SIGALRM, &VESmail_arch_sa_h_alrm);
}

int VESmail_arch_sigaction(int sig, void (* sigfn)(int)) {
    struct sigaction sa;
    sigaction(sig, NULL, &sa);
    sa.sa_handler = sigfn;
    return sigaction(sig, &sa, NULL) < 0 ? VESMAIL_E_IO : 0;
}

int VESmail_arch_set_nb(int fd, int nb) {
    if (!nb) {
	struct timeval tmout = {
	    .tv_sec = 30,
	    .tv_usec = 0
	};
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tmout, sizeof(tmout));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tmout, sizeof(tmout));
    }
    int flgs = fcntl(fd, F_GETFL, 0);
    if (flgs == -1) return VESMAIL_E_IO;
    flgs &= ~O_NONBLOCK;
    if (nb) flgs |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flgs) ? VESMAIL_E_IO : 0;
}

int VESmail_arch_thread(void *arg, void *(* threadfn)(void *), void **pth) {
    pthread_t pt;
    if (pthread_create(&pt, NULL, threadfn, arg)) return VESMAIL_E_IO;
    if (pth) {
	*pth = malloc(sizeof(pt));
	memcpy(*pth, &pt, sizeof(pt));
    } else {
	pthread_detach(pt);
    }
    return 0;
}

int VESmail_arch_thread_kill(void *th) {
    return th ? (pthread_kill(*((pthread_t *) th), SIGHUP) < 0 ? VESMAIL_E_IO : 0) : VESMAIL_E_PARAM;
}

void VESmail_arch_thread_done(void *th) {
    if (th) {
	pthread_join(*((pthread_t *) th), NULL);
	free(th);
    }
}

int VESmail_arch_mutex_lock(void **pmutex) {
    if (!*pmutex) {
	*pmutex = malloc(sizeof(pthread_mutex_t));
	pthread_mutex_init(*pmutex, NULL);
    }
    return pthread_mutex_lock(*pmutex);
}

int VESmail_arch_mutex_unlock(void **pmutex) {
    return pthread_mutex_unlock(*pmutex);
}

void VESmail_arch_mutex_done(void *mutex) {
    if (mutex) pthread_mutex_destroy(mutex);
    free(mutex);
}



int VESmail_arch_poll(int len, ...) {
    int r, i;
#ifdef HAVE_POLL_H
    struct pollfd pl[4];
    va_list va;
    va_start(va, len);
    if (len > sizeof(pl) / sizeof(*pl)) len = sizeof(pl) / sizeof(*pl);
    for (i = 0; i < len; i++) {
	pl[i].fd = va_arg(va, int);
	pl[i].events = POLLIN;
    }
    va_end(va);
    r = poll(pl, len, VESMAIL_POLL_TMOUT * 1000);
#else
    fd_set rd;
    struct timeval tmout = {
	.tv_sec = VESMAIL_POLL_TMOUT,
	.tv_usec = 0
    };
    FD_ZERO(&rd);
    int nfds = 1;
    va_list va;
    va_start(va, len);
    for (i = 0; i < len; i++) {
	int fd = va_arg(va, int);
	if (fd >= FD_SETSIZE) return VESMAIL_E_PARAM;
	if (fd >= nfds) nfds = fd + 1;
	FD_SET(fd, &rd);
    }
    va_end(va);
    r = select(nfds, &rd, NULL, NULL, &tmout);
#endif
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
	return strdup("localhost");
    }
}

int VESmail_arch_getpid() {
    return getpid();
}

int VESmail_arch_creat(const char *path) {
    if (!path) return VESMAIL_E_PARAM;
    return open(path, O_CREAT | O_EXCL | O_WRONLY, 0666);
}

int VESmail_arch_openr(const char *path) {
    if (!path) return VESMAIL_E_PARAM;
    return open(path, O_RDONLY);
}

int VESmail_arch_read(int fd, char *buf, int len) {
    return read(fd, buf, len);
}

int VESmail_arch_write(int fd, const char *src, int len) {
    return write(fd, src, len);
}

int VESmail_arch_setlinebuf(void *file) {
    return setlinebuf(file), 0;
}

int VESmail_arch_close(int fd) {
    return close(fd);
}

#ifndef VESMAIL_LOG_FACILITY
#define VESMAIL_LOG_FACILITY LOG_MAIL
#endif
#ifndef VESMAIL_LOG_LEVEL
#define VESMAIL_LOG_LEVEL LOG_NOTICE
#endif

int VESmail_arch_vlog(const char *fmt, va_list va) {
    static char started = 0;
    if (!started) {
	openlog("vesmail", LOG_PID, VESMAIL_LOG_FACILITY);
	started = 1;
    }
    vsyslog(VESMAIL_LOG_LEVEL, fmt, va);
    return 0;
}

int VESmail_arch_log(const char *fmt, ...) {
    va_list va;
    va_start(va, fmt);
    VESmail_arch_vlog(fmt, va);
    va_end(va);
    return 0;
}

int VESmail_arch_usleep(unsigned long int t) {
    struct timespec ts = {
	.tv_sec = t / 1000000,
	.tv_nsec = (t % 1000000) * 1000
    };
    return nanosleep(&ts, NULL);
}

unsigned long VESmail_arch_mtime(const char *path) {
    struct stat st;
    if (stat(path, &st)) return 0;
    return st.st_mtime;
}

int VESmail_arch_getuid() {
    return getuid();
}

int VESmail_arch_mkdir(const char *path, short mod) {
    if (!path) return VESMAIL_E_PARAM;
    return mkdir(path, mod);
}

