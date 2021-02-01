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

#include <winsock2.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <windows.h>
#include <sys/stat.h>
#include <stdio.h>


const char *VESmail_arch_NAME = "Win32";
WSADATA VESmail_arch_win_WSAdata;

void VESmail_arch_init() {
    WSAStartup(MAKEWORD(2, 2), &VESmail_arch_win_WSAdata);
}

int VESmail_arch_sigaction(int sig, void (* sigfn)(int)) {
    return VESMAIL_E_PARAM;
}

int VESmail_arch_set_nb(int fd, int nb) {
    if (!nb) {
	DWORD tmout = 30000;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tmout, sizeof(tmout));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tmout, sizeof(tmout));
    }
    u_long flags = nb ? 1 : 0;
    return NO_ERROR == ioctlsocket(fd, FIONBIO, &flags) ? 0 : VESMAIL_E_IO;
}

struct VESmail_arch_win_thread {
    void *(* threadfn)(void *);
    void *arg;
    void *thread;
    char detached;
};

DWORD WINAPI VESmail_arch_win_fn_thread(LPVOID arg) {
    struct VESmail_arch_win_thread *pt = arg;
    pt->threadfn(pt->arg);
    if (pt->detached) VESmail_arch_thread_done(pt);
    return 0;
}

int VESmail_arch_thread(void *arg, void *(* threadfn)(void *), void **pth) {
    struct VESmail_arch_win_thread *pt = malloc(sizeof(struct VESmail_arch_win_thread));
    pt->threadfn = threadfn;
    pt->arg = arg;
    pt->detached = !pth;
    if (!(pt->thread = CreateThread(NULL, 0, &VESmail_arch_win_fn_thread, pt, 0, NULL))) return free(pt), VESMAIL_E_IO;
    if (pth) *pth = pt;
    return 0;
}

int VESmail_arch_thread_kill(void *th) {
    return VESMAIL_E_PARAM;
}

void VESmail_arch_thread_done(void *th) {
    if (th) {
	struct VESmail_arch_win_thread *pt = th;
	CloseHandle(pt->thread);
	free(th);
    }
}

int VESmail_arch_mutex_lock(void **pmutex) {
    if (!*pmutex) {
	*pmutex = CreateMutex(NULL, 0, NULL);
	if (!*pmutex) return VESMAIL_E_IO;
    }
    DWORD r = WaitForSingleObject(*pmutex, INFINITE);
    if (r == WAIT_OBJECT_0) return 0;
    return VESMAIL_E_IO;
}

int VESmail_arch_mutex_unlock(void **pmutex) {
    return ReleaseMutex(*pmutex) ? 0 : VESMAIL_E_IO;
}

void VESmail_arch_mutex_done(void *mutex) {
    if (mutex) CloseHandle(mutex);
}


int VESmail_arch_poll(int len, ...) {
    int r, i;
    WSAPOLLFD pl[4];
    va_list va;
    va_start(va, len);
    if (len > sizeof(pl) / sizeof(*pl)) len = sizeof(pl) / sizeof(*pl);
    for (i = 0; i < len; i++) {
	pl[i].fd = va_arg(va, int);
	pl[i].events = POLLIN;
    }
    va_end(va);
    r = WSAPoll(pl, len, 5000);
    return r < 0 ? VESMAIL_E_IO : 0;
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

int VESmail_arch_setlinebuf(void *file) {
    return setvbuf(file, NULL, _IONBF, 0);
}

int VESmail_arch_close(int fd) {
    return close(fd);
}

int VESmail_arch_vlog(const char *fmt, void *va) {
    return 0;
}

int VESmail_arch_log(const char *fmt, ...) {
    return 0;
}

int VESmail_arch_usleep(unsigned long int usec) {
    Sleep(usec / 1000);
    return 0;
}

int VESmail_arch_getpid() {
    return _getpid();
}

unsigned long VESmail_arch_mtime(const char *path) {
    struct _stat st;
    if (_stat(path, &st)) return 0;
    return st.st_mtime;
}

