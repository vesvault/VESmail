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
#include <stdlib.h>
#include "../VESmail.h"
#include "arch.h"
#include "daemon.h"
#include "guard.h"

/* The guard supervises forked workers, so it needs the POSIX process API.
 * MinGW provides <unistd.h> but not fork()/<sys/wait.h>, so exclude _WIN32
 * (which falls through to the stub below). */
#if defined(HAVE_UNISTD_H) && !defined(_WIN32)

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>


int VESmail_guard(VESmail_daemon **daemons, int nworkers) {
    if (!nworkers) return 1;
    int total = nworkers * 2;
    VESmail_daemon **pd;
    for (pd = daemons; *pd; pd++) {
	int r = VESmail_daemon_listen(*pd);
	if (r) return r;
    }
    pid_t *workers = malloc(total * sizeof(pid_t));
    int i;
    for (i = 0; i < total; i++) workers[i] = 0;
    VESmail_arch_log("guard started");
    long long int tnext = time(NULL);
    char sig = 0;
    int ct = 0;
    while (1) {
	if (VESmail_daemon_SIG != sig) {
	    sig = VESmail_daemon_SIG;
	    if (sig) for (i = 0; i < total; i++) {
		if (workers[i]) {
		    VESmail_arch_log("guard kill pid=%d sig=%d", workers[i], sig);
		    kill(workers[i], sig);
		}
	    }
	    if (sig == SIGHUP) VESmail_daemon_SIG = 0;
	}
	for (i = 0; i < total; i++) {
	    if (workers[i]) {
		int st;
		int r = waitpid(workers[i], &st, WNOHANG);
		if (r > 0 || (r < 0 && errno == ECHILD)) {
		    VESmail_arch_log("worker died pid=%d st=%d", workers[i], st);
		    workers[i] = 0;
		    ct--;
		    tnext = time(NULL) + 30;
		}
	    } else if ((!sig && ct < nworkers && time(NULL) >= tnext) || sig == SIGHUP) {
		int f = fork();
		if (f < 0) {
		    tnext = time(NULL) + 60;
		    break;
		} else if (f) {
		    workers[i] = f;
		    ct++;
		} else {
		    free(workers);
		    VESmail_arch_log("worker started");
		    for (pd = daemons; *pd; pd++) {
			(*pd)->flags |= VESMAIL_DMF_KEEPSOCK;
		    }
		    return 1;
		}
	    }
	}
	if (sig && !ct) break;
	sleep(2);
    }
    VESmail_arch_log("guard exiting sig=%d", sig);
    free(workers);
    return 0;
}

#else

int VESmail_guard(VESmail_daemon **daemons, int nworkers) {
    if (!nworkers) return 1;
    return VESMAIL_E_PARAM;
}

#endif
