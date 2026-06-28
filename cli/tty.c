/***************************************************************************
 *          ___       ___
 *         /   \     /   \    VESvault
 *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
 *            \\     //                   https://vesvault.com https://ves.host
 *             \\   //
 *     ___      \\_//
 *    /   \     /   \         libVES:                      VESvault API library
 *    \__ /     \ __/
 *       \\     //            VES Utility:   A command line interface to libVES
 *        \\   //
 *         \\_//              - Key Management and Exchange
 *         /   \              - Item Encryption and Sharing
 *         \___/              - Stream Encryption
 *
 *
 * (c) 2018-2026 VESvault Corp
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
 * ves-util/tty.c             VES Utility: Terminal Operations (Unix/Windows)
 *
 ***************************************************************************/
#ifdef HAVE_CONFIG_H

#include "../config.h"

#ifdef HAVE_TERMIOS_H
#ifdef HAVE_SYS_IOCTL_H
#define VES_TTY_UNIX	1
#endif
#endif

#if HAVE_WINDOWS_H
#define VES_TTY_WIN	1
#endif

#else

#ifdef _WIN32
#define VES_TTY_WIN	1
#else
#define VES_TTY_UNIX	1
#endif

#endif

#ifdef VES_TTY_UNIX
#include "tty_u.c"
#else
#ifdef VES_TTY_WIN
#include "tty_w.c"
#else

int tty_get_width(int fd) {
    return -1;
}

char *tty_getpass(const char *prompt, size_t maxlen) {
    return NULL;
}

#endif
#endif
