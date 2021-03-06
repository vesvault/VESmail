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
 * (c) 2018 VESvault Corp
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
 * ves-util/tty_w.c           VES Utility: Terminal Operations (Windows)
 *
 ***************************************************************************/
#include <stddef.h>
#include <sys/types.h>
#include <windows.h>
#include <fcntl.h>
#include "tty.h"


int tty_get_width(int fd) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(_get_osfhandle(fd), &csbi);
    return csbi.srWindow.Right - csbi.srWindow.Left;
}

int tty_is_ansi(int fd) {
    int mode;
    return GetConsoleMode(_get_osfhandle(fd), &mode) && (mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING) && SetConsoleMode(_get_osfhandle(fd), mode);
}
