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
    GetConsoleScreenBufferInfo((HANDLE) _get_osfhandle(fd), &csbi);
    return csbi.srWindow.Right - csbi.srWindow.Left;
}

int tty_is_ansi(int fd) {
    DWORD mode;
    return GetConsoleMode((HANDLE) _get_osfhandle(fd), &mode) && (mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING) && SetConsoleMode((HANDLE) _get_osfhandle(fd), mode);
}
