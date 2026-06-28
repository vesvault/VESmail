@echo off

rem /***************************************************************************
rem  *  _____
rem  * |\    | >                   VESmail
rem  * | \   | >  ___       ___    Email Encryption made Convenient and Reliable
rem  * |  \  | > /   \     /   \                               https://vesmail.email
rem  * |  /  | > \__ /     \ __/
rem  * | /   | >    \\     //        - RFC5322 MIME Stream Encryption & Decryption
rem  * |/____| >     \\   //         - IMAP4rev1 Transparent Proxy Server
rem  *       ___      \\_//          - ESMTP Transparent Proxy Server
rem  *      /   \     /   \          - VES Encryption Key Exchange & Recovery
rem  *      \__ /     \ __/
rem  *         \\     //    _____                     ______________by______________
rem  *          \\   //  > |\    |
rem  *           \\_//   > | \   |                    VESvault
rem  *           /   \   > |  \  |                    Encrypt Everything
rem  *           \___/   > |  /  |                    without fear of losing the Key
rem  *                   > | /   |                              https://vesvault.com
rem  *                   > |/____|                                  https://ves.host
rem  *
rem  * (c) 2020-2026 VESvault Corp
rem  * Jim Zubov <jz@vesvault.com>
rem  *
rem  * Apache License, Version 2.0
rem  * You may use, copy, modify, merge, publish, distribute and/or sell copies
rem  * of the Software under the terms of the Apache License, Version 2.0, a copy
rem  * of which is provided in the COPYING file, or http://www.apache.org/licenses/LICENSE-2.0
rem  *
rem  * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
rem  * CONDITIONS OF ANY KIND, either express or implied.
rem  *
rem  ***************************************************************************/

copy /Y Makefile.win Makefile

echo *
echo * Quick config for Windows + Visual Studio
echo *
echo * Makefile created
echo *
echo * Set the proper paths to OpenSSL, libcURL and libVES in Makefile,
echo * then run nmake
echo *
