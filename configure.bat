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
rem  * (c) 2020 VESvault Corp
rem  * Jim Zubov <jz@vesvault.com>
rem  *
rem  * GNU General Public License v3
rem  * You may opt to use, copy, modify, merge, publish, distribute and/or sell
rem  * copies of the Software, and permit persons to whom the Software is
rem  * furnished to do so, under the terms of the COPYING file.
rem  *
rem  * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
rem  * KIND, either express or implied.
rem  *
rem  ***************************************************************************/

copy /Y Makefile.win Makefile

echo *
echo * Quick config for Windows + Visual Studio
echo *
echo * Makefile created
echo *
echo * Set the proper paths to OpenSSL and libcURL in Makefile,
echo * then run nmake
echo *
