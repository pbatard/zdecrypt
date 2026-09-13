zdecrypt: A decrypter for Zyxel `_encryp1_` fields
==================================================

[![Build status](https://img.shields.io/github/actions/workflow/status/pbatard/zdecrypt/vs2026.yml?style=flat-square&label=Windows%20Build)](https://github.com/pbatard/zdecrypt/actions/workflows/vs2026.yml)
[![Build status](https://img.shields.io/github/actions/workflow/status/pbatard/zdecrypt/linux.yml?style=flat-square&label=Linux%20Build)](https://github.com/pbatard/zdecrypt/actions/workflows/linux.yml)
[![Release](https://img.shields.io/github/release-pre/pbatard/zdecrypt.svg?style=flat-square)](https://github.com/pbatard/zdecrypt/releases)
[![Github stats](https://img.shields.io/github/downloads/pbatard/zdecrypt/total.svg?style=flat-square)](https://github.com/pbatard/zdecrypt/releases)
[![Licence](https://img.shields.io/badge/license-GPLv3-blue.svg?style=flat-square)](https://www.gnu.org/licenses/gpl-3.0.en.html)

## Description

`zdecrypt` is a console application that can be used to decrypt `_encryp1_` prefixed fields
found in modern Zyxel devices' JSON backup files.

It does so by trying to guess the encryption key used by the backup by trying all the 16-bit
derivations that Zyxel uses for their key generation.

While this was successfully tested against EE3301-00 and WE3300-00 JSON backups, no guarantee
is made that it will work for other devices. If that is the case, then please refer to the
_"Help, it doesn't work for me!"_ section below

## Usage

From a commandline, just run:

```
zdecrypt <Backup/Restore File>
```

Where `<Backup/Restore File>` is the path of the backup file you saved from your Zyxel device.

On Linux, you may need to ensure that you have the OpenSSL and json-c libraries installed.

## Compilation

Either open the `.sln` in Visual Studio 2026 on Windows or run `make` on Linux.

Note that on Linux, you will probably need to install the OpenSSL and json-c **development**
libraries to be able to compile the application.

On Windows, these dependencies are installed automatically through `vcpkg` so make sure that
your installation of Visual Studio does support `vcpkg`.

## Help, it doesn't work for me!

If it doesn't work for you then I will kindly ask that you attempt the following, provided
that you are proficient enough to perform these steps:

1. Gain root access to your device by following the procedure
   [described here](https://pete.akeo.ie/2026/09/gaining-root-access-on-zyxel-ee3301-and.html).
   Note that if you want to use SCP later, and you weren't able to extract the root password
   through serial access, you can always **temporarily** (until next reboot) set a root
   password of your choosing by issuing the command `passwd`.
2. Create a `/tmp/dump.sh` file with the following content:
   ```sh
   #!/bin/sh
   BS=4096
   DST=/tmp/dump
   mkdir $DST
   cat /proc/$1/maps | grep "rw-p" | awk '{print $1}' | ( IFS="-"
   while read a b; do
     dd if=/proc/$1/mem bs=$BS skip=$(( 0x$a / $BS )) count=$(( (0x$b - 0x$a) / $BS )) of="$DST/$1_mem_$a.bin"
   done )
   ```
3. Issue `chmod 755 /tmp/dump.sh`.
4. Issue `ps | grep zcmd | grep -v grep` to get the PID of `zcmd`.
   For instance, if the output produces:
   ```
    3334 root     21508 S    /bin/zcmd
   ```
   Then `3334` (the **first** number) is the PID you want.
5. Issue `/tmp/dump.sh <PID>` where you replace `<PID>` with the number you got above (e.g.
   `/tmp/dump.sh 3334`).
6. You should see a few lines about records in/out and a number of files will have been
   created in the `tmp/dump/` directory.
7. Using SCP (SFTP or FTP probably won't work but SCP should) or USB copy, if your device
   has a USB port, retrieve the content of the `/tmp/dump/` directory from your device.
8. Zip that content (using 7-zip or some other utility) and e-mail it to `pete@akeo.ie`, so
   that I can take a look and try to figure out the key derivation for your device...
