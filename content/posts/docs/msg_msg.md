---
date: '2025-01-14T19:00:00Z'
draft: false
title: 'Kpwn tecniques: struct msg_msg'
summary: "msg_msg is a really powerful and elastic kernel struct that can be abused to obtain strong primitives, such as arbitrary read/write/free."

categories: ["Docs"]
tags: ["kernel"]
author: "leo_something"
ShowToc: true
---

## Struct msg_msg

As I just started kernel exploitation I'll cover the basics of this struct, but at the bottom there are other useful links for further exploitation.
Maybe I'll write a part 2 in the future.

#### Overview
**msg_msg** is a struct used by 
```c
int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
``` 
and
```c
ssize_t msgrcv(int msqid, void msgp, size_t msgsz, long msgtyp, int msgflg);
```

These are syscalls responsible for sending and receiving messages to/from a queue identified by `msqid`.

This struct is composed as follows:
```c
struct msg_msg {
    struct list_head m_list;
    long m_type;
    size_t m_ts;      /* message text size */
    struct msg_msgseg *next;
    void *security;
    /* the actual message follows immediately */
};
```

So there are 0x30 bytes of metdata before the actual message.

If `message size > 0x1000 - 0x30` the message gets splitted into different allocations. These allocations are linked in a linked list, using the `next` pointer.
This pointer can be abused for **kheap leak** and **arbitrary read**.

As `sizeof(struct msg_msg) = message length + 0x30` this struct can be allocated inside an arbitrary kmalloc cache, starting from **kmalloc-64**, up to **kmalloc-4k**.

If `message size > 0xfd0 (0x1000-0x30)` multiple allocations are made by the kernel, but only the first one contains all of the message metadata. The other allocations will have only 8 bytes of metadata, occupied by the `next` pointer of the linked list.

```c
struct msg_msgseg {
    struct msg_msgseg *next;
    /* the next part of the message follows immediately */
};
```

#### Exploitation
This struct is very versatile, thus it can be exploited in many different ways.

The basic ones are:
- **Arbitrary Read**
	- Leverage an UAF or OOB write to override the `m_ts` and `next` pointer. 
		If `m_ts > 0xfd0` it means that the message is segmented into multiple allocations, but as we control `next` we decide where the next segment of message is.
	-  Now calling `msgrcv` will get the kernel to read `m_ts` bytes of message from the various segments. As we control `next` we gained arbitrary read on kernel memory.  

- **Kheap leak & Uninitialized memory access**
	- Allocate a **msg_msg** using `msgsnd`
	- Free it with `msgrcv`
	- We can allocate over this memory and leverage uninitialized memory access to leak kheap from the message metadata
	
	This can be abused further in specific cases, I did that to solve **empdb** from **BackdoorCTF 2023**.
	In that case, using **msg_msg** was an easy way to obtain a free chunk containing arbitrary values (the message text).  From there I could allocate an array of pointers over the freed **msg_msg** and, leveraging uninitialized memory access, I was able to gain arbitrary write. More on that here.

## Useful links & further exploitation
- https://syst3mfailure.io/wall-of-perdition/
- https://www.willsroot.io/2021/08/corctf-2021-fire-of-salvation-writeup.html
- https://hardenedvault.net/blog/2022-11-13-msg_msg-recon-mitigation-ved/
- https://linux.die.net/man/2/msgsnd