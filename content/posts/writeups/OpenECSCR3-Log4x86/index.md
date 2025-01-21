---
date: '2024-05-25T12:00:00Z'
draft: false
title: 'OpenECSC Round 3 - Log4x86'
summary: "This challenge comes from the 3rd round of openECSC 2024. The challenge was really really interesting: the exploitation tecnique involved a buffer overflow through a really short format string vulnerability."

categories: ["Writeups"]
tags: ["pwn", "format string", "bof"]
author: "leo_something"
ShowToc: True
---

## Challenge Description

Logging data from your application is very important. This is why we are logging ABSOLUTELY EVERYTHING in this small calculator app.

`nc log4x86.challs.open.ecsc2024.it 38019`

---
## Overview

Log4x86 is an x86 64 bit binary which consists in a simple calculator app wrapped with basic logging functionalities, such as:

- changing log level
- changing log format
- resetting log format 

Reading the decompiled code we can easily notice the intense use of `printf` and `snprinf`, which might be vulnerable to format string attacks.

---
## Reverse Engineering

Decompiling the binary with Ida we can get a pretty neat `main` function.
It's basically a while loop which gets our input with a well implemented `fgets`, then it parses it with the following instruction:

```c
__isoc99_sscanf(command, "%63s %31s %31s %31s", cmd, arg1, arg2, arg3);
```

Then we have a series of if statements that call different functions according to the command we inputted.
Each command is logged to stdout with the following code:

```c
if (GLOBAL_LOG_LEVEL <= 1 ) {
	if ( OLD_LOG != 999 ) {
		logLevel = logLevelResolver(1u, "reset_log_format");
		sprintf(
			  log_msg_base, 
			  LOG_FORMAT, 
			  logLevel, 
			  "logloglog.c", 
			  999LL, 
			  "Reset log format to: '%s'"
			);
		OLD_LOG = 999;
	}
printf(log_msg_base, LOG_FORMAT);
}
```

This basically writes a log message with the format string specified by `LOG_FORMAT` but, as I specified earlier, changing `LOG_FORMAT` is a functionality provided by the program itself so we could ideally inject a format-string exploit into it and then trigger it with the next `snprintf`. Fortunately or unfortunately (choice to you), this is not that easy, there are some checks and constraints to bypass:

1. The new `LOG_FORMAT` can be max 10 char long (including the NULL byte)
2. `LOG_FORMAT` cannot contain `$` and `*`
3. There is also a regex check, but we don't really care about it

Another great thing to notice is that `log_msg_base` is changed only the first time a specific log is triggered. In short, if we trigger the same command multiple times in a row, only the first time `log_msg_base` will change. Keep this in mind, it will come in useful.

---
## Exploitation

### First steps

First thing I like to do before pwning is running `pwninit` to patch the binary with the correct version of libc and create a Pwntools template script.

To get the correct libc version used by the remote we can pull the docker image specified in `docker-compose.yml` and then extract `libc.so.6` from it.

```shell
$ docker pull cybersecnatlab/challenge-jail@sha256:7bf77225063b039960f654307cf5d6f977f892ff548606357a2e8fe8067d0a88

REPOSITORY                      TAG       IMAGE ID       CREATED         SIZE
cybersecnatlab/challenge-jail   <none>    02becdec589e   8 months ago    139MB

$ docker cp "$(docker create 02becdec589e):/usr/lib/x86_64-linux-gnu/libc.so.6" "./"
Successfully copied 2.22MB to ./
```

Then run pwninit with

```shell
$ pwninit --bin=logloglog --libc=./libc.so.6
```

Another good practice is to run `checksec` on the binary

```shell
$ checksec --file=logloglog_patched
RELRO           STACK CANARY      NX            PIE
Partial RELRO   Canary found      NX enabled    PIE enabled
```

Mhhh, Partial RELRO... GOT override might be possible.

### Initial ideas

After finding the format string I tried some basic payloads like `%p`and leaked ASLR base address, but I couldn't do anything more seeing that I had only 9 chars to write my payload.

Messing around with the payload I figured out that we could trigger a sort of "second-order" format string attack by setting the log format to something like `%%p`.
This transforms into a `%p` after the `sprintf` and then is used by `printf`, with this technique I leaked the stack.

```shell
$ ./logloglog_patched
> change_log_format
%%p
[DBG-logloglog.c:103] Successfully read some bytes
0x597c3dd200f0
> aaaaaaa
0x7ffeaa48a0e0
```

Spoiler: this won't be really useful :(

As we cannot use `$` we can only interact with the first 3 parameters of printf, which are contained respectively in `rsi`, `rdx` and `rcx`. I inspected these register before every call to printf and sadly found out that there are no useful pointers to tamper in there.

### Bypassing the whitelist

After another few ours of trying random stuff and thinking hard I noticed that the `log_msg_base` global variable (which is the string where sprintf writes) is right on top of the `command` global variable (which contains our input taken by fgets), so changing the log format to `%256c` would cause `log_msg_base` to overflow into `command`, the next command will then override the terminator NULL byte of `log_msg_base`, causing it to be longer than 9 chars and bypass the whitelist.

_Memory after `%256c`:_
```
0x555555558120 <log_msg_base>:	    0x2020202020202020	0x2020202020202020
0x555555558130 <log_msg_base+16>:	0x2020202020202020	0x2020202020202020
0x555555558140 <log_msg_base+32>:	0x2020202020202020	0x2020202020202020
0x555555558150 <log_msg_base+48>:	0x2020202020202020	0x2020202020202020
0x555555558160 <log_msg_base+64>:	0x2020202020202020	0x2020202020202020
0x555555558170 <log_msg_base+80>:	0x2020202020202020	0x2020202020202020
0x555555558180 <log_msg_base+96>:	0x2020202020202020	0x2020202020202020
0x555555558190 <log_msg_base+112>:	0x2020202020202020	0x2020202020202020
0x5555555581a0 <log_msg_base+128>:	0x2020202020202020	0x2020202020202020
0x5555555581b0 <log_msg_base+144>:	0x2020202020202020	0x2020202020202020
0x5555555581c0 <log_msg_base+160>:	0x2020202020202020	0x2020202020202020
0x5555555581d0 <log_msg_base+176>:	0x2020202020202020	0x2020202020202020
0x5555555581e0 <log_msg_base+192>:	0x2020202020202020	0x2020202020202020
0x5555555581f0 <log_msg_base+208>:	0x2020202020202020	0x2020202020202020
0x555555558200 <log_msg_base+224>:	0x2020202020202020	0x2020202020202020
0x555555558210 <log_msg_base+240>:	0x2020202020202020	0x1c20202020202020
0x555555558220 <command>:	        0x6c5f65676e61000a	0x616d726f665f676f
```

From here it's all straight forward, we can write a format string as a command, thus overriding the NULL byte of `log_msg_base` (effectively enlarging `log_msg_base` itself).
When `printf(log_msg_base)` is called it will trigger our format string which, at this point, has only one constraint: it can contain only one pointer (because the string ends with a NULL byte).

### Arbitrary write and ret2libc

Now we can leak libc and think about how to achieve ACE.
My first idea was to override something on the GOT with a onegadget, but I didn't manage to find a GOT entry that satisfied the constraints of any onegadget. This was not a great moment, because I realized that I had to create a ROP chain on the stack with format strings.
After a good half-an-hour of pain I managed to ret2libc and flagged!

---
## Summary

1. Overflow `log_msg_base` into `command` with `%256c`
2. Override `log_msg_base`'s NULL byte with the next command, enlarging `log_msg_base` (our format string). Next commands will be appended to `log_msg_base`.
3. Leak libc with `%37$p`
4. Take a deep breath
5. Write a ret2libc payload on the stack with the format string (one pointer per command due to NULL bytes)

---
## Final Thoughts

This was a really ~~painful~~ fun challenge where I learned more about printf and buffer overflows through format string attacks.