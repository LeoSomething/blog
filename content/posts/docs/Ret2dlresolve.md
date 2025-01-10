---
date: '2024-06-12T12:00:00Z'
draft: false
title: 'Ret2dlresolve in 64bit binaries'
summary: "Ret2dlresolve is a really powerful tecnique to use in pwn challenges (even tho it's not frequently seen). It's useful when we don't have libc leaks or don't know the libc version."

categories: ["Docs"]
tags: ["pwn", "dlresolve"]
author: "leo_something"
ShowToc: true
---

### Overview
Use a the function `_dl_runtime_resolve_xsavec ( link_map , reloc_arg )` to relocate an arbitrary symbol (e.g. `system`) and call that function.

---

### Structures

There are 3 struct that handle the relocation process: `JMPREL`, `STRTAB`, `DYNSYM`.
##### JMPREL (.rela.plt)
This stores a relocation table

```
LOAD:04005C0 ; ELF JMPREL Relocation Table
LOAD:04005C0 Elf64_Rela <404018h, 200000007h, 0> ; R_X86_64_JUMP_SLOT write
LOAD:04005D8 Elf64_Rela <404020h, 300000007h, 0> ; R_X86_64_JUMP_SLOT strlen
LOAD:04005F0 Elf64_Rela <404028h, 400000007h, 0> ; R_X86_64_JUMP_SLOT setbuf
LOAD:0400608 Elf64_Rela <404030h, 500000007h, 0> ; R_X86_64_JUMP_SLOT read
```
_example of relocation table_

The type of these entries is `Elf64_Rela`, which is defined as follows. The size of one entry is 24 bytes.

```c
typedef struct
{
  Elf64_Addr        r_offset;    /* 64 bit - Address */
  Elf64_Xword       r_info;      /* 64 bit - Relocation type and symbol index */
  Elf64_Sxword      r_addend;    /* 64 bit - Addend */
} Elf64_Rela; // 24 bytes
/* How to extract and insert information held in the r_info field.*/
#define ELF64_R_SYM(i)         ((i) >> 32)
#define ELF64_R_TYPE(i)        ((i) & 0xffffffff)
#define ELF64_R_INFO(sym,type) ((((Elf64_Xword) (sym)) << 32) + (type))
```

- `ELF64_R_SYM(r_info)` gives the index of the Elf64_Sym in DYNSYM for the specified symbol.
- `ELF64_R_TYPE(r_info)` must be equal to 7.

##### DYNSYM (.dynsym)

```
LOAD:04003D8 ; ELF Symbol Table
LOAD:04003D8 Elf64_Sym <0>
LOAD:04003F0 Elf64_Sym <offset aLibcStartMain - offset unk_4004B0, 12h, 0, 0, 0, 0> ; "__libc_start_main"
LOAD:0400408 Elf64_Sym <offset aWrite - offset unk_4004B0, 12h, 0, 0, 0, 0> ; "write"
LOAD:0400420 Elf64_Sym <offset aStrlen - offset unk_4004B0, 12h, 0, 0, 0, 0> ; "strlen"
LOAD:0400438 Elf64_Sym <offset aSetbuf - offset unk_4004B0, 12h, 0, 0, 0, 0> ; "setbuf"
LOAD:0400450 Elf64_Sym <offset aRead - offset unk_4004B0, 12h, 0, 0, 0, 0> ; "read"
```
_example of symbol table_

This table holds relevant symbol information. Each entry is a `Elf32_Sym` structure and its size is 24 bytes.

```c
typedef struct
{
  Elf64_Word     st_name;    /* 32bit - Symbol name (string tbl index) */
  unsigned char  st_info;    /* Symbol type and binding */
  unsigned char  st_other;   /* Symbol visibility */
  Elf64_Section  st_shndx;   /* 16 bits - Section index */
  Elf64_Addr     st_value;   /* 64 bits - Symbol value */
  Elf64_Xword    st_size;    /* 64 bits - Symbol size */
} Elf64_Sym; // 24 bytes
```

Only `st_name` is important for the exploit.

##### STRTAB (.dynstr)

STRTAB is a simple table that stores the strings for symbols name.

```
0x804822c:	""
0x804822d:	"libc.so.6"
0x8048237:	"_IO_stdin_used"
0x8048246:	"read"
0x804824b:	"alarm"
0x8048251:	"__libc_start_main"
0x8048263:	"__gmon_start__"
0x8048272:	"GLIBC_2.0"
```
_example of STRTAB_

### Summary of GDB commands

Get JMPREL:

> gef➤ x/3xg (JMPREL) + (reloc_arg) * 24

> symbol_number = r_info >> 32  
> type = r_info & 0xffffffff

Get SYMTAB:

> gef➤ x/3xg (SYMTAB) + (symbol_number) * 24

Get STRTAB:

> gef➤ x/s (STRTAB) + (st_name)

---

### Relocation summary
A typical relocation goes as follows:
1. Call `_dl_runtime_resolve_xsavec ( link_map , reloc_arg )` where `link_map` is a list with all the loaded libraries and `reloc_arg` is the offset of the `Elf64_Rela` entry in JMPREL
2. Knowing the address of the `Elf36_Rela` for the specified symbol get `r_info`
3. Get `R_SYM` with `r_info >> 32 (ELF64_R_SYM macro)
4. Get `st_name` from the `Elf64_Sym` entry with `DYNSYM + R_SYM*24`
5. Get the symbol with `STRTAB + st_name`
6. Search for that symbol in `link_map` and then write its address to the correct GOT entry using `r_offset` from `Elf64_Rela`
7. Finally call the relocated function

---

### EXPLOIT

- Forge `Elf64_Rela` so that `DYNSYM + (r_info>>8)*24` points to a forged `Elf64_Sym`
- Forge `Elf64_Sym` so that `st_name` points to `"system"`
- Call `_dl_runtime_resolve ( link_map , rel_offset )`
