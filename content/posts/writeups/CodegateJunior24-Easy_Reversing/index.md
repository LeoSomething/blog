---
date: '2024-06-03T12:00:00Z'
draft: true
title: 'CodegateJunior24 - easy_reversing'
summary: "Intresting python-compiled (pyc) reverse-engineering challenge from the Codegate quals for juniors of 2024."

categories: ["Writeups"]
tags: ["rev", "python"]
author: "leo_something"
---

## CHALLENGE OVERVIEW

We are provided with a python script that uses a compiled `pyc` crypto library to check if our input is the flag.

```python
from calc import cipher

def main():
    user_input = input("Enter input: ")
    cipher_text = cipher(user_input.encode())
    if cipher_text == b"A\xd3\x87nb\xb3\x13\xcdT\x07\xb0X\x98\xf1\xdd{\rG\x029\x146\x1ah\xd4\xcc\xd0\xc4\x14\xc99'~\xe8y\x84\x0cx-\xbf\\\xce\xa8\xbdh\xb7\x89\x91\x81i\xc5Yj\xeb\xed\xd1\x0b\xb4\x8bZ%1.\xa0w\xb2\x0e\xb5\x9d\x16\t\xd0m\xc0\xf8\x06\xde\xcd":
        print("Correct!")
    else:
        print("Fail!")

if __name__ == '__main__':
    main()
```

Basically we need to decompile `calc.pyc` to understand how the encryption works and get the flag.

---
## SOLVE

To decompile `calc.pyc` I used [pycdc](https://github.com/zrax/pycdc)
```shell
pycdc calc.pyc
```

The decompiled code made me think of RC4 encryption algorithm, based on this knowledge I fixed the decompiled code (which was not totally correct).
The result was this:
```python
MOD = 256

def KSA(key):
	key_length = len(key)
	S = list(range(MOD))
	j = 0
	for i in range(MOD):
		j = (j + S[i] + key[i % key_length]) % MOD
		S[i], S[j] = S[j], S[i]
	return S
  
def PRGA(S):
	i = 0
	j = 0
	while True:
		i = (i + 1) % MOD
		j = (j + S[i]) % MOD
		S[i], S[j] = S[j], S[i]
		K = S[(S[i] + S[j]) % MOD]
		yield K
  

def get_keystream(key):
	S = KSA(key)
	return PRGA(S)
  

def cipher(text):
	key = 'neMphDuJDhr19Bb'
	key = (lambda a: [ ord(c) ^ 48 for c in a ])(key)
	keystream = get_keystream(key)
	text = text[-2:] + text[:-2]
	res = []
	for c in text:
		val = c ^ next(keystream)
		res.append(val)
	return bytes(res)
```
_calc.py_

As you can see the key is known so we just need to write a function to **decrypt the known ciphertext with the known key**. This is a good task for chatGPT!

```python
MOD = 256
 
def KSA(key):
	key_length = len(key)
	S = list(range(MOD))
	j = 0
	for i in range(MOD):
		j = (j + S[i] + key[i % key_length]) % MOD
		S[i], S[j] = S[j], S[i]
		return S
  
def PRGA(S):
	i = 0
	j = 0
	while True:
		i = (i + 1) % MOD
		j = (j + S[i]) % MOD
		S[i], S[j] = S[j], S[i]
		K = S[(S[i] + S[j]) % MOD]
		yield K
  
 
def get_keystream(key):
	S = KSA(key)
	return PRGA(S)
  
def decipher(ciphertext):
	key = 'neMphDuJDhr19Bb'
	key = (lambda a: [ ord(c) ^ 48 for c in a ])(key)
	keystream = get_keystream(key)
	decrypted = []
	for c in ciphertext:
		val = c ^ next(keystream)
		decrypted.append(val)
		return bytes(decrypted)
  
ciphertext = b"A\xd3\x87nb\xb3\x13\xcdT\x07\xb0X\x98\xf1\xdd{\rG\x029\x146\x1ah\xd4\xcc\xd0\xc4\x14\xc99'~\xe8y\x84\x0cx-\xbf\\\xce\xa8\xbdh\xb7\x89\x91\x81i\xc5Yj\xeb\xed\xd1\x0b\xb4\x8bZ%1.\xa0w\xb2\x0e\xb5\x9d\x16\t\xd0m\xc0\xf8\x06\xde\xcd"
plaintext = decipher(ciphertext)
flag = (plaintext[2:] + plaintext[:2]).decode()
print(flag)
```

**FLAG**:
codegate2024{da5d6bd71ff39f66b8b7200a92b0116b4f8e5e27d25d6119e63d3266bd4c8508}
