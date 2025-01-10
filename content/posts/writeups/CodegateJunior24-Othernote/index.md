---
date: '2024-06-03T12:03:00Z'
draft: false
title: 'CodegateJunior24 - Othernote'
summary: "Simple web challenge about prototype pollution in python. It was part of the Codegate quals for juniors of 2024 (I made the writeup only because it was required to move to the finals)."

categories: ["Writeups"]
tags: ["web", "python", "prototype pollution"]
author: "leo_something"
---

## CHALLENGE OVERVIEW

Othernote is a basic note taking website that has the options to create and edit notes for a logged user. The backend is written in python.
The main endpoints are:
- `/login` where a user can login with his credentials
- `/signup` where you can create your credentials for login
- `/notes` to display all the notes of a logged user
- `/notes/create` to create a new note
- `/notes/<string:note_id>/update` to update a note based on its note_id
- `/admin` which can only be accessed by admin user and contains the flag

---
## VULNERABILITIES

The function responsible of retrieving the notes for a user is vulnerable to path traversals:
```python
def load_user_notes(username):
	user_notes_file = os.path.join("user_notes", f"{username}.json")
	if os.path.exists(user_notes_file):
		with open(user_notes_file, 'r') as file:
			data = json.load(file)
			return {k: Note(v) for k, v in data.items()}
```
As you can see the username is used to get the json file containing the user's notes. So a username like `./admin` can make us read admin's notes.
Unfortunately this is not useful at all.

Another sus function in my opinion was `merge`:
```python
def merge(src, dst):
	for k, v in src.items():
		if hasattr(dst, '__getitem__'):
			if dst.get(k) and type(v) == dict:
				merge(v, dst.get(k))
			else:
				dst[k] = v
		elif hasattr(dst, k) and type(v) == dict:
			merge(v, getattr(dst, k))
		else:
			setattr(dst, k, v)
```

It is used to merge two json dictionaries together and it is called when we update a note.

This function made me think of prototype pollution, but as I never exploited this vulnerability on a python backend I searched if it would be possible, and sure it was!
I found [this](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/class-pollution-pythons-prototype-pollution) article on Hacktricks and basically copy-pasted the payload.

---

## EXPLOITATION
 
The exploitation phase went as follows:
- create an account and log in
- create a note
- update note making a PUT request with the following body
```json
{"__class__":{"__init__":{"__globals__":{"session":{"username":"admin"}}}}}
```
_this pollutes the session dict, making us admin_

- the server responds with a new session cookie
- using that cookie we can GET `/admin` to get the flag

**FLAG**:
codegate2024{78a5e12a3f3cdff9dfd8fc62215312abad910c78296d57003e5bf8b842b740aeb750eed0bfb54ddd30194baecfb5f2ebccd9be7bb4efa9}