# [__babyrev 👶__](#)

## Description: 

* The challenge is under construction, we are working on it..

## Objective: 

* `strings` and `base64`.

## Flag: 🏁
* `INSSEC{th1s_w4s_just_4_w4rmup!!}`

## Difficulty:
* Easy

## Challenge:

The interface looks like this:

```console
⛔ Under construction! ⛔
```

Nothing more, nothing less. Running `strings` on the binary we found something interesting.

```console
...
SU5TU0VDe3RoMXNfdzRzX2p1c3RfNF93NHJtdXAhIX0==
...
```

This looks like a `base64` string.

```console
$ echo "SU5TU0VDe3RoMXNfdzRzX2p1c3RfNF93NHJtdXAhIX0==" | base64 -d
INSSEC{th1s_w4s_just_4_w4rmup!!}base64: invalid input
```

