# shiyanba--pwn--pilot

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments

```

堆栈溢出的题目，主要是学习shellcode的使用

  题目会返回buf的地址

  我们往buf添加shellcode，然后溢出覆盖返回地址为buf的地址，最后就会执行shellcode

```
  -0000000000000020 buf             db ?
  -000000000000001F                 db ? ; undefined
  ...............
  -0000000000000002                 db ? ; undefined
  -0000000000000001                 db ? ; undefined
  +0000000000000000  s              db 8 dup(?)
  +0000000000000008  r              db 8 dup(?)

```

shellcode的制作
