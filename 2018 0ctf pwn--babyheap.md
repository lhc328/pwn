# 2018 0ctf pwn--babyheap

题目四个功能alloc  update  delete  view

![屏幕截图(87)](C:\Users\kOX\Pictures\Screenshots\屏幕截图(87).png)

我们利用ida找一下漏洞

alloc函数里

![屏幕截图(91)](C:\Users\kOX\Pictures\Screenshots\屏幕截图(91).png)

update函数里（漏洞之处）

![屏幕截图(92)](C:\Users\kOX\Pictures\Screenshots\屏幕截图(92).png)

可写的长度多了一位，刚好可以修改下一个chunk头的size。 术语叫  off-by-one

delete函数

![屏幕截图(93)](C:\Users\kOX\Pictures\Screenshots\屏幕截图(93).png)

## 利用漏洞思路

​	利用off-by-one的漏洞，泄露出libc_base 和 main_arena地址，求出malloc_hook地址，修改main_arena的内容，指向malloc_hook附近的地方，从而修改malloc_hook内容为shellcode地址，执行alloc函数 = getshell。

### 第一步 泄露出libc_base 和 main_arena

​	申请多个chunk，利用off-by-one的漏洞，update chunk0修改chunk1的size，使其包含两个chunk，即overlap。把chunk1 free掉，这时系统认为chunk1为small chunk，便把它扔到main_arena处，申请与chunk1原来大小的chunk，chunk1的fd，bk的内容就会到了chunk2的fd和bk，因为指针2并没有free掉，view（2）就会出现main_arena的地址。

![屏幕截图(94)](C:\Users\kOX\Pictures\Screenshots\屏幕截图(94).png)

chunk3的作用是防止chunk2被‘合并’。

main_arena = 0x7f68ce3a0b78 - 0x58

libc_base = 0x7f68ce3a0b78 - 0x39bb78(我机器的偏移)

heap地址也可以找到

申请chunk4 大小为chunk2，指针4就会和指针2指向同一处，再free chunk1和chunk2，view（4）就会出现chunk1的地址。减去0x50就是heap的地址。

### 第二步 修改malloc_hook的内容

为了修改malloc_hook的内容，由于题目限制最大申请内存为88，main地址处开头都是0x7f，所以我们不能直接修改malloc_hook的内容，我们只能先修改main_arena（注意main_arena 的位置都有 对应chunk的大小）的内容，使它指向malloc_hook附近的位置。

我们先申请一个0x58的chunk，把它free掉

```python
alloc(0x58)
delete(1)
```

这步可以称是 鬼斧神工之作。看上去好像没做什么，实际上很重要，它把main_arena的bk修改了。

![屏幕截图(95)](C:\Users\kOX\Pictures\Screenshots\屏幕截图(95).png)

0x000055c05750c140中的 55 便是帮助我们malloc时通过检查的size大小。我们把地址偏移一下，main_arena+37放到chunk2的fd中，注意指针2虽然free掉，但我们还有chunk4。

![屏幕截图(86)](C:\Users\kOX\Pictures\Screenshots\屏幕截图(86).png)

alloc两个chunk，指针2就会指向main_arena+37处，我们就可以修改top chunk

Top Chunk

当一个chunk处于一个arena的最顶部(即最高内存地址处)的时候，就称之为top chunk。该chunk并不属于任何bin，而是在系统当前的所有free chunk(无论那种bin)都无法满足用户请求的内存大小的时候，将此chunk当做一个应急消防员，分配给用户使用。如果top chunk的大小比用户请求的大小要大的话，就将该top chunk分作两部分：1）用户请求的chunk；2）剩余的部分成为新的top chunk。否则，就需要扩展heap或分配新的heap了——在main arena中通过sbrk扩展heap，而在thread arena中通过mmap分配新的heap。

其中要注意的是，为什么分配56字节呢，，，想想是不是还有0x58的chunk，为什么不会分配到它呢，，，，因为0x60时fast chunk，不可拆，，除非分配的刚刚好是0x50-0x58的chunk，就会分给它

所以，当找不到适合的free chunk时，就会找到top chunk，就会分配到 malloc_hook附近，偏移为 -0x30，shellcode由one_gadget 得到，就不多讲了。

修改完malloc_hook后，malloc一下就会getshell了

exp：

```

```

