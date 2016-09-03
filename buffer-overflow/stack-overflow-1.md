#缓冲区溢出1：原理

###哈尔滨工业大学 网络与信息安全 张宇 2016

参考课程: [MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm) by Prof. Nickolai Zeldovich

**预备知识**: Linux，C语言，x86体系结构，汇编，gcc/gdb

**缓冲区溢出（buffer overflow）**：在计算机安全和程序设计中的一种异常，当一个程序向缓冲区写入数据时，超出了缓冲区边界并且覆盖了相邻内存。

**栈缓冲区溢出（stack buffer overflow）**：程序向调用栈中原本缓冲区之外的内存地址写入数据，意图获取对指令指针的控制，将其指向恶意代码。

**调用栈（call stack）**：用于存储程序中运行子例程信息的栈数据结构，先入后出。

###Linux进程内存布局

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
低地址 —————> 高地址
```

###栈帧（stack frame）：函数调用数据结构单元

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
| callee saved registers |<——— callee’s stack pointer (new %esp)
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

###栈缓冲区溢出演示：

readreq程序读入用户输入的数字后，打印输出。

``` c
$ cat readreq.c 
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
* `leave`相当于`mov %ebp,%esp`, `pop %ebp`，此时`esp`指向返回地址。之后，`ret`执行`pop %eip`，将返回地址写入`$eip`

查看一下寄存器和栈帧中的内容，以此绘制栈帧结构图。

```
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

```
(gdb) n [运行gets()]
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
7	    i = atoi(buf);
```

此时发生了什么？大量的A（0x41）从`buf[0]`开始写入到栈中，从下向上覆盖之前栈中内容。下面查看栈中内容。

``` 
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

```
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

```
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

```
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

###问答

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











