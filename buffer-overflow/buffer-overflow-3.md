缓冲区溢出：攻防对抗
===
###哈尔滨工业大学 网络与信息安全 张宇 2016

参考课程: [MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm) 

---

本节学习缓冲区溢出攻击的防御方案与新型攻击技术，重点介绍一种边界检查机制Baggy，以及一种破解地址空间布局随机化的攻击技术BROP。

##避免攻击

回顾缓冲区溢出攻击要点：

1. **较长输入**通过缓冲区溢出来**改写栈中数据**
- **改写指令指针**劫持控制流
- 执行后注入或已存在**恶意指令**

避免缓冲区溢出，来从源头上杜绝**较长输入**通过缓冲区溢出来**改写栈中数据**。

###对策1：避免C代码中bug

仔细检查缓冲区，字符串，队列大小。使用带有缓冲区大小参数的函数，例如用`strncpy()`替代`strcpy()`，用`fgets()`替代`gets()`。新版本编译器会对程序中bug进行警告，不应忽略这个警告。

- 优点：从源头上避免问题！
- 缺点：难以保证代码没有bug，特别是代码库很大时。应用也可能自己定义除了`fgets()`或`strcpy()`之外的缓冲区操作函数。

###对策2：Bug检测工具

可分为静态检测和动态检测。考虑如下代码：

``` c
void foo(int *p){     int offset;     int *z = p + offset;     if(offset > 7){          bar(offset);     }}
```

静态检测在不运行代码的情况下进行。例如，我们很容易发现`offset`在未被初始化的情况下使用，而且传播到`bar()`函数中。代价较小，但准确性不足。

动态检测在代码运行时进行。例如，[模糊测试（fuzzing）](https://en.wikipedia.org/wiki/Fuzz_testing)自动或半自动地生成随机数据输入到一个程序中，并监视程序异常。[宽松边界检查（Baggy Bounds Checking）](https://www.usenix.org/legacy/events/sec09/tech/full_papers/akritidis.pdf)有效地在运行时检测缓冲区边界是否正确。

- 优点：能够显著减少bug。
- 缺点：难以保证完全没有bug。

###对策3：使用内存安全语言

例如JavaScript，C#，Python。

- 优点：通过不暴露原始内存地址以及自动垃圾回收来阻止内存错误。
- 缺点：
	- 底层运行态代码仍然使用原始内存地址，因此运行时核心程序不能有bug。例如[堆喷射(heap spraying)攻击](https://en.wikipedia.org/wiki/Heap_spraying)通过分配较大缓冲区来在特定位置写入数据。
	- 存在大量非安全语言代码（FORTRAN，COBOL）
	- 需要访问底层硬件功能，例如写设备驱动
	- 性能比C程序差很多？
		- 曾经是一个大问题，但情况越来越好，例如[JIT(即时编译)](https://en.wikipedia.org/wiki/Just-in-time_compilation)技术，和只比c慢2倍的[asm.js](https://en.wikipedia.org/wiki/Asm.js)
		- 仔细编码避免在关键流程中频繁地垃圾收集扰动
		- 选择正确的工具。避免用C来写文本处理程序

---

##缓解攻击

当缓冲区溢出发生时，阻止攻击者进行以下步骤：

- **改写代码指针**劫持控制流，例如返回地址，函数指针，C++ vtable， 异常处理句柄
- 在内存中后注入或已存在**恶意代码**
- 将恶意代码安置在**可预测位置**，令代码指针指向该位置


###对策1：金丝雀（canaries）[[参考](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Canaries)]

在被改写的代码指针被调用之前发现它。其思想是编译器在程序中安放canary变量，并检测canary变量是否被改写。类似用金丝雀在煤矿中检测一氧化碳。此类工作包括[StackGuard](https://www.usenix.org/legacy/publications/library/proceedings/sec98/full_papers/cowan/cowan.pdf)和[GCC的SSP（Stack Smashing Protector）]()。

在函数入栈时安放一个canary，返回前检查该canary。通常需要有源码，编译器插入canary检查。

- 问：canary应该在栈中什么位置？
- 答：canary必须在返回地址之前(更低地址)，任何改写返回地址的溢出也会改写canary。

```+——————————————————+|  return address  |    ^+——————————————————+    ||    saved %ebp    |    |+——————————————————+    ||     CANARY       |    | +——————————————————+    | | buf[127]         |    ||       ...        |    ||           buf[0] |
+——————————————————+ 
```

一个C程序例子：

``` c
void foo(const char* str)
{
	char buffer[16];
	strcpy(buffer, str);
}
```

SSP自动将上述代码转化：

``` c
extern uintptr_t __stack_chk_guard;
noreturn void __stack_chk_fail(void);
void foo(const char* str)
{
	uintptr_t canary = __stack_chk_guard;
	char buffer[16];
	strcpy(buffer, str);
	if ( (canary = canary ^ __stack_chk_guard) != 0 )
		__stack_chk_fail();
}
```

- 问：编译器用4字节`'a'`作为canary如何？
- 答：攻击者可以在缓冲中用相同canary。

因此，canary必须难以猜测，或即使被猜出也能抵抗攻击。
	
- “终止符canary”：四个字节 `0, CR, LF, -1`。C函数将这些字符作为终止符。若canary匹配这些终止符之一，则攻击者也必须在此写入终止符，令canary后面的内容无法被改写。
- 随机canary是更常用方法，但需要很好的随机化！还需要对canary进行保密，并防止攻击者从内存中读取canary。


然而，canary不能发现在canary之前的函数指针被改写。例如，

- 攻击者改写数据指针，利用该指针对任意内存改写，而不需连续改写缓冲区

```c
int *ptr = ...;char buf[128];gets(buf);  //Buffer is overflowed, and overwrites ptr.*ptr = 5;   //Writes to an attacker-controlled address!            //Canaries can't stop this kind of thing.

```

- 堆对象溢出（函数指针，C++ vtables）
- malloc/free溢出可以改写指定地址上数据，详见[Exploiting the heap](http://www.win.tue.nl/~aeb/linux/hh/hh-11.html)。考虑下面一个C程序。

```c
int main(int argc, char **argv) {     char *p, *q;     p = malloc(1024);     q = malloc(1024);
     
     if(argc >= 2)          strcpy(p, argv[1]);     free(q);     free(p);     return 0;}
```
`malloc()`在每个被分配内存块头部创建一个`size/status`结构体。假设`p`和`q`所分配的内存块相邻，堆结构如下：

```
+——————————————————+
| size + status    |            |
+——————————————————+ <—————— p  |
|   .. data ..     |            |
+——————————————————+            |
| size + status    |            |
+——————————————————+ <—————— q  |
|   .. data ..     |            v
+——————————————————+
```
若`p`被`argv[1]`溢出将改写`q`内存块结构体中`size`值。

`free()`更改`status`来"释放"内存，在块结尾创建一个`size/status`记录，并创建空闲块结构体，包括指向前继和后继空闲块结构体的指针。因此，一个块最小16字节。

```
+——————————————————+
|  size + status   |<—— update   ^
+——————————————————+             |
|  forward ptr     |——————————+  |
+——————————————————+          |  |
|  backward ptr    |—————————————+
+——————————————————+          |
|   .. free ..     |          |
+——————————————————+          v
|  size + status   |<—— create
+——————————————————+

```
`free()`合并相邻空闲块时，需要根据`size`来获取结构体指针，并更新前继和后继空闲块结构体中指针内容。错误的`size`值将导致某个指针所指向内容被改写！

``` c
ptr = get_free_block_struct(size);bck = ptr->bk;fwd = ptr->fd;fwd->bk = bck;   //Writes memory!bck->fd = fwd;   //Writes memory!
```

###对策2：边界检查（bounds checking）

C语言中难以区分有效指针和无效指针，例如下代码中的`ptr`。

```c
union u{    int i;    struct s{        int j;        int k;}; };int *ptr = &(u.s.k);
```

原因在于C语言中，指针本身不包含使用语义。因此，有许多工具并不试图猜测语义，而只是保证堆和栈中对象的内存边界，这被称为“边界检查”。基于编译器实现，在运行时检查指针是否合理范围之内。尽管不能保证指针一定被正确使用，但能确保程序一定在已分配的内存中操作。这被认为是C语言世界中的一大进步！

####电子围栏（electric fences）:

思想：每个堆对象分配一整个内存页，对象之后的页内空间（guard page）标记为不可访问，若访问则导致故障

- 优点：不需要源代码，不需要改变编译器或重编译程序！但需要重新链接到实现了电子围栏的malloc库
- 缺点：内存消耗巨大！每个页中只有一个对象，而且还有一个不用使用的哑页。也不能保护栈。

####胖指针（fat pointer）:

思想：更改指针表达，令其包含所指向对象在内存中的边界信息。

```
            Regular 32-bit pointer               +——————————————+               |   address    |               +——————————————+             Fat pointer (96 bits)+——————————————+——————————————+——————————————+|   obj_base   |   obj_end    | curr_address |+——————————————+——————————————+——————————————+
```

```c
int *ptr = malloc(sizeof(int) * 2);while(1){     *ptr = 42;    <———      ptr++;                       
}                                
```

第3行代码将检查指针当前地址并确保其在界内。因此，当循环到第3次时会发生故障。问题是每次解引用都检查代价太大！而且胖指针与许多存在的程序都不兼容，不能用在固定大小结构中，指针更新也不再是原子操作。

后面会详细介绍一种边界检查方案：Baggy。

###对策3：不可执行内存

硬件支持对内存读、写、执行的权限说明。例如，AMD的NX位，Intel的XD位，Windows DEP（Data Execution Prevention），Linux的Pax。可将栈标记为不可执行。一些系统强制“W^X”，即可写和可执行不能同时存在，但也不支持动态生成代码（同时需要写和执行）。详见[可执行空间保护](https://en.wikipedia.org/wiki/Executable_space_protection)。

###对策4：随机化内存地址

许多攻击需要在shellcode中编入地址。这些地址通过gdb等工具获得。因此，可通过地址随机化令攻击者难以猜测地址。

**栈随机化**：将栈移动到随机位置，或在栈中变量之间随机填充。攻击者难以猜测返回地址的位置，以及shellcode将会被插入到哪里。

**[ASLR (Address Space Layout Randmization)](https://en.wikipedia.org/wiki/Address_space_layout_randomization)**：随机布置栈，堆，动态库。动态链接器为每个库选择随机位置，攻击者难以找到`system()`位置。但也存在以下问题：

- 在32位机器上，可随机比特不够大（1比特用于区分内核/用户模式，12比特用于内存映射页与页边界对齐），攻击者可能蛮力猜测位置。
- 攻击者利用`usleep()`函数，该函数可能位置有2^16个或2^28个。猜测`usleep(16)`地址并写入返回地址，观察程序是否挂起了16秒。
- 程序产生栈trace或错误消息包含指针。
- 攻击者利用“Heap spraying”将shellcode填满内存，很可能随机跳到shellcode。


**实践中缓冲区溢出防御**：

- gcc和MSVC缺省启用金丝雀
- Linux和Windows缺省包含ASLR和NX
- 界限检查不太常用，因为：性能代价，需重编译，误报。有时，有些漏报但零误报 好于 零漏报但有些误报

---

##Baggy Bounds Checking

阅读资料：[Baggy Bounds Checking (2009)](supplyments/baggy-bound-checking-USENIX2009.pdf) [[online]](https://www.usenix.org/legacy/events/sec09/tech/full_papers/akritidis.pdf)

思想：为每个分配的对象，通过malloc或编译器来确定对象大小，并把对象大小记录下来。在两种指针操作中，检查指针是否出界：

- 指针算术：`char *q = p + 256;`
- 指针解引用：`char ch = *q;`

检查解引用操作的原因：无效指针并不意味着错误！不合理但无害！

- 模拟从1开始的数组(1-indexed array) 
- 预计算`p+(a-b)`时，计算`(p+a)-b` 
- 出界指针随后检查是有效的

检查算术操作的原因：用来追踪指针的来源，设置OOB(Out-Of-Bound)位。没有OOB位，无法知道一个派生的指针是否出界。

挑战1：如何确定一个普通指针的边界？

- 简单方案1：用哈希表或间隔树来实现地址到边界的映射
	- 优点：节省空间，只存储被使用的指针
	- 缺点：查询较慢，每次查询需多次访问内存

- 简单方案2：用一个队列存储每个内存地址的边界信息
	- 优点：速度快
	- 缺点：占用内存太大

挑战2：如何令出界指针的解引用产生故障？

- 简单方案1：检查每一个指针解引用
	- 优点：可行
	- 缺点：代价高，每个解引用都需要执行额外代码

为克服上述问题，Baggy实现了有效的内存分配与边界检查，主要包括5点技巧：

1. 按2的幂划分内存空间，分配的起点与2的幂对齐
- 将范围上界表示为log_2(分配大小)。对于32位指针，只需5比特来表示其范围上界。
- 将范围上界存储在一个线性数组中：每个元素1字节，实现快速查询。可用虚拟内存来按需分配数组。所有元素初始值为31，内存释放后恢复为31。
- 按一定粒度(slot)分配内存（例如16字节）：上界数组更短
- 利用虚拟内存系统（硬件实现）来处理出界解引用错误：将出界指针的最高有效位（OOB位）置1，并令地址空间上半部分的页标记为不可访问，于是不必为指针解引用做检查！

示例：

内存分配例子：slot大小为16字节，`table`数组中每个元素对应1个slot。

```c
slot_size = 16;p = malloc(16);     table[p/slot_size] = 4;  // 1 slotq = malloc(20);     table[p/slot_size] = 5;  // 2 slots
                    table[(p/slot_size)+1] = 5;
```
假设首块空闲内存有64字节，则内存分配过程如下：

```        
              memory               bounds table
     +—————+—————+—————+—————+    +——+——+——+——+
Step |                       |    |31|31|31|31|
 0   +—————+—————+—————+—————+    +——+——+——+——+
     0     16    32          64

     +—————+—————+—————+—————+    +——+——+——+——+
Step |  p  |     |           |    | 4|31|31|31|
 1   +—————+—————+—————+—————+    +——+——+——+——+
     0     16    32          64

     +—————+—————+—————+—————+    +——+——+——+——+
Step |  p  |     |     q     |    | 4|31| 5| 5|
 2   +—————+—————+—————+—————+    +——+——+——+——+
     0     16    32          64
     
```

分配空间要大于Object大小，多余空间可能被写入数据，但这并不会影响其他Object。为了避免从多余空间读入之前写入恶意数据，多余空间内容会被清除。

检查派生指针是否出界：

```c
q = p + i;
```
先获取`p`所在内存块信息，后对`q`进行边界检查：

``` c
size = 1 << table[p >> log_of_slot_size]; 
base = p & ~(size - 1); (q >= base) && ((q - base) < size) 
```
对上面边界检查优化：

``` c
(p^q) >> table[p >> log_of_slot_size] == 0
```

C语言中有一些情况需要使用出界指针，例如用`p-1`模拟下标从1开始的数组，用`p+sizeof(p)`表示buffer结尾。支持这类指针需要两个功能：

- 将指针标记为出界：将出界指针的最高有效位置1
- 该指针上操作的出界检查：用slot大小的一半作为上下界，这样可以判断出一个OOB指针是在Object之上还是Object之下。通过增加或减少一个slot大小，能够找到该指针对应的Object，从而知道界限范围。

```      
     |<———slot——>|             |<———slot——>|    
—————+—————+—————+—————~ ~—————+—————+—————+—————
     |     | half|   object    | half|     |
—————+—————+—————+—————~ ~—————+—————+—————+—————
```

对下面代码做出界检查，分析见注释。

```c
char *p = malloc(18);

//            memory                    table
//   +—————+—————+—————+—————+    +———+———+———+———+
//   |  p        |           |    | 5 | 5 |   |   |
//   +—————+—————+—————+—————+    +———+———+———+———+
//   0     16    32          64

char *q = p + 24;  // OK: 24 > 18, but < 32

char *r = q + 17;  // ERROR: (41-32)=9 > (8=16/2)

char *s = q + 9;   // set 's' OOB-bit: 33-32=1 < (8=16/2)

char *t = s - 10;  // unset 't' OOB-bit: 23 < 32

```

下面代码会引发异常吗？

``` c
char *p = malloc(32);char *q = p + 32;char ch = *q;```
- 第1行：32字节slot大小整数倍，且为2的幂，因此分配空间为32字节，无空闲空间。
- 第2行：`q`由于越界，OOB位被置1，但在slot大小一半之内，未引发错误。
- 第3行：解引用时OOB位=1相当于访问内存空间禁止访问的上半部分，引发故障。

---

##Blind Return-Oriented Programming

阅读资料：[Hacking Blind (2014)](supplyments/blind-return-oriented-programming.pdf) [[Slides]](blind-return-oriented-programming-slides.pdf) [[online]](http://www.scs.stanford.edu/brop/bittau-brop-slides.pdf)

假设目标系统实现了DEP和ASLR，那么缓冲区溢出攻击还能实施吗？如目标系统只实现了DEP而没有实现ASLR，可实施ROP攻击。若也实现了ASLR，则可实施BROP攻击。

###ROP [(Blackhat08)](http://cseweb.ucsd.edu/~hovav/talks/blackhat08.html)

之前我们已经学习过Return-to-libc攻击，该攻击通过改写返回值，调用了libc中函数，绕过不可执行栈防御。ROP是一连串利用函数返回来操纵控制流的技术。例如，攻击者打算多次重复调用某个libc函数`func(char * str)`。首先，需要3个地址：

- 函数`func()`的地址
- 参数`str`的地址
- `pop/ret`操作地址：
	- `pop %eax`: 弹出栈顶到`eax`
	- `ret`: 弹出栈顶到`eip`

上面的`pop/ret`操作片段称作一个“gadget”（小装置），是在已经存在的二进制文件中的有用片段，后面还会需要其他gadget。

然后，利用溢出改写返回地址，并在栈中伪造函数调用帧：

```
+————————————————————————+
|          (5)           | addr of str ————+ Fake calling
+————————————————————————+                 | frame for
|          (4)           | addr of pop/ret—+ func()
+————————————————————————+ 
|          (3)           | addr of func()
+————————————————————————+
|          (2)           | addr of str ————+ Fake calling
+————————————————————————+                 | frame for
|          (1)           | addr of pop/ret—+ func()
+————————————————————————+
|    return address      | addr of func()
+————————————————————————+
|      saved %ebp        |<——— new %ebp
+————————————————————————+
|buff[1023] ^            |
|           |            |
|           |     buff[0]|<——— new %esp
+————————————————————————+

```
当函数返回后，程序流程如下：

1. 返回地址（被改写为`func()`地址）出栈到`eip`，`esp`—>(1)
2. `func()`从`esp+4`—>(2)中读取参数地址，执行直到返回
3. `func()`中`ret`将栈顶，即`esp`—>(1)`pop/ret`地址，出栈到`eip`，此时`esp`—>(2)
4. `pop/ret`执行：(2)被弹出栈，`esp`—>(3)；`ret`执行弹出栈顶（3)`func()`地址到`$eip`，此时`esp`—>(4)
5. `func()`从`esp+4`—>(5)中读取参数地址，执行直到返回

###Blind ROP：

若采用了ASLR，则地址被随机化难以实现ROP。Blind ROP（BROP）能够在源代码未知、随机地址未知的条件下实施攻击。

BROP攻击分为三个阶段：

1. 读栈术（stack reading）：攻破Canary和ASLR
2. BROP：寻找足够的gadget来调用`write()`
3. 用`write()`获取二进制数据来寻找足够的gadget构造shellcode

####第一阶段：读栈术

许多服务程序崩溃后自动重启，而每次重启时地址随机化结果是一致的，例如，Linux的[PIE（Position-independent executable）](https://en.wikipedia.org/wiki/Position-independent_code#PIE)机制，用`fork()`来产生新服务进程，而不是`execve()`。由于`fork()`拷贝父进程地址空间，尽管地址布局未知，但每次子进程重启后地址布局都是相同的。

向栈中敏感位置写入一个字节的猜测值，观察服务器状态：

- 未崩溃：猜测正确
- 崩溃：猜测错误

一旦猜测正确，记录已经猜出的值，继续猜测新位置的值。以此读取canary和返回地址等敏感信息。

####第二阶段：BROP

**第1步： 寻找一个stop gadget**

stop gadget是一个指向令程序停止代码（例如`sleep()`）的返回地址，但不会导致程序崩溃。

寻找方法是将返回地址改写为猜测地址，观察客户端网络连接是否突然关闭：

- 连接关闭：猜测的地址不是stop gadget
- 连接保持：找到了一个stop gadget

**第2步： 寻找pop gadget**

一旦有了stop gadget，可寻找`pop`到不同寄存器的pop gadget，即`pop %X; ret;`。3个地址：

- probe: 猜测的pop gadget地址
- stop: 已找到的stop gadget地址
- crash: 不可执行代码（`0x0`）地址

利用ROP寻找pop gadget过程：

- 返回地址改为probe地址，后面跟着crash地址和stop地址
	- 若连接保持，则找到了pop gadget（需确认不是另一个stop）
	- 否则，则遇到了crash


```
                        +->sleep(5)<-++——— pop eax        ^   |            ||    ret            |   |            ||     \———>[stop]   |  0x5....       0x5.... 
|          [crash]  |  0x0           0x0    <—————————————————+
+——————————[probe]  |  0x4...8       0x4...c -->xor eax, eax  |                    |                           ret           |
                                                   \__________|
```

此时，攻击者找到了一些pop gadget，但不知道其中所使用的寄存器，也不知道`syscall`指令的地址。

**第3步： 寻找syscall()并确定pop gadget所用寄存器**

`pause()`系统调用无需参数。为了找到`pause()`，攻击者将所有pop gadget连在一起形成一个ROP链，将`pause()`的系统调用号入栈作为每个gadget的参数。在链底部放入所猜测的`syscall`地址，如下图：

```
+————————————————————————+
|                        | guessed addr of syscall()
+————————————————————————+
~                        ~ ...
+————————————————————————+ 
|                        | syscall number of pause
+————————————————————————+
|                        | addr of pop rdi; ret // Gadget 2
+————————————————————————+
|                        | syscall number of pause
+————————————————————————+
|    return address      | addr of pop rdi; ret // Gadget 1
+————————————————————————+
|      saved %ebp        |<——— new %ebp
+————————————————————————+
|buff[1023] ^            |
|           |            |
|           |     buff[0]|<——— new %esp
+————————————————————————+

```

这会将`pause()`调用号存入寄存器中。若其中有`exa`，而且`syscall()`猜测正确的话，则服务器会暂停。此时，就找到了`syscall()`地址。接着，用每个pop gadget单独重复这一过程，就能找到使用了`exa`的gadget。利用这一方法，还可以确定其他寄存器对应的gadget。

- 第4步：调用`write()`

用之前的方法找到以下gadget，用ROP实现`write()`调用。

``` gaspop edi; ret (socket)pop esi; ret (buffer)pop edx; ret (length)pop eax; ret (write syscall number)
syscall
```
####第三阶段：构造shellcode

至此，攻击者利用BROP来攻击web服务器，通过`write()`将服务器数据和代码地址作为参数，将敏感内容写入与攻击者客户端相连的socket，发送给攻击者。攻击者由此发现更多的gadget来构造shellcode。

####防御Blind BROP

每次服务崩溃重新随机化canary和地址空间！

- 用`exec()`替代`fork()`，由于`fork()`拷贝父进程地址空间
- Windows不怕BROP，因为Windows里没有类似`fork()`的调用

---





