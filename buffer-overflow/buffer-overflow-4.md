缓冲区溢出3：防御
===
###哈尔滨工业大学 网络与信息安全 张宇 2016

参考课程: [MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm) 

---
缓冲区溢出攻击要点：

1. **较长输入**通过缓冲区溢出来**改写栈中数据**
- **改写指令指针**劫持控制流
- 执行后注入或已存在**恶意指令**

##避免攻击：

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


###对策1：[金丝雀（canaries）](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Canaries)

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
p = get_free_block_struct(size);bck = p->bk;fwd = p->fd;fwd->bk = bck;   //Writes memory!bck->fd = fwd;   //Writes memory!
```

###对策2：边界检查（bounds checking）

C语言中难以区分有效指针和无效指针，例如下代码中的`ptr`。

```c
union u{    int i;    struct s{        int j;        int k;}; };int *ptr = &(u.s.k);
```

原因在于C语言中，指针本身不包含使用语义。因此，有许多工具并不试图猜测语义，而只是保证堆和栈中对象的内存边界，这被称为“边界检查”。基于编译器实现，在运行时检查指针是否合理范围之内。尽管不能保证指针一定被正确使用，但能确保程序一定在已分配的内存中操作。这被认为是C语言世界中的一大进步！

####电子围栏（electric fences）:

- 思想：令每个堆对象与一个守护(guard)页对齐，使用页表来保证当访问guard页时导致故障
- 优点：不需要源代码，不需要改变编译器或重编译程序！但需要重新链接到实现了电子围栏的malloc库
- 缺点：内存消耗巨大！每个页中只有一个对象，而且还有一个不用使用的哑页。也不能保护栈。

####胖指针（fat pointer）:

- 思想：更改指针表达，令其包含所指向对象在内存中的边界信息

```
            Regular 32-bit pointer               +——————————————+               |   address    |               +——————————————+             Fat pointer (96 bits)+——————————————+——————————————+——————————————+|   obj_base   |   obj_end    | curr_address |+——————————————+——————————————+——————————————+
```

```c
int *ptr = malloc(sizeof(int) * 2);while(1){     *ptr = 42;    <———      ptr++;                       
}                                
```

- 第3行代码将检查指针当前地址并确保其在界内。因此，当循环到第3次时会发生故障。
- 问题是每次解引用都检查代价太大！而且胖指针与许多存在的程序都不兼容，不能用在固定大小结构中，指针更新也不再是原子操作。

####使用影子数据结构跟踪边界信息：

思想：为每个分配的对象，通过malloc或编译器来确定对象大小，并把对象大小记录下来。检查每个指针的两种操作：

- 指针算术：`char *q = p + 256;`
- 指针解引用：`char ch = *q;`

检查解引用操作的原因：无效指针并不意味着错误！

- 模拟从1开始的数组(1-indexed array) 
- 预计算`p+(a-b)`时，计算`(p+a)-b` 
- 出界(OOB)指针随后检查是有效的

检查算术操作的原因：用来追踪指针的来源，设置OOB位。没有OOB位，无法知道一个派生的指针是否出界

挑战1：如何确定一个普通指针的边界？

- 方案1：用哈希表或间隔树来实现地址到边界的映射
	- 优点：节省空间，只存储被使用的指针
	- 缺点：查询较慢，每次查询需多次访问内存

- 方案2：用一个队列存储每个内存地址的边界信息
	- 优点：速度快
	- 缺点：占用内存太大

挑战2：如何令出界指针的解引用产生故障？

- 方案1：检查每一个指针解引用
	- 优点：可行
	- 缺点：代价高，每个解引用都需要执行额外代码

[宽松边界检查（Baggy Bounds Checking）](https://www.usenix.org/legacy/events/sec09/tech/full_papers/akritidis.pdf)中的5个技巧：

1. 按2的次方分配内存，分配的起点与2的次方对齐。
- 将范围上界表示为log_2(分配大小)。对于32位指针，只需5比特来表示其范围上界。
- 将范围上界存储在一个线性数组中：每个元素1字节，实现快速查询。可用虚拟内存来按需分配数组。
- 按一定粒度(slot)分配内存（例如16字节）：上界数组更短
- 使用虚拟内存系统来组织出界解引用：将OOB指针的最高有效位置1，并令地址空间上半部分的页标记为不可访问。于是不必为指针解引用配置特殊工具来阻止恶意内存访问！

示例：

```c
slot_size = 16;p = malloc(16);     table[p/slot_size] = 4;p = malloc(32);     table[p/slot_size] = 5;
                    table[(p/slot_size)+1] = 5;
```
派生指针：

```c
q = p + i;
```
边界检查：

``` c
size = 1 << table[p >> log_of_slot_size]; 
base = p & ~(size - 1); (q >= base) && ((q - base) < size) 
```
优化边界检查：

```
(p^q) >> table[p >> log_of_slot_size] == 0
```


