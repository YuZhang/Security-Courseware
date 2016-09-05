#缓冲区溢出3：防御

###哈尔滨工业大学 网络与信息安全 张宇 2016

参考课程: [MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm) 

---
####缓冲区溢出攻击要点

1. **较长输入**通过缓冲区溢出来**改写栈中数据**
- 改写返回地址/函数指针**劫持控制流**
- 执行后注入或已存在**恶意指令**

###避免攻击：

避免缓冲区溢出，来从源头上杜绝**较长输入**通过缓冲区溢出来**改写栈中数据**。

####对策1：避免C代码中bug

仔细检查缓冲区，字符串，队列大小。使用带有缓冲区大小参数的函数，例如用`strncpy()`替代`strcpy()`，用`fgets()`替代`gets()`。新版本编译器会对程序中bug进行警告，不应忽略这个警告。

- 优点：从源头上避免问题！
- 缺点：难以保证代码没有bug，特别是代码库很大时。应用也可能自己定义除了`fgets()`或`strcpy()`之外的缓冲区操作函数。

####对策2：Bug检测工具

可分为静态检测和动态检测。考虑如下代码：

``` c
void foo(int *p){     int offset;     int *z = p + offset;     if(offset > 7){          bar(offset);     }}
```

静态检测在不运行代码的情况下进行。例如，我们很容易发现`offset`在未被初始化的情况下使用，而且传播到`bar()`函数中。代价较小，但准确性不足。

动态检测在代码运行时进行。例如，[模糊测试（fuzzing）](https://en.wikipedia.org/wiki/Fuzz_testing)自动或半自动地生成随机数据输入到一个程序中，并监视程序异常。[宽松边界检查（Baggy Bounds Checking）](https://www.usenix.org/legacy/events/sec09/tech/full_papers/akritidis.pdf)有效地在运行时检测缓冲区边界是否正确。

- 优点：能够显著减少bug。
- 缺点：难以保证完全没有bug。

####对策3：使用内存安全语言

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

###缓解攻击

当缓冲区溢出发生时，防止改写返回地址/函数指针**劫持控制流**，或执行后注入或已存在**恶意指令**。

####对策1：[金丝雀（canaries）](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Canaries)

在被改写的代码指针被调用之前发现它。其思想是编译器在程序中安放canary变量，并检测canary变量是否被改写。类似用金丝雀在煤矿中检测一氧化碳。

[StackGuard](https://www.usenix.org/legacy/publications/library/proceedings/sec98/full_papers/cowan/cowan.pdf)：




[gcc的SSP（Stack Smashing Protector）]():


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
