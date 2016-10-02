#网络与信息安全

哈尔滨工业大学 张宇 2016

参考课程: 

- [MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm) 
- [Stanford CS155 Computer and Network Security](https://crypto.stanford.edu/cs155/)

教学大纲：

1. [安全简介](introduction.md)
1. [缓冲区溢出](buffer-overflow)  
	1. [原理](buffer-overflow/buffer-overflow-1.md)
	- [分析与触发](buffer-overflow/buffer-overflow-2.md)
	- [Shellcode与漏洞利用](buffer-overflow/buffer-overflow-3.md) (实验1)
	- [防御、Baggy、BROP](buffer-overflow/buffer-overflow-4.md) (实验1)
- [漏洞防御](vulnerability-defense)
	1. [特权分离](vulnerability-defense/privilege-separation.md) 
	2. [沙箱与隔离](vulnerability-defense/sandboxing-isolation.md)
	3. [符号执行](vulnerability-defense/symbolic-execution.md)
- [网络安全](network-security)
 	1. [TCP/IP安全](network-security/tcp-ip-sec.md)
	- [关键互联网基础设施安全——DNS安全](network-security/dns-sec.pptx)
	- 	[关键互联网基础设施安全——BGP安全](network-security/bgp-sec.pptx)
- [Web安全](web-security) 