#网络与信息安全

哈尔滨工业大学 张宇 2016

参考课程: 

- [MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm) 
- [Stanford CS155 Computer and Network Security](https://crypto.stanford.edu/cs155/)

教学大纲：

1. [安全概述](introduction.md)
1. [缓冲区溢出](buffer-overflow) (实验1) 
	1. [原理与实验](buffer-overflow/buffer-overflow-1.md)
	- [漏洞利用](buffer-overflow/buffer-overflow-2.md) (Shellcode)
	- [攻防技术](buffer-overflow/buffer-overflow-3.md) (Baggy, BROP)
- [漏洞防御](vulnerability-defense)
	1. [特权分离](vulnerability-defense/privilege-separation.md) (OKWS) 
	2. [沙箱](vulnerability-defense/sandboxing-isolation.md) (Capsicum)
- [网络安全](network-security)
 	1. [TCP/IP安全](network-security/tcp-ip-sec.md) (TCP Hijack)
	- [DNS安全](network-security/dns-sec.pptx) (DNSSEC)
	- [BGP安全](network-security/bgp-sec.pptx) (RPKI)
	- [分布式拒绝服务(DDoS)](network-security/ddos.md) (Shrew, IP-Traceback)
- [Web安全](web-security) 
	1. 1
	- 2 
- [总结](summary.md)