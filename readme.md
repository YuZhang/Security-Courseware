#网络与信息安全

哈尔滨工业大学 张宇 2016

参考课程: 

- [MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm) 
- [Stanford CS155 Computer and Network Security](https://crypto.stanford.edu/cs155/)
- [UCBerkley CS161 Computer Security](http://inst.eecs.berkeley.edu/~cs161/fa16/)
- [UCBerkley CS261N Internet/Network Security](http://www.icir.org/vern/cs261n/)

课件：[https://github.com/YuZhang/Security-Courseware](https://github.com/YuZhang/Security-Courseware)

实验材料：[https://pan.baidu.com/s/1c1AV0Bm](https://pan.baidu.com/s/1c1AV0Bm)

教学大纲：

1. [安全概述](introduction.md)
2. [缓冲区溢出](buffer-overflow) (实验1) 
	1. [原理与实验](buffer-overflow/buffer-overflow-1.md)
	2. [漏洞利用](buffer-overflow/buffer-overflow-2.md) (Shellcode)
	3. [攻防技术](buffer-overflow/buffer-overflow-3.md) (Baggy, BROP)
3. [系统安全](system-security)
	1. [特权分离](system-security/privilege-separation.md) (OKWS) 
	2. [能力与沙箱](system-security/capabilities-sandbox.md) (Capsicum)
	3. [移动系统安全](system-security/ios-security.md) (Apple iOS, Pegasus)
4. [网络安全](network-security)
 	1. [TCP/IP安全](network-security/tcp-ip-sec.md) (TCP Hijack)
	2. [DNS安全](network-security/dns-sec.pptx) (Cache Poisoning, DNSSEC)
	3. [BGP安全](network-security/bgp-sec.pptx) (Prefix Hijack, RPKI)
	4. [分布式拒绝服务(DDoS)](network-security/ddos.md) (Shrew, IP-Traceback)
5. [Web安全](web-security) 
	1. [Injection，XSS与CSRF](web-security/web-sec-1.md)
	2.  [Phishing与Clickjacking](web-security/web-sec-2.md)
	3.  [SSL/TLS安全](web-security/tls.md)（BEAST, CRIME, POODLE, 3HS...）
6. [新进展（待）]()
	1. 匿名通信（Tor，）
	2. BitCoin（...）
7. [总结](summary.md)
8. [论文阅读](reading.md)