# 网络与信息安全（2016-2021）


哈尔滨工业大学
张宇

- 网络与信息安全（硕士研究生课程，秋季学期，2016 ～）
- 互联网基础设施安全（硕士研究生课程，春季学期，2019 ～）

部分参考课程:

- [MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm)
- [Stanford CS155 Computer and Network Security](https://crypto.stanford.edu/cs155/)
- [UCBerkley CS161 Computer Security](http://inst.eecs.berkeley.edu/~cs161/fa16/)
- [UCBerkley CS261N Internet/Network Security](http://www.icir.org/vern/cs261n/)

课件：[https://github.com/YuZhang/Security-Courseware](https://github.com/YuZhang/Security-Courseware)

教学大纲：

1. [安全概述](introduction.md)
2. [缓冲区溢出](buffer-overflow)
	1. [原理与实验](buffer-overflow/buffer-overflow-1.md)
	2. [漏洞利用](buffer-overflow/buffer-overflow-2.md) (Shellcode) [[实验材料]](https://pan.baidu.com/s/1c1AV0Bm)
	4. [攻防技术](buffer-overflow/buffer-overflow-3.md) (Baggy, BROP)
2. [系统安全](system-security)
	1. [特权分离](system-security/privilege-separation.md) (OKWS)
	2. [能力与沙箱](system-security/capabilities-sandbox.md) (Capsicum)
	3. [移动系统安全](system-security/ios-security.md) (Apple iOS, Pegasus)
3. [密码学与应用](crypto)
	1. [密码学原理](crypto/crush-course.pdf) ([密码学原理本科课程课件](https://github.com/YuZhang/cryptography/)，包含[中文讲义](https://github.com/YuZhang/cryptography/tree/master/lecturenotes-Chinese))
	2. 	[SSL/TLS安全](crypto/tls.md)（BEAST, CRIME, POODLE, 3HS...）
4. [Web安全](web-security)
	1. [Injection，XSS与CSRF](web-security/web-sec-1.md)
	2. [Phishing与Clickjacking](web-security/web-sec-2.md)
5. [网络安全1](network-security)
	1. [TCP/IP安全1](network-security/tcp-ip-sec.md) (TCP Hijack)
	2. [TCP/IP安全2](network-security/ip-sec.md) (Idle Scan, LSRR)
	4. [入侵检测系统(IDS)](network-security/ids.md) (Bro，ML-based Anomaly Detection)
6. [网络安全2 - 互联网基础设施安全](internet-security)
	1. [互联网基础设施安全课程简介](internet-security/intro.pptx)
	2. [互联网体系结构与安全](internet-security/arch-sec.pptx) (from D. Clark "Design an internet")
	3. [DNS安全](internet-security/dns-sec.pptx) (Root issue, Cache Poisoning, DNSSEC) (新幻灯片PART [1](internet-security/dns-sec-1.pptx), [2](internet-security/dns-sec-2.pptx), [3](internet-security/dns-sec-3.pptx), [4](internet-security/dns-sec-4.pptx), [5](internet-security/dns-sec-5.pptx), [6](internet-security/dns-sec-6.pptx))
	4. [BGP安全1](internet-security/bgp-sec.pptx) (Prefix Hijack, RPKI，ICANN OCTO RPKI技术分析[译文](internet-security/RPKI技术分析-1209.pdf)，BGPSec)（新幻灯片PART [1](internet-security/bgp-sec-1.pptx), [2](internet-security/bgp-sec-2.pptx), [3](internet-security/bgp-sec-3.pptx), [4](internet-security/bgp-sec-4.pptx))
	5. [BGP安全2](internet-security/sidr.md)（Blackholing against DoS，Route Leak，Opt-security，BCAB）（新幻灯片PART [5](internet-security/bgp-sec-5.pptx), [6](internet-security/bgp-sec-6.pptx), [7](internet-security/bgp-sec-7.pptx), [8](internet-security/bgp-sec-8-BCAB.pdf)) 
	6. [匿名通信](advance/anonymous.md) (Crowds, Mix, Tor and deanonymization) （[幻灯片](advance/supplyments/anonymous.pptx)）
	7. [物理基础设施测量](advance/infrastructure.md)（Mapping facilities and IXP）
	8. [比特币](advance/blockchain.md) (Bitcoin, Selfish-mining，[Bitcoin研究综述](advance/bitcoin-sok.md))（[幻灯片](advance/supplyments/bitcoin.pptx)）
	9. [分布式拒绝服务(DDoS)](network-security/ddos.md) (Shrew, IP-Traceback)（[幻灯片](network-security/ddos.pptx)）
	10. [互联网体系演进与革命](internet-security/arch-discuss.pptx)（IPv6，NDN，evolution vs. clean-slate）
8. [总结](summary.md)

