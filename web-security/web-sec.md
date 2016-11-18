#Web安全

###哈尔滨工业大学 网络与信息安全 张宇 2016

---

##1. Web简介

###1.1 HTTP简介

[HTTP（Hypertext Transfer Protocol）](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol)：一种请求-应答式、无状态、客户端-服务器模式应用层协议，由Tim Berners-Lee在1989年开发，是WWW中数据通信的基础。

相关标准：

- [RFC2616: Hypertext Transfer Protocol -- HTTP/1.1](https://tools.ietf.org/html/rfc2616)
- [RFC7230: HTTP/1.1: Message Syntax and Routing](https://tools.ietf.org/html/rfc7230)
- [RFC7231: HTTP/1.1: Semantics and Content](https://tools.ietf.org/html/rfc7231)
- [RFC7232: HTTP/1.1: Conditional Requests](https://tools.ietf.org/html/rfc7232)
- [RFC7233: HTTP/1.1: Range Requests](https://tools.ietf.org/html/rfc7233)
- [RFC7234: HTTP/1.1: Caching](https://tools.ietf.org/html/rfc7234)
- [RFC7235: HTTP/1.1: Authentication](https://tools.ietf.org/html/rfc7235)
- [RFC7540: HTTP/2](https://tools.ietf.org/html/rfc7540)

HTTP请求（Request）格式：

```
[METH] [REQUEST-URI] HTTP/[VER]
Field1: Value1
Field2: Value2

[request body, if any]
```
- 请求方法：
	- GET：（读）获取URI指向资源
	- HEAD：（读）与GET一样，但只请求资源头部
	- POST：（改）请求服务器接受请求中包含数据
	- PUT：（增）请求服务器创建资源
	- DELETE：（删）删除指定资源
	- TRACE：（测）返回所接收到的请求
	- CONNECT：请求代理建立隧道
	- PATCH：（改）请求更改资源
	- OPTIONS：（查）返回服务器所支持方法
- 安全（safe）方法：HEAD，GET，OPTIONS，TRACE为读操作，其他方法可能改写资源是非安全方法
- 幂等操作（idempotent）：执行多次和只执行一次的效果相同，安全方法应是幂等的，PUT和DELETE也是
- 不同实现中，GET也可实现POST，PUT，DELETE效果

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

- 状态码（常用）：
	- 1XX：Informational
		- 100 Continue：继续提交请求负载
	- 2XX：Success
		- 200 OK
	- 3XX：Redirection
		- 300 Mutiple Choices：所请求资源有多个选择
		- 301 Moved Permanently：资源已经移动
		- 302 Found：资源临时移动
	- 4XX：Client Error
		- 400 Bad Request：请求错误
		- 403 Forbidden：拒绝响应
		- 404 Not Found
	- 5XX：Server Error
		- 500 Internal Server Error
		- 503 Service Unavailable 
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

###1.2 网页简介

- [HTML（HyperText Markup Language）](https://en.wikipedia.org/wiki/HTML)：（内容）结构化文档语言
- [CSS（Cascading Style Sheets）](https://en.wikipedia.org/wiki/Cascading_Style_Sheets)：（风格）描述文档的表现形式
- [JavaScript](https://en.wikipedia.org/wiki/JavaScript)：（程序）操纵网页的程序语言
- [DOM（Document Object Model）](https://en.wikipedia.org/wiki/Document_Object_Model)：跨平台接口来表达和交互HTML中对象

---

##2. Web安全风险

- 风险1：恶意网站破坏用户系统
	- 防御：沙箱化Javascript；避免浏览器bug；特权分离；自动更新等
- 风险2：恶意网站窃听/篡改用户与其他网站通信
	- 防御：[同源策略（same-origin policy）](https://en.wikipedia.org/wiki/Same-origin_policy)：一个网页中脚本只能访问同源的其他网页
- 风险3：在用户服务器上存储数据被攻击者访问
	- 防御：服务器安全

###2.1 同源策略

[RFC6454: The Web Origin Concept](https://tools.ietf.org/html/rfc6454)：源=协议+主机+端口

```
http://www.example.com/dir/page.html
Compared URL                             | Outcome | Reason
-------------------------------------------------------------------------------------------
http://www.example.com/dir/page2.html	 | Success | Same protocol, host and port
http://www.example.com/dir2/other.html	 | Success | Same protocol, host and port
http://www.example.com:81/dir/other.html | Failure | Same protocol and host but diff port
https://www.example.com/dir/other.html	 | Failure | Different protocol
http://en.example.com/dir/other.html     | Failure | Different host
http://example.com/dir/other.html        | Failure | Different host (exact match required)
http://www.example.com:80/dir/other.html | Depends | Port explicit. Depends on implementation
```

###2.2 注入攻击

[SQL注入（SQL Injection）]()


###

[跨站点脚本（Cross-site scripting (XSS)）](https://en.wikipedia.org/wiki/Cross-site_scripting)



[跨站点请求伪造（Cross-site request forgery (CSRF)）]()

