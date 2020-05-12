# tlstunnel
tlstunnel是沃航武汉科技股份有限公司倾力出品的一款tcp传输加密软件，该软件可以将任何的tcp协议通过tls协议进行加密，最高支持tls1.3版本。 为企业的数据传输安全加一道锁。 

# 支持平台
该软件由C语言与go语言两种语言编写，借由go语言那强大的跨平台特性，该可支持windows与linux等所有支持的平台。无论是x86架构，还是arm架构，甚至是mips架构，均可通过go编译器打包。  
而C语言版本可以用于设备性能非常极端的条件下。如优酷路由宝等地段设备。  

# 文件说明
tlsclient.go go语言开发的tls隧道客户端  
tlsserver.go go语言开发的tls隧道服务端  
tlsclient.c  c语言开发的tls隧道客户端  
tlsserver.c  c语言开发的tls隧道服务端（开发中）  

# 所需依赖
go语言版本无需任何依赖，直接运行go build xxx.go就可以生成所需要的软件。  
c语言版本依赖openssl库（加密tcp协议使用）以及jansson库（解析json使用），需要先安装相关的依赖包才能正常编译以及使用。  

# 技术合作
如果您有其他的需求，可以联系 [沃航科技](https://www.worldflying.cn/, "沃航科技")  

# 其他
软件包中有一个用go语言写的socks5代理服务器，方便大家测试该tcp加密隧道工具，请不要将该软件用于违法事情上。  
