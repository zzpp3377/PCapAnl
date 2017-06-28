运行环境：jre1.7.0
开发环境：jdk1.7.0 ,idea intelliJ, maven
配置文件：config/setting.properties
使用说明：
    本程序支持抓包与分析功能，使用本程序需要先安装wincap。运行程序之前，先在config/setting.properties中配置抓包器工作模式，包括捕获过滤器、是否混杂模式等。然后运行bin/目录下的
脚本即可（windows平台：start.bat，linux平台：start.sh）。
本程序支持的协议：
    Ethernet
    ARP
    RARP
    IP
    ICMP
    IGMP
    UDP
    TCP
