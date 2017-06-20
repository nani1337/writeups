# windows smb protocol reverse engineering

## windows smb协议


## windows对smb的实现

讲述一下smb如何处理smb数据包的过程

能否用一句话或一张图，简单明了地解释SMB协议的作用。哪些数据包和哪些sys中的函数相互关联，彻底搞清楚每个数据包在服务端都干了什么。从github/google搜索有关Windows SMB逆向的资料。对Windows SMB协议做到烂熟于心。

## 逆向srv.sys和.sys


## linux smb源码阅读

通过上述，看Linux的实现，深入理解Linux与Windows的不同。

## 补丁对比

分析历年来srv.sys和.sys的改动

## 相关漏洞分析

将08年以来SMB协议的可用漏洞研究一番。

## smb协议fuzzing

能否研究基于函数的fuzzing方法（提取出来srv.sys或srvnet.sys的函数，对某个函数的输入参数进行fuzzing），或者基于数据包的fuzz ing方法。
从github/google 上寻找相关项目。可以fuzzing windows/Linux/Mac。





