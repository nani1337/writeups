## 0x01_crackme

第一题属于入门型crackme，后续复盘主要看一下浮点指令的运算，自己刚开始是暴力破解的，应该找到准确的公式。

第二题没看，纯计算pass掉吧。

## 0x03_crackme

本题用到的入口点修改、堆栈段寄存器反调试结合花指令还是比较有意思的，不知道的就进入坑中出不来了。 

最后两个公式，用matlab或python科学计算器或暴力破解得出，记得总结。


## 0x04_pwn

本题含有double free漏洞，栈溢出漏洞，自己分析的是栈溢出漏洞，最后思路都已经有了，但最终调试时，死在了对到底栈中填充了多少字节这些细节没处理好。

时间又紧，就over了。python和pwntools的

复盘复现栈溢出漏洞的利用并学习double free漏洞的利用。从而对pwn入门。


## 0x05_crackme

这是一道android crackme，第一次做，自然是趟路。

Dex2jar + jd_gui  --> 得到Android的java源码

分析源码发现，android程序内部将输入的字符串通过check函数传递给了libctf.so文件，核心算法需要从so中查找。

安装android studio：
下载并解压
https://dl.google.com/dl/android/studio/ide-zips/3.0.0.2/android-studio-ide-171.4056697-windows.zip

安装android sdk：
https://dl.google.com/android/installer_r24.4.1-windows.exe

根据下面这个博客配置IDA调试Android so文件：
http://www.cnblogs.com/shaoge/p/5425220.html
