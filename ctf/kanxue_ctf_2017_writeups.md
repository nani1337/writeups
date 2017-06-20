* 目录
  * [0x01_windows_crackme](/ctf/kanxue_ctf_2017_writeups_0x01.md)
  * [0x02_windows_crackme]()
  * [0x03_vb_crackme]()
  * [0x04_linux_pwn]()
  * [0x05_winxp_crackme]()
  * [0x06_android_crackme]()
  * [0x07_windows_crackme](/ctf/kanxue_ctf_2017_writeups_0x07.md)
  * [0x08_windows_crackme](/ctf/kanxue_ctf_2017_writeups_0x08.md)

## 0x02_windows_crackme
第二题没看，纯计算pass掉吧。

## 0x03_vb_crackme

本题用到的入口点修改、堆栈段寄存器反调试结合花指令还是比较有意思的，不知道的就进入坑中出不来了。 

最后两个公式，用matlab或python科学计算器或暴力破解得出，记得总结。


## 0x04_linux_pwn

本题含有double free漏洞，栈溢出漏洞，自己分析的是栈溢出漏洞，最后思路都已经有了，但最终调试时，死在了对到底栈中填充了多少字节这些细节没处理好。

时间又紧，就over了。python和pwntools

复现栈溢出漏洞的利用并学习double free漏洞的利用。从而对pwn入门。


## 0x05_winxp_crackme


## 0x06_android_crackme

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

将android-sdk\platform-tools目录添加至系统变量Path中，便于在cmd中直接调用adb.exe.

安装apk：

```bash
>adb install 6.apk
6.apk: 1 file pushed. 10.8 MB/s (923554 bytes in 0.082s)
        pkg: /data/local/tmp/6.apk
Success
```

卸载apk需要指定apk包名，即AndroidMainifest.xml中<manifest>节点下package元素所指定的名字。

```bash
>adb uninstall com.miss.rfchen
Success
```

将IDA目录中的dbgsrv\android_server上传至android系统并执行：

```bash
>adb push android_server /data/local/tmp/
android_server: 1 file pushed. 5.3 MB/s (523480 bytes in 0.095s)
>adb shell
# su -c setenforce 0
# cd /data/local/tmp
# chmod 777 android_server                                                       <
# ./android_server
IDA Android 32-bit remote debug server(ST) v1.19. Hex-Rays (c) 2004-2015
Listening on port #23946...
```
在执行adb shell时会出现error:device offline，选择关闭Android Emulator和Android Virtual Device Manager重新执行上述命令即可。

转发Windows到android的端口通信：
```bash
>adb forward tcp:23946 tcp:23946
```

在IDA中选择Debugger-->Attach-->Remote ARMLinux/Android debugger，配置Hostname:localhost/Port:23946，点击OK。

弹出Warning: Bogus or irresponsive remote server，表明权限不够.


## 0x07_windows_crackme

