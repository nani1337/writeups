* [目录](/notes/ctf_kanxue_ctf_2017_writeups.md)

## 0x08_windows_crackme

PEiD 打开程序，Visual C++ 8.0编译，Win32 console，加壳未知，入口点偏移42E1。

Win7x86下运行程序，提示`Please input the key:`，随便输入后弹出`your key is not right!`的Messagebox，点击确定后，console程序退出。

然后用OD加载程序，程序暂停在00402D00位置，并不是入口点，先F9执行上述过程，程序能够正常执行并判断，看起来一切正常。

IDA打开EXE，main函数00402D40，查看Imports输入表：
```assembly
004050B4  scanf 		MSVCR80
004050E0  MessageBoxA 		USER32
004050BC  printf 		MSVCR80
00405058  exit 			MSVCR80
0040502C  IsDebuggerPresent 	KERNEL32
00405084  _crt_debugger_hook 	MSVCR80
00405004  ExitProcess 		KERNEL32
```
查看导出表：
```assembly
TlsCallback_0 00402D00             
TlsCallback_1 00402D20             
TlsCallback_2 00402D30             
start         004042E1 [main entry]
```
发现导出表除了入口点之外，还有先于入口点执行的3个Tls回调函数，OD第一次暂停的地方就是第一个Tls回调函数的起始位置。

正常程序是没有Tls回调的，很可能作者在入口点之前的Tls回调函数中设置了反调试，后面再详细分析。

Shift+F12查看字符串窗口，发现了`CTF2017`等常规字符串外，还发现了其它不常见的字符串：
```assembly
.rdata:00405184 0000001F C --------???CTF2017--------\n\n\n                    
.rdata:00405144 00000035 C abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz
.data:00406490 0000004E C 1309506909921632660501024580877953527721154132445655806
```
但奇怪的是，并没有发现`Please input the key:`和出错提醒`your key is not right!`。

程序浏览到这里，大致有了crack的思路：

1. 找到“消失的”字符串`Please input the key:`和`your key is not right!`
2. 查看scanf函数，找到处理输入字符串的程序逻辑
3. Tls回调的作用
4. IsDebuggerPresent的作用
5. 特殊字符串与数字串的用途

通过输入表找到MessageBoxA：
```assembly
.idata:004050E0 ; int __stdcall MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
.idata:004050E0                 extrn MessageBoxA:dword ; CODE XREF: sub_403440+18p
```
右击MessageBoxA选择`Xrefs graph to...`得到交叉引用：
```assembly
__tmainCRTStartup -->  _main --> sub_403590 --> sub_403440 --> MessageBoxA
```
双击进入调用MessageBoxA的流程：
```assembly
.text:00403440 sub_403440      proc near              
.text:00403440 arg_0           = dword ptr  4
.text:00403440 arg_4           = dword ptr  8
.text:00403440
.text:00403440                 mov     eax, [esp+arg_4]
.text:00403444                 push    esi
.text:00403445                 mov     esi, [esp+4+arg_0]
.text:00403449                 mov     ecx, [esi+4]
.text:0040344C                 mov     edx, [esi]
.text:0040344E                 push    0               ; uType
.text:00403450                 add     ecx, eax
.text:00403452                 push    ecx             ; lpCaption
.text:00403453                 add     edx, eax
.text:00403455                 push    edx             ; lpText
.text:00403456                 push    0               ; hWnd
.text:00403458                 call    ds:MessageBoxA
.text:0040345E                 add     dword ptr [esi+14h], 1
.text:00403462                 pop     esi
.text:00403463                 retn
.text:00403463 sub_403440      endp
```
F5反编译：
```C
int __cdecl sub_403440(int a1, int a2)
{
  int result; // eax@1

  result = MessageBoxA(0, (LPCSTR)(a2 + *(_DWORD *)a1), (LPCSTR)(a2 + *(_DWORD *)(a1 + 4)), 0);
  ++*(_DWORD *)(a1 + 20);
  return result;
}
```
可以看到MessageBoxA显示的文本在内存中的位置是经过a1和a2计算的，用OD加载程序，在0040344E下断点，执行：
```assembly
018728E0:	"--------???CTF2017--------\n\n\n"  
018728E0+0x110:	"...〤TF2017"
018728E0+0x140:	"your key is not right!"
```
根据下面这个偏移：
```assembly
.rdata:00405184 0000001F C --------???CTF2017--------\n\n\n    
```
向后+0x110和0x140并没有找到想要的字符串，因此很有可能字符串是通过某种计算得到的，并没有直接存储在EXE中。

调用MessageBoxA继续单步执行后，发现retn指令返回的是00403573位置，查看其所在函数：
```assembly
.text:0040356B loc_40356B:                             
.text:0040356B                 mov     eax, [esi+eax*8+1Ch]
.text:0040356F                 push    ebp
.text:00403570                 push    esi
.text:00403571                 call    eax  //这里调用了sub_403440函数
.text:00403573                 add     esp, 8
.text:00403576
.text:00403576 loc_403576:                            
.text:00403576                 mov     ecx, [esi+14h]
.text:00403579                 cmp     byte ptr [ecx], 0A3h
.text:0040357C                 jnz     short loc_403551
.text:0040357E                 pop     edi
.text:0040357F
.text:0040357F loc_40357F:                            
.text:0040357F                 pop     ebp
.text:00403580                 retn
.text:00403580 sub_403540      endp
···
该代码片段位于sub_403540内，因此修正后的调用关系：
```bash
__tmainCRTStartup -->  _main --> sub_403590 --> sub_403440 --> MessageBoxA
```
to
```bash
__tmainCRTStartup -->  _main --> sub_403540 --> sub_403440 --> MessageBoxA
```
再观察scanf的交叉引用：
```bash
__tmainCRTStartup -->  _main --> sub_403590 --> sub_403480 --> scanf
```
查看sub_403480依旧是根据调用参数，确定输入内容存放的内存位置：
```assembly
.text:00403480 sub_403480      proc near              
.text:00403480 arg_0           = dword ptr  4
.text:00403480 arg_4           = dword ptr  8
.text:00403480                 push    esi
.text:00403481                 mov     esi, [esp+4+arg_0]
.text:00403485                 mov     eax, [esi]
.text:00403487                 add     eax, [esp+4+arg_4]
.text:0040348B                 push    eax
.text:0040348C                 push    offset Format   ; "%s"
.text:00403491                 call    ds:scanf
.text:00403497                 add     dword ptr [esi+14h], 1
.text:0040349B                 add     esp, 8
.text:0040349E                 pop     esi
.text:0040349F                 retn
.text:0040349F sub_403480      endp
```
```C
int __cdecl sub_403480(int a1, int a2)
{
  int result; // eax@1

  result = scanf("%s", a2 + *(_DWORD *)a1);
  ++*(_DWORD *)(a1 + 20);
  return result;
}
```
OD加载程序，在00403485下断点：
```assembly
.text:00403481                 mov     esi, [esp+4+arg_0]
	堆栈 ss:[0012FD5C]=0012FD98
.text:00403485                 mov     eax, [esi]
	堆栈 ds:[0012FD98]=00000160
.text:00403487                 add     eax, [esp+4+arg_4]
	堆栈 ss:[0012FD60]=002227D0, (ASCII "--------...〤TF2017--------\n\n\n")
	eax=00000160
.text:0040348B                 push    eax
	eax=00222930
.text:0040348C                 push    offset Format   ; "%s"
.text:00403491                 call    ds:scanf
```
scanf输入的字符串地址也是根据偏移计算得到的，而且借助的基址和MessageBoxA借助的基址一样，观察002227D0并不是栈地址，那估计是申请的堆地址吧，暂且后面在分析。
修正一下scanf的交叉引用：
```assembly
__tmainCRTStartup -->  _main --> sub_403590 --> sub_403480 --> scanf
```
to
```assembly
__tmainCRTStartup -->  _main --> sub_403540 --> sub_403480 --> scanf
```
同样继续F8单步执行到retn指令，发现返回至00403573，和MessageBoxA返回了同一个函数，这里就不得不看一看这个函数了：
```C
int __usercall sub_403540@<eax>(int result@<eax>, int a2@<esi>, int a3)
{
  _BYTE *v3; // ecx@2

  *(_DWORD *)(a2 + 20) = result;
  while ( **(_BYTE **)(a2 + 20) != -93 )
  {
    result = 0;
    v3 = (_BYTE *)(a2 + 24);
    while ( result < 32 )
    {
      if ( **(_BYTE **)(a2 + 20) == *v3 )
      {
		//下面是调用的scanf和MessageBoxA的地方
        result = (*(int (__cdecl **)(int, int))(a2 + 8 * result + 28))(a2, a3);
        break;
      }
      ++result;
      v3 += 8;
    }
  }
  return result;
}
```
而_main调用sub_403540的逻辑非常简单：
```assembly
v3 = malloc(0x1000u);
......
*((_DWORD *)v3 + 72) = v29;
*((_DWORD *)v3 + 73) = v6;
*((_DWORD *)v3 + 74) = v7;
*((_DWORD *)v3 + 75) = v4;
*((_DWORD *)v3 + 76) = v5;
*((_WORD *)v3 + 154) = v34;
*((_DWORD *)v3 + 80) = v23;
*((_DWORD *)v3 + 81) = v24;
......
//前面申请了一个堆，然后各种赋值，最后调用这个函数
sub_403540((int)&v35, (int)&v17, (int)v3);
free(v3);
return 0;
```
看来主逻辑都是在sub_403540完成的，猜测scanf之后对输入字符串的处理也是和scanf与MessageBoxA一样，在循环中调用，常规来说，接下来，在sub_403540的while循环下断点，分析_main和sub_403540也许就能得到答案，但分析到这里，3个TlsCallback回调和IsDebuggerPresent函数都没有涉及到，这是不正常的，为了不至于入坑，先将这两个疑点分析清楚。
```assembly
TlsCallback_0 00402D00             
TlsCallback_1 00402D20             
TlsCallback_2 00402D30    
```
TlsCallback_0:
```assembly
00402D00    51              push ecx
00402D01    50              push eax
00402D02    64:A1 30000000  mov eax,dword ptr fs:[0x30]     //PEB
00402D08    0FB640 02       movzx eax,byte ptr ds:[eax+0x2] //PEB->BeingDebugged
00402D0C    894424 04       mov dword ptr ss:[esp+0x4],eax  
00402D10    58              pop eax                                  
00402D11    59              pop ecx   //PEB->BeingDebugged存入ecx                              
00402D12    C2 0C00         retn 0xC
```
这里用StrongOD插件Patch过的OD加载程序，即可绕过这个反调试，StrongOD勾选：
```bash
1. !*Kill BadPE Bug
2. Break On Tls
3. Hide PEB 
```
前两个选项可以让OD在Tls回调函数起始位置暂停下来，第三个选项，可以让PEB->BeingDebugged恒为0，在TlsCallback_1入口00402D20下断点，OD继续运行程序：
```assembly
00402D20    E8 DBE2FFFF     call crackme.00401000
00402D25    C2 0C00         retn 0xC
```
进入主体函数00401000：
```assembly
00401000    55                    push ebp
00401001    8BEC                  mov ebp,esp
00401003    6A FE                 push -0x2
00401005    68 78534000           push crackme.00405378
0040100A    68 45464000           push crackme.00404645
0040100F    64:A1 00000000        mov eax,dword ptr fs:[0]
00401015    50                    push eax
00401016    83EC 08               sub esp,0x8
00401019    53                    push ebx                                 
0040101A    56                    push esi
0040101B    57                    push edi
0040101C    A1 00604000           mov eax,dword ptr ds:[0x406000]
00401021    3145 F8               xor dword ptr ss:[ebp-0x8],eax
00401024    33C5                  xor eax,ebp
00401026    50                    push eax
00401027    8D45 F0               lea eax,dword ptr ss:[ebp-0x10]
0040102A    64:A3 00000000        mov dword ptr fs:[0],eax
00401030    8965 E8               mov dword ptr ss:[ebp-0x18],esp
00401033    C745 FC 00000000      mov dword ptr ss:[ebp-0x4],0x0
0040103A    CD 2D                 int 0x2D
0040103C    40                    inc eax
0040103D    C745 FC FEFFFFFF      mov dword ptr ss:[ebp-0x4],-0x2
00401044    B8 01000000           mov eax,0x1
00401049    8B4D F0               mov ecx,dword ptr ss:[ebp-0x10]
0040104C    64:890D 00000000      mov dword ptr fs:[0],ecx
00401053    59                    pop ecx                                 
00401054    5F                    pop edi                                  
00401055    5E                    pop esi                                  
00401056    5B                    pop ebx                                  
00401057    8BE5                  mov esp,ebp
00401059    5D                    pop ebp                                  
0040105A    C3                    retn
```
大致浏览后，发现了从未见过的int 0x2d指令，补充了以下相关资料：

> int 2d原为内核模式中运行DebugServices触发断点异常的指令，也可以在ring3模式下使用它.
> 如果一个正常的程序执行int 2d，将会触发SEH异常，但程序在调试运行时，却不会触发异常.
> 附加调试器的程序，在运行完int 2d后，会跳过指令之后的一个字节继续执行。

上述流程在调试器汇总运行时，忽略int 2d之后的一字节的inc eax指令，继续执行0040103D以及后续指令；在非调试正常运行时，程序执行至int 2d就会去执行SEH handler。

如何构造SEH handler呢？
> FS:0指向线程环境块TEB，而TEB的第一个元素FS:[0]指向当前线程的结构化异常处理SEH。

在执行int 2d指令前，首先要构造新的SEH通常采用如下方式：
```assembly
push offset_seh  //构造新的SEH handler
push fs:[0]
mov fs:[0],esp
int 2d  //非调试情况下会触发SEH
nop //any one byte instruction
pop fs:[0] //恢复SEH
add esp, 4
jmp debugged
_seh:
  jmp not_debugged
```	
静态分析并动态调试00401000的处理流程，可以得到在int 2d指令前，程序将SEH链表构造为：
```assembly
0018F9CC   0018FA34  指向下一个 SEH 记录的指针
0018F9D0   00404645  SE处理程序
0018FA34  0018FB20  指向下一个 SEH 记录的指针
0018FA38  772658C5  SE处理程序
```
查看00404645代码：
```assembly
00404645    FF7424 10       push dword ptr ss:[esp+0x10]
00404649    FF7424 10       push dword ptr ss:[esp+0x10]
0040464D    FF7424 10       push dword ptr ss:[esp+0x10]
00404651    FF7424 10       push dword ptr ss:[esp+0x10]
00404655    68 23404000     push crackme.00404023                    
0040465A    68 00604000     push crackme.00406000
0040465F    E8 DC000000     call <jmp.&MSVCR80._except_handler4_comm>
00404664    83C4 18         add esp,0x18
00404667    C3              retn
```
如何绕过int 2d呢？OD中的`StrongOD插件勾选Options-->Skip Some Exceptions`即可。

利用Patch后的OD在00404645下断点，可以发现程序正常执行了00404645处的指令，F8跟踪了一会，发现能够进入入口点正常执行程序。

接下来看最后一个Tls回调TlsCallback_2，Ctrl+G跳转至00402D30处，但貌似OD没有正确反汇编，选择00402D30至00402D3C内容，右击-->分析-->分析代码+在下次分析时，将选中部分视为Command， 即可正确反汇编。
```assembly
00402D30      837C24 08 01     cmp dword ptr ss:[esp+0x8],0x1
00402D35      75 05            jnz short crackme.00402D3C
00402D37      E8 34FFFFFF      call crackme.00402C70
00402D3C      C2 0C00          retn 0xC
```
如果[esp+0x8]为1，则调用00402C70函数，否则直接retn返回：
```C
HANDLE sub_402C70()
{
  hMutex = CreateMutexW(0, 0, "Mutex");
  CreateThread(0, 0, StartAddress, 0, 0, 0);
  CreateThread(0, 0, sub_402970, 0, 0, 0);
  CreateThread(0, 0, sub_402A90, 0, 0, 0);
  CreateThread(0, 0, sub_402BB0, 0, 0, 0);
  CreateThread(0, 0, sub_402BF0, 0, 0, 0);
  return CreateThread(0, 0, sub_402C30, 0, 0, 0);
}
```
创建这么多线程，每个函数看起来十分复杂，但仔细分析，发现有规律可循，StartAddress、sub_402970、sub_402A90根据dword_99B6EC的数值分别对loc_401EC0、loc_402090和loc_4021D0后的47个字节进行改写：
```C
void __stdcall __noreturn StartAddress(LPVOID lpThreadParameter)
{
  while ( 1 )
  {
    if ( dword_99B6EC == 1 )
    {
      v1 = 1;
      do
      {
        *(&loc_401EC0 + v1 - 1) ^= byte_4064F0[v1 - 1];
        *(&loc_401EC0 + v1) ^= byte_4064F0[v1];
        v1 += 2;
      }
      while ( v1 - 1 < 46 );

      dword_99B6EC = 0;
    }
  }
}
```
```C
void __stdcall __noreturn sub_402970(LPVOID lpThreadParameter)
{
  while ( 1 )
  {
    WaitForSingleObject(hMutex, 0xFFFFFFFF);
    if ( dword_99B6EC == 2 )
    {
      v1 = 1;
      do
      {
        *(&loc_402090 + v1 - 1) ^= byte_406520[v1 - 1];
        *(&loc_402090 + v1) ^= byte_406520[v1];
        v1 += 2;
      }
      while ( v1 - 1 < 46 );
      dword_99B6EC = 0;
    }
  }
}
```
```C
void __stdcall __noreturn sub_402A90(LPVOID lpThreadParameter)
{
  while ( 1 )
  {
    if ( dword_99B6EC == 3 )
    {
      v1 = 1;
      do
      {
        *(&loc_4021D0 + v1 - 1) ^= byte_406550[v1 - 1];
        *(&loc_4021D0 + v1) ^= byte_406550[v1];
        v1 += 2;
      }
      while ( v1 - 1 < 46 );
      dword_99B6EC = 0;
    }
  }
}
```
sub_402BB0、sub_402BF0、sub_402C30则是简单的Sleep：
```C
while ( 1 )
{
  v1 = 0;
  do
    ++v1;
  while ( v1 < 519 or 514 or 519 );
  Sleep(50);
}
```
那么创建这些线程函数的关键判断ss:[esp+0x8]是如何得到的呢？Tls回调函数的传入参数：
```C
void NTAPI TLS_CALLBACK(PVOID DllHandle, DWORD Reason, PVOID Reserved)
```
第一个参数为模块句柄，即加载地址，第二个参数为调用原因，通常有4种：
```C
#define DLL_PROCESS_ATTACH 1
#define DLL_THREAD_ATTACH 2
#define DLL_THREAD_DETACH 3
#define DLL_PROCESS_ATTACH 0
```
在Main函数之前的TlsCallback回调，都是DLL_PROCESS_ATTACH，也就是必定调用sub_402C70来创建这些线程。
如果第3个TlsCallback正常情况下执行了sub_402C70，难不成必须又这些线程修改对应位置的指令，程序逻辑才能正常执行？

为了检测ss:[esp+0x8]是不是在正常情况下也为1，利用UltraEdit修改第三个Tls回调函数起始位置指令的第一个字节为int 3：
```assembly
00002d30h: 83 7C 24 08 01 75 05 E8 34 FF FF FF C2 0C 00 CC 
```
修改为：
```assembly
00002d30h: CC 7C 24 08 01 75 05 E8 34 FF FF FF C2 0C 00 CC 
```
得到Patch后的EXE在正常情况下执行，理论上，程序会因为int 3崩溃，但奇怪的事情发生了，程序能够正常运行！为了防止前两个Tls回调有可能某些没分析到的地方影响程序流程，没有执行第3个Tls回调。

将3个回调函数起始位置的第一个字节，全部修改为CC，再重新运行Patch后的程序，奇怪的事情发生了，程序仍旧能够正常执行。

`这？？？这？？？这？？？`

经过多次做实验分析，发现程序执行到int 3之后，F7/F8单步执行，都会转去执行入口点00402DE1，这难不成是Tls回调的特性，希望知道原因的大牛能告知一下。

默认情况下，Tls回调的第二个参数都为DLL_PROCESS_ATTACH，也就是必定要调用sub_402C70创建那些线程函数。
Tls回调先分析到这里，待程序流程用到这些线程函数修改的内存位置loc_401EC0、loc_402090和loc_4021D0时，再继续分析。

接下来查看IsDebuggerPresent的交叉调用:
```C
TlsCallback_0-->sub_401000-->__except_handler4-->__Security_check_cookie-->___report_gsfailure-->IsDebuggerPresent
__tmainCRTStartup-->__main-->__Security_check_cookie-->___report_gsfailure-->IsDebuggerPresent
__tmainCRTStartup-->__main-->sub_402700-->sub_402450__Security_check_cookie-->___report_gsfailure-->IsDebuggerPresent
```
由于在分析TLs回调时已经设置StrongOD插件的OD可以绕过IsDebuggerPresent了，这里就没必须再去分析这些流程了，下面直接看_main函数，寻找算法。

Main函数的结构很简单，首先在栈中开辟两个相邻的栈内存，一个从0018FD9C到0018FEAF，0x114大小，存放了一些函数的偏移；另一个从0018FEB0至0018FF33，共0x84=132字节，全部被常量赋值，但其中有4个字节其实没有赋值，分别为0018FEC6、0018FEC7、0018FEDE、0018FEDF，先记下来，后面有可能用到。
```assembly
0018FD9C  -astart-
0018FDB0   000000A0
0018FDB4   004034C0  看雪CTF2.004034C0
0018FDB8   000000A1
0018FDBC   004033C0  看雪CTF2.004033C0
0018FDC0   000000A2
0018FDC4   004033D0  看雪CTF2.004033D0
0018FDC8   000000A4
0018FDCC   00403440  看雪CTF2.00403440
0018FDD0   000000A5
0018FDD4   00403470  看雪CTF2.00403470
0018FDD8   000000A3
0018FDDC   00403430  看雪CTF2.00403430
0018FDE0   000000A6
0018FDE4   00403400  看雪CTF2.00403400
0018FDE8   000000A7
0018FDEC   00403480  看雪CTF2.00403480
0018FDF0   000000A8
0018FDF4   004034A0  看雪CTF2.004034A0
0018FDF8   000000A9			//在后续栈向堆拷贝过程中补充进来的
0018FDFC   00402700  看雪CTF2.00402700  
0018FE00   000000AA
0018FE04   00402720  看雪CTF2.00402720
0018FEAC  --aend--
0018FEB0  -bstart-
```
第二个栈：
```assembly
0018FEB0  18 0D 16 16 45 0D 02 11 49 03 18 4C 03 01 1B 50  ....E...I..L...P
0018FEC0  03 1B 14 1C 01 57 00 00 18 0D 16 44 02 09 13 48  .....W.....D...H
0018FED0  1D 02 0E 4C 1F 07 08 18 05 52 18 11 0C 57 00 00  ...L.....R...W..
0018FEE0  AA 15 20 01 00 00 AA 15 40 01 00 00 A0 10 00 00  .. .....@.......
0018FEF0  00 00 A8 A0 10 F0 00 00 00 A8 A0 10 60 01 00 00  ............`...
0018FF00  A7 AA 11 80 00 00 00 AA 10 60 00 00 00 AA 12 B0  .........`......
0018FF10  00 00 00 A9 A2 EA A6 0E A0 10 20 01 00 00 A0 11  ...?..... .....
0018FF20  10 01 00 00 A4 A5 A0 10 40 01 00 00 A0 11 10 01  ........@.......
0018FF30  00 00 A4 A5       
0018FF30  --bend--
```
然后Main函数又申请了一个0x1000大小的堆内存，先拷贝进去一些界面显示用的字符串：
```assembly
00312970  2D 2D 2D 2D 2D 2D 2D 2D BF B4 D1 A9 43 54 46 32  --------...〤TF2
00312980  30 31 37 2D 2D 2D 2D 2D 2D 2D 2D 0A 0A 0A 00 00  017--------.....
00312990  61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70  abcdefghijklmnop
003129A0  71 72 73 74 75 76 77 78 79 7A 61 62 63 64 65 66  qrstuvwxyzabcdef
003129B0  67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76  ghijklmnopqrstuv
003129C0  77 78 79 7A 00 00 00 00 00 00 00 00 00 00 00 00  wxyz............
003129D0  58 5A 54 52 50 52 54 5A 58 5A 52 54 5A 58 5A 44  XZTRPRTZXZRTZXZD
003129E0  42 40 42 44 44 44 44 00 00 00 00 00 00 00 00 00  B@BDDDD.........
003129F0  50 57 57 5D 52 5E 57 5E 5C 58 5B 5F 5B 5C 5A 48  PWW]R^W^\X[_[\ZH
00312A00  45 4A 47 40 47 42 40 4D 48 4D 51 57 52 54 57 51  EJG@GB@MHMQWRTWQ
00312A10  5F 59 51 52 5F 5F 55 58 5E 41 42 00 00 00 00 00  _YQR__UX^AB.....
00312A20  58 55 56 57 54 54 53 5E 51 5A 52 5B 58 5D 5E 42  XUVWTTS^QZR[X]^B
00312A30  45 44 4B 44 4C 41 42 4B 48 48 55 54 5B 54 5C 51  EDKDLABKHHUT[T\Q
00312A40  52 5B 58 58 5F 5A 55 5E 00 00 00 00 00 00 00 00  R[XX_ZU^........
00312A50  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00312A60  70 6C 65 61 73 65 20 69 6E 70 75 74 20 74 68 65  please input the
00312A70  20 6B 65 79 3A 0A 00 00 00 00 00 00 00 00 00 00   key:...........
00312A80  BF B4 D1 A9 43 54 46 32 30 31 37 00 00 00 00 00  ...〤TF2017.....
```
然后又将第2个栈内存的数据拷贝进来，但不是从栈内存顺序拷贝：
```assembly
00312A90  18 0D 16 44 02 09 13 48 1D 02 0E 4C 1F 07 08 18  ...D...H...L.... 0x40 byte
00312AA0  05 52 18 11 0C 57 00 00 00 00 00 00 00 00 00 00  .R...W..........
00312AB0  18 0D 16 16 45 0D 02 11 49 03 18 4C 03 01 1B 50  ....E...I..L...P
00312AC0  03 1B 14 1C 01 57 00 00 00 00 00 00 00 00 00 00  .....W..........
00312AD0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00312AE0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00312AF0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00312B00  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00312B10  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00312B20  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00312B30  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00312B40  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00312B50  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00312B60  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00312B70  18 0D 16 44 02 09 13 48 1D 02 0E 4C 1F 07 08 18  ...D...H...L.... 0x40 byte
00312B80  05 52 18 11 0C 57 00 00 00 00 00 00 00 00 00 00  .R...W..........
00312B90  18 0D 16 16 45 0D 02 11 49 03 18 4C 03 01 1B 50  ....E...I..L...P
00312BA0  03 1B 14 1C 01 57 00 00 00 00 00 00 00 00 00 00  .....W..........
00312BB0  BF B4 D1 A9 43 54 46 32 30 31 37 00 00 00 00 00  ...〤TF2017.....
```
最后一行内存00312BB0拷贝等同于00312A80处，估计用于标题作用。可以有趣地发现，上述拷贝生成了两个0x40大小的堆内存00312A90和00312B70，数据都是从第2个栈内存拷贝，猜测后续的算法有可能用到这里的数据，进行变换，再进行比较。

最后Main函数就进入了核心函数sub_403540：
```C
sub_403540(&v35, &v17, v3);
```
传入的3个参数分别为：
```C
eax = 0018FEE0, a2 = 0018FD98, a3 = heap_start_addr
```
```C
int __usercall sub_403540@<eax>(int result@<eax>, int a2@<esi>, int a3)
{
  _BYTE *v3; // ecx@2

  *(a2 + 20) = result;
  while ( **(a2 + 20) != 0xA3u ) // 起初为AA
  {
    result = 0;
    v3 = (a2 + 0x18);
    while ( result < 32 )
    {
      if ( **(a2 + 20) == *v3 )
      {
        result = (*(a2 + 8 * result + 28))(a2, a3);
        break;
      }
      ++result;
      v3 += 8;
    }
  }
  return result;
}
```
```assembly
0018FD98   00000000
0018FD9C   00000000
0018FDA0   00000000
0018FDA4   00000000
0018FDA8   00000000
0018FDAC   0018FEE0  <-- AA
0018FDB0   000000A0  <-- 0从此处开始比较是否等于AA，等于则执行对应的函数
0018FDB4   004034C0  看雪CTF2.004034C0
0018FDB8   000000A1  <-- 1
0018FDBC   004033C0  看雪CTF2.004033C0
0018FDC0   000000A2  <-- 2
0018FDC4   004033D0  看雪CTF2.004033D0
0018FDC8   000000A4  <-- 3
0018FDCC   00403440  看雪CTF2.00403440
0018FDD0   000000A5  <-- 4
0018FDD4   00403470  看雪CTF2.00403470
0018FDD8   000000A3  <-- 5
0018FDDC   00403430  看雪CTF2.00403430
0018FDE0   000000A6  <-- 6
0018FDE4   00403400  看雪CTF2.00403400
0018FDE8   000000A7  <-- 7
0018FDEC   00403480  看雪CTF2.00403480
0018FDF0   000000A8  <-- 8
0018FDF4   004034A0  看雪CTF2.004034A0
0018FDF8   000000A9  <-- 9	
0018FDFC   00402700  看雪CTF2.00402700  
0018FE00   000000AA  <-- A
0018FE04   00402720  看雪CTF2.00402720

0018FEE0  AA    
```
符合条件的会去执行：
```C
result = (*(a2 + 8 * result + 28))(a2, a3);
```
我们在执行这一指令的地址00403571上下断点：
```assembly
.text:00403571                 call    eax
```
运行程序，在随意输入key：123456出错的情况下，得到了一条函数执行序列：
```assembly
00402720-->00402720-->004024c0-->004034a0 输出“----看雪ctf2017----”

-->004034c0-->004024a0 输出“Please input the key:”
-->004034c0-->00403480 scanf输入字符串
-->00402720-->00402720-->00402720
-->00402700-->004033d0-->00403400
-->004034c0-->004034c0-->00403440 MessageBoxA
-->00403470 ExitProcess
```
传入的参数是0018FD98和堆内存的起始地址，很明显，第一次符合条件的只能是result=A，即调用00402720函数，F5反编译浏览一下sub_402720函数：
```C
char __cdecl sub_402720(int a1, int a2)
{
  v2 = *(a1 + 20);
  v4 = *(v2 + 1);
  if ( v4 == 0x10 )
  {
	......
  }
  if ( v4 == 0x11 )
  {
	......
  }
  else
  {
    if ( v4 != 0x12 )
    { 
	......
    }
  }  
}
```
根据第一次传入的a1=0018FEE0，a2=堆内存起始地址，可以发现v4代表的是0018FEE0之后的1个字节0x15：
```assembly
0018FEE0  AA 15 20 01 00 00 AA 15 40 01 00 00 A0 10 00 00  .. .....@.......
0018FEF0  00 00 A8 A0 10 F0 00 00 00 A8 A0 10 60 01 00 00  ............`...
0018FF00  A7 AA 11 80 00 00 00 AA 10 60 00 00 00 AA 12 B0  .........`......
0018FF10  00 00 00 A9 A2 EA A6 0E A0 10 20 01 00 00 A0 11  ...?..... .....
0018FF20  10 01 00 00 A4 A5 A0 10 40 01 00 00 A0 11 10 01  ........@.......
0018FF30  00 00 A4 A5                                      ....
```
进入函数判断的是0018FEE0，函数进入之后又会根据后续一个字节进行不同的操作。仔细观察0018FEE0后续内存，将其按照A0-AA分割，可以发现如下规律：
```assembly
AA 15 20 01 00 00 	00402720
AA 15 40 01 00 00 	00402720
A0 10 00 00 00 00 	004034C0
A8 			004034A0 --看雪ctf2017--
A0 10 F0 00 00 00 	004034C0
A8 			004034A0 Please input the key:
A0 10 60 01 00 00   	004034C0
A7 			0403480 scanf
AA 11 80 00 00 00   	00402720 
AA 10 60 00 00 00   	00402720
AA 12 B0 00 00 00   	00402720
A9                  	00402700
A2 EA 			004033D0
A6 0E 			00403400
A0 10 20 01 00 00 	004034C0 
A0 11 10 01 00 00 	004034C0 
A4 			00403440 MessageBoxA
A5 			00403430 00403470 [x]
A0 10 40 01 00 00 	00402720 00402470-->ExitProcess [x]
A0 11 10 01 00 00 	00402720
A4 			00403440
A5 00 00		00403430
```
对照刚才随意输入字符串，弹出MessageBoxA错误提示的命令序列，不一致的命令已经用[x]标注出来。这说明，在算法运行过程中，命令序列可能因为输入不正确而进行了调整。

此时查看堆内存已经改变，我们注意到，又多了一些字符串，you got the right key、your key is not right!和输入的字符串：
```assembly
003F2B90  2D 2D 2D 2D 2D 2D 2D 2D BF B4 D1 A9 43 54 46 32  --------...〤TF2
003F2BA0  30 31 37 2D 2D 2D 2D 2D 2D 2D 2D 0A 0A 0A 00 00  017--------.....
003F2BB0  61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70  abcdefghijklmnop
003F2BC0  71 72 73 74 75 76 77 78 79 7A 61 62 63 64 65 66  qrstuvwxyzabcdef
003F2BD0  67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76  ghijklmnopqrstuv
003F2BE0  77 78 79 7A 00 00 00 00 00 00 00 00 00 00 00 00  wxyz............
003F2BF0  58 5A 54 52 50 52 54 5A 58 5A 52 54 5A 58 5A 44  XZTRPRTZXZRTZXZD
003F2C00  42 40 42 44 44 44 44 00 00 00 00 00 00 00 00 00  B@BDDDD.........
003F2C10  50 57 57 5D 52 5E 57 5E 5C 58 5B 5F 5B 5C 5A 48  PWW]R^W^\X[_[\ZH
003F2C20  45 4A 47 40 47 42 40 4D 48 4D 51 57 52 54 57 51  EJG@GB@MHMQWRTWQ
003F2C30  5F 59 51 52 5F 5F 55 58 5E 41 42 00 00 00 00 00  _YQR__UX^AB.....
003F2C40  58 55 56 57 54 54 53 5E 51 5A 52 5B 58 5D 5E 42  XUVWTTS^QZR[X]^B
003F2C50  45 44 4B 44 4C 41 42 4B 48 48 55 54 5B 54 5C 51  EDKDLABKHHUT[T\Q
003F2C60  52 5B 58 58 5F 5A 55 5E 00 00 00 00 00 00 00 00  R[XX_ZU^........
003F2C70  00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00  ................
003F2C80  70 6C 65 61 73 65 20 69 6E 70 75 74 20 74 68 65  please input the
003F2C90  20 6B 65 79 3A 0A 00 00 00 00 00 00 00 00 00 00   key:...........
003F2CA0  BF B4 D1 A9 43 54 46 32 30 31 37 00 00 00 00 00  ...〤TF2017.....
003F2CB0  79 6F 75 20 67 6F 74 20 74 68 65 20 72 69 67 68  you got the righ
003F2CC0  74 20 6B 65 79 21 00 00 00 00 00 00 00 00 00 00  t key!..........
003F2CD0  79 6F 75 72 20 6B 65 79 20 69 73 20 6E 6F 74 20  your key is not
003F2CE0  72 69 67 68 74 21 00 00 00 00 00 00 00 00 00 00  right!..........
003F2CF0  31 32 33 34 35 36 37 38 39 00 00 00 00 00 00 00  123456789.......
003F2D00  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
003F2D10  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
003F2D20  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
003F2D30  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
003F2D40  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
003F2D50  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
003F2D60  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
003F2D70  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
003F2D80  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
003F2D90  18 0D 16 44 02 09 13 48 1D 02 0E 4C 1F 07 08 18  ...D...H...L....
003F2DA0  05 52 18 11 0C 57 00 00 00 00 00 00 00 00 00 00  .R...W..........
003F2DB0  18 0D 16 16 45 0D 02 11 49 03 18 4C 03 01 1B 50  ....E...I..L...P
003F2DC0  03 1B 14 1C 01 57 00 00 00 00 00 00 00 00 00 00  .....W..........
003F2DD0  BF B4 D1 A9 43 54 46 32 30 31 37 00 00 00 00 00  ...〤TF2017.....
```
重新跟踪命令序列，结合每个函数的F5反编译后的大致流程，并查看命令序列后堆和栈内存的变化，可以推测：
```assembly
AA 15 20 01 00 00 	00402720 堆内存0120偏移异或计算写入you got the right key!
AA 15 40 01 00 00 	00402720 堆内存0140偏移写入your key is not right!
A0 10 00 00 00 00 	004034C0 后4字节放入0018FD98 00000000偏移
A8 			004034A0 --看雪ctf2017-- printf("%s", heap_start_addr + *0018FD98);
A0 10 F0 00 00 00 	004034C0 后4字节放入0018FD98 000000F0偏移
A8 			004034A0 Please input the key:
A0 10 60 01 00 00   	004034C0 后4字节放入0018FD98 00000160偏移
A7 			00403480 scanf 将输入的字符串放入堆内存的00000160偏移
AA 11 80 00 00 00   	00402720 堆偏移0x80 xor 堆0x20偏移共0x2B字节存入00406038
AA 10 60 00 00 00   	00402720 堆偏移0x60 xor 堆0x20偏移共0x17字节存入00406020
AA 12 B0 00 00 00   	00402720 堆偏移0xB0 xor 堆0x20偏移共0x28字节存入00406064
A9                  	00402700 计算字符串，得到的结果存入栈内存
A2 EA 			004033D0 析0018FD98处是否恒等于堆中EA偏移固定写入的1
A6 0E 			00403400
A0 10 20 01 00 00 	004034C0 
A0 11 10 01 00 00 	004034C0 
A4 			00403440 MessageBoxA
A5 			0403430 00403470 [x]
A0 10 40 01 00 00 	00402720 00402470-->ExitProcess [x]
A0 11 10 01 00 00 	00402720
A4 			00403440
A5 00 00		00403430
```
其中三次xor计算得出相邻的三串数字，估计后面算法会用到：
```assembly
AA 11 80 00 00 00   00402720 堆偏移0x80 xor 堆0x20偏移共0x2B字节存入00406038
AA 10 60 00 00 00   00402720 堆偏移0x60 xor 堆0x20偏移共0x17字节存入00406020
AA 12 B0 00 00 00   00402720 堆偏移0xB0 xor 堆0x20偏移共0x28字节存入00406064
```
详细解释如下：
```assembly
00AC29F0  50 57 57 5D 52 5E 57 5E 5C 58 5B 5F 5B 5C 5A 48  PWW]R^W^\X[_[\ZH
00AC2A00  45 4A 47 40 47 42 40 4D 48 4D 51 57 52 54 57 51  EJG@GB@MHMQWRTWQ
00AC2A10  5F 59 51 52 5F 5F 55 58 5E 41 42 00              _YQR__UX^AB.
```
xor
```assembly
003C2990  61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70  abcdefghijklmnop
003C29A0  71 72 73 74 75 76 77 78 79 7A 61 62 63 64 65 66  qrstuvwxyzabcdef
003C29B0  67 68 69 6A 6B 6C 6D 6E 6F 70 71 72              ghijklmnopqr
```
得到的结果存入：
```assembly
00406038  31 35 34 39 37 38 30 36 35 32 30 33 36 32 35 38  1549780652036258
00406048  34 38 34 34 32 34 37 35 31 37 30 35 31 30 32 37  4844247517051027
00406058  38 31 38 38 34 33 38 36 31 31 33 00              81884386113.
```
最后一位不参与运算，以00AC29F0处碰到00计算就停止，00406038末尾的00内存原本就有的，此处故意设计为结束符。
```assembly
00AC29D0  58 5A 54 52 50 52 54 5A 58 5A 52 54 5A 58 5A 44  XZTRPRTZXZRTZXZD
00AC29E0  42 40 42 44 44 44 44 00 00 00 00 00 00 00 00 00  B@BDDDD.........
```
xor
```assembly
00AC2990  61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70  abcdefghijklmnop
00AC29A0  71 72 73 74 75 76 77 78 79 7A 61 62 63 64 65 66  qrstuvwxyzabcdef
```
得到的结果存入：
```assembly
00406020  39 38 37 36 35 34 33 32 31 30 39 38 37 36 35 34  9876543210987654
00406030  33 32 31 30 31 32 33 00                          3210123.
```
```assembly
00AC2A20  58 55 56 57 54 54 53 5E 51 5A 52 5B 58 5D 5E 42  XUVWTTS^QZR[X]^B
00AC2A30  45 44 4B 44 4C 41 42 4B 48 48 55 54 5B 54 5C 51  EDKDLABKHHUT[T\Q
00AC2A40  52 5B 58 58 5F 5A 55 5E 00 00 00 00 00 00 00 00  R[XX_ZU^........
```
xor
```assembly
00AC2990  61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70  abcdefghijklmnop
00AC29A0  71 72 73 74 75 76 77 78 79 7A 61 62 63 64 65 66  qrstuvwxyzabcdef
00AC29B0  67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76  ghijklmnopqrstuv
00AC29C0  77 78 79 7A 00 00 00 00 00 00 00 00 00 00 00 00  wxyz............
```
得到的结果存入：
```assembly
00406064  39 37 35 33 31 32 34 36 38 30 39 37 35 33 31 32  9753124680975312
00406074  34 36 38 30 39 37 35 33 31 32 34 36 38 30 39 37  4680975312468097
00406084  35 33 31 32 34 36 38 30 00                       53124680.
```
综合三个xor得到：
```assembly
00AC29D0  58 5A 54 52 50 52 54 5A 58 5A 52 54 5A 58 5A 44  XZTRPRTZXZRTZXZD
00AC29E0  42 40 42 44 44 44 44 00 00 00 00 00 00 00 00 00  B@BDDDD.........
00AC29F0  50 57 57 5D 52 5E 57 5E 5C 58 5B 5F 5B 5C 5A 48  PWW]R^W^\X[_[\ZH
00AC2A00  45 4A 47 40 47 42 40 4D 48 4D 51 57 52 54 57 51  EJG@GB@MHMQWRTWQ
00AC2A10  5F 59 51 52 5F 5F 55 58 5E 41 42 00 00 00 00 00  _YQR__UX^AB.....
00AC2A20  58 55 56 57 54 54 53 5E 51 5A 52 5B 58 5D 5E 42  XUVWTTS^QZR[X]^B
00AC2A30  45 44 4B 44 4C 41 42 4B 48 48 55 54 5B 54 5C 51  EDKDLABKHHUT[T\Q
00AC2A40  52 5B 58 58 5F 5A 55 5E 00 00 00 00 00 00 00 00  R[XX_ZU^........
```
xor
```assembly
00AC2990  61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70  abcdefghijklmnop
00AC29A0  71 72 73 74 75 76 77 78 79 7A 61 62 63 64 65 66  qrstuvwxyzabcdef
00AC29B0  67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76  ghijklmnopqrstuv
00AC29C0  77 78 79 7A 00 00 00 00 00 00 00 00 00 00 00 00  wxyz............
```
得到的结果存入：
```assembly
00406020  39 38 37 36 35 34 33 32 31 30 39 38 37 36 35 34  9876543210987654
00406030  33 32 31 30 31 32 33 00 31 35 34 39 37 38 30 36  3210123.15497806
00406040  35 32 30 33 36 32 35 38 34 38 34 34 32 34 37 35  5203625848442475
00406050  31 37 30 35 31 30 32 37 38 31 38 38 34 33 38 36  1705102781884386
00406060  31 31 33 00 39 37 35 33 31 32 34 36 38 30 39 37  113.975312468097
00406070  35 33 31 32 34 36 38 30 39 37 35 33 31 32 34 36  5312468097531246
00406080  38 30 39 37 35 33 31 32 34 36 38 30 00           809753124680.
```
接着就调用00402700算法函数：
```C
int __cdecl sub_402700(int a1, int a2)
{
  int result; // eax@1
  //传入的参数a1=[0018FD98]=0x160，a2=堆起始地址
  result = sub_402450((a2 + *a1)); //传入的参数为输入字符串的起始地址
  ++*(a1 + 20);
  *a1 = result;
  return result;
}
```
```C
int __cdecl sub_402450(const char *a1)
{
  //修改了004068E0之后的0x16个字节，其中44个自己本来就有内容
  lpAddress = &loc_4025DC;
  dword_4068E0 = &loc_40263C;
  dword_4068EC = &loc_40269C;
  if ( sub_4027F0(v1) )
  {
    v9 = strlen(a1);
    if ( v9 <= 256 )
    {
      v3 = 0;
      memset(&Dst, 0, 0xFFu);
      v10 = sub_401D50(a1, v9, &v3);
      if ( strlen(&v3) == 90 && v5 == 45 && v6 == 45 && v7 == 45 && v8 == 45 )
      {
        if ( !sub_4027F0(0x2D) )
          ExitProcess(1u);
        dword_99B6EC = 1;
        while ( dword_99B6EC ) ;
      }
    }
  }
  return 0;
}
```
首先调用sub_4027F0(v1)，v1是A9：
```C
bool __thiscall sub_4027F0(void *this)
{
  int v1; // ecx@1
  int v2; // ecx@2

  return sub_401080(this, sub_403DC0) == 0x91424319 //成立
      && sub_401080(v1, sub_403EA0) == 0xCE2A555D //成立
      && sub_401080(v2, sub_402720) == 0xC295E8BB; //成立
}
```
满足这个条件后进入if语句，调用memest和sub_401D50
```C
memset(&Dst, 0, 0xFFu);
v10 = sub_401D50(a1, v9, &Dst);
```
memset在栈上开辟一个0xFF=256大小的空间，然后将其连同a1=输入字符串起始地址，v9=strlen(a1)传入sub_401D50，如果F8单步跳过执行sub_401D50，可以发现根据某个计算规律，将结果存入memset的栈内存空间中，计算过程和栈空间分布见图纸。

计算规律大致意思为：

1. 输入字符串的每4个字符可以生成至多3个字符存入memset的栈内存，首先判断第1个字符等于某个asscii码或在某个asscii码区间，得到一个v8，然后判断第2个字符，得到v10，计算结果的第1个字符就等于：
```C
*(v4+v3) = 4*v8 + (v10 >> 4);
```
2. 然后判断第3个字符不等于61号asscii码的情况下，如果满足等于某个asscii码或在某个asscii码区间，得到v6，计算结果的第2个字符就等于：
```C
*(v4++ + v3) = 16*v10 + (v6 >> 2);
```
3. 然后判断第4个字符不等于61号asscii码的情况下，如果满足等于某个asscii码或在某个asscii码区间，得到v13，计算结果的第3个字符就等于：
```C
*(v4++ + v3) = v13 + (v6 << 6);
```
如果第3或第4个字符等于61号asscii码，则不会产生计算结果的第2或第3个字符。

执行sub_401D50后，将得到的栈内存进行如下判断：
```C
if ( strlen(&Dst) == 90 && *(Dst+20) == 0x2D && *(Dst+21) == 0x2D 
  && *(Dst+61) == 0x2D && *(Dst+62) == 0x2D )
{
  if ( !sub_4027F0(0x2D) )
    ExitProcess(1u);
  dword_99B6EC = 1;
  while ( dword_99B6EC )
    ;
}
```
栈内存计算结果的长度为90字节，其中4个字节必须等于0x2D=45才能进入条件分支。我们先通过修改F8单步跳过执行后的栈内存空间，使之满足上述条件。

条件分支先执行了sub_4027F0(0x2D)恒等于1，然后修改了0099B6EC为1.

还记得TlsCallback_2中开启的3个线程函数吗？0099B6EC为1后即可进入第一个线程函数StartAddress的分支：
```C
void __stdcall __noreturn StartAddress(LPVOID lpThreadParameter)
{
  while ( 1 )
  {
    if ( dword_99B6EC == 1 )
    {
	  //首先修改00401EC0后0x2E=46个字节
      v1 = 1;
      do
      {
        *(&loc_401EC0 + v1 - 1) ^= byte_4064F0[v1 - 1];
        *(&loc_401EC0 + v1) ^= byte_4064F0[v1];
        v1 += 2;
      }
      while ( v1 - 1 < 0x2E );
	  
	  //然后修改[004068E4]=004025DC后6个字节
      v2 = 0;
      v3 = 004068E4 - &v8;
      do
      {
        v4 = *(&v8 + v2);
        v5 = &v8 + v2;
        v6 = *(&v8 + v2++ + v3);
        v5[v3] = v4;
        *v5 = v6;
      }
      while ( v2 < 6 );
      dword_99B6EC = 0;
    }
  }
}
```
如果细心的话， 能够发现，修改的004025DC后6个字节即为while ( dword_99B6EC )语句结束的位置：
```assembly
004025C6   > \C705 .....    mov dword ptr ds:[0x99B6EC],0x1
004025D0   > /A1 ECB69900   mov eax,dword ptr ds:[0x99B6EC]
004025D5   . |83F8 00       cmp eax,0x0
004025D8   . |74 02         je short 看雪CTF2.004025DC
004025DA   .^\EB F4         jmp short 看雪CTF2.004025D0
004025DC   >  68 EA264000   push 看雪CTF2.004026EA   //此后6个字节被修改
004025E1   .  C3            retn                                     
```
将0x99B6EC赋值为1后，在StartAddress函数中下断点：
```assembly
.text:00402879                 cmp     dword_99B6EC, 1
.text:00402880                 jnz     loc_402948
```
修改00401EC0后46字节：
```assembly
00401EC0  55 8B EC 83 E4 F8 83 EC 2C 53 56 57 8B C0 8B DB  U.......,SVW....
00401ED0  8B C9 8B D2 8B C0 8B DB 8B C9 8B D2 8B C0 8B DB  ................
00401EE0  8B C9 DB D2 0F 31 89 54 24 10 89 44 24 14        .....1.T$..D$.
```
根据
```assembly
004068E0  3C 26 40 00 DC 25 40 00 68 00 00 00 9C 26 40 00  <&@..%@.h....&@.
```
修改了004025DC后的6个字符
```assembly
004025DC  8B C0 8B FF 8B DB                                ......
```
```assembly
004025DC   >  68 EA264000   push 004026EA
004025E1   .  C3            retn   
```
修改为：
```assembly
004025DC   > \8BC0                      mov eax,eax
004025DE   ?  8BFF                      mov edi,edi                              
004025E0   ?  8BDB                      mov ebx,ebx
```
将这些修改Patch后的EXE，查看00402450函数，发现while循环之后的内容已经改变：
```C
if ( strlen(&Dst) == 90 && *(Dst+20) == 0x2D && *(Dst+21) == 0x2D && *(Dst+61) == 0x2D && *(Dst+62) == 0x2D )
{
  if ( !sub_4027F0(0x2D) )
    ExitProcess(1u);
  dword_99B6EC = 1;
  while ( dword_99B6EC )
    ;
	
  if ( !sub_401EC0(&v4) )
	  return 0;
  dword_99B6EC = 1;
  while ( dword_99B6EC ) 
	  ;
  if ( !sub_4027F0(v2) )
	  ExitProcess(1u);
  dword_99B6EC = 2;
  while ( dword_99B6EC )
	  ;	
}
```
当dword_99B6EC=2时会触发TlsCallback_2创建的第二个线程函数：
```C
void __stdcall __noreturn sub_402970(LPVOID lpThreadParameter)
{
  while ( 1 )
  {
    if ( dword_99B6EC == 2 )
    {
	  //首先修改0040402090后0x2E=46个字节
      v1 = 1;
      do
      {
        *(&loc_402090 + v1 - 1) ^= byte_406520[v1 - 1];
        *(&loc_402090 + v1) ^= byte_406520[v1];
        v1 += 2;
      }
      while ( v1 - 1 < 46 );
	  //然后修改[004068E0]=0040263C后6个字节
      v2 = 0;
      v3 = dword_4068E0 - &v8;
      do
      {
        v4 = *(&v8 + v2);
        v5 = &v8 + v2;
        v6 = *(&v8 + v2++ + v3);
        v5[v3] = v4;
        *v5 = v6;
      }
      while ( v2 < 6 );
      dword_99B6EC = 0;
    }
  }
}
```
经过dword_99B6EC=1后，在263C处的内容：
```assembly
.text:00402626                   mov     dword_99B6EC, 2
.text:00402630
.text:00402630   loc_402630:                             
.text:00402630                   mov     eax, dword_99B6EC
.text:00402635                   cmp     eax, 0
.text:00402638                   jz      short loc_40263C
.text:0040263A                   jmp     short loc_402630
.text:0040263C   loc_40263C:                             
.text:0040263C                                           
.text:0040263C                   push    offset loc_4026EA
.text:00402641                   retn
```
可以发现第2个线程函数继续修改，退出while循环后，继续能执行，重复在线程函数中下断点，得到完整流程：

00402090修改后：
```assembly
00402090  55 8B EC 83 E4 F8 83 EC 14 53 56 57 8B C0 8B DB  U........SVW....
004020A0  8B C9 8B D2 8B C0 8B DB 8B C9 8B D2 8B C0 8B DB  ................
004020B0  8B C9 DB D2 0F 31 89 54 24 10 89 44 24 14        .....1.T$..D$.
```
0040263C修改后：
```assembly
0040263C  8B C0 8B DB 8B FF                                ......
```
第3个线程函数修改004021D0后46个字节和0040269C后6个字节.

004021D0修改后：
```assembly
004021D0  55 8B EC 83 E4 F8 81 EC F4 02 00 00 A1 00 60 40  U.............`@
004021E0  00 33 C4 89 84 24 F0 02 00 00 53 56 57 8B C0 8B  .3...$....SVW...
004021F0  DB 8B C9 8B D2 8B C0 8B DB 8B C9 8B D2 8B        ..............
```
0040269C修改后：
```assembly
0040269C  8B FF 8B C0 8B DB                                ......
```
全部Patch后，得到00402450的完整函数：
```C
if ( strlen(&Dst) == 90 && *(Dst+20) == 0x2D && *(Dst+21) == 0x2D 
  && *(Dst+61) == 0x2D && *(Dst+62) == 0x2D )
{
    if ( !(unsigned __int8)sub_4027F0(90) )
      ExitProcess(1u);
    dword_99B6EC = 1;
    while ( dword_99B6EC )
      ;
    if ( sub_401EC0(&v5) )
    {
      dword_99B6EC = 1;
      while ( dword_99B6EC )
        ;
      if ( !(unsigned __int8)sub_4027F0(v2) )
        ExitProcess(1u);
      dword_99B6EC = 2;
      while ( dword_99B6EC )
        ;
      if ( sub_402090(&v5) )
      {
        dword_99B6EC = 2;
        while ( dword_99B6EC )
          ;
        if ( !(unsigned __int8)sub_4027F0(v3) )
          ExitProcess(1u);
        dword_99B6EC = 3;
        while ( dword_99B6EC )
          ;
        if ( sub_4021D0(&v5) )
        {
          dword_99B6EC = 3;
          while ( dword_99B6EC )
            ;
          if ( !(unsigned __int8)sub_4027F0(v4) )
            ExitProcess(1u);
          result = 1;
        }
        else
        {
          result = 0;
        }
      }
      else
      {
        result = 0;
      }
    }
    else
    {
      result = 0;
    }
  }
  else
  {
    result = 0;
  }
  return result;
}
```
精简后得到:
```C
sub_401D50(str, strlen(str), &Dst);
v1 = strlen(&Dst) == 90 && *(Dst+20) == 0x2D && *(Dst+21) == 0x2D && 
  *(Dst+61) == 0x2D && *(Dst+62) == 0x2D ;
if (v1 && sub_401EC0(&str) &&   sub_402090(&str) && sub_4021D0(&str))
{
  return 1 ;
}
else{
  return 0 ;
}
```
将上述赋值的地方全部Patch
```assembly
.text:004025C6                 mov     dword_99B6EC, 1
.text:004025FC                 mov     dword_99B6EC, 1
.text:00402626                 mov     dword_99B6EC, 2
.text:0040265C                 mov     dword_99B6EC, 2
.text:00402686                 mov     dword_99B6EC, 3
.text:004026B9                 mov     dword_99B6EC, 3
```
全部再次Patch为：
```assembly
mov     dword_99B6EC, 0
```
使得程序不进入Tls创建的线程中去，再次OD加载执行。

在调用sub_401D50、sub_401EC0、sub_402090、sub_4021D0的地方分别下断点，通过修改返回值的方式，发现只有上述精简后的关系式全部成立return 1后，程序才能弹出you got the right key!的提示。

因此下面就是算法的主要逻辑：
```C
sub_401D50(str, strlen(str), &Dst);
v1 = strlen(&Dst) == 90 && *(Dst+20) == 0x2D && *(Dst+21) == 0x2D 
  && *(Dst+61) == 0x2D && *(Dst+62) == 0x2D ;
if (v1 && sub_401EC0(&str) &&   sub_402090(&str) && sub_4021D0(&str))
{
  return 1 ;
}
else{
  return 0 ;
}
```
先写到这里吧，必须同时满足v1 && sub_401EC0(&str) &&   sub_402090(&str) && sub_4021D0(&str)，每个函数里的算法看着太复杂了......
