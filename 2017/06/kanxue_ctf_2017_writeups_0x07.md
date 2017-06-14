## 07_windows_crackme


Win7x64下直接运行，提示“应用程序无法正常启动0xc0000018，请单击确定关闭程序”

这是什么鬼？既然直接运行不通过，那先看看PE文件信息。


PEiD打开程序，显示未知语言，未知加壳：

yoda's Protector v1.02 (.dll,.ocx) -> Ashkbiz Danehkar (h) *



IDA打开：


.text:00414422 start           proc near               ; DATA XREF: HEADER:00400148o
.text:00414422                 add     esp, [edx+5Dh]
.text:00414425                 int     3               ; Trap to Debugger
.text:00414426                 call    near ptr 0A7CBFBC7h
.text:0041442B                 xor     edi, [ebp-4B0AF802h] ; CODE XREF: sub_413A56+91p
.text:0041442B                                         ; sub_414A06+1Bp
.text:0041442B start           endp ; sp-analysis failed
.text:0041442B


发现第二条指令直接int3，肯定有问题。观察00414426处E8字节开始的第三条指令，又被IDA解析异常了（参考第一题crackme）。

因此想打开OD，查看实际代码，发现OD无法加载目标程序，同样报0xc0000018错误。

难不成int 3直接搞怪？


通过IDA查看了程序的Imports和Exports表，发现导出表除了入口点外多了TlsCallback_0函数，位于0040C120处：

TlsCallback_0 0040C120             
start         00414422 [main entry]

网上搜集TlsCallback相关信息，会惊奇地发现一些TlsCallback反调试的知识，大致总结如下：

Thread Local Storage，TLS，线程本地存储，是Windows为解决一个进程中多个线程同时访问全局变量而提供的一种机制。
在多线程编程中，同一个变量，如果要让多个线程共享访问，那么这个变量可以使用关键字volatile进行声明；如果一个变量不想使多个线程共享访问，那么该怎么办呢？这个办法就是TLS。
多线程同步问题在于对全局变量的访问，TLS在操作系统的支持下，通过把全局变量打包到一个特殊的节，当每次创建线程时把这个节中的数据当做副本，拷贝到进程空闲的地址空间中。以后线程可以像访问局部变量一样访问该异于其他线程的全局变量的副本，而不用加同步控制。

线程本地存储分为动态和静态两种，动态线程本地存储使用TlsAlloc, TlsFree, TlsSetValue和TlsGetValue等API实现，与反调试无关。

静态线程存储，在 Windows的PE/COFF可执行文件格式中支持静态线程局部存储。TLS回调函数要执行经历下面3个步骤：

1、在链接（link）时，链接器要在PE文件中创建TLS目录（详见PE格式）。
2、 在创建线程时，加载器（loader）会从TEB（thread environment block，线程环境块，通过FS寄存器可以获取TEB的位置）中获取一个指向TLS回调函数数组的指针。
3、如果在TLS回调函数数组不是一个空的数组，加载器就会顺序执行这个数组中的各个回调函数。

我们设一个单线程的进程，TLS回调函数是在创建主线程时执行的（设是使用DLL_PROCESS_ATTACH，详见代码中的注释），而程序的start函数（Entry Point）不过是在主线程起始地址，它只是相当于我们创建其他进程时传给CreateThead()的第三个参数。所以只有当主线程创建之后才能轮到它执行的，而所以它当然就在start函数执行之前就已经被执行过了。


基于TLS的反调试，原理实为在实际的入口点代码执行之前执行检测调试器代码，实现方式便是使用TLS回调函数实现。通过TLS反调试实现的效果，形如下图，在OD动态调试器加载程序到入口点之前便已经执行反调试代码并退出程序。


WIN10 X64下通过TLS实现反调试 ，x86与x64的TLS实现不同，导致x64系统无法运行？

Crackme在没有调试器加载的情况下，应该是正常运行，因此利用win7x86虚拟机加载目标程序，发现，程序正常执行了。

任意输入字符串，点击开始验证，无响应。


OD加载目标程序，如果OD中有StrongOD插件，并设置了插件-->StrongOD-->Options: Break on TLS，就会发现程序暂停在了0040C120处：

IDA：

.text:0040C120                 public TlsCallback_0
.text:0040C120                 push    ebp
.text:0040C121                 mov     ebp, esp
......
.text:0040C189                 call    sub_413F5B
.text:0040C18E                 mov     esp, ebp
.text:0040C190                 pop     ebp
.text:0040C191                 retn    0Ch
.text:0040C191 TlsCallback_0   endp


然后F9能够运行，此时出现程序主界面，可以输入字符串，并点击开始验证。

这时候想，那直接找到点击按钮后获取输入字符串的地方，下断点试试。IDA Imports导入表中搜索GetDlgItemTextA：

00453E28  GetDlgItemTextA USER32


.idata:00453E28 ; UINT __stdcall GetDlgItemTextA(HWND hDlg, int nIDDlgItem, LPSTR lpString, int cchMax)
.idata:00453E28                 extrn GetDlgItemTextA:dword ; CODE XREF: sub_4104CD+2Fp


只有sub_004104CD+2F=004104FC一处引用：

.text:004104EE                 lea     eax, [ebp-80h]
.text:004104F1                 push    64h             ; cchMax
.text:004104F3                 push    eax             ; lpString
.text:004104F4                 push    3E8h            ; nIDDlgItem
.text:004104F9                 push    dword ptr [esi+4] ; hDlg
.text:004104FC                 call    ds:GetDlgItemTextA
.text:00410502                 lea     eax, [ebp-80h]
.text:00410505                 push    eax
.text:00410506                 lea     ecx, [ebp-98h]
.text:0041050C                 call    sub_40FD2D

在OD中004104FC位置F2下断点，F8单步跳过执行，发现：
[0012FB48 - 0x80]=0012FAC8, (ASCII "123456")
eax=00000006

说明此处即为获取输入字符串的程序流程，F5反编译004104FC所在的sub_004104CD函数：

int __userpurge sub_4104CD@<eax>(int a1@<ebp>, int a2, int a3, int a4, int a5)
{
  int v5; // ecx@1
  int v6; // esi@1
  int v7; // ecx@1
  int v9; // [sp-1Ch] [bp-1Ch]@1
  int v10; // [sp-18h] [bp-18h]@1
  int v11; // [sp-14h] [bp-14h]@1
  signed int v12; // [sp-10h] [bp-10h]@1
  int v13; // [sp-Ch] [bp-Ch]@1
  signed int v14; // [sp-8h] [bp-8h]@1
  int v15; // [sp-4h] [bp-4h]@1

  sub_413FD7(-112);
  v6 = v5;
  sub_4156A0((_BYTE *)(a1 - 128), 0, 101);
  GetDlgItemTextA(*(HWND *)(v6 + 4), 1000, (LPSTR)(a1 - 128), 100);
  sub_40FD2D(a1 - 152, a1 - 128);  //传入的第2参数是输入的字符串
  *(_DWORD *)(a1 - 4) = 0;
  v14 = 5;
  v13 = a1 - 24;
  *(_DWORD *)(a1 - 24) = 1229210960;
  v12 = 426;
  *(_BYTE *)(a1 - 20) = 89;
  sub_410DD6(sub_411B30, v12, v13, v14);
  v10 = v7;
  v9 = v7;
  *(_DWORD *)(a1 - 156) = &v9;
  sub_40FD07((int)&v9, a1 - 152);
  *(_BYTE *)(a1 - 4) = 1;
  *(_BYTE *)(a1 - 4) = 0;
  sub_411B30(v6 + 64, v9, v10, v11, v12, v13, v14, v15);
  sub_410DD6(sub_411B30, 426, a1 - 24, 5);
  sub_411825(v6 + 64);
  *(_DWORD *)(a1 - 4) = -1;
  sub_410AE3(1, 0);
  return sub_413F81();
}


ebp -ox80处存储的是得到的输入字符串，
004104EE    8D45 80         lea eax,dword ptr ss:[ebp-0x80]
004104F1    6A 64           push 0x64
004104F3    50              push eax
004104F4    68 E8030000     push 0x3E8
004104F9    FF76 04         push dword ptr ds:[esi+0x4]
004104FC    FF15 283E4500   call dword ptr ds:[<&USER32.GetDlgItemTe>; user32.GetDlgItemTextA
00410502    8D45 80         lea eax,dword ptr ss:[ebp-0x80]
00410505    50              push eax
00410506    8D8D 68FFFFFF   lea ecx,dword ptr ss:[ebp-0x98]
0041050C    E8 1CF8FFFF     call 7.0040FD2D

调用0040FD2D：
0040FD2D    55              push ebp
0040FD2E    8BEC            mov ebp,esp
0040FD30    56              push esi
0040FD31    FF75 08         push dword ptr ss:[ebp+0x8]  //输入的字符串
0040FD34    8BF1            mov esi,ecx
0040FD36    8366 10 00      and dword ptr ds:[esi+0x10],0x0
0040FD3A    C746 14 0F00000>mov dword ptr ds:[esi+0x14],0xF
0040FD41    C606 00         mov byte ptr ds:[esi],0x0
0040FD44    E8 A20F0000     call 7.00410CEB
0040FD49    59              pop ecx                                  ; 0012FA90
0040FD4A    50              push eax
0040FD4B    FF75 08         push dword ptr ss:[ebp+0x8]
0040FD4E    8BCE            mov ecx,esi
0040FD50    E8 790E0000     call 7.00410BCE
0040FD55    8BC6            mov eax,esi
0040FD57    5E              pop esi                                  ; 0012FA90
0040FD58    5D              pop ebp                                  ; 0012FA90
0040FD59    C2 0400         retn 0x4

//传入的第2参数是输入的字符串
void *__thiscall sub_40FD2D(int this, int a2)
{
  void *v2; // esi@1
  int v3; // eax@1

  v2 = (void *)this;
  *(_DWORD *)(this + 16) = 0;
  *(_DWORD *)(this + 20) = 15;
  *(_BYTE *)this = 0;
  v3 = sub_410CEB((_BYTE *)a2);
  sub_410BCE(v2, (char *)a2, v3);
  return v2;
}


调用：
00410CEB    55              push ebp
00410CEC    8BEC            mov ebp,esp
00410CEE    8B45 08         mov eax,dword ptr ss:[ebp+0x8]
00410CF1    8038 00         cmp byte ptr ds:[eax],0x0 //判断第1个字符串是否为0
00410CF4    75 04           jnz short 7.00410CFA
00410CF6    33C0            xor eax,eax
00410CF8    5D              pop ebp                                  ; 0012FA90
00410CF9    C3              retn

int __cdecl sub_410CEB(_BYTE *a1)
{
  int result; // eax@2

  if ( *a1 )  //判断第1个字符串是否为0
    result = sub_421780(a1);
  else
    result = 0;
  return result;
}









int __cdecl sub_421780(char *a1)
{
  char *v1; // ecx@1
  char v2; // al@2
  int v3; // eax@4
  int v4; // eax@5

  v1 = a1;
  if ( !((unsigned __int8)a1 & 3) )
    goto LABEL_4;
  do
  {
    v2 = *v1++;
    if ( !v2 )
      return v1 - 1 - a1;
  }
  while ( (unsigned __int8)v1 & 3 );
  while ( 1 )
  {
    do
    {
LABEL_4:
      v3 = (*(_DWORD *)v1 + 2130640639) ^ ~*(_DWORD *)v1;
      v1 += 4;
    }
    while ( !(v3 & 0x81010100) );
    v4 = *((_DWORD *)v1 - 1);
    if ( !(_BYTE)v4 )
      break;
    if ( !BYTE1(v4) )
      return v1 - 3 - a1;
    if ( !(v4 & 0xFF0000) )
      return v1 - 2 - a1;
    if ( !(v4 & 0xFF000000) )
      return v1 - 1 - a1;
  }
  return v1 - 4 - a1;
}


看着这个判断挺复杂，云里雾里的。现在还是看一下TlsCallback。



.text:0040AD44 TlsDirectory    dd offset TlsStart      ; DATA XREF: HEADER:004001E0o
.text:0040AD48 TlsEnd_ptr      dd offset TlsEnd
.text:0040AD4C TlsIndex_ptr    dd offset TlsIndex
.text:0040AD50 TlsCallbacks_ptr dd offset TlsCallbacks


.text:00400440 TlsCallbacks    dd offset TlsCallback_0 ; DATA XREF: .text:TlsCallbacks_ptro
.text:00400444                 dd 0
.text:00400448                 dd 0

TlsCallbacks数组中0040C120，这也就是唯一的一个回调函数，我们先删除一下：


00400440  20 C1 40 00 00 00 00 00  00 00 00 00 00 00 00 00   .@.............

修改为：


00400440  20 C1 40 00 00 00 00 00  00 00 00 00 00 00 00 00   .@.............
删除TLS回调函数后，会发现，程序会直接将00401442作为入口点执行，第二条即为int 3指令，因此可以肯定的是在TlsCallback回调函数中对入口点指令进行了修改。

利用OD动态调试TlsCallback_0函数：



0040C120    55              push ebp
0040C121    8BEC            mov ebp,esp
0040C123    83EC 10         sub esp,0x10
0040C126    A1 84044000     mov eax,dword ptr ds:[0x400484]
0040C12B    33C5            xor eax,ebp
0040C12D    8945 FC         mov dword ptr ss:[ebp-0x4],eax
0040C130    837D 0C 01      cmp dword ptr ss:[ebp+0xC],0x1
0040C134    53              push ebx                                 
0040C135    56              push esi
0040C136    57              push edi
0040C137    75 48           jnz short crackme.0040C181
0040C139    8365 F0 00      and dword ptr ss:[ebp-0x10],0x0
0040C13D    60              pushad
0040C13E    64:A1 18000000  mov eax,dword ptr fs:[0x18]
0040C144    64:A1 18000000  mov eax,dword ptr fs:[0x18]
0040C14A    8B40 30         mov eax,dword ptr ds:[eax+0x30]
0040C14D    8B40 08         mov eax,dword ptr ds:[eax+0x8]
0040C150    8B58 3C         mov ebx,dword ptr ds:[eax+0x3C]
0040C153    03D8            add ebx,eax
0040C155    8B5B 28         mov ebx,dword ptr ds:[ebx+0x28]
0040C158    03D8            add ebx,eax
0040C15A    895D F0         mov dword ptr ss:[ebp-0x10],ebx          
0040C15D    61              popad
0040C15E    8D45 F4         lea eax,dword ptr ss:[ebp-0xC]
0040C161    C745 F4 EB7458C>mov dword ptr ss:[ebp-0xC],0xCC5874EB
0040C168    66:C745 F8 E875 mov word ptr ss:[ebp-0x8],0x75E8
0040C16E    6A 06           push 0x6
0040C170    50              push eax
0040C171    68 C8000000     push 0xC8
0040C176    FF75 F0         push dword ptr ss:[ebp-0x10]             
0040C179    E8 584C0000     call crackme.00410DD6
0040C17E    83C4 10         add esp,0x10
0040C181    8B4D FC         mov ecx,dword ptr ss:[ebp-0x4]
0040C184    5F              pop edi                                 
0040C185    5E              pop esi                                 
0040C186    33CD            xor ecx,ebp
0040C188    5B              pop ebx                                 
0040C189    E8 CD7D0000     call crackme.00413F5B
0040C18E    8BE5            mov esp,ebp
0040C190    5D              pop ebp                                 
0040C191    C2 0C00         retn 0xC







.text:0040C120                 public TlsCallback_0
.text:0040C120 TlsCallback_0   proc near               ; DATA XREF: .text:TlsCallbackso
.text:0040C120
.text:0040C120 var_10          = dword ptr -10h
.text:0040C120 var_C           = dword ptr -0Ch
.text:0040C120 var_8           = word ptr -8
.text:0040C120 var_4           = dword ptr -4
.text:0040C120 arg_4           = dword ptr  0Ch
.text:0040C120
.text:0040C120                 push    ebp
.text:0040C121                 mov     ebp, esp
.text:0040C123                 sub     esp, 10h
.text:0040C126                 mov     eax, ds:___security_cookie
.text:0040C12B                 xor     eax, ebp
.text:0040C12D                 mov     [ebp+var_4], eax
.text:0040C130                 cmp     [ebp+arg_4], 1  //创建进程时
.text:0040C134                 push    ebx
.text:0040C135                 push    esi
.text:0040C136                 push    edi
.text:0040C137                 jnz     short loc_40C181
.text:0040C139                 and     [ebp+var_10], 0
.text:0040C13D                 pusha
.text:0040C13E                 mov     eax, large fs:18h
.text:0040C144                 mov     eax, large fs:18h
.text:0040C14A                 mov     eax, [eax+30h]
.text:0040C14D                 mov     eax, [eax+8]
.text:0040C150                 mov     ebx, [eax+3Ch]
.text:0040C153                 add     ebx, eax
.text:0040C155                 mov     ebx, [ebx+28h]
.text:0040C158                 add     ebx, eax
.text:0040C15A                 mov     [ebp+var_10], ebx //上述操作把入口点00414422存入[ebp+var_10]
.text:0040C15D                 popa
.text:0040C15E                 lea     eax, [ebp+var_C]
.text:0040C161                 mov     [ebp+var_C], 0CC5874EBh
.text:0040C168                 mov     [ebp+var_8], 75E8h
.text:0040C16E                 push    6
.text:0040C170                 push    eax
.text:0040C171                 push    0C8h   //200字节
.text:0040C176                 push    [ebp+var_10] //入口点00414422
.text:0040C179                 call    sub_410DD6
.text:0040C17E                 add     esp, 10h
.text:0040C181
.text:0040C181 loc_40C181:                             ; CODE XREF: TlsCallback_0+17j
.text:0040C181                 mov     ecx, [ebp+var_4]
.text:0040C184                 pop     edi
.text:0040C185                 pop     esi
.text:0040C186                 xor     ecx, ebp
.text:0040C188                 pop     ebx
.text:0040C189                 call    sub_413F5B  //判断___security_cookie防止栈溢出，这应该是编译器添加的
.text:0040C18E                 mov     esp, ebp
.text:0040C190                 pop     ebp
.text:0040C191                 retn    0Ch
.text:0040C191 TlsCallback_0   endp


F5反编译：

int __stdcall TlsCallback_0(int a1, int a2, int a3)
{
  int v3; // et1@2
  int v4; // eax@2
  int v5; // ST2C_4@2
  int result; // eax@2
  int v7; // [sp+10h] [bp-Ch]@2
  __int16 v8; // [sp+14h] [bp-8h]@2

  if ( a2 == 1 )  //创建进程时
  {
    v3 = *MK_FP(__FS__, 24);
    v4 = *(_DWORD *)(*(_DWORD *)(__readfsdword(24) + 48) + 8);
    v5 = v4 + *(_DWORD *)(v4 + *(_DWORD *)(v4 + 60) + 40);
    v7 = -866618133;
    v8 = 30184;
    result = sub_410DD6(v5, 200, &v7, 6);
  }
  return result;
}


其中调用了sub_410DD6函数：
.text:00410DD6 sub_410DD6      proc near               ; CODE XREF: TlsCallback_0+59p
.text:00410DD6                                         ; sub_4104CD+65p ...
.text:00410DD6
.text:00410DD6 arg_0           = dword ptr  8
.text:00410DD6 arg_4           = dword ptr  0Ch
.text:00410DD6 arg_8           = dword ptr  10h
.text:00410DD6 arg_C           = dword ptr  14h
.text:00410DD6
.text:00410DD6                 push    ebp
.text:00410DD7                 mov     ebp, esp
.text:00410DD9                 mov     ecx, [ebp+arg_0]
.text:00410DDC                 push    esi
.text:00410DDD                 xor     esi, esi
.text:00410DDF                 cmp     [ebp+arg_4], esi
.text:00410DE2                 jle     short loc_410DFB
.text:00410DE4                 push    edi
.text:00410DE5                 mov     edi, [ebp+arg_8]
.text:00410DE8
.text:00410DE8 loc_410DE8:                             ; CODE XREF: sub_410DD6+22j
.text:00410DE8                 mov     eax, esi
.text:00410DEA                 cdq
.text:00410DEB                 idiv    [ebp+arg_C]
.text:00410DEE                 mov     al, [edx+edi]
.text:00410DF1                 xor     [ecx], al
.text:00410DF3                 inc     ecx
.text:00410DF4                 inc     esi
.text:00410DF5                 cmp     esi, [ebp+arg_4]
.text:00410DF8                 jl      short loc_410DE8
.text:00410DFA                 pop     edi
.text:00410DFB
.text:00410DFB loc_410DFB:                             ; CODE XREF: sub_410DD6+Cj
.text:00410DFB                 pop     esi
.text:00410DFC                 pop     ebp
.text:00410DFD                 retn
.text:00410DFD sub_410DD6      endp




char __cdecl sub_410DD6(_BYTE *a1, signed int a2, int a3, signed int a4)
{
  _BYTE *v4; // ecx@1
  signed int i; // esi@1
  char result; // al@2

  v4 = a1;
  for ( i = 0; i < a2; ++i )
  {
    result = *(_BYTE *)(i % a4 + a3);
    *v4++ ^= result;
  }
  return result;
}

从入口点00414422开始的0xc8=200字节，与某个值做异或运算，

从00414422到004144E9共200字节

IDA：

原：
00414422  03 62 5D CC E8 9C B7 8A  A7 33 BD FE 07 F5 B4 E8  .b]......3......
00414432  EB 75 EB 27 0E A6 FF 9D  B9 DE 5B CC 6D B5 9F 71  .u.'......[.m..q
00414442  D3 81 E0 B8 C2 47 AE 41  6D A9 17 8B A7 A4 24 77  .....G.Am.....$w
00414452  EB 74 0E 9C 61 40 0B 5E  1D CC 00 4A F9 74 58 4F  .t..a@.^...J.tXO
00414462  2C 79 62 F1 D4 31 17 8A  62 F9 D0 31 17 8A 62 E1  ,yb..1..b..1..b.
00414472  DC 31 17 8A 62 E9 D8 31  17 8A 62 C1 24 31 17 8A  .1..b..1..b.$1..
00414482  62 C9 20 31 17 8A 8D F8  CD 68 15 8A 14 12 D4 41  b. 1.....h.....A
00414492  70 88 14 8B 3E 40 75 01  16 8B A7 AA 64 F0 9B 89  p...>@u.....d...
004144A2  A7 33 8E F9 4E 18 A5 33  17 13 67 D9 30 31 17 8A  .3..N..3..g.01..
004144B2  77 FB DD 50 15 8A 14 FF  1D C8 61 F0 7F 89 A7 33  w..P......a....3
004144C2  65 30 EF FD DD 6C 15 8A  14 B3 DD 10 14 8A 14 75  e0...l.........u
004144D2  58 CD E8 FE AB 88 32 9C  61 F0 7B 89 A7 33 65 30  X.....2.a.{..3e0
004144E2  43 22 08 24 5E 64 EB 74  8B 45 04 83 C4 0C C7 45  C".$^d.t.E.....E
004144F2  A8 15 00 00 40 C7 45 AC  01 00 00 00 89 45 B4 FF  ....@.E......E..

转换为：

OD：

00414422 >E8 16 05 00 00 E9 5C FE FF FF 55 8B EC 81 EC 24  ?..閈?U嬱侅$
00414432  03 00 00 53 56 6A 17 E8 52 AA 03 00 85 C0 74 05  ..SVj鑂?.吚t
00414442  8B 4D 08 CD 29 33 F6 8D 85 DC FC FF FF 68 CC 02  婱?3鰨呠?h?
00414452  00 00 56 50 89 35 E0 2A 45 00 E8 3F 12 00 00 83  ..VP??E.?..?
00414462  C4 0C 89 85 8C FD FF FF 89 8D 88 FD FF FF 89 95  ?墔岧墠堼墪
00414472  84 FD FF FF 89 9D 80 FD FF FF 89 B5 7C FD FF FF  匌墲€?壍|?
00414482  89 BD 78 FD FF FF 66 8C 95 A4 FD FF FF 66 8C 8D  壗x?f寱f實
00414492  98 FD FF FF 66 8C 9D 74 FD FF FF 66 8C 85 70 FD  橗f対t?f寘p?
004144A2  FF FF 66 8C A5 6C FD FF FF 66 8C AD 68 FD FF FF  f尌l?f尛h?
004144B2  9C 8F 85 9C FD FF FF 8B 45 04 89 85 94 FD FF FF  湉厹?婨墔旪
004144C2  8D 45 04 89 85 A0 FD FF FF C7 85 DC FC FF FF 01  岴墔狚菂茳
004144D2  00 01 00 8B 40 FC 6A 50 89 85 90 FD FF FF 8D 45  ..婡黬P墔慅岴
004144E2  A8 56 50 E8 B6 11 00 00 8B 45 04 83 C4 0C C7 45  ╒P瓒..婨兡.荅
004144F2  A8 15 00 00 40 C7 45 AC 01 00 00 00 89 45 B4 FF  ?..@荅?...塃?


00414422 >  E8 16050000     call crackme.0041493D
00414427  ^ E9 5CFEFFFF     jmp crackme.00414288
0041442C    55              push ebp
0041442D    8BEC            mov ebp,esp
0041442F    81EC 24030000   sub esp,0x324
00414435    53              push ebx                                 ; crackme.0040C120
00414436    56              push esi
00414437    6A 17           push 0x17
00414439    E8 52AA0300     call <jmp.&KERNEL32.IsProcessorFeaturePr>
0041443E    85C0            test eax,eax
00414440    74 05           je short crackme.00414447
00414442    8B4D 08         mov ecx,dword ptr ss:[ebp+0x8]           ; crackme.00400000
00414445    CD 29           int 0x29
00414447    33F6            xor esi,esi

这里发现入库点指令已经改变，call 0041493D，TlsCallback调用完sub_410DD6的指令，主体功能就结束了，因此TlsCallback的主体功能为修改程序入口点200字节的内容。


单步跳过运行至0040C191处TlsCallback结束，然后在入口点00414422处下断点：

00414422 >  E8 16050000     call crackme.0041493D
00414427  ^ E9 5CFEFFFF     jmp crackme.00414288


首先调用了0041493d的函数：

汇编太繁琐，直接大体浏览了一下F5反编译的内容：

int sub_41493D()
{
  int result; // eax@3
  DWORD v1; // ecx@4
  LARGE_INTEGER PerformanceCount; // [sp+8h] [bp-14h]@4
  struct _FILETIME SystemTimeAsFileTime; // [sp+10h] [bp-Ch]@1
  DWORD v4; // [sp+18h] [bp-4h]@4

  SystemTimeAsFileTime.dwLowDateTime = 0;
  SystemTimeAsFileTime.dwHighDateTime = 0;
  if ( __security_cookie != -1153374642 && __security_cookie & 0xFFFF0000 )
  {
    result = ~__security_cookie;
    dword_400480 = ~__security_cookie;
  }
  else
  {
    GetSystemTimeAsFileTime(&SystemTimeAsFileTime);
    v4 = SystemTimeAsFileTime.dwLowDateTime ^ SystemTimeAsFileTime.dwHighDateTime;
    v4 ^= GetCurrentThreadId();
    v4 ^= GetCurrentProcessId();
    QueryPerformanceCounter(&PerformanceCount);
    result = (int)&v4;
    v1 = (unsigned int)&v4 ^ v4 ^ PerformanceCount.LowPart ^ PerformanceCount.HighPart;
    if ( v1 == -1153374642 )
    {
      v1 = -1153374641;
    }
    else if ( !(v1 & 0xFFFF0000) )
    {
      result = (v1 | 0x4711) << 16;
      v1 |= result;
    }
    __security_cookie = v1;
    dword_400480 = ~v1;
  }
  return result;
}

这里是对__security_cookie和dword_400480进行某种赋值，查看这两个变量的位置：
.text:00400480 dword_400480       dd 44BF19B1h         ; DATA XREF: sub_413C65+E3r
.text:00400480                                         ; sub_41493D+29w ...
.text:00400484 ___security_cookie dd 0BB40E64Eh        ; DATA XREF: .text:0040AD24o
.text:00400484                                         ; sub_40C0C7+13r ...





这里使用了GetCurrentThreadId、GetCurrentProcessId和QueryPerformanceCounter函数，大体感觉函数的功能是判断__security_cookie是否满足某个条件，


不满足则执行GetCurrentThreadId、GetCurrentProcessId和QueryPerformanceCounter函数，修改__security_cookie与dword_400480的值。

这里是什么作用呢？查找了一下“GetCurrentThreadId GetCurrentProcessId反调试”没有多少有用的东西，再搜索

“QueryPerformanceCounter反调试”查找了一些相关的东西：


使用kernel32的QueryPerformanceCounter也是1种有效的反调试手段。这个API调用ntdll的NtQueryPerformanceCounter，后者又包装了对ZwQueryPerformanceCounter的调用。同样，也找不到简单的方法可以绕过这种技术。

大致意思是根据内核模式定时器 调试与非调试状态下的时间不同，检测是否处于调试中。

上述函数时将QueryPerformanceCounter得到的PerformanceCount写入到dword_400480与__security_cookie，很自然想到，如果这是反调试的话，作者后续还会调用这两个位置，以便对这两个位置进行某种检测，从而确定是否在反调试。
