* [目录](/notes/ctf_kanxue_ctf_2017_writeups.md)

## 0x01_windows_crackme

一道普通的CrackMe，Windows 32位程序，无壳、无VM、无密码学的三无CrackMe。

运行WannaLOL2.exe，随便输入123456，点击注册，弹出`error !`。

用IDA打开程序，View-->Open subviews-->Strings查看程序中的字符串：
```assembly
.data:00408030 0000000F C PEDIY CTF 2017
.data:00408040 00000008 C error !                  
.data:00408048 00000014 C CrackMe 2017 CTF v2      
.data:0040805C 0000001A C Registration successful !
.data:00408078 00000011 C CrackMe 2017 CTF         
```
除了error字符串，还发现`Registration successful !`字符串等重要信息，双击进入00408040位置：
```assembly
.data:00408030 WindowName      db 'PEDIY CTF 2017',0  ; DATA XREF: WinMain(x,x,x,x)+B9
.data:0040803F                 align 10h
.data:00408040 aError          db 'error !',0          ; DATA XREF: .text:loc_4012D6
.data:00408048 aCrackme2017C_0 db 'CrackMe 2017 CTF v2',0 ; DATA XREF: .text:004012D1
.data:0040805C aRegistrationSu db 'Registration successful !',0 ; DATA XREF: .text:004012C8
.data:00408076                 align 4
.data:00408078 aCrackme2017Ctf db 'CrackMe 2017 CTF',0 ; DATA XREF: .text:004012BE
```
每一行的最后，IDA都备注了对这些字符串的交叉引用XREF信息，引用error和successful字符串位于.text代码段的004012D1和004012C8处。双击交叉引用信息进入.text代码段：
```assembly
.text:004011F4 loc_4011F4:                             ; CODE XREF: DialogFunc+42p
.text:004011F4                 push    ebp
.text:004011F5                 mov     ebp, esp
.text:004011F7                 sub     esp, 1Ch
.text:004011FA                 lea     eax, [ebp-1Ch]
.text:004011FD                 push    15h
.text:004011FF                 push    eax
.text:00401200                 push    3E9h
.text:00401205                 push    hDlg
.text:0040120B                 call    ds:GetDlgItemTextA //获取输入的字符串-->[ebp-1ch]存放输入的字符串
.text:00401211                 push    1F4h
.text:00401216                 call    ds:Sleep //Sleep
.text:0040121C                 lea     eax, [ebp-1Ch]
.text:0040121F                 push    eax
.text:00401220                 call    _strlen  //获取字符串长度
.text:00401225                 cmp     eax, 4  //字符串长度是否为4
.text:00401228                 pop     ecx
.text:00401229                 jnz     loc_4012CF
.text:0040122F                 push    30h
.text:00401231                 pop     ecx
.text:00401232                 cmp     [ebp-1Ch], cl //比较第1个字符是否为0x30即0
.text:00401235                 jz      loc_4012CF
.text:0040123B                 cmp     [ebp-1Bh], cl //比较第2个字符是否为0
.text:0040123E                 jz      loc_4012CF
.text:00401244                 cmp     [ebp-1Ah], cl //比较第3个字符是否为0
.text:00401247                 jz      loc_4012CF
.text:0040124D                 cmp     [ebp-19h], cl //比较第4个字符是否为0
.text:00401250                 jz      short loc_4012CF
.text:00401252                 cmp     byte ptr [ebp-1Ch], 31h //第1个字符是否为0x31即1
.text:00401256                 jnz     short loc_4012CF
.text:00401258                 cmp     byte ptr [ebp-1Bh], 35h //第2个字符是否为5
.text:0040125C                 jnz     short loc_4012CF
.text:0040125E                 jz      short near ptr loc_401262+1
.text:00401260                 jnz     short near ptr loc_401262+1
.text:00401262 loc_401262:                             ; CODE XREF: .text:0040125Ej
.text:00401262                                         ; .text:00401260j
.text:00401262                 call    near ptr 48CACDh
.text:00401267                 xor     ax, 7
.text:0040126B                 movsx   eax, byte ptr [ebp-1Ah] //第3个字符减去0x30
.text:0040126F                 sub     eax, ecx
.text:00401271                 mov     [ebp-4], eax
.text:00401274                 movsx   eax, byte ptr [ebp-1Ch] 
.text:00401278                 fild    dword ptr [ebp-4] //压入st浮点数栈
.text:0040127B                 sub     eax, ecx //第1个字符减去0x30即1
.text:0040127D                 mov     [ebp-4], eax
.text:00401280                 movsx   eax, byte ptr [ebp-1Bh]
.text:00401284                 fild    dword ptr [ebp-4] //压入st浮点数栈
.text:00401287                 sub     eax, ecx //第2个字符减去0x30即5
.text:00401289                 mov     [ebp-4], eax
.text:0040128C                 fidiv   dword ptr [ebp-4] //1除以5得浮点数0.2 结果放在st0
.text:0040128F                 movsx   eax, byte ptr [ebp-19h]
.text:00401293                 sub     eax, ecx //第4个字符减去0x30
.text:00401295                 mov     [ebp-4], eax
.text:00401298                 fsubp   st(1), st //假设第3个字符为x 第4个字符为y 则该条指令结果为x-0.2
.text:0040129A                 fimul   dword ptr [ebp-4] // st0 = (x-0.2) * y
.text:0040129D                 fmul    ds:flt_40711C //0040711C处存放的为实数16.00 st0 = (x-0.2) * y * 16
.text:004012A3                 fstp    dword ptr [ebp-4]
.text:004012A6                 jz      short near ptr loc_4012AA+1
.text:004012A8                 jnz     short near ptr loc_4012AA+1
.text:004012AA loc_4012AA:                             ; CODE XREF: .text:004012A6j
.text:004012AA                                         ; .text:004012A8j
.text:004012AA                 call    near ptr 48CB15h
.text:004012AF                 xor     ax, 7
.text:004012B3                 fld     dword ptr [ebp-4]
.text:004012B6                 fcomp   ds:flt_407118 //00407118处存放的是实数384.00 比较(x-0.2) * y * 16 = 384.00
.text:004012BC                 push    0
.text:004012BE                 push    offset aCrackme2017Ctf ; "CrackMe 2017 CTF"
.text:004012C3                 fnstsw  ax
.text:004012C5                 sahf
.text:004012C6                 jnz     short loc_4012D6 //(x-0.2) * y * 16 = 384.00成立则success 否则error
.text:004012C8                 push    offset aRegistrationSu ; "Registration successful !"
.text:004012CD                 jmp     short loc_4012DB
.text:004012CF loc_4012CF:                             ; CODE XREF: .text:00401229j
.text:004012CF                                         ; .text:00401235j ...
.text:004012CF                 push    0
.text:004012D1                 push    offset aCrackme2017C_0 ; "CrackMe 2017 CTF v2"
.text:004012D6
.text:004012D6 loc_4012D6:                             ; CODE XREF: .text:004012C6j
.text:004012D6                 push    offset aError   ; "error !"
.text:004012DB
.text:004012DB loc_4012DB:                             ; CODE XREF: .text:004012CDj
.text:004012DB                 push    hWnd
.text:004012E1                 call    ds:MessageBoxA
.text:004012E7                 leave
.text:004012E8                 retn
```
上述代码就是crackme的主要逻辑，仔细阅读上述代码，可以发现0040120B处调用了GetDlgItemTextA函数：

```assembly
.text:004011FA                 lea     eax, [ebp-1Ch]
.text:004011FD                 push    15h
.text:004011FF                 push    eax
.text:00401200                 push    3E9h
.text:00401205                 push    hDlg
.text:0040120B                 call    ds:GetDlgItemTextA
```
猜测该函数用于获取输入的字符串，利用OllyDbg动态调试该程序，在0040120B处下断点，F8单步执行，查看[ebp-1ch]存储了输入的字符串，EAX返回的是字符串的长度，从而可以判断，上述猜测是正确的。

根据IDA静态分析+Ollydbg动态调试，可以分析出上述代码的大致含义（详细见上述代码注释）：
> 输入的字符串长度为4且第一个字符为数字1，第二个字符为数字5，第三和第四个字符需满足以下公式：
> `(x-0.2) * y * 16 = 384.00`

输入的每个字符占1个字节，即0x0-0xFF之间，直接利用循环爆破：
```C
for(float x=0;x<=0xFF;x++){
  for(float y=0;y<=0xFF;y++){
    float result = (x-0.2) * y * 16;
    if(result == 384.00) 
      printf("key:15%c%c\n",x,y);
  }
}
```
即可得到key为1555或151N，另外还有一组不可见解。

在分析过程中会发现IDA与OD反汇编不一致的地方：

IDA：
```assembly
.text:0040125E                 jz      short near ptr loc_401262+1
.text:00401260                 jnz     short near ptr loc_401262+1
.text:00401262 loc_401262:                             ; CODE XREF: .text:0040125Ej
.text:00401262                                         ; .text:00401260j
.text:00401262                 call    near ptr 48CACDh
.text:00401267                 xor     ax, 7
```
OD：
```assembly
0040125C   . /75 71         jnz short WannaLOL.004012CF
0040125E   . |74 03         je short WannaLOL.00401263
00401260   . |75 01         jnz short WannaLOL.00401263
00401262     |E8            db E8
00401263   . |66:B8 0800    mov ax,0x8
00401267   . |66:35 0700    xor ax,0x7
```
对比可以发现00401262处的E8并没有被调用，OD正确地将00401262和00401263区分为两条指令，IDA却没有正确解析，同样之后004012AA处也是这种情况：
IDA：
```assembly
.text:004012A6                 jz      short near ptr loc_4012AA+1
.text:004012A8                 jnz     short near ptr loc_4012AA+1
.text:004012AA loc_4012AA:                             ; CODE XREF: .text:004012A6j
.text:004012AA                                         ; .text:004012A8j
.text:004012AA                 call    near ptr 48CB15h
.text:004012AF                 xor     ax, 7
```
OD：
```assembly
004012A6   . /74 03         je short WannaLOL.004012AB
004012A8   . |75 01         jnz short WannaLOL.004012AB
004012AA     |E8            db E8
004012AB   . \66:B8 0800    mov ax,0x8
004012AF   .  66:35 0700    xor ax,0x7
```
这两个地方的错误解析，也导致了IDA无法正确实现F5功能，直接在代码片段中F5，会提示Please position the cursor within a function警告。如果在该代码片段中右击-->create function会提示：
```bash
.text:00401263: The function has undefined instruction/data at the specified address.
.text:004012AB: The function has undefined instruction/data at the specified address.
```
由于E8字节的干扰，IDA无法将00401263和004012AB翻译成指令，从而也出现了未定义指令的情况。

解决办法：将00401262和004012AA处的E8修改为NOP指令，得到patch后的exe然后F5得到反编译代码：
```C
int sub_4011F4()
{
  double v0; // st7@8
  double v1; // st6@8
  const CHAR *v3; // [sp-Ch] [bp-28h]@9
  const CHAR *v4; // [sp-8h] [bp-24h]@8
  CHAR String; // [sp+0h] [bp-1Ch]@1 第1个字符
  char v6; // [sp+1h] [bp-1Bh]@3 第2个字符
  char v7; // [sp+2h] [bp-1Ah]@4 第3个字符
  char v8; // [sp+3h] [bp-19h]@5 第4个字符
  int v9; // [sp+18h] [bp-4h]@8

  GetDlgItemTextA(hDlg, 1001, &String, 21);
  Sleep(0x1F4u);
  //判断字符串长度是否为4 & 所有字符都不为0 & 第1个字符为数字1 & 第2个字符为数字5
  if ( strlen(&String) != 4 || String == 48 || v6 == 48 || v7 == 48 || v8 == 48 || String != 49 || v6 != 53 )
  {
    v4 = Caption;
    goto LABEL_11;
  }
  v9 = v7 - 48;
  v0 = (double)v9;
  v9 = String - 48;
  v1 = (double)v9;
  v9 = v8 - 48;
  *(float *)&v9 = (v0 - v1 / (double)5) * (double)v9 * 16.0;
  v4 = aCrackme2017Ctf;
  // (x - 0.2) * y * 16.0 = 384.0
  if ( *(float *)&v9 != 384.0 )
  {
LABEL_11:
    v3 = Text;
    return MessageBoxA(hWnd, v3, v4, 0);
  }
  v3 = aRegistrationSu;
  return MessageBoxA(hWnd, v3, v4, 0);
}
```
得到反编译后的类C代码，可以直接得到计算公式，比汇编清爽不少。另外，也可以在不修改exe的情况下，用鼠标选择004011F4至004012E8的所有代码，按住快捷键P（create function），然后再按F5即可得到反编译代码。但这是一种取巧的方法：
```
JUMPOUT(v8 == 53, (char *)&loc_401262 + 1);
  JUMPOUT(0, (char *)&loc_401262 + 1);
  v48CACD();  //00401262仍旧被翻译为call指令
  v11 = v9 - v0;
```
并没有解决E8指令的干扰问题，在某些会影响到后续指令的程序中，这样做有可能改变程序的原有逻辑，从而得到错误的反编译代码。

另外，在上述指令计算过程中，需要理解浮点指令是如何存储和运算的。
运算：
```
FLD src 装入实数到st(0) st(0) <- src 
FMUL    乘上一个实数    st(0) <- st(0) * st(1)
FMULP st(i),st         st(i) <- st(0) * st(i) 然后执行一次出栈操作
```
存储：
```
.text:0040129A                 fimul   dword ptr [ebp-4] // st0 = (x-0.2) * y
.text:0040129D                 fmul    ds:flt_40711C
```
以0040129D处指令为例，IDA中已经将0040711C识别为float类型，其实在OD中上述指令是这样的：
```
0040129D   .  D80D 1C714000 fmul dword ptr ds:[0x40711C]
```
很显然，0040711C处存储的是dword类型，查看0040711C处存储的内容：
```assembly
0040711C  41800000
00407120  FFFFFFFF
```
在计算机内存中，一般以4字节存储float类型的实数，8字节存储double类型的实数，dword为4个字节，这也是为何IDA将其识别为float类型的原因。flt_40711C的数值实际上为0x41800000，转换为float类型的浮点数为16.00.

总结：此题是入门题，没有任何反调试手段，主要考验分析crackme的基本功，涉及知识点包括：
1. 浮点数的运算与存储
2. IDA反编译功能F5的修正
