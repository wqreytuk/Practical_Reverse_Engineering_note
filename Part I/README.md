Title: Practical Reverse Engineering notes -- Part I
Date: 2022-07-29
Category: 逆向



[https://github.com/wqreytuk/Practical_Reverse_Engineering_note](https://github.com/wqreytuk/Practical_Reverse_Engineering_note)

目录可能会稍微有点乱，不要介意，凑合看吧

### 约定

不知道该怎么翻译的，我一律直接用英文原文，只可意会不可言传，自己悟去吧



[内核调试配置](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-universal-drivers---step-by-step-lab--echo-kernel-mode-#connectto)

windbg启动命令

```bash
windbg32 –k net:port=50000,key=2steg4fzbj2sz.23418vzkd4ko3.1g34ou07z4pev.1sp3yo9yz874p


windbg64 –k net:port=50100,key=2steg4fzbj2sz.23418vzkd4ko3.1g34ou07z4pev.1sp3yo9yz874p
```



## 第三章

我他妈直接从第三章开始读



在读这本书的时候我一共用到了三个镜像



windows 1903 x64

[windows 8.1 RTM x64]( https://archive.org/details/windows_8_professional_rtm)

[windows 8.1 RTM x86](https://archive.org/details/windows-8-pro-rtm-english-isos)



关于windows 1903 x64的下载，我使用的是[rufus](https://rufus.ie/en/)的下载功能，如下图所示



![image-20220727170159014](https://img-blog.csdnimg.cn/13d728eff41444a28366d2b0dc0478fc.png)



![image-20220727170332691](https://img-blog.csdnimg.cn/1ca6fdd8bc694457984327d51360cec6.png)



在书中，作者说，如果把逆向windows驱动的任务分成两部分，那么有90%的任务是理解Windows是怎么工作的，只有10%是阅读汇编代码





这一章的主要内容就是讲解Windows内核，而且是针对逆向的内核讲解

最后以对rootkit的逆向作为这一章知识点的总结

### Windows基础



先讨论Windows内核的核心概念，以及与其关联的基础数据结构和与驱动编程相关的内核对象以及逆向





#### 内存布局

和许多操作系统的做法一样，Windows将虚拟内存分为了两部分：内核和用户空间



在32位操作系统中，用户空间为

```
0~0x7fffffff
```

![image-20220727203729253](https://img-blog.csdnimg.cn/c3ae007fee384ef7916f0f1a0ef04c25.png)

即2GB



内核空间为

```
0x80000000~0xFFFFFFFF
```

![image-20220727204007400](https://img-blog.csdnimg.cn/9cf33db42b1542dd9cb3a4e508ceeb50.png)

也是2GB

因为32位操作系统的寻址范围就是4个GB



在64位操作系统中，概念是一样的，只不过略有不同

用户空间的范围是

```
0~0x000007ff`ffffffff
```

8TB



内核的内存空间是

```
 0xffff0800`00000000~0xffffffff`ffffffff
```

248TB

![image-20220727211451130](https://img-blog.csdnimg.cn/e691cb175ff140318aea945fe60140fe.png)



当一个进程中的线程获得CPU时间片得以运行的时候，操作系统会从一个寄存器中获得属于该进程的page directory base地址，这使得虚拟地址的映射只针对当前进程而不是其他的进程

这也是为什么存在于操作系统中的多个进程都会以为自己拥有整个用户空间的内存而互不影响



存储page directory base的寄存器是CR3



对于32位操作系统，在boot options中设置`/3GB`选项可以使得用户空间增长为3GB，内核空间缩小为1GB



用户和内核空间地址范围存储在两个变量中

- 用户空间

  - `MmHighestUserAddress`

- 内核空间

  - `MmSystemRangeStart`

  

下面是32位操作系统中这两个变量的值



```
kd> ddp nt!MmHighestUserAddress L1
8102c46c  7ffeffff
kd> ddp nt!MmSystemRangeStart L1
8102c470  80000000
```

可以看到完全符合上图中的地址范围



下面是64位的

```
kd> dqp nt!MmHighestUserAddress L1
fffff801`c07cd040  000007ff`fffeffff
kd> dqp nt!MmSystemRangeStart L1
fffff801`c07cd168  ffff0800`00000000
```





注意32和64位的用户和内核空间中间都隔了64KB（0x10000bytes->65556bytes）



这个主要是为了避免意外的越界，这64KB的空间通常被称作no-access region



根据[Canonical Address](https://blog.csdn.net/ma_de_hao_mei_le/article/details/126025473?csdn_share_tail=%7B%22type%22%3A%22blog%22%2C%22rType%22%3A%22article%22%2C%22rId%22%3A%22126025473%22%2C%22source%22%3A%22ma_de_hao_mei_le%22%7D&ctrtid=syGUR)的定义，64位的内核空间的起始地址并不符合要求

`0xffff080000000000`的二进制形式为

```
11111111 11111111 00001000 00000000 00000000 00000000 00000000 00000000
```

bits48-63为1，但是bits47为0



因此这个地址并不是内核空间真正的起始地址，真正的起始地址是`0xffff800000000000`

### 处理器的初始化



系统启动的时候会对每一个处理器进行初始化，处理器初始化的细节对与日常逆向工作来讲并不是很重要，但是了解一些核心结构体还是很重要的



PCR——processor control region

每一个处理器都拥有一个PCR，用于存储CPU的重要信息和状态

在32位操作系统中，PCR中包含了IDT的基地址以及当前的IRQL（Interrupt Request Level）

在PCR中还存在着另外一个结构体PRCB——processor region control block



PCR和PRCB都是没有文档的，只能通过windbg的内核调试来观察他们的定义

```
dt nt!_KPCR
dt nt!_KPRCB
```



当前处理器的PCR总是可以在内核模式下通过特殊的寄存器访问到

Windows内核中有两个例程可以获取到当前的EPROCESS和ETHREAD结构体

- PsGetCUrrentProcess
- PSGetCurrentThread

这两个例程就是通过查询PCR/PRCB来实现的



```assembly
kd> uf nt!PsGetCurrentThread
nt!PsGetCurrentThread:
fffff800`2ff63770 65488b042588010000 mov   rax,qword ptr gs:[188h]
fffff800`2ff63779 c3              ret
```

`gs[0]`是PCR结构体的地址，0x180是PRCB在PCR结构体中的偏移量

![image-20220728105020054](https://img-blog.csdnimg.cn/7766d263cf274f39b78e2b5388046418.png)

![image-20220728105055967](https://img-blog.csdnimg.cn/7a36faf13bd146759c1bb724debbd1ce.png)

0x8是CurrentThread在PRCB中的偏移量

因此使用`gs[188h]`就能获取到ETHREAD结构体

```assembly
kd> uf nt!PsGetCurrentProcess
nt!PsGetCurrentProcess:
fffff800`2fec9770 65488b042588010000 mov   rax,qword ptr gs:[188h]
fffff800`2fec9779 488b80b8000000  mov     rax,qword ptr [rax+0B8h]
fffff800`2fec9780 c3              ret
```



此时rax已经指向了ETHREAD结构体，然后有取得了ETHREAD结构体0xB8偏移量的值，下面是THREAD结构体的定义

```
kd> dt nt!_KTHREAD
   +0x000 Header           : _DISPATCHER_HEADER
   +0x018 SListFaultAddress : Ptr64 Void
   +0x020 QuantumTarget    : Uint8B
   +0x028 InitialStack     : Ptr64 Void
   +0x030 StackLimit       : Ptr64 Void
   +0x038 StackBase        : Ptr64 Void
   +0x040 ThreadLock       : Uint8B
   +0x048 CycleTime        : Uint8B
   +0x050 CurrentRunTime   : Uint4B
   +0x054 ExpectedRunTime  : Uint4B
   +0x058 KernelStack      : Ptr64 Void
   +0x060 StateSaveArea    : Ptr64 _XSAVE_FORMAT
   +0x068 SchedulingGroup  : Ptr64 _KSCHEDULING_GROUP
   +0x070 WaitRegister     : _KWAIT_STATUS_REGISTER
   +0x071 Running          : UChar
   +0x072 Alerted          : [2] UChar
   +0x074 KernelStackResident : Pos 0, 1 Bit
   +0x074 ReadyTransition  : Pos 1, 1 Bit
   +0x074 ProcessReadyQueue : Pos 2, 1 Bit
   +0x074 WaitNext         : Pos 3, 1 Bit
   +0x074 SystemAffinityActive : Pos 4, 1 Bit
   +0x074 Alertable        : Pos 5, 1 Bit
   +0x074 CodePatchInProgress : Pos 6, 1 Bit
   +0x074 UserStackWalkActive : Pos 7, 1 Bit
   +0x074 ApcInterruptRequest : Pos 8, 1 Bit
   +0x074 QuantumEndMigrate : Pos 9, 1 Bit
   +0x074 UmsDirectedSwitchEnable : Pos 10, 1 Bit
   +0x074 TimerActive      : Pos 11, 1 Bit
   +0x074 SystemThread     : Pos 12, 1 Bit
   +0x074 ProcessDetachActive : Pos 13, 1 Bit
   ...
   +0x098 ApcState         : _KAPC_STATE
   +0x098 ApcStateFill     : [43] UChar
   +0x0c3 Priority         : Char
   +0x0c4 UserIdealProcessor : Uint4B
   +0x0c8 WaitStatus       : Int8B
   +0x0d0 WaitBlockList    : Ptr64 _KWAIT_BLOCK
   +0x0d8 WaitListEntry    : _LIST_ENTRY
   ...
```

首先在THREAD结构体中并没有0xB8这个偏移量，只有0x98，很明显该偏移量是一个union，显然应该是ApcState

![image-20220728105800239](https://img-blog.csdnimg.cn/16e6734acf1f4fbe84aeacbeaa109af2.png)

再加上0x20的偏移量，正好就是0xB8，进而获取到EPROCESS



### 系统调用



系统调用的实现细节也是没有文档的

系统调用的相关信息存储在这两个数据结构中

- service table descriptor
- array of function pointers/offsets

service table descriptor没有文档，是别人通过分析`KiSystemCall64`和`KiSystemService`例程从而得到该结构的定义的

```c
typedef struct _KSERVICE_TABLE_DESCRIPTOR
{
 PULONG Base; // array of fucntion addresses or offsets
 PULONG Count;
 ULONG Limit; // size of the array
 PUCHAR Number;
 ...
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;
```

system call number就是Base指向的数组中的索引，Limit就是Base指向的数组的长度



内核中有两个全局数组：

- KeServiceDescriptorTable
- KeServiceDescriptorTableShadow

后者比前者多可一个GUI系统调用表



另外还有两个全局指针分别指向非GUI系统调用的地址以及GUI系统调用的地址：

- KiSserviceTable
- W32pServiceTable



下面是在32位操作系统中那两个全局数组和两个全局指针的关系

![image-20220728111503059](https://img-blog.csdnimg.cn/f4c0fd8e3b204570975e5453f76c5608.png)

![image-20220728112325765](https://img-blog.csdnimg.cn/7c3b153736dd42db89d252b4faacb986.png)

![image-20220728112352350](https://img-blog.csdnimg.cn/52551d2024e44a83acbb7c7fbe7b13ab.png)

**在64位操作系统中，情况稍有不同**



![image-20220728112545589](https://img-blog.csdnimg.cn/88fb15a9ba944b968d140f9c37f6c16d.png)

这里出现了两个`nt!KiServiceTable`，不要感到意外，因为`nt!KeServiceDescriptorTable`本身就是一个表，里面的元素就是一个个的`KSERVICE_TABLE_DESCRIPTOR`，因此出现一次两次或者更多都是正常现象



先来看一下`ntdll!NtCreateFile`函数的实现代码：

```assembly
kd> uf ntdll!NtCreateFile
ntdll!NtCreateFile:
000007fc`2bca30f0 4c8bd1          mov     r10,rcx
000007fc`2bca30f3 b853000000      mov     eax,53h
000007fc`2bca30f8 0f05            syscall
000007fc`2bca30fa c3              ret
```

上面的汇编代码中，eax就是system call number，即0x53

数组的起始地址：

```
kd> x nt!KiServiceTable
fffff803`eb4f7200 nt!KiServiceTable (<no parameter info>)
```

每个系统调用在数组中占用4bytes

那么第0x53号系统调用的值应该为：

```
kd> dd nt!KiServiceTable+(0x53*4) L1
fffff803`eb4f734c  03e93907
```

这个数字`03e93907`是一个被编码过的数字，编码规则如下：

>高28位表示偏移量，低4位表示使用需要使用栈传递的参数个数



```assembly
kd> uf nt!KiServiceTable + (03e93907>>4)
nt!NtCreateFile:
fffff803`eb8e0590 4881ec88000000  sub     rsp,88h
fffff803`eb8e0597 33c0            xor     eax,eax
fffff803`eb8e0599 4889442478      mov     qword ptr [rsp+78h],rax
fffff803`eb8e059e c744247020000000 mov     dword ptr [rsp+70h],20h
fffff803`eb8e05a6 89442468        mov     dword ptr [rsp+68h],eax
fffff803`eb8e05aa 4889442460      mov     qword ptr [rsp+60h],rax
...
fffff803`eb8e05ff 4889442420      mov     qword ptr [rsp+20h],rax
fffff803`eb8e0604 e837f5ffff      call    nt!IopCreateFile (fffff803`eb8dfb40)
fffff803`eb8e0609 4881c488000000  add     rsp,88h
fffff803`eb8e0610 c3              ret
```

需要通过栈进行传递的参数是7个

![image-20220728122219459](https://img-blog.csdnimg.cn/6aa3ac1c1adf43bbb67d6fa97f49934c.png)

**一共需要11个参数，前4个是通过寄存器进行传递的**



系统调用一般通过中断或者处理器特有的指令实现



#### Faults Traps Interrupts



这里介绍一些专业术语以便更好的解释外围设备和软件是如何与处理器进行交互的



当代计算机系统中，处理器一般通过数组总线比如PCI、FireWire或者USB等和外围设备进行连接

外围设备发起请求的时候会引发一个*interrupt*强制中断处理器当前的任务，而让处理器转而去处理该外围设备的请求



**笼统的讲，*interrupt*会和一个数字关联，该数字是一个函数指针数组的索引，当处理器收到请求时，就会根据该*interrupt*关联的索引找到对应的函数来对该请求进行处理**



处理完成（函数返回）后，处理器会返回到之前的任务继续执行



上面这种被称作*hardware interrupt*，由于外围设备的特性，这种中断天生就是异步的（请求可能在任意时刻产生）



处理器在执行指令的时候可能会遇到异常，比如零除、空指针等

异常可以被分为两类

- faults——错误
- traps——陷阱



faults是可以被修复的异常

faults：

> 比如一个指令引用了一个合法的地址，但是该地址中并无数据，此时会引发一个page fault（页错误）异常，并调用page fault handler来修复此异常（通过page in缺失的数据），然后重新执行之前引发异常的指令

traps通常由特殊类型的指令执行引发

traps:

>比如在64位操作系统中，SYSCALL指令会使得处理器执行由MSR寄存器指定的地址处的代码，执行完成之后，SYSCALL指令之后的代码会被立即执行

这两者的区别就是handler执行完成之后，下一条指令的位置，前者是同一条指令，而后者则是下一条指令



##### Interrupts

因特尔架构的处理器定义了一个IDT——interrupt descriptor table

此表长度位256，每一个表项都是一个包含了interrupt handler信息的结构体，IDT的基地址保存在IDTR寄存器中



IDT一部分的表项是预定义的保留项，32-255项可以由用户自行定义



32位操作系统中表项的结构体定义如下，一共是8bytes

```
kd> dt nt!_KIDTENTRY
   +0x000 Offset           : Uint2B
   +0x002 Selector         : Uint2B
   +0x004 Access           : Uint2B
   +0x006 ExtendedOffset   : Uint2B
```

64位：

```
kd> dt nt!_KIDTENTRY64
   +0x000 OffsetLow        : Uint2B
   +0x002 Selector         : Uint2B
   +0x004 IstIndex         : Pos 0, 3 Bits
   +0x004 Reserved0        : Pos 3, 5 Bits
   +0x004 Type             : Pos 8, 5 Bits
   +0x004 Dpl              : Pos 13, 2 Bits
   +0x004 Present          : Pos 15, 1 Bit
   +0x006 OffsetMiddle     : Uint2B
   +0x008 OffsetHigh       : Uint4B
   +0x00c Reserved1        : Uint4B
   +0x000 Alignment        : Uint8B
```

interrupt handler的offset被分为了高中低三部分



下面来看一下如何解析IDT（x86）

```
kd> r @idtr
idtr=80efc400
kd> dt nt!_KIDTENTRY 80efc400
   +0x000 Offset           : 0x5284
   +0x002 Selector         : 8
   +0x004 Access           : 0x8e00
   +0x006 ExtendedOffset   : 0x8117
kd> u 0x81175284
nt!KiTrap00:
81175284 6a00            push    0
81175286 66c74424020000  mov     word ptr [esp+2],0
8117528d 55              push    ebp
8117528e 53              push    ebx
8117528f 56              push    esi
81175290 57              push    edi
81175291 0fa0            push    fs
81175293 bb30000000      mov     ebx,30h
```

很简单，就是把`ExtendedOffset`作为高16位，`Offset`作为低16位拼接起来就可以得到interrupt handler的地址了



![image-20220728130907319](https://img-blog.csdnimg.cn/52d2a695714c4094b7f62efdb00d0317.png)



下面来看一下使用interrupt实现的系统调用

环境位`windows7 x86 sp1`（debuggee）和`windows10 x64 1903`（debugger）

调试环境和遇到的问题：

- [https://blog.csdn.net/ma_de_hao_mei_le/article/details/126049947](https://blog.csdn.net/ma_de_hao_mei_le/article/details/126049947)
- [https://blog.csdn.net/ma_de_hao_mei_le/article/details/126051148](https://blog.csdn.net/ma_de_hao_mei_le/article/details/126051148)
- [鸣谢汪哥](https://citrusice.github.io/)

win7镜像依然通过[rufus](https://rufus.ie/en/)进行下载

```assembly
kd> uf ntdll!NtCreateFile
ntdll!NtCreateFile:
776850f0 b842000000      mov     eax,42h
776850f5 ba0003fe7f      mov     edx,offset SharedUserData!SystemCallStub (7ffe0300)
776850fa ff12            call    dword ptr [edx]
776850fc c22c00          ret     2Ch
```

可以看到，调用了`SharedUserData!SystemCallStub`指向的函数



书上说，在所有架构的处理器中都有一个叫做`KUSER_SHARED_DATA`的结构体会映射到`0x7ffe0000`上

```c
kd> dt ntdll!_KUSER_SHARED_DATA
   +0x000 TickCountLowDeprecated : Uint4B
   +0x004 TickCountMultiplier : Uint4B
   ...
   +0x2f8 TestRetInstruction : Uint8B
   +0x300 SystemCall       : Uint4B
   ...
   +0x3d8 DEPRECATED_SystemDllWowRelocation : Uint4B
   +0x3dc XStatePad        : [1] Uint4B
   +0x3e0 XState           : _XSTATE_CONFIGURATION
```

那么`KUSER_SHARED_DATA`偏移量为0x300的地方就是`SystemCall`，是一个32位的地址

```assembly
kd> u poi(SharedUserData!SystemCallStub)
ntdll!KiFastSystemCall:
77686bb0 8bd4            mov     edx,esp
77686bb2 0f34            sysenter
ntdll!KiFastSystemCallRet:
77686bb4 c3              ret
77686bb5 8da42400000000  lea     esp,[esp]
77686bbc 8d642400        lea     esp,[esp]
ntdll!KiIntSystemCall:
77686bc0 8d542408        lea     edx,[esp+8]
77686bc4 cd2e            int     2Eh
77686bc6 c3              ret
```

最后进入了0x2E号中断

```assembly
kd> !idt 0x2E

Dumping IDT: 80b93000

a6eeb3870000002e:	82a4546a nt!KiSystemService

kd> u 82a4546a 
nt!KiSystemService:
82a4546a 6a00            push    0
82a4546c 55              push    ebp
82a4546d 53              push    ebx
82a4546e 56              push    esi
82a4546f 57              push    edi
82a45470 0fa0            push    fs
82a45472 bb30000000      mov     ebx,30h
82a45477 668ee3          mov     fs,bx
```

可以看到`KiSystemSserice`是syscall handler dispatcher







##### Traps

前面已经提到过64位操作系统中`ntdll!NtCreateFile`使用的`0x53`号系统调用



```
kd> uf ntdll!NtCreateFile
ntdll!NtCreateFile:
000007fc`2bca30f0 4c8bd1          mov     r10,rcx
000007fc`2bca30f3 b853000000      mov     eax,53h
000007fc`2bca30f8 0f05            syscall
000007fc`2bca30fa c3              ret
```

`syscall`指令可以将执行流程切换至内核模式，那这个切换如何实现的呢？



根据SYSCALL文档，当syscall指令被执行的时候，RIP寄存器会从`IA32_LSTAR  MSR (0xc0000082)`中取值

```
kd> rdmsr 0xC0000082
msr[c0000082] = fffff803`eb4fadc0
kd> u fffff803`eb4fadc0
nt!KiSystemCall64:
fffff803`eb4fadc0 0f01f8          swapgs
fffff803`eb4fadc3 654889242510000000 mov   qword ptr gs:[10h],rsp
fffff803`eb4fadcc 65488b2425a8010000 mov   rsp,qword ptr gs:[1A8h]
fffff803`eb4fadd5 6a2b            push    2Bh
fffff803`eb4fadd7 65ff342510000000 push    qword ptr gs:[10h]
fffff803`eb4faddf 4153            push    r11
fffff803`eb4fade1 6a33            push    33h
fffff803`eb4fade3 51              push    rcx
```

世界的尽头就是`nt!KiSystemCall64`

Windows在系统启动阶段对处理器进行初始化的时候将`IA32 LSTAR MSR`设置为`nt!KiSystemCall64`函数的地址

具体实现代码在`nt!KiInitializeBootStructures`

```assembly
uf nt!KiInitializeBootStructures
...
fffff803`eb7e4990 488d052964d1ff  lea     rax,[nt!KiSystemCall64 (fffff803`eb4fadc0)]
fffff803`eb7e4997 b9820000c0      mov     ecx,0C0000082h
fffff803`eb7e499c 488bd0          mov     rdx,rax
fffff803`eb7e499f 48c1ea20        shr     rdx,20h
fffff803`eb7e49a3 0f30            wrmsr
...
```

`wrmsr`指令会将`EDX:EAX`写入由ECX寄存器指定的MSR寄存器中：[https://www.felixcloutier.com/x86/wrmsr](https://www.felixcloutier.com/x86/wrmsr)

```
MSR[ECX] ← EDX:EAX
```

在上面的汇编代码中，首先将`nt!KiSystemCall64 `函数的地址放到了rax中，然后给rcx赋值

**rax值复制到rdx，rdx右移32bit，这样一来edx就是`nt!KiSystemCall64`函数地址的高32位，eax就是该地址的低32位，执行完wrmsr指令后即可将`nt!KiSystemCall64`函数的地址写入`IA32_LSTAR  MSR (0xc0000082)`**



在执行syscall指令之前，RCX中已经保存了返回地址，因此当syscall做完自己的工作后，就会将RCX中的值放到RIP寄存器中，这样就可以返回到syscall之后的指令处继续执行了



[使用traps实现的syscall代码注释](https://blog.csdn.net/ma_de_hao_mei_le/article/details/126048975#mark_71)



下面来看x86的，32位的Windows操作系统使用SYSENTER指令实现系统调用



```assembly
kd> u ntdll!NtQueryInformationProcess
ntdll!NtQueryInformationProcess:
770c4fc0 b8b0000000      mov     eax,0B0h
770c4fc5 e803000000      call    ntdll!NtQueryInformationProcess+0xd (770c4fcd)
770c4fca c21400          ret     14h
770c4fcd 8bd4            mov     edx,esp
770c4fcf 0f34            sysenter
770c4fd1 c3              ret
770c4fd2 8bff            mov     edi,edi
```

`ntdll!NtQueryInformationProcess+0xd`的代码是

```assembly
770c4fca c21400          ret     14h
770c4fcd 8bd4            mov     edx,esp
```



`ret 14h`说明传入了20字节的参数，一个按照4字节，就是5个参数，用户空间的rsp被保存到了edx寄存器中



Intel文档中规定SYSENTER指令会将EIP设置为MSR（0x176h）的值



```assembly
kd> rdmsr 176
msr[176] = 00000000`811741d0
kd> u 811741d0
nt!KiFastCallEntry:
811741d0 b923000000      mov     ecx,23h
811741d5 6a30            push    30h
811741d7 0fa1            pop     fs
811741d9 8ed9            mov     ds,cx
811741db 8ec1            mov     es,cx
811741dd 648b0d40000000  mov     ecx,dword ptr fs:[40h]
811741e4 8b6104          mov     esp,dword ptr [ecx+4]
811741e7 6a23            push    23h
```

和SYSCALL指令不同的是，SYSENTER并不会在寄存器中设置返回地址，那么在系统调用执行完成后，是如何返回到之前的执行流程的呢



关于函数调用过程中，栈空间的变化，[参考这篇文章](https://blog.csdn.net/ma_de_hao_mei_le/article/details/124604874?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165933404716781790774988%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=165933404716781790774988&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_ecpm_v1~rank_v31_ecpm-1-124604874-null-null.nonecase&utm_term=%E6%A0%88&spm=1018.2226.3001.4450)

那么在上面`ntdll!NtQueryInformationProcess`代码中，函数`ntdll!NtQueryInformationProcess+0xd`的第一条指令就是将esp保存到edx中，而此时的esp指向的正是该函数的返回地址，也就是`RET 14h`指令的地址（**不要问我为什么不是ebp，因为此处根本就没有push ebp的操作，和参考文章略有不同**）



```assembly
kd> bp ntdll!NtQueryInformationProcess
kd> g
kd> u
ntdll!NtQueryInformationProcess:
770c4fc0 b8b0000000      mov     eax,0B0h
770c4fc5 e803000000      call    ntdll!NtQueryInformationProcess+0xd (770c4fcd)
770c4fca c21400          ret     14h
770c4fcd 8bd4            mov     edx,esp
770c4fcf 0f34            sysenter
770c4fd1 c3              ret
770c4fd2 8bff            mov     edi,edi
kd> dd /c 1 esp L4
03c8eab0  747d10e1
03c8eab4  ffffffff
03c8eab8  0000001a
03c8eabc  03c8eacc
03c8eaec  0002017c
kd> t
eax=000000b0 ebx=063c41e0 ecx=00000030 edx=00000320 esi=06279490 edi=06279480
eip=770c4fc5 esp=03c8eab0 ebp=03c8ead0 iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000286
ntdll!NtQueryInformationProcess+0x5:
001b:770c4fc5 e803000000      call    ntdll!NtQueryInformationProcess+0xd (770c4fcd)
kd> t
eax=000000b0 ebx=063c41e0 ecx=00000030 edx=00000320 esi=06279490 edi=06279480
eip=770c4fcd esp=03c8eaac ebp=03c8ead0 iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000286
ntdll!NtQueryInformationProcess+0xd:
001b:770c4fcd 8bd4            mov     edx,esp
kd> dd /c 1 esp L4
03c8eaac  770c4fca
03c8eab0  747d10e1
03c8eab4  ffffffff
03c8eab8  0000001a
```

系统调用完成后，syscall dispatcher会执行SYSEXIT指令，根据定义，SYSEXIT指令会将EIP设置为EDX的值，将ESP设置为ECX的值



实际情况是EDX保存的是`ntdll!KiFastSystemCallRet`函数的地址，ECX保存的是调用`ntdll!NtQueryInformationProcess+0xd (770c4fcd)`函数之后的esp的值



```assembly
kd> bp KiSystemCallExit2+18
kd> bl
     0 e Disable Clear  81174458     0001 (0001) nt!KiSystemCallExit2+0x18

kd> g
Breakpoint 0 hit
eax=00000000 ebx=063c41e0 ecx=03c8eaac edx=770c6954 esi=06279490 edi=06279480
eip=81174458 esp=8ba6dfcc ebp=03c8ead0 iopl=0         nv up ei ng nz na pe nc
cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00000286
nt!KiSystemCallExit2+0x18:
81174458 0f35            sysexit
kd> dd /c 1 ecx L1
03c8eaac  770c4fca
kd> u edx
ntdll!KiFastSystemCallRet:
770c6954 c3              ret
770c6955 8da42400000000  lea     esp,[esp]
770c695c 8d642400        lea     esp,[esp]
ntdll!KiIntSystemCall:
770c6960 8d542408        lea     edx,[esp+8]
770c6964 cd2e            int     2Eh
770c6966 c3              ret
770c6967 90              nop
770c6968 90              nop
```



将EIP设置为EDX的值将会立即执行`ntdll!KiFastSystemCallRet`函数的`ret`指令，从栈中取出返回地址，即ecx指向的地址`770c4fca`，也就是`ntdll!NtQueryInformationProcess`函数中的`ret 14h`这条指令的地址



### 中断请求等级

IRQL——Interrupt Request Level



简单来讲，IRQL就是一个数字，定义在KIRQL结构体中，是一个UCHAR类型，也就是说长度只有1字节，这是一个分配给处理器的数字



IRQL的值越大，优先级就越高



处理器的本地中断控制器中有两个寄存器，一个是可编程的TPR，一个是只读的PPR，可以通过TPR来控制IRQL的值，PPR用于保存当前IRQL的值



在Windows中，可以通过KeRaiseIrql和KeLowerIrql这两个内核函数来控制IRQL，在X64中，可以通过CR8寄存器快速访问TPR





```assembly
kd> u nt!KzRaiseIrql
nt!KzRaiseIrql:
fffff800`6ccd7260 440f20c0        mov     rax,cr8
fffff800`6ccd7264 0fb6c9          movzx   ecx,cl
fffff800`6ccd7267 440f22c1        mov     cr8,rcx
fffff800`6ccd726b c3              ret
```





```assembly
kd> u nt!KzLowerIrql
nt!KzLowerIrql:
fffff800`6ccd72c0 0fb6c1          movzx   eax,cl
fffff800`6ccd72c3 440f22c0        mov     cr8,rax
fffff800`6ccd72c7 c3              ret
```





### Pool Memory



在内存分配方面，内核模式和用户模式很相似，都是在运行时进行



内核模式下的内存叫做pool memory，相当于用户模式下的heap memory



pool memory有两种类型：

- paged pool
- non-paged pool



[关于内存分页机制](https://blog.csdn.net/ma_de_hao_mei_le/article/details/125445860)



这两种类型的pool memory的区别在于，前者可以在任意时刻被交换到硬盘中，而后者永远都不会被交换到硬盘中



对于paged pool，如果内核模式下的代码访问的内存被交换出去了，那么page-fault会被触发从而将对应的内存交换回来，而后者不会触发page-fault



对于运行在高IRQL（>APC_LEVEL）的内核代码，只能使用non-paged pool，因为如果使用paged pool，可能会触发page-fault，从而导致page-fault handler发起缺页中断请求，但是当前运行线程的IRQL太高，比自己低的都会被阻塞，那么这个处理器就完全死掉了，**进入了死锁，缺页中断在等待内核代码降低自己IRQL从而将内存交换回来，而内核代码在等待缺页中断将内存交换回来**，这将会直接导致内核崩溃

[https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-hardware-priorities](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-hardware-priorities?redirectedfrom=MSDN)

>Any routine that is running at greater than IRQL APC_LEVEL can neither allocate memory from paged pool nor access memory in paged pool safely. If a routine running at IRQL greater than APC_LEVEL causes a page fault, it is a fatal error.



pool memory的分配和释放分别使用`ExAllocatePool *`和`ExFreePool *`函数



### Memory Descriptor Lists

MDL



关于MDL的介绍，我放到了[这里](https://blog.csdn.net/ma_de_hao_mei_le/article/details/126121350?csdn_share_tail=%7B%22type%22%3A%22blog%22%2C%22rType%22%3A%22article%22%2C%22rId%22%3A%22126121350%22%2C%22source%22%3A%22ma_de_hao_mei_le%22%7D&ctrtid=isKDm)



多个MDL可以组成链表，MDL中有一个Next成员用于指向下一个MDL



一段buffer的MDL创建之后，对应的物理内存页就可以被锁定在内存中（意味着这段内存暂时不能被复用），然后可以讲这段物理内存映射到虚拟内存中



MDL的一个应用场景就是写入不可写的内存，可以先初始化一个MDL，上锁，然后把这段不可写的虚拟内存对应的物理内存重新映射到可写的虚拟内存中



### 进程和线程



在Windows操作系统中，线程通过两个内核结构体定义：

- ETHREAD
- KTHREAD



前者保存一些基本信息，比如线程ID、关联进程等等信息

后者保存调度信息，比如线程栈信息，运行在哪颗处理器上

ETHREAD结构体中包含一个类型为KTHREAD的成员

windows调度器是针对线程进行调度的，而不是进程



一个进程至少包含一个线程（主线程），进程由内核中的两个结构体定义：

- EPROCESS
- KPROCESS

前者保存进程的基本信息，比如进程ID，security token，线程列表等信息

后者保存调度信息，page directory table，ideal processor等信息

EPROCESS结构体中包含一个类型为KPROCESS的成员





可以通过windbg的`dt`命令查看这几个结构体的定义



这里以x64举例

```
kd> dt nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x2c8 ProcessLock      : _EX_PUSH_LOCK
   +0x2d0 CreateTime       : _LARGE_INTEGER
   +0x2d8 RundownProtect   : _EX_RUNDOWN_REF
   +0x2e0 UniqueProcessId  : Ptr64 Void
   +0x2e8 ActiveProcessLinks : _LIST_ENTRY
   ...
kd> dt nt!_KPROCESS
   +0x000 Header           : _DISPATCHER_HEADER
   +0x018 ProfileListHead  : _LIST_ENTRY
   +0x028 DirectoryTableBase : Uint8B
   +0x030 ThreadListHead   : _LIST_ENTRY
   +0x040 ProcessLock      : Uint4B
   +0x044 Spare0           : Uint4B
   +0x048 Affinity         : _KAFFINITY_EX
   ...
kd> dt nt!_ETHREAD
   +0x000 Tcb              : _KTHREAD
   +0x348 CreateTime       : _LARGE_INTEGER
   +0x350 ExitTime         : _LARGE_INTEGER
   +0x350 KeyedWaitChain   : _LIST_ENTRY
   +0x360 ChargeOnlySession : Ptr64 Void
   +0x368 PostBlockList    : _LIST_ENTRY
   ...
kd> dt nt!_KTHREAD
   +0x000 Header           : _DISPATCHER_HEADER
   +0x018 SListFaultAddress : Ptr64 Void
   +0x020 QuantumTarget    : Uint8B
   +0x028 InitialStack     : Ptr64 Void
   +0x030 StackLimit       : Ptr64 Void
   +0x038 StackBase        : Ptr64 Void
   ...
```



rootkit通过删除_EPROCESS结构体中的ActiveProcessLinks成员来隐藏特定的进程

不过该成员在结构体中的偏移量可能会随着windows版本的不同而发生变化





在用户模式中，也由于上述结构体对应的概念存在，PEB和TED分别为进程环境块和线程环境块，用于描述进程和线程的基本信息

- nt!_PEB
- nt!_TEB



用户模式的代码可以通过FS（x86）和GS（x64）段寄存器访问TEB

### execution context



从内核的角度来看，execution context可以被分为三类

- Thread Context
- System Context
- Arbitrary Context



代码运行时所处的context决定了你当前位于哪块地址空间以及你所拥有的security privilege



### 内核同步原语

事件、自旋锁、互斥量、资源锁、定时器这些是最常用的同步原语

事件可以有两种状态

- signaled
- non-signaled

事件在内核中通过KEVENT结构体定义，通过KeInitializeEvent函数来初始化

线程可以通过KeWaitForSingleObject或KeWaitForMultipleObjects来等待事件



事件通常被驱动用来通知其他的线程某种特定的条件已被满足



定时器在内核中由KTIMER结构体定义，通过KeInitializeTimer(Ex)初始化

可以在初始化定时器的时候指定一个DPC例程，当定时器过期的时候执行该例程

互斥量、自旋锁不再介绍，学过操作系统原理的都懂



## Lists

链表是创建内核和驱动中的动态数据块的重要基础

许多内核结构体都是基于链表创建的

在WDK头文件中，可能会存在几个操作链表的函数：

- InsertHeadList
- InsertTailList
- RemoveHeadList
- RemoveEntryList
- ...

但是这些函数基本上都是使用`inline`关键字修饰的，在编译阶段会被优化到caller中变成一段代码，而不是函数，因此你不会在汇编代码中看到类似`call InsertHeadList`这样的指令



### 实现细节

WDK中定义的函数支持以下几种类型的链表

- 单链表——每个entry中只有一个Next指针
- Sequenced单链表——与上面单链表的唯一区别就是它支持原子操作，在更改这种类型的链表之前不需要申请加锁
- 循环双链表——每个entry中拥有两个指针，指向前面entry的Blink以及指向后面entry的Flink



本章只介绍最后一种类型的链表，因为它是用的最多的

双链表entry（节点）的定义

```c
typedef struct _LIST_ENTRY {
	struct _LIST_ENTRY *Flink；  // forward link，指向自己后面的节点
	struct _LIST_ENTRY *Blink;	 // backward link，指向自己前面的节点
} LIST_ENTRY, *PLIST_ENTRY;
```

一般来讲，LIST_ENTRY中会存储数据，但是实际上，LIST_ENTRY只存储了两个LIST_ENTRY指针，LIST_ENTRY会被嵌入到真正储存数据的其他结构体中



使用函数InitializaListHead函数初始化链表，该函数会使设置Flink和Blink这两个指针指向链表头结点

```c
VOID InitializeListHead(PLIST_ENTRY ListHead) {
 	ListHead->Flink = ListHead->Blink = ListHead;
 	return;
}
```

![image-20220803150917176](https://img-blog.csdnimg.cn/34b024dcd1244e85bb87ae9ebc4e9a93.png)

该函数的汇编代码

![image-20220803151504802](https://img-blog.csdnimg.cn/1da046234725458e8fffa5af45a9ef20.png)

4和8是Blink在LIST_ENTRY中的偏移量，eax和r11是ListHead

在初始化之后，就可以对链表进行插入了，可以插入到头部或者尾部

看一下KDPC结构体的定义

```assembly
kd> dt nt!_KDPC
   +0x000 Type             : UChar
   +0x001 Importance       : UChar
   +0x002 Number           : Uint2B
   +0x008 DpcListEntry     : _LIST_ENTRY     ; 正如上面所说，LIST_ENTRY被嵌入到其他结构体中
   +0x018 DeferredRoutine  : Ptr64     void 
   +0x020 DeferredContext  : Ptr64 Void
   +0x028 SystemArgument1  : Ptr64 Void
   +0x030 SystemArgument2  : Ptr64 Void
   +0x038 DpcData          : Ptr64 Void
```

插入之后链表就变成了下面这个样子

![image-20220803151945135](https://img-blog.csdnimg.cn/7ccf145e88dc4cbebc6ed13960841dc7.png)

由原来的Flink和Blink都指向自己变成了都指向KDPC结构体中的LIST_ENTRY结构体（DPCListEntry）

然后DpcListEntry的Flink和Blink都指向头结点（因为现在只有两个节点，所以每个节点的头尾指针指向的都是同一个节点）



使用InsertHeadList从头部插入一个KDPC节点，此时链表将会变成下面这个样子

![image-20220803152316934](https://img-blog.csdnimg.cn/6d69337a69b34f988a31cd67f8be663f.png)



注意在上图中，中间的那个是新插入的节点，可以集合下面的反编译代码理解



下面是反编译出来的InsertHeadList函数
```c
VOID InsertHeadList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry) {
     PLIST_ENTRY Flink;
     Flink = ListHead->Flink;
     Entry->Flink = Flink;
     Entry->Blink = ListHead;
     Flink->Blink = Entry;
     ListHead->Flink = Entry;
     return;
}
```

新插入节点的Flink将会指向之前的节点，而之前的节点就是`Listhead->Flink`，因此有`Entry->Flink = ListHead->Flink`

新节点的Blink将会指向头结点，即`Entry->Blink =  ListHead`

头结点的Flink将会指向新的节点，`ListHead->Flink = Entry`

之前的节点，也就是`ListHead->Flink`的Blink将会指向新的节点，因此有`ListHead->Flink(Flink)->Blink = Entry`

头结点的Blink和之前节点的Flink无需变动



汇编代码

![image-20220803154324092](https://img-blog.csdnimg.cn/4fba534426b44ce3803348d4e40c6a27.png)

上面的x86代码中，ebx是`ListHead`，ecx是`Entry`，由于Flink是ListEntry第一个成员，所以和`ListHead->Flink`就是`[ebx]`

x64代码中，rdi是`ListHead`，rax是`Entry`





使用InsertTailList可以从链表尾部插入一个节点，链表将会变成下面这个样子

![image-20220803155408127](https://img-blog.csdnimg.cn/09de1211182b44f0ab423793f55c6423.png)

结合下面的反汇编代码理解

```c
VOID InsertTailList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry) {
    PLIST_ENTRY Blink;
    Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
    return;
}
```

Header的Blink和OldEntry的Flink发生了变化，都变成指向NewEntry

`ListHead->Blink = Entry`

`ListHead->Flink/Blink(Blink)->Flink = Entry`

NewEntry的Flink和Blink分别指向Header和OldEntry

`Entry->Flink= ListHead`

`Entry->Blink = ListHead->Flink/Blink(Blink)`



汇编代码

![RDI](https://img-blog.csdnimg.cn/2ca1689c252a48e4ab938033ef688662.png)

x86：ebx是ListHead，eax是Entry

x64：rdi是ListHead，rax是Entry



移除节点的函数有三个

- RemoveHeadList
- RemoveTailList
- RemoveEntryList



这几个函数在执行之前都会先执行一下`IsListEmpty`这个函数来**判断当前链表的头结点的Flink是不是指向他自己**，如果是，说明该链表只有一个头结点，也就相当于这个链表是空的



*isListEmpty:*

```c
BOOLEAN IsListEmpty(PLIST_ENTRY ListHead) {
	return (BOOLEAN)(ListHead->Flink == ListHead);
}
```



汇编代码

![image-20220803212455257](https://img-blog.csdnimg.cn/eb84a0c2d4944dd09d2f315204cdac9b.png)

代码很好理解，esi和rbx是ListHead，`[esi]`和`[rbx]`是`ListHead->Flink`



*RemoveHeadList*

```c
PLIST_ENTRY RemoveHeadList(PLIST_ENTRY ListHead) {
    PLIST_ENTRY Flink;
    PLIST_ENTRY Entry;
    Entry = ListHead->Flink;
    Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}
```

把头结点的Flink所指向的节点删除掉了，头结点的Flink转而指向`ListHead->Flink->Flink`，即要删除的节点的Flink所指向的节点

而`ListHead->Flink->Flink`的Blink转而指向ListHead

汇编代码

![image-20220803212835769](https://img-blog.csdnimg.cn/82f05138043a47248eb8053e7c24b057.png)

esi和rbx是ListHead，eax和rax是要删除的节点，ecx和rcx是要删除的节点的Flink指向的节点





*RemoveTailList*

```c
PLIST_ENTRY RemoveTailList(PLIST_ENTRY ListHead) { 
	PLIST_ENTRY Blink;
	PLIST_ENTRY Entry;
	Entry = ListHead->Blink;
	Blink = Entry->Blink;
	ListHead->Blink = Blink;
	Blink->Flink = ListHead;
	return Entry;
}
```

不再赘述，和RemoveHeadList差不多



![image-20220803213730785](https://img-blog.csdnimg.cn/5e1274bbb2dc4506aa7f68e48c1cc89d.png)

![image-20220803213737231](https://img-blog.csdnimg.cn/468db7647ffd4de08ea1fdc2e1825287.png)

edi和rdi是ListHead，ebx和rsi是Entry，eax和rax是要删除的节点Blink指向的节点



上面这些操作都是单纯的针对链表本身进行的操作，而我们最感兴趣的是存储数据的节点，ListEntry是嵌入在存储数据的结构体中的，我们需要通过ListEntry来去访问真正感兴趣的数据



通过下面这个宏可以达到目的

```c
#define CONTAINING_RECORD(address, type, field) ((type *)((PCHAR)(address) - (ULONG_PTR)(&((type*)0)->field)))
```

**使用ListEntry的地址减去ListEntry成员在当前结构体中的偏移量，即可获取到当前结构体的地址**

[https://social.msdn.microsoft.com/Forums/officeocs/en-US/c5068503-2daf-4e60-803f-70a1ffd3ba72/what-is-macro-containingrecord-doing?forum=wdk](https://social.msdn.microsoft.com/Forums/officeocs/en-US/c5068503-2daf-4e60-803f-70a1ffd3ba72/what-is-macro-containingrecord-doing?forum=wdk)

上面宏定义中的一些细节：

>ULONG_PTR用于将指针转换成长整型，PCHAR用于将地址单位转换成字节，而不是该地址的类型的size

可以通过下面这段代码来理解

```c
#include <stdio.h>
#include <windows.h>

typedef struct TEST {
	int a;
	int b;
} test, *ptest;

int main(void)
{
	test test_test;
	test_test.b = 520;
	int* addr_b = &test_test.b;
	printf("base address of test_test: \t%p\n", &test_test);
	printf("address of addr_b: \t\t%p\n", addr_b);
	ULONG ret1 = ULONG_PTR(&((ptest)0)->b);
	printf("field \"b\" offset in TEST: \t%u\n", ret1);
	printf("address with no PCHAR cast: \t%p\n", addr_b - ret1);
	printf("address with PCHAR cast: \t%p\n", (PCHAR)addr_b -ret1);
	return 0;
}
```

![image-20220804102157350](https://img-blog.csdnimg.cn/0dc692a816a2473bb16fb276aa979a46.png)

可以看到在不转换为PCHAR的情况下，实际上减去的是`4*sizeof(int)`，而转换之后就是减去4



拿KDPC结构体举例

```c
PKDEFERRED_ROUTINE ReadEntryDeferredRoutine (PLIST_ENTRY entry) {
	PKDPC p;
	p = CONTAINING_RECORD(entry, KDPC, DpcListEntry);
	return p->DeferredRoutine;
}
```

`CONTAINING_RECORD`这个宏一般会在节点删除和节点遍历中用到



### walk-thorugh

书中提到了一个驱动Sample C，可能是在随书光盘里的文件，但是我没找到这个，只能凑合看了



下面是这个驱动中的一个函数`sub_115DA`的代码片段

```assembly
01: .text:000115FF mov eax, dword_1436C
02: .text:00011604 mov edi, ds:wcsncpy
03: .text:0001160A mov ebx, [eax]
04: .text:0001160C mov esi, ebx
05: .text:0001160E loop_begin: 
06: .text:0001160E cmp dword ptr [esi+20h], 0
07: .text:00011612 jz short failed
08: .text:00011614 push dword ptr [esi+28h] 
09: .text:00011617 call ds:MmIsAddressValid
10: .text:0001161D test al, al
11: .text:0001161F jz short failed
12: .text:00011621 mov eax, [esi+28h]
13: .text:00011624 test eax, eax
14: .text:00011626 jz short failed
15: .text:00011628 movzx ecx, word ptr [esi+24h]
16: .text:0001162C shr ecx, 1
17: .text:0001162E push ecx ; size_t
18: .text:0001162F push eax ; wchar_t *
19: .text:00011630 lea eax, [ebp+var_208]
20: .text:00011636 push eax ; wchar_t *
21: .text:00011637 call edi ; wcsncpy
22: .text:00011639 lea eax, [ebp+var_208]
23: .text:0001163F push eax ; wchar_t *
24: .text:00011640 call ds:_wcslwr
25: .text:00011646 lea eax, [ebp+var_208]
26: .text:0001164C push offset aKrnl ; "krnl"
27: .text:00011651 push eax ; wchar_t *
28: .text:00011652 call ds:wcsstr
29: .text:00011658 add esp, 18h
30: .text:0001165B test eax, eax
31: .text:0001165D jnz short matched_krnl
32: .text:0001165F mov esi, [esi]
33: .text:00011661 cmp esi, ebx
34: .text:00011663 jz short loop_end
35: .text:00011665 jmp short loop_begin
36: .text:00011667 matched_krnl: 
37: .text:00011667 lea eax, [ebp+var_208]
38: .text:0001166D push '\' ; wchar_t
39: .text:0001166F push eax ; wchar_t *
40: .text:00011670 call ds:wcsrchr
41: .text:00011676 pop ecx
42: .text:00011677 test eax, eax
```



代码中的前四行访问了一个指针`dword_1436C`，并将其指向的内容保存到了ebx和esi中

然后在循环体中，有三处引用了esi

- `[esi+20h]`
- `[esi+28h]`
- `[esi+24h]`

据此可以推测出esi是一个长度至少为2ch的结构体

在循环体的最后，从结构体的第一个成员中读出一个指针，然后和指向该结构体的指针进行比较，相等则结束循环，否则继续循环

**据此可以推断出，该循环可能是在遍历一个循环双链表，且该结构体的第一个成员是next，因为它在判断next是否指向头部，并且把esi设置为了next所指向的节点地址**

但是目前还不能断定一定就存在LIST_ENTRY，可能存在，也可能不存在



然后找一下`dword_1436C`这个变量是从哪里来的

函数`sub_11553`使用STDCALL调用约定接受两个参数，一个是指向DRIVER_OBJECT的指针，另一个是指向全局变量`dword_1436C`的指针

感兴趣的代码片段：

```assembly
01: .text:00011578 mov eax, 0FFDFF034h
02: .text:0001157D mov eax, [eax]
03: .text:0001157F mov eax, [eax+70h]
04: ...
05: .text:0001159E mov ecx, [ebp+arg_4] ; pointer to the global var
06: .text:000115A1 mov [ecx], eax
```

这段代码中有一个硬编码的地址`0FFDFF034h`，然后取出该结构体偏移量为70h的成员的值写入到全局变量中



这个硬编码地址在XP中可以被分为两部分，`0FFdFF000h`和偏移量`34h`，其中前者为processor control block结构体（KPCR）的地址，后者是成员KdVersionBlock成员的偏移量，KdVersionBlock偏移量为70h的成员是个什么东西呢？

![image-20220804151218304](https://img-blog.csdnimg.cn/e468cfefbf6144edaab96db14df5b423.png)



这个成员是PsLoadedModuleList，一个指向全局链表头部的指针

该链表中的每一个节点都是KLDR_DATA_TABLE_ENTRY类型，它存储了当前载入的内核模块信息

该结构体的第一个成员是一个LIST_ENTRY，这和上面的汇编代码是吻合的，esi就是LIST_ENTRY，[esi]就是Flink

如果你对上面的结论有疑问，请看下面的代码：

```c
#include <stdio.h>
#include <windows.h>

typedef struct LE {
	struct LE* flink;
	struct LE* blink;
} le, * ple;
typedef struct TEST {
	le mle;
	int b;
} test, * ptest;

int main(void)
{
	test test_test;
	le mle;
	mle.flink = mle.blink = &mle;
	test_test.mle = mle;
	test_test.b = 520;
	printf("%p\n", &test_test);
	printf("%p\n", &test_test.mle);
	printf("%p\n", &test_test.mle.flink);
	return 0;
}
```

![image-20220804171634369](https://img-blog.csdnimg.cn/01d7bf3d931a4ad3a43515d68638388c.png)

可以看到这三个地址是完全一样的，如果说`esi`是`test_test`的地址的话，那么`[esi]`就是对`test_test.mle.flink`取值（`*test_test.mle.flink`）



经过以上分析，可以对这两个函数`sub_115DA`和`sub_11553`做出如下总结

- `sub_11553`，从processor control block中读取KdVersionBlock指针，然后再从该指针中获取到PsLoadedModuleList指针，该指针指向链表的Head，该链表的节点类型位KLDR_DATA_TABLE_ENTRY；将这个函数的名称改为`GetLoadedModuleList`
- `sub_115DA`，遍历LoadedModuleList链表，直到找到一个entry的名字是`krnl`；将这个函数名改为`GetKernelName`



翻译成C语言代码：

```c
typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY ListEntry;
    ...
    UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
    ...
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

BOOL GetLoadedModuleList(PDRIVER_OBJECT drvobj, PLIST_ENTRY g_modlist) {
    ...
    g_modlist = (PCR->KdVersionBlock) + 0x70;
    ...
}

BOOL GetKernelName() {
    WCHAR fname[...];
    PKLDR_DATA_TABLE_ENTRY entry;
    PLIST_ENTRY p = g_modlist->Flink;
    while(p = _modlist) {
        entry = CONTAINING_RECORD(p, KLDR_DATA_TABLE_ENTRY, ListEntry);
        ...
        wcsncpy(fname, entry->FullDllName.Buffer, entry->FullDllName.Length*2);
        ...
        if(wcsstr(fname, L"krnl") != NULL { ... }
        p = p->Flink;
    }
    ...
}
```



由于上面的驱动程序中存在硬编码的地址和偏移量，在某些版本的windows操作系统中可能无法正常运行



```assembly
12: .text:00011621 mov eax, [esi+28h]
13: .text:00011624 test eax, eax
14: .text:00011626 jz short failed
15: .text:00011628 movzx ecx, word ptr [esi+24h]
16: .text:0001162C shr ecx, 1
17: .text:0001162E push ecx ; size_t
18: .text:0001162F push eax ; wchar_t *
19: .text:00011630 lea eax, [ebp+var_208]
20: .text:00011636 push eax ; wchar_t *
21: .text:00011637 call edi ; wcsncpy
```

上面的代码调用`了wcsncpy`对UNICODE_STRING进行复制，偏移量24h为UNICODE_STRING的长度，28h为UNICODE_STRING字符串的地址

UNICODE_STRING结构体定义如下

```c
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
```

上面的代码中，作为长度的ecx右移了一位，相当于x2，是为了保证源buffer中的内容一定会被全部拷贝到目的buffer



也就是说如果在偏移量为24h的地方如果不存在UNICODE_STRING结构体，那么这个驱动代码也无法正常执行，因为esi所代表的的结构体，也就是KLDR_DATA_TABLE_ENTRY是一个没有公开文档的结构体，微软可能在新的版本中对该结构体的成员进行增删，那么UNICODE_STRING的偏移量也会产生变化



还有就是这个驱动程序在遍历链表的时候有模块被卸载掉了，那么可能会引起空指针异常（访问违例），因为他在遍历链表的时候没加锁



之所以能够分析明白上面两个函数，是因为之前已经拥有了内核相关知识以及内核模式下的驱动分析经验，所以可以一眼看出那些像谜一样的16进制数字到底代表着什么含义



结合esi所代表的结构体的一系列特征，推测出该结构体可能为KLDR_DATA_TABLE_ENTRY，该结构体与具有公开定义的LDR_DATA_TABLE_ENTRY非常相似

[https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm)

![image-20220804145307368](https://img-blog.csdnimg.cn/52803f9b3a51441980fbd0819a84fa7f.png)



进行逆向分析需要大量的操作系统知识和经验



作者说了，在一开始的时候你可能并不具备那么多知识以及敏锐的直觉，所以一开始你看不懂也是很正常的事情

入典：

>foundational knowledge + intuition + experience + patience = skills

### 习题



作者给了一堆win8 x64的函数，说这些函数内联了InitalizeListHead函数代码

这个应该很简单，毕竟上面已经分析过InitializeListHead的汇编代码了，我去搞一下

InitializeListHead在64位中有一个很明显的模式：

```assembly
lea REG, [MEM_LOCATION]
mov [REG+8], REG
mov [REG], REG
```

网上有一个[别人做完的](https://bin.re/blog/practical-reverse-engineering-solutions-page-123-part-i/)，待会回来跟他对一下

在做题时遇到的问题

- [windbg查看函数汇编代码失败](https://blog.csdn.net/ma_de_hao_mei_le/article/details/126175510?csdn_share_tail=%7B%22type%22%3A%22blog%22%2C%22rType%22%3A%22article%22%2C%22rId%22%3A%22126175510%22%2C%22source%22%3A%22ma_de_hao_mei_le%22%7D&ctrtid=4lmdy)

#### nt!CcAllocateInitializeMbcb

1

![image-20220804165155698](https://img-blog.csdnimg.cn/5fd1d98a14764ab3860e40871caf6397.png)

#### nt!CmpInitCallbacks

1

![image-20220805003206066](https://img-blog.csdnimg.cn/63116aaf33374a209d8220563935a7d3.png)

这里rax就是`nt!CallbackListHead`

#### nt!ExCreateCallback



![image-20220805003626608](https://img-blog.csdnimg.cn/d4e23fe6716c4b1eb88dfb89306708d5.png)

#### nt!ExpInitSystemPhase0

3

![image-20220805133357122](https://img-blog.csdnimg.cn/e9a0104c67924a00bd3f9fa82227c805.png)

![image-20220805133453141](https://img-blog.csdnimg.cn/32d63d7e9d404194a9d65e6023190b90.png)

![image-20220805133628677](https://img-blog.csdnimg.cn/fb3cda3d3bcc44baaf97bbde47735a85.png)

和别人做的答案对比之后发现漏掉了一个，跟我自己找到的第三个几乎是挨着的，眼花了，没看到。。

![image-20220805150525887](https://img-blog.csdnimg.cn/422ccfc42ca1449c81179a031f52adb4.png)

#### nt!ExpInitSystemPhase1

![image-20220805133826953](https://img-blog.csdnimg.cn/d490c5aa55924c05938646bec15b44ef.png)

#### nt!ExpTimerInitialization

1

![image-20220805134313225](https://img-blog.csdnimg.cn/0923e1caa8934feda64dc199b11b9d88.png)

#### nt!InitBootProcessor

2

![image-20220805134445024](https://img-blog.csdnimg.cn/5cb80419306c4bc783647ae4a2f7c851.png)

![image-20220805134755750](https://img-blog.csdnimg.cn/05574fba2057454397ef6765666e8e19.png)

#### nt!IoCreateDevice

3

![image-20220805102407447](https://img-blog.csdnimg.cn/480909f4a199425eb492f410ab34444c.png)



![image-20220805103014705](https://img-blog.csdnimg.cn/b1ed3dbdeb914b1880b424080f161673.png)



#### nt!IoInitializeIrp

1

![image-20220805103745561](https://img-blog.csdnimg.cn/20e1f0fb88734798bc24ec0da412d6ee.png)

#### nt!KeInitThread

4

![image-20220805105104274](https://img-blog.csdnimg.cn/158ae81749864229a401f45e0111a557.png)

![image-20220805105236835](https://img-blog.csdnimg.cn/2d065d1dbe0943cf8ff0d863ffce439b.png)

![image-20220805105502833](https://img-blog.csdnimg.cn/e94322ce8054457c9bba438ef9277e5b.png)

![image-20220805105542624](https://img-blog.csdnimg.cn/d2bc5ef2160345769f57bdf2110017f0.png)

#### nt!KeInitializeMutex

1

![image-20220805110033154](https://img-blog.csdnimg.cn/d71f7b6b29a34229a1a5444136461e4b.png)

#### nt!KeInitializeProcess

5

![image-20220805113051727](https://img-blog.csdnimg.cn/a125337d7f274812b38895de227555bd.png)

![image-20220805113130238](https://img-blog.csdnimg.cn/8e38b543f25743a18337ed88ac2fac85.png)

![image-20220805113205062](https://img-blog.csdnimg.cn/770bfa864edf4c29a576642d0b560b11.png)

![image-20220805113221823](https://img-blog.csdnimg.cn/2814bc0946ea4d00b84dd5e30867cb12.png)

![image-20220805113240042](https://img-blog.csdnimg.cn/e3d077ec06444ad69841c9d77484462b.png)



#### nt!KeInitializeTimerEx

1

![image-20220805113719380](https://img-blog.csdnimg.cn/43cac5a9f5334f9bb9ca6be9e89f303c.png)

#### nt!KeInitializeTimerTable

1

![image-20220805114805733](https://img-blog.csdnimg.cn/6dbd4d03f62f4f06bb2b16bcaf4ffbdf.png)



#### nt!KiInitializeProcessor

1

![image-20220805115039422](https://img-blog.csdnimg.cn/35480d6e89ae4ecb8403d6537ce9f9c0.png)



#### nt!KiInitializeThread

1

这个稍微有点不是太好找

![image-20220805135531522](https://img-blog.csdnimg.cn/bfad14778a6e4ce3958c0e6890e9ba68.png)

跟到跳转的地址

![image-20220805140704021](https://img-blog.csdnimg.cn/f9ba3c562d5947b18dbd05fbf578df99.png)



#### nt!MiInitializeLoadedModuleList

2

![image-20220805141605683](https://img-blog.csdnimg.cn/c11d9b4bf6d749319a172a003d28be98.png)

![image-20220805141646551](https://img-blog.csdnimg.cn/98f82d703f014fb9a368bc4e7b8a5067.png)

#### nt!MiInitializePrefetchHead

3

![image-20220805142027069](https://img-blog.csdnimg.cn/9e49412113484a9a8b8be0aea4b9bc59.png)

#### nt!PspAllocateProcess

2

![image-20220805142330218](https://img-blog.csdnimg.cn/30f83499d6d64d15b3647ff084f530f1.png)

![image-20220805142404799](https://img-blog.csdnimg.cn/98daa49a8fe847dda88cb5704d864d23.png)

#### nt!PspAllocateThread

5

![image-20220805143810902](https://img-blog.csdnimg.cn/5b1d21c3f341440d87877663868dcac9.png)
