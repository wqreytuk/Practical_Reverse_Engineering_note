[https://144.one/practical-reverse-engineering-du-shu-bi-ji.html](https://144.one/practical-reverse-engineering-du-shu-bi-ji.html)

目录可能会稍微有点乱，不要介意，凑合看吧

### 约定

不知道该怎么翻译的，我一律直接用英文原文，只可意会不可言传，自己悟去吧

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
