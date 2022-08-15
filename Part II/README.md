[Practical Reverse Engineering notes -- Part II](http://144.34.164.217/practical-reverse-engineering-notes-part-ii.html)


目录可能会稍微有点乱，不要介意，凑合看吧

### 约定

不知道该怎么翻译的，我一律直接用英文原文，只可意会不可言传，自己悟去吧



[内核调试配置](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-universal-drivers---step-by-step-lab--echo-kernel-mode-#connectto)

windbg启动命令

```bash
windbg32 –k net:port=50000,key=2steg4fzbj2sz.23418vzkd4ko3.1g34ou07z4pev.1sp3yo9yz874p


windbg64 –k net:port=50100,key=2steg4fzbj2sz.23418vzkd4ko3.1g34ou07z4pev.1sp3yo9yz874p
```



[书中使用到的所有恶意样本](https://github.com/wqreytuk/Practical_Reverse_Engineering_note/blob/main/malware_samples.zip)

密码是`infected`



## List##Excercise

接着做题，他这个题是真的多༼☯﹏☯༽

在汇编代码中找`InsertHeadList`的内联代码

先观察该函数汇编代码的模式

把`ListHead`给`Entry`的`Blink`

```assembly
mov	[rax+8], rdi
```

取出`ListHead`的`Flink`给`Entry`的`Flink`

```ass
mov	rcx, [rdi]
mov [rax], rcx
```

把`Entry`给`ListHead`的`Flink`的`Blink`和`ListHead`的`Flink`

```assembly
mov	[rcx+8], rax
mov	[rdi], rax
```

模式大概就是：

>有两个地址需要往后偏移8并进行写入值的操作
>
>有两个地址需要进行写入值的操作
>
>这两个写入操作有一个重叠地址（不考虑偏移量），这个地址就是新增的Entry
>
>未产生交集的两个地址，偏移8进行写入的是OldEntry，另一个就是ListHead
>
>其中ListHead会分别进行一次读取值和写入值的操作

在做题的过程中，我又发现一个模式

>判断OldEntry的Blink是否指向ListHead
>
>cmp     qword ptr [r8+8], rax
>
>jne        MEM_LOCATION  Branch
>
>这里r8是OldEntry，rax是ListHead

这样的话，就直接找cmp和jne连着的地方，基本上就大差小不差了

### nt!CcSetVacbInFreeList

1

![image-20220805155923958](https://img-blog.csdnimg.cn/57d51e5150494f0ba81b2304e91c5338.png)

根据上面总结出来的模式

>rax为Entry
>
>rdx（nt!CcVacbFreeList）为ListHead
>
>未产生交集且偏移8进行写入操作的rcx是OldEntry



### nt!CmpDoSort

1

![image-20220805161330946](https://img-blog.csdnimg.cn/048fa32948f24d5c864fd930f81f8c69.png)

正好5条指令

>r11为OldEntry
>
>rbx为新增Entry
>
>r12为ListHead

### nt!ExBurnMemory

1

![image-20220805161631597](https://img-blog.csdnimg.cn/b2ec155a965745c9a8a977a7981d4eee.png)

>r8为ListHead
>
>rax为OldEntry
>
>rcx（nt!BurnMemoryDescriptor）为新增Entry



### nt!ExFreePoolWithTag

1

这两千多行的代码，我就是快速扫一眼都扫了半天，眼都快瞎了

![image-20220805163027240](https://img-blog.csdnimg.cn/8c03ca34eba843179b3c3e413c41a154.png)

>rcx是ListHead
>
>rbx是新增的Entry
>
>rax是OldEntry

### nt!IoPageRead

1

![image-20220805163721352](https://img-blog.csdnimg.cn/90d970051790437598fb07640a2aa721.png)

不用我勾选，上图中的5个mov指令就是链表插入操作，具体每个寄存器代表什么我也不写了，一眼就能看出来

里面的cmp指令用于判断`OldEntry`的`Blink`是否指向`ListHead`，正常情况下是相等的，具体什么情况下会不相等，我也不知道

### nt!IovpCallDriver1

1

![image-20220805164529861](https://img-blog.csdnimg.cn/c2020935d57f4a31865e36e0bea1147d.png)

### nt!KeInitThread

1

![image-20220805164839465](https://img-blog.csdnimg.cn/33e91073092f41728e69825ea2b44373.png)

### nt!KiInsertQueueApc

2

![image-20220805165609452](https://img-blog.csdnimg.cn/c38f4c31170c4371965716ee56f629f7.png)

![image-20220805170430627](https://img-blog.csdnimg.cn/e885add2007b4237a95b8ccd4e4a5c72.png)

### nt!KeInsertQueueDpc

1

![image-20220805205021803](https://img-blog.csdnimg.cn/f2c575bc5d234a87a45e8121e6a00232.png)

### nt!KiQueueReadyThread

1

![image-20220805205713363](https://img-blog.csdnimg.cn/f416714456a7407cb12a00dc5e0db31b.png)

### nt!MiInsertInSystemSpace

1

![image-20220805205907582](https://img-blog.csdnimg.cn/c16a7ecbb7734bc7950253dc80c0da36.png)

### nt!MiUpdateWsle

1

![image-20220805211227519](https://img-blog.csdnimg.cn/4026f12b97c441dab4766b0511368f2a.png)

### nt!ObpInsertCallbackByAltitude

![image-20220805211428551](https://img-blog.csdnimg.cn/3ba8134bdd264e5596c44a3652782927.png)



定位`InsertTailList`这个函数的inline代码我就不做了，因为和`InsertHeadList`非常相似，模式几乎是一样的，只不过是改成了从尾部插入而已



做一下`RemoveHeadList`好了，题解我就不放在这里了，因为太占地方了

[在这里查看题解](https://blog.csdn.net/ma_de_hao_mei_le/article/details/126188091?csdn_share_tail=%7B%22type%22%3A%22blog%22%2C%22rType%22%3A%22article%22%2C%22rId%22%3A%22126188091%22%2C%22source%22%3A%22ma_de_hao_mei_le%22%7D&ctrtid=yR9O6)

在往后的一道题就是说之前做的Insert和Remove链表节点的几个函数代码都有一个共同的特征，这个我在做题的时候也发现了，而且记录了下来，就是CMP和JNE指令

类似于下面这种

![image-20220806144922613](https://img-blog.csdnimg.cn/66e243be4fdf425eae40c8f77682ce55.png)

这个CMP指令的结果正常情况下应该是相等的，如果不相等，说明链表出现了问题，后面的代码就没办法正常执行了，因此直接跳转走并触发中断

每次判断失败的时候，就会执行

```assembly
mov ecx, 3
int 29h
```

题目提示说需要使用查看IDT，那就来看一下29h中断是啥

```
kd> !idt 29

Dumping IDT: fffff8038577f080

29:	fffff803858fb800 nt!KiRaiseSecurityCheckFailure
```



在windows 8 x64中INT指令的背后进行了哪些一系列的操作，什么TrapFrame又是啥东西，这些我都不是很清楚，也许永远都不会清楚，如果清楚了，我会更新的



通过在驱动程序中嵌入汇编代码，我可以跟进29h号中断的代码里，并观察到rsp指向的是RIP，此时的RIP是指向int指令的下一条指令的，后面的我就没戏看了，暂时还没必要，而且我也不是很清楚具体都压进去了什么东西到栈里面







## Asynchronous and Ad-Hoc Execution

Ad-Hoc好像是老外的俚语，意思可能是立即，我也不清楚，硬着头皮往下看先



### System Threads

就他妈离谱，上来就让我写个驱动去测试东西，我哪里会写驱动啊



OK，我会写驱动了，我也会调试驱动了，没什么难的

[https://github.com/wqreytuk/x64_ASM_Kernel_Mode](https://github.com/wqreytuk/x64_ASM_Kernel_Mode)



这一节就是讲的PsCreateSystemThread这个函数，然后让判断下面这段话是否正确

> 在IOCTL handler中调用该函数并将ProcessHandle（第四个参数）设为NULL，那么创建出来的线程是运行在发起IO请求的用户空间的那个进程中的



答案是这句话是错误的，我自己写了个驱动测试了一下，[项目地址](https://github.com/wqreytuk/windows_driver/blob/main/ioctl.sln)

这个项目包含一个驱动和一个console app，其中console app用于向驱动程序发起IO请求，将console app和驱动程序放到一个路径下执行console app即可，console app会首先安装驱动，然后使用getchar阻塞等待按键，这个时候在debugger中设置好windbg并加载好符号设置好断点（Test Function），回到debuggee回车触发断点即可



通过观察传入的最后一个参数获取到ThreadHandle的值

```assembly
fffff807`54a95316 e8e5bcffff      call    SIoctl!TestFunction (fffff807`54a91000)
fffff807`54a9531b 48c744243000000000 mov   qword ptr [rsp+30h],0
fffff807`54a95324 488d05b5bdffff  lea     rax,[SIoctl!thread_routine (fffff807`54a910e0)]
fffff807`54a9532b 4889442428      mov     qword ptr [rsp+28h],rax
fffff807`54a95330 48c744242000000000 mov   qword ptr [rsp+20h],0
fffff807`54a95339 4533c9          xor     r9d,r9d
fffff807`54a9533c 4533c0          xor     r8d,r8d
fffff807`54a9533f ba00000010      mov     edx,10000000h
fffff807`54a95344 488d8c24d8000000 lea     rcx,[rsp+0D8h]
fffff807`54a9534c ff15deccffff    call    qword ptr [SIoctl!_imp_PsCreateSystemThread (fffff807`54a92030)]
```

在PsCreateSystemThread函数调用完成后查看`rsp+d8`即可

```
4: kd> dq /c 1 (rsp+d8) L1
ffff808d`dffdf1b8  ffffffff`80004aec
```

`ffffffff80004aec`是一个HANDLE对象，即句柄，**它并不是一个地址，而是一个索引值**，可以在windbg中使用`!handle`来查看该句柄关联的信息

![image-20220812131145784](https://img-blog.csdnimg.cn/189bfb6f9a45419eb0f3815e96f71c4c.png)

圈起来的这个值就是句柄代表的对象的地址，就是ETHREAD(KTHREAD)结构体的地址，这两个结构体的地址是一样的，因为KTHREAD是ETHREAD的第一个成员

```
4: kd> dt nt!_KTHREAD ffff8a071f0e3080
   +0x000 Header           : _DISPATCHER_HEADER
   +0x018 SListFaultAddress : (null) 
   +0x020 QuantumTarget    : 0x4758c54
   ...
   +0x098 ApcState         : _KAPC_STATE
   +0x098 ApcStateFill     : [43]  "???"
   ...
```

进入ApcState成员

```
4: kd> dx -id 0,0,ffff8a07222e60c0 -r1 (*((ntkrnlmp!_KAPC_STATE *)0xffff8a071f0e3118))
(*((ntkrnlmp!_KAPC_STATE *)0xffff8a071f0e3118))                 [Type: _KAPC_STATE]
    [+0x000] ApcListHead      [Type: _LIST_ENTRY [2]]
    [+0x020] Process          : 0xffff8a0715a64380 [Type: _KPROCESS *]
    [+0x028] InProgressFlags  : 0x0 [Type: unsigned char]
    [+0x028 ( 0: 0)] KernelApcInProgress : 0x0 [Type: unsigned char]
    [+0x028 ( 1: 1)] SpecialApcInProgress : 0x0 [Type: unsigned char]
    [+0x029] KernelApcPending : 0x0 [Type: unsigned char]
    [+0x02a] UserApcPendingAll : 0x0 [Type: unsigned char]
    [+0x02a ( 0: 0)] SpecialUserApcPending : 0x0 [Type: unsigned char]
    [+0x02a ( 1: 1)] UserApcPending   : 0x0 [Type: unsigned char]
```

这时就已经看到KPROCESS(EPROCESS)的地址了`0xffff8a0715a64380`

```
4: kd> dt nt!_EPROCESS 0xffff8a0715a64380
   +0x000 Pcb              : _KPROCESS
   +0x2e0 ProcessLock      : _EX_PUSH_LOCK
   ...
   +0x448 ImageFilePointer : (null) 
   +0x450 ImageFileName    : [15]  "System"
   ...
   +0x870 CoverageSamplerContext : (null) 
   +0x878 MmHotPatchContext : (null) 
```

可以看到ImageFileName成员的值是System，如果上面的那句话是正确的话，那么这里应该是`ioctlapp.exe`（console app的名称）

可以通过查看ioctlapp.exe进程的所有线程来进一步确认使用PsCreateSystemThread创建出来的线程并不在用户进程下

```
4: kd> !process ffff8a07222e60c0
PROCESS ffff8a07222e60c0
    SessionId: 2  Cid: 2f38    Peb: 6d2896e000  ParentCid: 1e94
    DirBase: 1572d5000  ObjectTable: ffffa282a0fe1d80  HandleCount:  65.
    Image: ioctlapp.exe
    VadRoot ffff8a072092b780 Vads 33 Clone 0 Private 175. Modified 2. Locked 0.
    DeviceMap ffffa2829bdb1e90
    Token                             ffffa2829f758060
    ElapsedTime                       00:05:33.095
    UserTime                          00:00:00.000
    KernelTime                        00:00:00.000
    QuotaPoolUsage[PagedPool]         30720
    QuotaPoolUsage[NonPagedPool]      5008
    Working Set Sizes (now,min,max)  (956, 50, 345) (3824KB, 200KB, 1380KB)
    PeakWorkingSetSize                912
    VirtualSize                       2101299 Mb
    PeakVirtualSize                   2101300 Mb
    PageFaultCount                    1001
    MemoryPriority                    BACKGROUND
    BasePriority                      8
    CommitCharge                      202

        THREAD ffff8a072084b080  Cid 2f38.3474  Teb: 0000006d2896f000 Win32Thread: 0000000000000000 RUNNING on processor 4
        IRP List:
            ffff8a071d3fc2d0: (0006,0118) Flags: 00060070  Mdl: 00000000
        Not impersonating
        DeviceMap                 ffffa2829bdb1e90
        Owning Process            ffff8a07222e60c0       Image:         ioctlapp.exe
        Attached Process          N/A            Image:         N/A
        Wait Start TickCount      72069          Ticks: 1 (0:00:00:00.015)
        Context Switch Count      36             IdealProcessor: 5             
        UserTime                  00:00:00.000
        KernelTime                00:00:00.046
        Win32 Start Address 0x00007ff67f522800
        Stack Init ffff808ddffdf650 Current ffff808ddffde730
        Base ffff808ddffe0000 Limit ffff808ddffd9000 Call 0000000000000000
        Priority 9 BasePriority 8 PriorityDecrement 0 IoPriority 2 PagePriority 5
        Child-SP          RetAddr           Call Site
        ffff808d`dffdf0e0 fffff807`4e631f39 SIoctl!SioctlDeviceControl+0x109 [C:\Users\Administrator\Documents\microsoft Windows-driver-samples main setup-devcon (1)\microsoft windows-driver-samples main general-ioctl_wdm\sys\sioctl.c @ 310] 
        ffff808d`dffdf1e0 fffff807`4ebe8345 nt!IofCallDriver+0x59
        ffff808d`dffdf220 fffff807`4ebe8150 nt!IopSynchronousServiceTail+0x1a5
        ffff808d`dffdf2c0 fffff807`4ebe7526 nt!IopXxxControlFile+0xc10
        ffff808d`dffdf3e0 fffff807`4e7d2915 nt!NtDeviceIoControlFile+0x56
        ffff808d`dffdf450 00007ff9`7909c1b4 nt!KiSystemServiceCopyEnd+0x25 (TrapFrame @ ffff808d`dffdf4c0)
        0000006d`2877f488 00007ff9`762f57b7 0x00007ff9`7909c1b4
        0000006d`2877f490 0000006d`00000000 0x00007ff9`762f57b7
        0000006d`2877f498 00007ff9`426b3c20 0x0000006d`00000000
        0000006d`2877f4a0 00000001`00000001 0x00007ff9`426b3c20
        0000006d`2877f4a8 00000001`00000001 0x00000001`00000001
        0000006d`2877f4b0 0000006d`2877f4e0 0x00000001`00000001
        0000006d`2877f4b8 00007ff9`9c402408 0x0000006d`2877f4e0
        0000006d`2877f4c0 00007ff6`7f529ce0 0x00007ff9`9c402408
        0000006d`2877f4c8 0000016e`0000003c 0x00007ff6`7f529ce0
        0000006d`2877f4d0 00007ff6`7f529d60 0x0000016e`0000003c
        0000006d`2877f4d8 00007ff9`00000064 0x00007ff6`7f529d60
        0000006d`2877f4e0 00000000`00000000 0x00007ff9`00000064

        THREAD ffff8a071d5a3040  Cid 2f38.0bd4  Teb: 0000006d28977000 Win32Thread: 0000000000000000 WAIT: (WrQueue) UserMode Alertable
            ffff8a071db12a80  QueueObject
        Not impersonating
        DeviceMap                 ffffa2829bdb1e90
        Owning Process            ffff8a07222e60c0       Image:         ioctlapp.exe
        Attached Process          N/A            Image:         N/A
        Wait Start TickCount      71866          Ticks: 204 (0:00:00:03.187)
        Context Switch Count      2              IdealProcessor: 5             
        UserTime                  00:00:00.000
        KernelTime                00:00:00.000
        Win32 Start Address 0x00007ff979033d60
        Stack Init ffff808de0a8f650 Current ffff808de0a8ee20
        Base ffff808de0a90000 Limit ffff808de0a89000 Call 0000000000000000
        Priority 8 BasePriority 8 PriorityDecrement 0 IoPriority 2 PagePriority 5
        Child-SP          RetAddr           Call Site
        ffff808d`e0a8ee60 fffff807`4e63c77d nt!KiSwapContext+0x76
        ffff808d`e0a8efa0 fffff807`4e63b604 nt!KiSwapThread+0xbfd
        ffff808d`e0a8f040 fffff807`4e63f4be nt!KiCommitThreadWait+0x144
        ffff808d`e0a8f0e0 fffff807`4e63efb9 nt!KeRemoveQueueEx+0x27e
        ffff808d`e0a8f190 fffff807`4e63ec8e nt!IoRemoveIoCompletion+0x99
        ffff808d`e0a8f2b0 fffff807`4e7d2915 nt!NtWaitForWorkViaWorkerFactory+0x25e
        ffff808d`e0a8f450 00007ff9`7909fa64 nt!KiSystemServiceCopyEnd+0x25 (TrapFrame @ ffff808d`e0a8f4c0)
        0000006d`28aff568 00007ff9`79034060 0x00007ff9`7909fa64
        0000006d`28aff570 00000000`00000000 0x00007ff9`79034060

        THREAD ffff8a071ff3a080  Cid 2f38.2df4  Teb: 0000006d28979000 Win32Thread: 0000000000000000 WAIT: (WrQueue) UserMode Alertable
            ffff8a071db12a80  QueueObject
        Not impersonating
        DeviceMap                 ffffa2829bdb1e90
        Owning Process            ffff8a07222e60c0       Image:         ioctlapp.exe
        Attached Process          N/A            Image:         N/A
        Wait Start TickCount      71866          Ticks: 204 (0:00:00:03.187)
        Context Switch Count      2              IdealProcessor: 6             
        UserTime                  00:00:00.000
        KernelTime                00:00:00.000
        Win32 Start Address 0x00007ff979033d60
        Stack Init ffff808de09d7650 Current ffff808de09d6e20
        Base ffff808de09d8000 Limit ffff808de09d1000 Call 0000000000000000
        Priority 8 BasePriority 8 PriorityDecrement 0 IoPriority 2 PagePriority 5
        Child-SP          RetAddr           Call Site
        ffff808d`e09d6e60 fffff807`4e63c77d nt!KiSwapContext+0x76
        ffff808d`e09d6fa0 fffff807`4e63b604 nt!KiSwapThread+0xbfd
        ffff808d`e09d7040 fffff807`4e63f4be nt!KiCommitThreadWait+0x144
        ffff808d`e09d70e0 fffff807`4e63efb9 nt!KeRemoveQueueEx+0x27e
        ffff808d`e09d7190 fffff807`4e63ec8e nt!IoRemoveIoCompletion+0x99
        ffff808d`e09d72b0 fffff807`4e7d2915 nt!NtWaitForWorkViaWorkerFactory+0x25e
        ffff808d`e09d7450 00007ff9`7909fa64 nt!KiSystemServiceCopyEnd+0x25 (TrapFrame @ ffff808d`e09d74c0)
        0000006d`28bff918 00007ff9`79034060 0x00007ff9`7909fa64
        0000006d`28bff920 0000006d`00000003 0x00007ff9`79034060
        0000006d`28bff928 0000006d`2896e000 0x0000006d`00000003
        0000006d`28bff930 0000016e`7600a150 0x0000006d`2896e000
        0000006d`28bff938 00000000`00000000 0x0000016e`7600a150
```



我傻了，可以不用这么麻烦的，直接用`!thread addr`可以直接看到该线程所属的进程



这个问题后面还有一个问题，就是将第四个参数（ProcessHandle）设置为非Non-NULL的再测试一下，我设置成了当前进程的句柄，结果显示创建出来的线程是运行在用户进程下的，对驱动程序代码做了如下修改

```c
HANDLE process_id = PsGetCurrentProcessId();
// retrive process handle
HANDLE process = NULL;
OBJECT_ATTRIBUTES obj_attr;
CLIENT_ID cid;
cid.UniqueProcess = process_id; //PsGetCurrentProcessId();
cid.UniqueThread = NULL; //(HANDLE)0;
InitializeObjectAttributes(&obj_attr, NULL, 0, NULL, NULL);
ZwOpenProcess(&process, PROCESS_ALL_ACCESS, &obj_attr, &cid);
HANDLE thread_handle;
NTSTATUS ret = PsCreateSystemThread(&thread_handle, GENERIC_ALL, NULL, process, NULL, thread_routine, NULL);
```

```
5: kd> dq /c 1 (rsp+128h) L1
DBGHELP: SharedUserData - virtual symbol module
ffff808d`e25871b8  ffffffff`8000477c
5: kd> !handle ffffffff`8000477c

PROCESS ffff8a0722f240c0
    SessionId: 2  Cid: 2d5c    Peb: c4ee341000  ParentCid: 1e94
    DirBase: 1b7ff7000  ObjectTable: ffffa2829aacfd80  HandleCount:  65.
    Image: ioctlapp.exe

Kernel handle table at ffffa28294c05ac0 with 4835 entries in use

8000477c: Object: ffff8a0721bd4080  GrantedAccess: 001fffff (Protected) (Audit) Entry: ffffa2829d4fbdf0
Object: ffff8a0721bd4080  Type: (ffff8a0715aa24e0) Thread
    ObjectHeader: ffff8a0721bd4050 (new version)
        HandleCount: 1  PointerCount: 2
5: kd> !thread ffff8a0721bd4080
THREAD ffff8a0721bd4080  Cid 2d5c.27c8  Teb: 0000000000000000 Win32Thread: 0000000000000000 TERMINATED
Not impersonating
DeviceMap                 ffffa2829bdb1e90
Owning Process            ffff8a0722f240c0       Image:         ioctlapp.exe
Attached Process          N/A            Image:         N/A
Wait Start TickCount      0              Ticks: 78372 (0:00:20:24.562)
Context Switch Count      1              IdealProcessor: 5             
UserTime                  00:00:00.000
KernelTime                00:00:00.000
Win32 Start Address SIoctl!thread_routine (0xfffff80754a610e0)
Stack Init ffff808de123f650 Current ffff808de123f5e0
Base ffff808de1240000 Limit ffff808de1239000 Call 0000000000000000
Priority 8 BasePriority 8 PriorityDecrement 0 IoPriority 2 PagePriority 5
Child-SP          RetAddr           : Args to Child                                                           : Call Site
ffff808d`e123f620 00000000`00000000 : ffff808d`e1240000 ffff808d`e1239000 00000000`00000000 00000000`00000000 : nt!KiStartSystemThread+0x2a
```

可以看到是在用户进程下的

### Work Items

workitems是等待被线程处理的任务队列，本质上是一个链表

```
kd> dt nt!_IO_WORKITEM
   +0x000 WorkItem         : _WORK_QUEUE_ITEM
   +0x020 Routine          : Ptr64     void 
   +0x028 IoObject         : Ptr64 Void
   +0x030 Context          : Ptr64 Void
   +0x038 Type             : Uint4B
   +0x03c ActivityId       : _GUID
kd> dt nt!_WORK_QUEUE_ITEM
   +0x000 List             : _LIST_ENTRY
   +0x010 WorkerRoutine    : Ptr64     void 
   +0x018 Parameter        : Ptr64 Void
```



在初始化之后会被插入到由KPRCB中的ParentNode指针指向的一个队列中



```assembly
kd> dt nt!_KPRCB
+0x5338 ParentNode       : Ptr64 _KNODE
```



这个KNODE和ENODE的关系跟ETHREAD和KTHREAD是一样的，因为KNODE是ENODE的第一个成员，所以两者的地址也是一样的

```assembly
kd>  dt nt!_ENODE
   +0x000 Ncb              : _KNODE
   +0x0c0 ExWorkerQueues   : [7] _EX_WORK_QUEUE
   +0x2f0 ExpThreadSetManagerEvent : _KEVENT
   +0x308 ExpWorkerThreadBalanceManagerPtr : Ptr64 _ETHREAD
   +0x310 ExpWorkerSeed    : Uint4B
   +0x314 ExWorkerFullInit : Pos 0, 1 Bit
   +0x314 ExWorkerStructInit : Pos 1, 1 Bit
   +0x314 ExWorkerFlags    : Uint4B
kd> dt nt!_KNODE
   +0x000 DeepIdleSet      : Uint8B
   +0x040 ProximityId      : Uint4B
   +0x044 NodeNumber       : Uint2B
```

`ExWorkerQueues`就是workitem将要被插入的队列

```assembly
kd>  dt nt!_EX_WORK_QUEUE
   +0x000 WorkerQueue      : _KQUEUE
   +0x040 WorkItemsProcessed : Uint4B
   +0x044 WorkItemsProcessedLastPass : Uint4B
   +0x048 ThreadCount      : Int4B
   +0x04c TryFailed        : UChar
```

函数ExQueueWorkItemEx负责将workitem插入队列，ExpWorkerThread函数负责从队列中取出workitem

稍微看一下`ExQueueWorkItemEx`的汇编代码

```assembly
kd>  uf nt!ExQueueWorkItemEx
...
fffff802`35bfefc3 65488b042520000000 mov   rax,qword ptr gs:[20h]
fffff802`35bfefcc 4c8b8038530000  mov     r8,qword ptr [rax+5338h]
fffff802`35bfefd3 410fb74044      movzx   eax,word ptr [r8+44h]		; eax就是KNODE的NodeNumber字段，再往后的代码我也看不太懂了，不管了，先做题
fffff802`35bfefd8 8bc8            mov     ecx,eax
fffff802`35bfefda 488d0440        lea     rax,[rax+rax*2]
fffff802`35bfefde 48c1e006        shl     rax,6
fffff802`35bfefe2 4803c5          add     rax,rbp
fffff802`35bfefe5 493904ce        cmp     qword ptr [r14+rcx*8],rax
fffff802`35bfefe9 0f84010ce6ff    je      nt!ExQueueWorkItemEx+0xe0 (fffff802`35a5fbf0)  Branch
...
```



由于ExpWorkerThread运行在System下，所以workitem也是在System下被执行的，IRQL位PASSIVE_LEVEL

题目是：

> 如何确定ExpWorkerThread是负责从队列中取出并执行workeritem的函数，该函数没有文档
>
> 提示：编写驱动



[驱动项目地址](https://github.com/wqreytuk/ExpWorkerThread_test/blob/main/ioctl.sln)

关键代码

```c
PIO_WORKITEM work_item= IoAllocateWorkItem(DeviceObject);
IoQueueWorkItem(work_item, &WorkItem, CriticalWorkQueue, NULL);
```

这里的`WorkItem`是将要被线程执行的例程

```c
VOID WorkItem(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);
    TestFunction();
}
```

只要在TestFunction下断点，然后在TestFunction第二次被触发的时候查看调用栈即可找到处理WorkItem的是哪个函数

![image-20220813004826202](https://img-blog.csdnimg.cn/576b9e4b186a416391763a261a05e33c.png)

他后面还有一个问题，就是怎么知道ExpWorkerThread是运行在System下的，这个问题也很好解答，对WorkItem例程稍作修改即可

```c
VOID WorkItem(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);
    TestFunction();
    PKTHREAD  Self = KeGetCurrentThread();
    KeSetPriorityThread(Self, LOW_REALTIME_PRIORITY);
}
```

还是在TestFunction方法下断点，在第二次触发的时候，观察KeGetCurrentThread函数调用之后rax的值，此时rax作为该函数的返回值就是KTHREAD结构体的地址

![image-20220813230257357](https://img-blog.csdnimg.cn/a82979b519f4427192871361830f5460.png)



接着做题，下一题是让跟一下几个函数的汇编代码，解释一下他们是怎么工作的，这里我就只做第一个，`IoAllocateWorkItem`函数



