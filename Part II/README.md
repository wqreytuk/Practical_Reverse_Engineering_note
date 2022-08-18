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



接着做题，下一题是让跟一下几个函数的汇编代码，解释一下他们是怎么工作的，这里我就只做第一个，`IoAllocateWorkItem`函，[题解](https://blog.csdn.net/ma_de_hao_mei_le/article/details/126342522?spm=1001.2014.3001.5501)



### Asynchronous Procedure Call -- APC



字面意思就是异步过程调用

APC用于实现很多重要的操作，例如异步IO，线程挂起以及进程终止等操作



这个东西几乎是没有文档的，[官方的驱动的开发手册](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/types-of-apcs)只稍微提了一嘴，并没有提供更详细的东西

不过对于日常的逆向工作，并不用了解太多APC的底层细节

这节将会介绍APC是啥玩意及用法



#### APC基础

通俗来讲，ACP就是一个运行在特定线程context下的函数

可以被分成用户模式和内核模式，内核模式下的APC又可以被分为normal和special

- normal：运行在PASSIVE_LEVEL下
- special：运行在APC_LEVEL下

由于APC是运行在线程中的，所以总是会和一个ETHREAD关联

APC的定义如下：

```c
kd> dt nt!_KAPC
   +0x000 Type             : UChar
   +0x001 SpareByte0       : UChar
   +0x002 Size             : UChar
   +0x003 SpareByte1       : UChar
   +0x004 SpareLong0       : Uint4B
   +0x008 Thread           : Ptr64 _KTHREAD
   +0x010 ApcListEntry     : _LIST_ENTRY
   +0x020 KernelRoutine    : Ptr64     void 
   +0x028 RundownRoutine   : Ptr64     void 
   +0x030 NormalRoutine    : Ptr64     void 
   +0x020 Reserved         : [3] Ptr64 Void
   +0x038 NormalContext    : Ptr64 Void
   +0x040 SystemArgument1  : Ptr64 Void
   +0x048 SystemArgument2  : Ptr64 Void
   +0x050 ApcStateIndex    : Char
   +0x051 ApcMode          : Char
   +0x052 Inserted         : UChar
```

该结构体由KeInitializeApc进行初始化

```c
NTKERNELAPI VOID KeInitializeApc(
    PKAPC Apc,
    PKTHREAD Thread,
    KAPC_ENVIRONMENT Environment,
    PKKERNEL_ROUTINE KernelRoutine,
    PKRUNDOWN_ROUTINE RundownRoutine,
    PKNORMAL_ROUTINE NormalRoutine,
    KPROCESSOR_MODE ProcessorMode,
    PVOID NormalContext
);
 
NTKERNELAPI BOOLEAN KeInsertQueueApc(
	PRKAPC Apc,
	PVOID SystemArgument1,
	PVOID SystemArgument2,
	KPRIORITY Increment
);
```

Callback prototypes

```
typedef VOID (*PKKERNEL_ROUTINE)(
	PKAPC Apc,
	PKNORMAL_ROUTINE *NormalRoutine,
	PVOID *NormalContext,
	PVOID *SystemArgument1,
	PVOID *SystemArgument2
);
typedef VOID (*PKRUNDOWN_ROUTINE)(
 	PKAPC Apc
);

typedef VOID (*PKNORMAL_ROUTINE)(
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
);

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;
```



上面的这些定义是没有文档的，书中给出来的是从别的论坛中搞的， 不保熟



```c
NTKERNELAPI VOID KeInitializeApc(
    PKAPC Apc,
    PKTHREAD Thread,
    KAPC_ENVIRONMENT Environment,
    PKKERNEL_ROUTINE KernelRoutine,
    PKRUNDOWN_ROUTINE RundownRoutine,
    PKNORMAL_ROUTINE NormalRoutine,
    KPROCESSOR_MODE ProcessorMode,
    PVOID NormalContext
);
```

参数说明：

- Apc：由调用者分配的一块buffer，从non-paged pool中分配（ExAllocatePool）
- Thread，该apc所关联的线程
- Environment：apc的执行环境，例如：OriginalApcEnvironment意味着apc将会运行在线程的进程context中（什么玩意儿，完全看不懂在说啥）
- KenerlRoutine：在APC_LEVEL下以内核模式执行的函数
- RundownRoutine：线程终止的时候，该例程将会被执行
- NormalRoutine：在PASSIVE_LEVEL下以ProcessorMode执行的函数



在KTHREAD的ApcState成员中有一个ListEntry

```
kd> dt nt!_KTHREAD
   ...
   +0x098 ApcState         : _KAPC_STATE
   ...
kd> dt nt!_KAPC_STATE
   +0x000 ApcListHead      : [2] _LIST_ENTRY
   +0x020 Process          : Ptr64 _KPROCESS
   +0x028 KernelApcInProgress : UChar
   +0x029 KernelApcPending : UChar
   +0x02a UserApcPending   : UChar
```

ApcState中存储了两个队列，一个用于内核模式，另一个用于用户模式

这个在[后面的调试过程中](http://144.34.164.217/practical-reverse-engineering-notes-part-ii.html#makabakayezhendehenxihuanwo)是可以观察到的：

`fffffa801a332b00`为插入APC的线程地址

首先使用windbg的`!apc`命令得到内核模式和用户模式两个队列（链表）的地址，可以看到分别为`fffffa801a332b98`和`fffffa801a332ba8`

```
kd> !apc thre fffffa801a332b00
Thread fffffa801a332b00 ApcStateIndex 0 ApcListHead fffffa801a332b98 [KERNEL]
Thread fffffa801a332b00 ApcStateIndex 0 ApcListHead fffffa801a332ba8 [USER]
    KAPC @ fffffa801a332090
      Type           12
      KernelRoutine  fffff8007a1d4f48 nt!AlpcpFreeBuffer+0
      RundownRoutine fffff8007a07bc50 nt!ExFreePool+0
```

下面通过解析结构体来进行验证

```
dt nt!_KTHREAD fffffa801a332b00
```

获取到ApcState成员的地址`0xfffffa801a332b98`

```
kd> dt nt!_KAPC_STATE 0xfffffa801a332b98
   +0x000 ApcListHead      : [2] _LIST_ENTRY [ 0xfffffa80`1a332b98 - 0xfffffa80`1a332b98 ]
   +0x020 Process          : 0xfffffa80`1ad56080 _KPROCESS
   +0x028 KernelApcInProgress : 0 ''
   +0x029 KernelApcPending : 0 ''
   +0x02a UserApcPending   : 0 ''
```

再查看`ApcListHead`，**注意看上面的输出，第二个成员Process的偏移量为0x20，说明ApcListHead长度为0x20，即32bytes，而一个ListEntry结构体只有16字节（Flink+Blink），因此ApcListHead包含两个ListEntry**，这一点从上面输出中的`[2]`也可以体现出来

```
kd> dt nt!_LIST_ENTRY 0xfffffa80`1a332b98
 [ 0xfffffa80`1a332b98 - 0xfffffa80`1a332b98 ]
   +0x000 Flink            : 0xfffffa80`1a332b98 _LIST_ENTRY [ 0xfffffa80`1a332b98 - 0xfffffa80`1a332b98 ]
   +0x008 Blink            : 0xfffffa80`1a332b98 _LIST_ENTRY [ 0xfffffa80`1a332b98 - 0xfffffa80`1a332b98 ]

kd> dt nt!_LIST_ENTRY (0xfffffa80`1a332b98+0x10)
 [ 0xfffffa80`1a3320a0 - 0xfffffa80`1a3320a0 ]
   +0x000 Flink            : 0xfffffa80`1a3320a0 _LIST_ENTRY [ 0xfffffa80`1a332ba8 - 0xfffffa80`1a332ba8 ]
   +0x008 Blink            : 0xfffffa80`1a3320a0 _LIST_ENTRY [ 0xfffffa80`1a332ba8 - 0xfffffa80`1a332ba8 ]
```

这两个链表，前者存储内核模式的APC，后者存储用户模式的APC，这里通过Flink获取到用户模式的APC，即KAPC结构体中ListEntry成员的地址`0xfffffa801a3320a0 `，[减去其在KAPC中的偏移量`0x10`](https://144.one/practical-reverse-engineering-notes-part-i.html#wozhendehenxihuanmakabaka)即可得到APC的真正地址`fffffa801a332090`







#### 使用APC实现线程挂起操作



当一个程序想挂起一个线程的时候，内核会把一个APC弄到这个线程里面，准确来说是KTHREAD的SchedulerApc成员

使用KeInitThread函数进行初始化，然后使用KiSchedulerApc函数占用SuspendEvent事件，当程序想恢复这个线程的时候，使用KeResumeThread释放这个事件就行了



如果你不是在逆向Windows内核或者写内核模式下的RootKit，那么应该是碰不到使用APC的代码的

主要是因为这个东西他没有文档，因此很少在商业驱动中使用

但是在RootKit中，APC使用的相当频繁，因为可以使用APC从内核模式将代码注入到用户模式

RootKit的做法是将一个用户模式的APC加入到他们想要注入的进程的线程的队列中



这本书真尼玛离谱，啥都没讲，上来就让我写驱动使用APC



我在网上找到了[这篇文章](https://repnz.github.io/posts/apc/user-apc/)，先来读一下看看

这篇文章中给了一个项目地址，里面有很多APC的用法，相关的代码注释我放到了[这里](https://github.com/wqreytuk/APC)，下面是对其中一些用法的笔记

##### [QueueUserAPC](https://github.com/wqreytuk/APC/blob/main/ApcDllInjector/ApcDllInjector.c#L101)

这个项目中有三个APC选项，这里先来搞一下win32，就是使用微软文档中公开的方法进行APC的插入操作

大概的流程就是在目标进程的虚拟地址空间中开辟出一块内存写入要加载的dll的路径，然后获取到目标进程的一个线程句柄，最后通过QueueUserAPC将一个方法插入到该线程的APC队列中

```c
if (!QueueUserAPC((PAPCFUNC) LoadLibraryAPtr, ThreadHandle, (ULONG_PTR) RemoteLibraryAddress)
```

`LoadLibraryAPtr`是要插入的方法，`ThreadHandle`是APC要插入到的线程，`RemoteLibraryAddress`是方法的参数



这里选择将7z.dll注入到notepad.exe进程中

![image-20220817160324363](https://img-blog.csdnimg.cn/653e764b25e44517878d2a96bbdb2e99.png)

为了调试方便，我在代码中加入了一个判断文件是否存在的代码，通过在debuggee中创建指定文件来触发断点



![image-20220817160435588](https://img-blog.csdnimg.cn/43018bcaa8f54885bb3d75116ceff904.png)

`ApcDllInjector.exe`执行后会阻塞，循环检测该文件是否存在，这时候启动windbg加载`ApcDllInjector.pdb`并[切换到`ApcDllInjector.exe`进程空间](https://blog.csdn.net/ma_de_hao_mei_le/article/details/126051148)



在`QueueUserAPC`函数调用完成后，查看notepad.exe进程

![image-20220817160745078](https://img-blog.csdnimg.cn/13bd48daf9454da782f2b66b9ecd300b.png)

获取到线程地址后，使用`!apc`查看该线程中的APC

![image-20220817160851974](https://img-blog.csdnimg.cn/2e0afb5111d6426d9991ac0efb50e3d8.png)

可以清楚地看到这里显示了两个ApcListHead，一个是KERNEL，一个是USER



其实!apc已经给出了KAPC结构体的地址，但是通过ApcListHead的地址，也可以找到KAPC的地址

根据之前了解到的[通过ListEntry定位结构体地址](http://144.34.164.217/practical-reverse-engineering-notes-part-i.html#wozhendehenxihuanmakabaka)的方法，即可计算出KACP的地址为`0xfffffa801bc89720-0x10`

![image-20220817163023402](https://img-blog.csdnimg.cn/f18477dcadf94560a76e5a09935c8c30.png)

![image-20220817163133035](https://img-blog.csdnimg.cn/5a7f51fea9394c81b8d8e2fb9d66535b.png)

可以看到Thread地址是正确的，说明地址计算无误



KAPC结构体中的NormalContext就是使用QueueUserAPC插入的方法，即`LoadLibraryA`函数

需要切换到目标进程（notepad.exe）来查看该字段

```assembly
kd> !process 0 0 notepad.exe
PROCESS fffffa801a19b080
    SessionId: 1  Cid: 0424    Peb: 7f62186b000  ParentCid: 0ef8
    DirBase: 1b10b000  ObjectTable: fffff8a0018e15c0  HandleCount: <Data Not Accessible>
    Image: notepad.exe

kd> .process /i /p /r fffffa801a19b080  
You need to continue execution (press 'g' <enter>) for the context
to be switched. When the debugger breaks in again, you will be in
the new process context.
kd> g
Break instruction exception - code 80000003 (first chance)
nt!DbgBreakPointWithStatus:
fffff800`79e81930 cc              int     3
kd> u 0x000007fb`988928ac L 20
000007fb`988928ac 48895c2408      mov     qword ptr [rsp+8],rbx
000007fb`988928b1 4889742410      mov     qword ptr [rsp+10h],rsi
000007fb`988928b6 57              push    rdi
000007fb`988928b7 4883ec20        sub     rsp,20h
000007fb`988928bb 488bf9          mov     rdi,rcx
000007fb`988928be 4885c9          test    rcx,rcx
000007fb`988928c1 7415            je      000007fb`988928d8
000007fb`988928c3 488d1556ed0100  lea     rdx,[000007fb`988b1620]
000007fb`988928ca ff15e8ac1100    call    qword ptr [000007fb`989ad5b8]
000007fb`988928d0 85c0            test    eax,eax
000007fb`988928d2 0f84979a0800    je      000007fb`9891c36f
000007fb`988928d8 4533c0          xor     r8d,r8d
000007fb`988928db 33d2            xor     edx,edx
000007fb`988928dd 488bcf          mov     rcx,rdi
000007fb`988928e0 ff153abf1100    call    qword ptr [000007fb`989ae820]
000007fb`988928e6 488b5c2430      mov     rbx,qword ptr [rsp+30h]
000007fb`988928eb 488b742438      mov     rsi,qword ptr [rsp+38h]
000007fb`988928f0 4883c420        add     rsp,20h
000007fb`988928f4 5f              pop     rdi
000007fb`988928f5 c3              ret
000007fb`988928f6 90              nop
000007fb`988928f7 90              nop
000007fb`988928f8 90              nop
000007fb`988928f9 90              nop
000007fb`988928fa 90              nop
000007fb`988928fb 90              nop
000007fb`988928fc 4883ec28        sub     rsp,28h
000007fb`98892900 ff156aac1100    call    qword ptr [000007fb`989ad570]
000007fb`98892906 3d0d0000c0      cmp     eax,0C000000Dh
000007fb`9889290b 0f84545c0400    je      000007fb`988d8565
000007fb`98892911 3d590000c0      cmp     eax,0C0000059h
000007fb`98892916 740a            je      000007fb`98892922
```

使用IDA查看`kernel32.dll`中的`LoadLibraryA`函数的汇编代码

![image-20220817163544040](https://img-blog.csdnimg.cn/cab87d26bf73420c818a198518fda99f.png)

```
kd> db /c 1 000007fb`988b1620 L10
000007fb`988b1620  74  t
000007fb`988b1621  77  w
000007fb`988b1622  61  a
000007fb`988b1623  69  i
000007fb`988b1624  6e  n
000007fb`988b1625  5f  _
000007fb`988b1626  33  3
000007fb`988b1627  32  2
000007fb`988b1628  2e  .
000007fb`988b1629  64  d
000007fb`988b162a  6c  l
000007fb`988b162b  6c  l
000007fb`988b162c  00  .
000007fb`988b162d  90  .
000007fb`988b162e  90  .
000007fb`988b162f  90  .
```

可以确定`0x000007fb988928ac`就是`LoadLibraryA`函数，插入成功

后面的`SystemArguments1`字段是QueueUserAPC的第三个参数，即传给LoadLibraryA函数的参数

```
kd> db /c 1 0x00000013`39f00000 L20
00000013`39f00000  43  C
00000013`39f00001  3a  :
00000013`39f00002  5c  \
00000013`39f00003  50  P
00000013`39f00004  72  r
00000013`39f00005  6f  o
00000013`39f00006  67  g
00000013`39f00007  72  r
00000013`39f00008  61  a
00000013`39f00009  6d  m
00000013`39f0000a  20   
00000013`39f0000b  46  F
00000013`39f0000c  69  i
00000013`39f0000d  6c  l
00000013`39f0000e  65  e
00000013`39f0000f  73  s
00000013`39f00010  5c  \
00000013`39f00011  37  7
00000013`39f00012  2d  -
00000013`39f00013  5a  Z
00000013`39f00014  69  i
00000013`39f00015  70  p
00000013`39f00016  5c  \
00000013`39f00017  37  7
00000013`39f00018  7a  z
00000013`39f00019  2e  .
00000013`39f0001a  64  d
00000013`39f0001b  6c  l
00000013`39f0001c  6c  l
00000013`39f0001d  00  .
00000013`39f0001e  00  .
00000013`39f0001f  00  .
```



没毛病



##### [NtQueueApcThread](https://github.com/wqreytuk/APC/blob/main/ApcDllInjector/ApcDllInjector.c#L131)



这个函数会被上面的QueueUserAPC函数调用，调用栈如下：

```
0033:000007f7`b2131378 ff159a1c0100    call    qword ptr [ApcDllInjector!_imp_QueueUserAPC (000007f7`b2143018)]
0033:000007f9`4bd63650 48ff2599a91100  jmp     qword ptr [KERNEL32!_imp_QueueUserAPC (000007f9`4be7dff0)]
0033:000007f9`497ffa88 ff1522950b00    call    qword ptr [KERNELBASE!_imp_NtQueueApcThread (000007f9`498b8fb0)]
ntdll!NtQueueApcThread:
0033:000007f9`4c572ff0 4c8bd1          mov     r10,rcx
```

注意上面的call和jmp指令后面的是取地址，当时看的时候人傻了，以为是直接跳到这个地址上，[闹笑话了](https://citrusice.github.io/)

![image-20220818160405056](https://img-blog.csdnimg.cn/a55d96cb8b6d4524a83d82474aa4bf5a.png)

这是一个没有文档的函数，俗称`Native API`



