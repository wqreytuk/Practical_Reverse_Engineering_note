Title: Practical Reverse Engineering notes -- Part II
Date: 2022-08-05
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



