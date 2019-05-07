# angrybird

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>今天就来讲讲一些anti-debug或者anti-run题，并且介绍一个非常简单的用angr绕过的办法——直接跳过。至于hook反调试函数的例子以后再更新，题目在文件里可以下载，那么用IDA打开看看可以看到是一长串判断正确的反汇编CFG图：</font></br>

![IDA CFG图](https://raw.githubusercontent.com/fangdada/learning-angr/master/ctf/%E5%8F%8Danti/IDA_CFG.png)

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>虽然程序也不算特别长，但是拿头逆的话非常累人，更何况这个还是anti-run的，用gdb调试的话需要不断的patch，非常麻烦，所以这里又需要用到我们的angr符号执行来解决了，先来看看main函数开头的反运行代码：</font></br>

```assembly
.text:0000000000400761 ; __unwind {
.text:0000000000400761                 push    rbp
.text:0000000000400762                 mov     rbp, rsp
.text:0000000000400765                 add     rsp, 0FFFFFFFFFFFFFF80h
.text:0000000000400769                 mov     rax, fs:28h
.text:0000000000400772                 mov     [rbp+var_8], rax
.text:0000000000400776                 xor     eax, eax
.text:0000000000400778                 cmp     eax, 0
.text:000000000040077B                 jz      _exit
.text:0000000000400781                 mov     [rbp+var_70], offset off_606018
.text:0000000000400789                 mov     [rbp+var_68], offset off_606020
.text:0000000000400791                 mov     [rbp+var_60], offset off_606028
.text:0000000000400799                 mov     [rbp+var_58], offset off_606038
.text:00000000004007A1                 mov     eax, 0
.text:00000000004007A6                 call    sub_4006F6
.text:00000000004007AB                 mov     [rbp+n], eax
.text:00000000004007AE                 mov     eax, 0
.text:00000000004007B3                 call    sub_40070C
.text:00000000004007B8                 mov     eax, 0
.text:00000000004007BD                 call    sub_40072A
.text:00000000004007C2                 mov     rdx, cs:stdin   ; stream
.text:00000000004007C9                 mov     ecx, [rbp+n]
.text:00000000004007CC                 lea     rax, [rbp+s]
.text:00000000004007D0                 mov     esi, ecx        ; n
.text:00000000004007D2                 mov     rdi, rax        ; s
.text:00000000004007D5                 call    _fgets
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>`xor eax, eax |	cmp eax, 0	|	jz _exit`这是摆明了要退出啊，继续往下看，`call sub_4006F6`函数只是单纯的输出一个字符串，而`call sub_40070C`则是栈检查，用gdb的话也是比较难以patch，直接跳过比较省事，最后`call sub_40072A`同样检查了一个栈上的字符串，这些都是对程序求解无关的反运行指令，如果用gdb的话可以直接到了main函数后跳过这一段代码，直接来到0x4007C2处从fgets函数开始。所以我们可以直接用angr完成上面这一部分工作：</font></br>

```python
import angr
 
START_ADDR = 0x4007c2
 
p = angr.Project('angrybird')
state = p.factory.entry_state()
sm=p.factory.successors(state,num_inst=1)
sm=sm.successors[0]

while sm.addr!=0x400776:
    sm=p.factory.successors(sm,num_inst=1)
    sm=sm.successors[0]

sm.regs.rip=START_ADDR
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>不过别忘了上面的anti-run有这样一段代码：</font></br>

```assembly
.text:0000000000400781                 mov     [rbp+var_70], offset off_606018
.text:0000000000400789                 mov     [rbp+var_68], offset off_606020
.text:0000000000400791                 mov     [rbp+var_60], offset off_606028
.text:0000000000400799                 mov     [rbp+var_58], offset off_606038
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这段是把一部分got表放入了栈里，如果不修复的话程序可能会出问题，因为按照程序逻辑这些got表里的地址也参与了运算，所以同样用angr修复一下：</font></br>

```python
sm.mem[state.regs.rbp - 0x70].long = 0x606018
sm.mem[state.regs.rbp - 0x68].long = 0x606020
sm.mem[state.regs.rbp - 0x60].long = 0x606028
sm.mem[state.regs.rbp - 0x58].long = 0x606038
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>完成这些工作之后就可以用run啦，如果输入正确，程序应当会输出"you typed: "这样开头的一串字符串，所以最后部分的angr脚本如下：</font></br>

```python
sim=p.factory.simulation_manager(sm)
sim.run()

for i in sim.deadended:
    if "you typed" in i.posix.dumps(1):
        print i.posix.dumps(0)
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>执行结果如下（忽视警告信息就行）：</font></br>

```shell
➜  temp python solve.py 
WARNING | 2019-03-26 11:10:08,757 | angr.analyses.disassembly_utils | Your version of capstone does not support MIPS instruction groups.
WARNING | 2019-03-26 11:10:51,808 | angr.state_plugins.symbolic_memory | Concretizing symbolic length. Much sad; think about implementing.
WARNING | 2019-03-26 11:11:11,470 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV64 (if (((0xffffffffffffffff + 0x0#32 .. mem_7fffffffffefefc_7_32)[63:7] == 0x0) && ((127 + mem_7fffffffffefefc_7_32[6:0]) <= 95)) then 0 else packet_0_stdin_8_2048[1287:1280]) .. (if (((0xffffffffffffffff + 0x0#32 .. mem_7fffffffffefefc_7_32)[63:7] == 0x0) && ((127 + mem_7fffffffffefefc_7_32[6:0]) <= 94)) then 0 else packet_0_stdin_8_2048[1295:1288]) .. (if (((0xffffffffffffffff + 0x0#32 .. mem_7fffffffffefefc_7_32)[63:7] == 0x0) && ((127 + mem_7fffffffffefefc_7_32[6:0]) <= 93)) then 0 else packet_0_stdin_8_2048[1303:1296]) .. (if (((0xffffffffffffffff + 0x0#32 .. mem_7fffffffffefefc_7_32)[63:7] == 0x0) && ((127 + mem_7fffffffffefefc_7_32[6:0]) <= 92)) then 0 else packet_0_stdin_8_2048[1311:1304]) .. (if (((0xffffffffffffffff + 0x0#32 .. mem_7fffffffffefefc_7_32)[63:7] == 0x0) && ((127 + mem_7fffffffffefefc_7_32[6:0]) <= 91)) then 4 else packet_0_stdin_8_2048[1319:1312]) .. (if (((0xffffffffffffffff + 0x0#32 .. mem_7fffffffffefefc_7_32)[63:7] == 0x0) && ((127 + mem_7fffffffffefefc_7_32[6:0]) <= 90)) then 0 else packet_0_stdin_8_2048[1327:1320]) .. (if (((0xffffffffffffffff + 0x0#32 .. mem_7fffffffffefefc_7_32)[63:7] == 0x0) && ((127 + mem_7fffffffffefefc_7_32[6:0]) <= 89)) then 0 else packet_0_stdin_8_2048[1335:1328]) .. (if (((0xffffffffffffffff + 0x0#32 .. mem_7fffffffffefefc_7_32)[63:7] == 0x0) && ((127 + mem_7fffffffffefefc_7_32[6:0]) <= 88)) then 72 else packet_0_stdin_8_2048[1343:1336])>
Im_so_cute&pretty_:)�������������������������������������
➜  temp       
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>完整脚本：</font></br>

```python
import angr
 
START_ADDR = 0x4007c2
 
p = angr.Project('angrybird')
state = p.factory.entry_state()
sm=p.factory.successors(state,num_inst=1)
sm=sm.successors[0]

while sm.addr!=0x400776:
    sm=p.factory.successors(sm,num_inst=1)
    sm=sm.successors[0]

sm.regs.rip=START_ADDR
sm.mem[state.regs.rbp - 0x70].long = 0x606018
sm.mem[state.regs.rbp - 0x68].long = 0x606020
sm.mem[state.regs.rbp - 0x60].long = 0x606028
sm.mem[state.regs.rbp - 0x58].long = 0x606038

#print sm.regs.rip
sim=p.factory.simulation_manager(sm)
sim.run()

for i in sim.deadended:
    if "you typed" in i.posix.dumps(1):
        print i.posix.dumps(0)
```

