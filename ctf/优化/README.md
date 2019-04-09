# 9447 nobranch

> <font size=2>(取自官方文档)</font>
>
> Q：为什么angr执行的这么慢？
>
> A：因为angr非常复杂！

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>许久不更新了，其中一个原因是前一段时间去学Linux kernel了，还有一种最主要的原因就是这个脚本当时看不懂2333，就搁置了一会儿，上次打完TCTF之后方向又转到angr来学习二进制了，花了一两天好好熟悉了一下angr就有了这篇优化的文章。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>为什么我们要优化呢？这不是一般吃饱了没事干做的事吗？写脚本就是图个方便为何要优化？错了，因为angr执行很慢，angr要考虑的事情非常多，为了更全面的测试二进制程序，angr牺牲了速度。开发者也为了优化angr的速度做出了一番努力，但我们在实际使用angr的时候也不能无脑explore，无论是CTF还是真实环境我们都要考虑**时间成本**和**路径爆炸**问题，路径爆炸问题本文就不介绍了，主要讲一下我遇到的angr优化的问题：</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>假设有如下代码：</font></br>

```C
__asm__ volatile("movq %0,%%rcx\t\n"
                 "leaq (%%rip),%%rdi\t\n"
                 "mov (%%rbx),%%al\t\n"
                 "test %%al,%%al\t\n"
                 "jz (0x8a9)\t\n"
                 "xor %1,%%al\t\n"
                 "mov %%al,(%%rbx)\t\n"
                 "inc %%rbx\t\n"
                 "jmp %%rdi\t\n"
                 "jmp %%rsi\t\n"
                 ::"r"((unsigned long)0),"r"((char)1)
                 :"rcx","rdi","rbx","rax","rsi");
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>（这题是从我最近出的题里改编来的2333）这段汇编很简单，就是对rbx指向的一个数组里面的元素逐个异或1而已，是最简单的加密。我把这段汇编放在栈里执行的时候用angr求解只需要几秒，这个速度是可以接受的，但是如果我加上这么短短一段代码dump数组数据：</font></br>

```C
for(char* ptr=buf;*ptr;ptr++)
{
    printf("0x%x,",*ptr);
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>angr所要执行的时间就会激增到65s！这就有点难以接受了，这么简单的加密却需要跑一分多钟，那么我们该怎么减小这个时间呢？我经过实验得出以下方法：</font></br>

- patch掉这些求解无用代码；
- 从使用Sim_Manager的run()方法改为explore并指定find和avoid地址；
- 减小符号变量的复杂度，也就是减小AST的深度（用于比较复杂的程序或者加密）；
- （**以下为新更新内容**）使用blank_state()只执行求解相关代码；
- 分段执行代码避免路径爆炸；
- hook函数。

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>那么我们一个个讲起吧，先从第一个开始，如何patch这些代码呢？直接修改二进制程序的话太过于麻烦了，我们直接在angr装载的内存空间里修改就行了，用state.memory.store()就可以做到，如下代码：</font></br>

```python
for i in range(0x4007db,0x400858):
    st.memory.store(i, 0x90,1)
op=st.memory.load(0x4007db)
print op

now=time.time()
print "patch:"+str(now-before)
# no patch:65s
# after: 19s
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>直接把机器码patch为无用的nop指令就行了，angr执行时间立马从漫长的65s减小到了19s！</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>第二个方法比较简单，一般只能省下不到1s的时间，除非程序路径非常多，按如下方式就能成功优化了：</font></br>

```python
# sm.run()
'''
out=b''
for pp in sm.deadended:
    out=pp.posix.dumps(1)
    print out
    if b'success' in out:
        print pp.posix.dumps(0)
'''

# 改为：
sm.explore(find=0x4008c6,avoid=0x4008e8)
print sm.found[0].posix.dumps(0)


```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>注释里的那一段代码主要是针对期望结果与程序输出有关的情况下才会使用，一般的话下面的explore就能简单快速的完成了。那么接下来看看高大上的第三个方法，解释原理之前先看看题目，也就是我们的题目nobranch。用IDA一打开直接就提示`Sorry, this node is too big to display`，代码段非常长，是经过了mov混淆的：</font></br>

```assembly
.text:0000000000400400 ; __unwind {
.text:0000000000400400                 push    r15
.text:0000000000400402                 mov     cs:byte_61606E, 0Ah
.text:0000000000400409                 push    r14
.text:000000000040040B                 push    r13
.text:000000000040040D                 push    r12
.text:000000000040040F                 push    rbp
.text:0000000000400410                 push    rbx
.text:0000000000400411                 mov     rcx, [rsi+8]
.text:0000000000400415                 movzx   eax, byte ptr [rcx+11h]
.text:0000000000400419                 and     eax, 3Fh
.text:000000000040041C                 mov     edx, eax
.text:000000000040041E                 shr     dl, 1
.text:0000000000400420                 movzx   edx, dl
..............................
..............................
..............................
.text:0000000000415197                 mov     cs:byte_616058, dl
.text:000000000041519D                 mov     edx, 1Fh        ; count
.text:00000000004151A2                 shr     al, 1
.text:00000000004151A4                 xor     eax, ebx
.text:00000000004151A6                 mov     cs:byte_61605D, al
.text:00000000004151AC                 mov     eax, 1
.text:00000000004151B1                 syscall                 ; LINUX - sys_write
.text:00000000004151B3                 pop     rbx
.text:00000000004151B4                 pop     rbp
.text:00000000004151B5                 pop     r12
.text:00000000004151B7                 pop     r13
.text:00000000004151B9                 pop     r14
.text:00000000004151BB                 xor     eax, eax
.text:00000000004151BD                 pop     r15
.text:00000000004151BF                 retn
.text:00000000004151BF ; } // starts at 400400
.text:00000000004151BF main            endp
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>八万五千多行的反汇编23333这谁顶得住啊，拿头逆吗？所以我们还是用angr吧，根据题目描述给定程序一个输入，输出应当是："HMQhQLi6VqgeOj78AbiaqquK3noeJt"，也就是说输入flag，输出这一行密文，看上去是hash算法类型的。那么我们只需要把符号变量作为输入，然后添加约束条件使输出为上面的值就行了。但是这么长的算法，最终生成的符号变量岂不是特别复杂，能求解吗？这个时候就需要优化一下，如下代码：</font></br>

```python
    while state.history.jumpkind == 'Ijk_Boring':                                                   # symbolically execute until we hit the syscall at the end
        i += 1
        print(i)
        ss = p.factory.successors(state, num_inst=1)                                                # only step one instruction at a time
        state = ss.successors[0]
        reg_names = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

        assert not state.regs.rsp.symbolic

        for reg_name in reg_names:                                                                  # for each register and memory location that matters in the program,
            val = state.registers.load(reg_name)                                               # after each step, if the symbolic AST for that value has become larger than
            if val.symbolic and val.depth > 3:                                                      # three nodes deep, stub it out by replacing it with a single symbolic value
                newval = claripy.BVS('replacement', len(val))                                       # constrained to be equal to the original value. This makes the constraints much
                state.solver.add(newval == val)                                                    # easier for z3 to bite into in smaller chunks. It might also indicate that there
                state.registers.store(reg_name, newval)                                        # some issues with angr's current usage of z3 :-)

        for mem_addr in list(range(outaddr, outaddr + 0x1f)) + [state.regs.rsp - x for x in range(0x40)]:
            val = state.memory.load(mem_addr, 1)
            if val.symbolic and val.depth > 3:
                newval = claripy.BVS('replacement', len(val))
                state.solver.add(newval == val)
                state.memory.store(mem_addr, newval)

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>state.history.jumpkind就是上条指令执行完后的跳转类型，如果是"Ijk_Boring"那就说明没有发生call，ret或者syscall这样的情况，而是普通的地址跳转（jz，jne，jg等）；p.factory.successors(state,num_inst=1)则代表每次执行一条指令，后面的for循环则是优化的逻辑了，每当参与符号执行的符号变量的计算AST深度达到3的时候，则另取一个新的符号变量添加约束为等于原来的值并替换，这是一个以空间度换复杂度的方法，若不懂claripy的AST深度看如下代码：</font></br>

```assembly
  40049b:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
  4004a2:	48 c7 c3 02 00 00 00 	mov    $0x2,%rbx
  4004a9:	48 c7 c1 03 00 00 00 	mov    $0x3,%rcx
  4004b0:	48 01 d8             	add    %rbx,%rax
  4004b3:	48 0f af c1          	imul   %rcx,%rax

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后用angr测试：</font></br>

```python
In [2]: import angr
   ...: import claripy
   ...: import monkeyhex
   ...: 
   ...: p=angr.Project('./AST')
   ...: initial_state=p.factory.entry_state()
   ...: 
   ...: sm=p.factory.successors(initial_state,num_inst=1)
   ...: sm=sm.successors[0]
   ...: 
   ...: while sm.addr!=0x4004b0:
   ...:     sm=p.factory.successors(sm,num_inst=1)
   ...:     sm=sm.successors[0]
   ...: 
   ...: sym1=claripy.BVS("sym1",64)
   ...: sym2=claripy.BVS("sym2",64)
   ...: sym3=claripy.BVS("sym3",64)
   ...: sm.registers.store("rax", sym1)
   ...: sm.registers.store("rbx", sym2)
   ...: sm.registers.store("rcx", sym3)
   ...: 
WARNING | 2019-03-25 23:52:53,721 | angr.analyses.disassembly_utils | Your version of capstone does not support MIPS instruction groups.

In [3]: sm.addr
Out[3]: 0x4004b0L

In [4]: sm.registers.load("rax").depth
Out[4]: 0x1

In [5]: sm=p.factory.successors(sm,num_inst=1)

In [6]: sm=sm.successors[0]

In [7]: sm.registers.load("rax").depth
Out[7]: 0x2

In [8]: sm=p.factory.successors(sm,num_inst=1)

In [9]: sm=sm.successors[0]

In [10]: sm.registers.load("rax").depth
Out[10]: 0x3

In [11]: 
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>AST中的叶节点就是符号变量，子节点为运算符号。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>我们回到nobranch的脚本，那一串for就是减小了插入寄存器和插入内存的符号变量的运算深度以获得更快的求解速度，所以这就是第三种优化方法，方法还有很多，要随机应变，这次就先讲到这吧，官方脚本的全部内容如下：</font></br>

```python
# coding: utf-8

#
# This file solves the problem `nobranch` from 9447 CTF 2015. It got the first blood solution!
# It takes a VERY long time to run! I took a well-deserved nap while it was solving :)
#

import angr, claripy
p = angr.Project('nobranch')
all_blocks = []
mainaddr = 0x400400
outaddr = 0x616050

shouldbe = 'HMQhQLi6VqgeOj78AbiaqquK3noeJt'

def main():
    state = p.factory.blank_state(addr=mainaddr, add_options={angr.options.LAZY_SOLVES})            # set up the initial state at the start of main
    state.memory.store(state.regs.rsp, claripy.BVV(0x4141414141414141, 64), endness='Iend_LE')      # set fake return address
    state.memory.store(state.regs.rsp + 8, state.regs.rsp + 64, endness='Iend_LE')                  # I can't remember if I even need this... better safe than sorry
    state.memory.store(state.regs.rsp + 16, claripy.BVV(0, 64), endness='Iend_LE')                  # see above

    state.memory.store(state.regs.rsp + 64, state.regs.rsp + 128, endness='Iend_LE')                # set first argv string pointer
    state.memory.store(state.regs.rsp + 72, state.regs.rsp + 129, endness='Iend_LE')                # set second argv string pointer
    state.memory.store(state.regs.rsp + 80, claripy.BVV(0, 64), endness='Iend_LE')

    state.memory.store(state.regs.rsp + 128, claripy.BVV(0, 8))                                     # set first argv string to the empty string
    flag = claripy.BVS('flag', 18*8)
    state.memory.store(state.regs.rsp + 129, flag)                                                  # set second argv string to symbolic flag!

    state.regs.rdi = 2                                                                              # set argc = 2
    state.regs.rsi = state.regs.rsp + 64                                                            # set argv = args
    state.regs.rdx = state.regs.rsp + 80                                                            # set envp = empty list

    i = 0
    while state.history.jumpkind == 'Ijk_Boring':                                                   # symbolically execute until we hit the syscall at the end
        i += 1
        print(i)
        ss = p.factory.successors(state, num_inst=1)                                                # only step one instruction at a time
        state = ss.successors[0]
        reg_names = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

        assert not state.regs.rsp.symbolic

        for reg_name in reg_names:                                                                  # for each register and memory location that matters in the program,
            val = state.registers.load(reg_name)                                               # after each step, if the symbolic AST for that value has become larger than
            if val.symbolic and val.depth > 3:                                                      # three nodes deep, stub it out by replacing it with a single symbolic value
                newval = claripy.BVS('replacement', len(val))                                       # constrained to be equal to the original value. This makes the constraints much
                state.solver.add(newval == val)                                                    # easier for z3 to bite into in smaller chunks. It might also indicate that there
                state.registers.store(reg_name, newval)                                        # some issues with angr's current usage of z3 :-)

        for mem_addr in list(range(outaddr, outaddr + 0x1f)) + [state.regs.rsp - x for x in range(0x40)]:
            val = state.memory.load(mem_addr, 1)
            if val.symbolic and val.depth > 3:
                newval = claripy.BVS('replacement', len(val))
                state.solver.add(newval == val)
                state.memory.store(mem_addr, newval)

    fstate = state.copy()
    fstate.solver._solver.timeout = 0xfffffff                                                           # turn off z3's timeout for solving :^)
    for i, c in enumerate(shouldbe):
        fstate.solver.add(fstate.memory.load(0x616050 + i, 1) == ord(c))                                # constrain the output to what we were told it should be

    cflag = bytes.fromhex(hex(fstate.solver.eval(flag))[2:])                                        # solve for the flag!
    return cflag

def test():
    f = main()
    assert f.startswith(b'9447{') and f.endswith(b'}')
    # lol I don't have the flag onhand and I don't want to wait hours for it to re-solve :P
    # you can verify it by running ./nobranch `cat flag`
    # and verifying that it prints out the shouldbe value at the top

if __name__ == '__main__':
    print(main())
```

***

**更新**

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>如何使用blank_state()优化时间复杂呢？假如有以下代码需要探索（n1为全局变量无需操作）：</font></br>

```C
unsigned __int64 __fastcall secret_phase(__int64 a1)
{
  const char *v1; // rdi
  unsigned int v2; // ebx

  v1 = (const char *)read_line(a1);
  v2 = strtol(v1, 0LL, 10);
  if ( v2 - 1 > 0x3E8 )
    explode_bomb(v1, 0LL);
  if ( (unsigned int)fun7(&n1, v2) != 2 )
    explode_bomb(&n1, v2);
  puts("Wow! You've defused the secret stage!");
  return phase_defused();
}
```

```assembly
.text:0000000000401242                 public secret_phase
.text:0000000000401242 secret_phase    proc near               ; CODE XREF: phase_defused+6C↓p
.text:0000000000401242 ; __unwind {
.text:0000000000401242                 push    rbx
.text:0000000000401243                 call    read_line
.text:0000000000401248                 mov     edx, 0Ah        ; base
.text:000000000040124D                 mov     esi, 0          ; endptr
.text:0000000000401252                 mov     rdi, rax        ; nptr
.text:0000000000401255                 call    _strtol
.text:000000000040125A                 mov     rbx, rax
.text:000000000040125D                 lea     eax, [rax-1]
.text:0000000000401260                 cmp     eax, 3E8h
.text:0000000000401265                 jbe     short loc_40126C
.text:0000000000401267                 call    explode_bomb
.text:000000000040126C ; ---------------------------------------------------------------------------
.text:000000000040126C
.text:000000000040126C loc_40126C:                             ; CODE XREF: secret_phase+23↑j
.text:000000000040126C                 mov     esi, ebx
.text:000000000040126E                 mov     edi, offset n1
.text:0000000000401273                 call    fun7
.text:0000000000401278                 cmp     eax, 2
.text:000000000040127B                 jz      short loc_401282
.text:000000000040127D                 call    explode_bomb
.text:0000000000401282 ; ---------------------------------------------------------------------------
.text:0000000000401282
.text:0000000000401282 loc_401282:                             ; CODE XREF: secret_phase+39↑j
.text:0000000000401282                 mov     edi, offset aWowYouVeDefuse ; "Wow! You've defused the secret stage!"
.text:0000000000401287                 call    _puts
.text:000000000040128C                 call    phase_defused
.text:0000000000401291                 pop     rbx
.text:0000000000401292                 retn
.text:0000000000401292 ; } // starts at 401242
.text:0000000000401292 secret_phase    endp
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>我们可以直接跳过前面一大段代码从strtol后的返回值处插入符号变量进行执行，只需要在fun7函数的调用处将rsi设置为我们的符号变量地址，相应实现如下：</font></br>

```python
import angr
import claripy

start=0x40125A
end=0x401282
avoid=0x40143a

p=angr.Project('./bomb')
state=p.factory.blank_state(addr=start)

flag=claripy.BVS("flag",64,explicit_name=True)
state.regs.rax=flag
state.add_constraints(flag-1<=0x3E8)

sm=p.factory.simulation_manager(state)
sm.explore(find=end,avoid=avoid)

found=sm.found[0]
print(found.solver.eval(flag))
# cost:1.2971761226654053
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>以hook函数的方法来做就是这样：</font></br>

```python
class readline_hook(angr.SimProcedure):
    def run(self):
        pass

class strtol_hook(angr.SimProcedure):
    def run(self, str, end, base):
        return self.state.solver.BVS("flag", 64, explicit_name=True)

def solve_secret():
    start = 0x401242
    find = 0x401282
    avoid = (0x40127d, 0x401267,)
    readline = 0x40149e
    strtol = 0x400bd0

    p = angr.Project("./bomb", auto_load_libs=False)
    p.hook(readline, readline_hook())
    p.hook(strtol, strtol_hook())
    state = p.factory.blank_state(addr=start, remove_options={angr.options.LAZY_SOLVES})
    flag = claripy.BVS("flag", 64, explicit_name=True)
    state.add_constraints(flag -1 <= 0x3e8)
    sm = p.factory.simulation_manager(state)
    sm.explore(find=find, avoid=avoid)
    ### flag found
    found = sm.found[0]
    flag = found.solver.BVS("flag", 64, explicit_name="True")
    return str(found.solver.eval(flag))
  # cost:1.3441410064697266
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>上面就是利用blank_state()和hook函数优化的时间耗费数，如果用最简单的explore直接探索的话，结果如下：</font></br>

```python
import angr
import time

before=time.time()
p=angr.Project('./bomb')
state=p.factory.blank_state(addr=0x401242)

sm=p.factory.simulation_manager(state)
sm.explore(find=0x401282,avoid=(0x40127d,0x401267,))
after=time.time()

found=sm.found[0]

found.add_constraints(found.regs.rbx-1<=0x3e8)
print(found.solver.eval(found.regs.rbx))
print("cost:"+str(after-before))

# Out[6]: <SimulationManager with 349 active, 1 found, 97 avoid>
# cost:116.71986317634583
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>探索路径结果竟达到了超过400条！产生的时间消耗竟接近120s！所以优化还是很有必要的，不要无脑explore 23333。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>路径分段的优化其实是非常简单的，思路就是把一块代码分为两段执行，先探索第一段，然后取其found路径，在其基础上再次进行explore，可以避免很多一级无效路径产生的二级无效路径（只是我自己这么称呼2333），这样就能减少需要探索的路径进而减少时间复杂度。代码如下：</font></br>

```C
__int64 __fastcall phase_6(__int64 a1)
{
  int *v1; // r13
  signed int v2; // er12
  signed int v3; // ebx
  char *v4; // rax
  unsigned __int64 v5; // rsi
  _QWORD *v6; // rdx
  signed int v7; // eax
  int v8; // ecx
  __int64 v9; // rbx
  char *v10; // rax
  __int64 i; // rcx
  __int64 v12; // rdx
  signed int v13; // ebp
  __int64 result; // rax
  int v15[6]; // [rsp+0h] [rbp-78h]
  char v16; // [rsp+18h] [rbp-60h]
  __int64 v17; // [rsp+20h] [rbp-58h]
  char v18; // [rsp+28h] [rbp-50h]
  char v19; // [rsp+50h] [rbp-28h]

  v1 = v15;
  read_six_numbers(a1, v15);
  v2 = 0;
  while ( 1 )
  {
    if ( (unsigned int)(*v1 - 1) > 5 )
      explode_bomb(a1, v15);
    if ( ++v2 == 6 )
      break;
    v3 = v2;
    do
    {
      if ( *v1 == v15[v3] )
        explode_bomb(a1, v15);
      ++v3;
    }
    while ( v3 <= 5 );
    ++v1;
  }
  v4 = (char *)v15;
  do
  {
    *(_DWORD *)v4 = 7 - *(_DWORD *)v4;
    v4 += 4;
  }
  while ( v4 != &v16 );
  // 第一次探索到这
  v5 = 0LL;
  do
  {
    v8 = v15[v5 / 4];
    if ( v8 <= 1 )
    {
      v6 = &node1;
    }
    else
    {
      v7 = 1;
      v6 = &node1;
      do
      {
        v6 = (_QWORD *)v6[1];
        ++v7;
      }
      while ( v7 != v8 );
    }
    *(__int64 *)((char *)&v17 + 2 * v5) = (__int64)v6;
    v5 += 4LL;
  }
  while ( v5 != 24 );
  v9 = v17;
  v10 = &v18;
  for ( i = v17; ; i = v12 )
  {
    v12 = *(_QWORD *)v10;
    *(_QWORD *)(i + 8) = *(_QWORD *)v10;
    v10 += 8;
    if ( v10 == &v19 )
      break;
  }
  *(_QWORD *)(v12 + 8) = 0LL;
  v13 = 5;
  do
  {
    result = **(unsigned int **)(v9 + 8);
    if ( *(_DWORD *)v9 < (signed int)result )
      explode_bomb(a1, &v19);
    v9 = *(_QWORD *)(v9 + 8);
    --v13;
  }
  while ( v13 );
  return result;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>可以先用angr探索到注释处，然后取其found，然后探索到末尾，代码如下：</font></br>

```python
def solve_flag_6():
    start = 0x4010f4
    read_num = 0x40145c

    #split the function to two parts to avoid path explosion
    find1 = 0x401188
    find2 = 0x4011f7

    avoid = 0x40143A
    p = angr.Project("./bomb", auto_load_libs=False)
    p.hook(read_num, read_6_ints())
    state = p.factory.blank_state(addr=start, remove_options={angr.options.LAZY_SOLVES})
    sm = p.factory.simulation_manager(state)

    # enumerate all possible paths in the first part
    while len(sm.active) > 0:
        sm.explore(find=find1, avoid=avoid)

    # dive further to part2
    found_list = sm.found
    for found in found_list:
        sm = p.factory.simulation_manager(found)
        sm.explore(find=find2, avoid=avoid)
        if len(sm.found) > 0:
            found = sm.found[0]
            break

    answer = [found.solver.eval(x) for x in read_6_ints.answer_ints]
    return ' '.join(map(str, answer))
```

***

# C++优化

> 相应文件可在[angr学习 第十一节求解C++](<https://fanda.cloud/2019/04/09/angr%E5%AD%A6%E4%B9%A0-%E7%AC%AC%E5%8D%81%E4%B8%80%E8%8A%82%E6%B1%82%E8%A7%A3c/>)里下载

##csaw_wyvern

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这一节我们来学习如何用angr应对C++程序，angr自己只实现了一些常用的C函数，而没有C++函数，所以在遇到C++的题时用常规的做法是非常耗时间的（因为angr需要一直执行C++的库函数直到遇到C++库函数底层调用的C函数部分）。在进入正题之前我们先来看一个demo：</font></br>

```C
#include <iostream>

int main()
{
	using namespace std;
	int a;
	int b;

	cout<<"hello"<<endl;

	cin>>a;
	cout<<"get your input!"<<endl;	//在此处测试angr执行C++库函数的速度
	if(a==2)
		cout<<"good"<<endl;
	else
		cout<<"failed"<<endl;

	return 0;
}

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这是一个非常简单的C++程序，接受单个输入，然后判断是否为2。按照我以前的做法，肯定是直接在if前生成blank_state瞬间就可以破了这个demo，但是我们要检验一下angr执行C++库函数的效率，所以我们先用以下脚本尝试执行看需要耗费多少时间：</font></br>

```python
import angr
import claripy
import time

start=0x4008c1
end=0x4008fe
avoid=0x400932

before=time.time()
p=angr.Project('./test')
state=p.factory.blank_state(addr=start)

state.regs.rbp=state.regs.rsp
state.regs.rsp=state.regs.rsp-0x40
state.mem[state.regs.rbp-0x8].int=claripy.BVS("flag1",32,explicit_name=True)

sm=p.factory.simulation_manager(state)
sm.explore(find=end,avoid=avoid)
after=time.time()

print("cost:"+str(after-before))
found=sm.found[0]
print(found.solver.eval(claripy.BVS("flag1",32,explicit_name=True),cast_to=int))

'''
balabalabalabala.......lots of warnings!
........................................
WARNING | 2019-04-08 19:25:59,203 | angr.state_plugins.symbolic_memory | Filling memory at 0xffffffffffffffd6 with 8 unconstrained bytes
WARNING | 2019-04-08 19:25:59,343 | angr.state_plugins.symbolic_memory | Filling memory at 0xfe00000000000060 with 8 unconstrained bytes
WARNING | 2019-04-08 19:25:59,619 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV64 mem_fe00000000000060_155_64{UNINITIALIZED}>
cost:31.564738273620605
2
'''
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>程序生成了大量的warning，光一个cout输出一个字符串和一个换行符就执行了超过30s！这要是C实现的秒解好吧。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>那么什么是angr解C++的正确做法呢？首先我们需要用`full_init_state()`来初始化程序，而不是用`blank_state()`，否则angr在执行程序的时候会花相当多的时间耗费在C++库函数的探索上。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>我们改一下代码改成如下所示，使用`full_init_state()`初始化程序，然后使用run方法探索：</font></br>

```python
import angr
import claripy
import time

before=time.time()
p=angr.Project('./test')
flag=claripy.BVS("flag",8,explicit_name=True)
state=p.factory.full_init_state(args=['./test'],stdin=flag)

sm=p.factory.simulation_manager(state)
sm.run()
after=time.time()
print("cost:"+str(after-before))
# cost:74.04902362823486
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>额，时间怎么要这么久？因为`full_init_state()`会加载所有的库然后到装载器的一个空间里执行一些类似初始化操作，然后再跑到入口处开始执行，形象一点的话代码如下：</font></br>

```python
import angr
import time

p=angr.Project('./test')

state=p.factory.full_init_state()
sm=p.factory.successors(state,num_inst=1)
sm=sm.successors[0]

before=time.time()
while sm.addr!=0x400870:
    sm=p.factory.successors(sm,num_inst=1)
    sm=sm.successors[0]
after=time.time()

print("step to main cost:"+str(after-before))
# step to main cost:113.31757998466492

before=time.time()
sm=p.factory.simulation_manager(sm)
sm.explore(find=0x4008aa) # 从main开头执行完第一个cout<<"hello"<<endl;函数
after=time.time()

print("cout<<strings<<end cost:"+str(after-before))
# cout<<strings<<end cost:1.9847142696380615
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>与第一个`blank_state()`相比，不算初始化的话，差距达到了近**16:1**！所以如果是比较大型的二进制程序的话，建议用`full_init_state()`装载执行。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>那么还有没有再次提升的办法呢？有！用unicorn引擎进行装载执行。将之前直接用run方法的代码加上一个`add_options=angr.options.unicorn`就行了，看看时间消耗：</font></br>

```python
import angr
import claripy
import time

before=time.time()
p=angr.Project('./test')
flag=claripy.BVS("flag",8,explicit_name=True)
state=p.factory.full_init_state(args=['./test'],add_options=angr.options.unicorn
,stdin=flag)

sm=p.factory.simulation_manager(state)
sm.run()
after=time.time()
print("cost:"+str(after-before))
# cost:17.34348964691162

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>非常可观的时间优化，执行完所有的路径探索甚至比`blank_state()`光光执行两个cout还要快，所以一般遇到这类C++写的二进制程序时应当使用angr的unicorn引擎加载，执行指令非常快，只不过缺点可能就是无法像`blank_state()`那样指定一段地址执行了。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这里插一个题外话，要再次提速可以试试用pypy，把python转为JIT执行，会进一步缩小脚本执行时间（后来我笔记本快没电了2333，实际上正式题目中pypy可以缩小很多时间耗费，不信看下面的正式题目），搭建这个只需要几步即可：</font></br>

```shell
wget https://bitbucket.org/pypy/pypy/downloads/pypy3.6-v7.1.0-linux64.tar.bz2
tar -xvf pypy3.6-v7.1.0-linux64.tar.bz2
# 可以直接设置pypy的bin目录进入环境变量，就可以直接通过pypy3使用了
wget https://bootstrap.pypa.io/get-pip.py
pypy3 get-pip.py
pypy3 -m pip install angr
# 然后就可以正常使用了，相当于pypy3来替代python3
<pypy3 your_scripy.py>
# 例如
➜  test pypy3 c++.py
cost:17.257989168167114
```

***

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>在上面扯完了C++在angr中的不同之处和优化后，我们正式来看看这道题目：</font></br>

**main**

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // ST24_4
  __int64 v4; // rdx
  char v6; // [rsp+80h] [rbp-140h]
  char v7; // [rsp+88h] [rbp-138h]
  char v8; // [rsp+A0h] [rbp-120h]
  char v9; // [rsp+A8h] [rbp-118h]
  char s; // [rsp+B0h] [rbp-110h]
  int v11; // [rsp+1BCh] [rbp-4h]

  v11 = 0;
  std::operator<<<std::char_traits<char>>(&std::cout, (unsigned int)"+-----------------------+\n", envp);
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    (unsigned int)"|    Welcome Hero       |\n",
    "|    Welcome Hero       |\n");
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    (unsigned int)"+-----------------------+\n\n",
    "+-----------------------+\n\n");
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    (unsigned int)"[!] Quest: there is a dragon prowling the domain.\n",
    "[!] Quest: there is a dragon prowling the domain.\n");
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    (unsigned int)"\tbrute strength and magic is our only hope. Test your skill.\n\n",
    "\tbrute strength and magic is our only hope. Test your skill.\n\n");
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    (unsigned int)"Enter the dragon's secret: ",
    "Enter the dragon's secret: ");
  fgets(&s, 257, stdin);
  std::allocator<char>::allocator(&v8, 257LL);
  std::string::string(&v9, &s, &v8);
  std::allocator<char>::~allocator(&v8);
  std::string::string((std::string *)&v7, (const std::string *)&v9);
  v3 = start_quest((std::string *)&v7);
  std::string::~string((std::string *)&v7);
  if ( v3 == 4919 )
  {
    std::string::string((std::string *)&v6, (const std::string *)&v9);
    reward_strength(&v6, &v9);
    std::string::~string((std::string *)&v6);
  }
  else
  {
    std::operator<<<std::char_traits<char>>(
      &std::cout,
      (unsigned int)"\n[-] You have failed. The dragon's power, speed and intelligence was greater.\n",
      v4);
  }
  v11 = 0;
  std::string::~string((std::string *)&v9);
  return v11;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>其中对输入加密有关的函数是`start_quest()`，这个函数经过大量混淆，拿头逆是不可能的，肯定要借助某些工具或者方法，那么用angr我们就可以很简单的探索出我们需要的预期解，也就是输出"success"。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>整个程序除了混淆的函数比较复杂之外，没有什么angr需要特别绕过的地方（比如置换表或者计数等会路径爆炸的东西，这都是angr的天敌），所以只需要用类似之前的办法，利用一个stdin传入符号变量就能约束求解了，完整脚本如下：</font></br>

```python
#!/usr/bin/env python
# coding: utf-8
import angr
import claripy
import time

def main():
    # Load the binary. This is a 64-bit C++ binary, pretty heavily obfuscated.
    # its correct emulation by angr depends heavily on the libraries it is loaded with,
    # so if this script fails, try copying to this dir the .so files from our binaries repo:
    # https://github.com/angr/binaries/tree/master/tests/x86_64
    p = angr.Project('wyvern')

    # It's reasonably easy to tell from looking at the program in IDA that the key will
    # be 29 bytes long, and the last byte is a newline. Let's construct a value of several
    # symbols that we can add constraints on once we have a state.

    flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(28)]
    flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

    # This block constructs the initial program state for analysis.
    # Because we're going to have to step deep into the C++ standard libraries
    # for this to work, we need to run everyone's initializers. The full_init_state
    # will do that. In order to do this peformantly, we will use the unicorn engine!
    st = p.factory.full_init_state(
            args=['./wyvern'],
            add_options=angr.options.unicorn,
            stdin=flag,
    )

    # Constrain the first 28 bytes to be non-null and non-newline:
    for k in flag_chars:
        st.solver.add(k != 0)
        st.solver.add(k != 10)

    # Construct a SimulationManager to perform symbolic execution.
    # Step until there is nothing left to be stepped.
    sm = p.factory.simulation_manager(st)
    sm.run()

    # Get the stdout of every path that reached an exit syscall. The flag should be in one of these!
    out = b''
    for pp in sm.deadended:
        out = pp.posix.dumps(1)
        if b'flag{' in out:
            return next(filter(lambda s: b'flag{' in s, out.split()))

    # Runs in about 15 minutes!

def test():
    assert main() == b'flag{dr4g0n_or_p4tric1an_it5_LLVM}'

if __name__ == "__main__":
    before = time.time()
    print(main())
    after = time.time()
    print("Time elapsed: {}".format(after - before))
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>我们看看pypy3和python3跑这个脚本的时间消耗：</font></br>

```shell
➜  csaw_wyvern git:(master) python3 solve.py
WARNING | 2019-04-09 10:00:03,175 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2019-04-09 10:00:03,175 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2019-04-09 10:00:03,175 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2019-04-09 10:00:03,175 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2019-04-09 10:00:03,175 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2019-04-09 10:00:03,176 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffeff00 with 8 unconstrained bytes
WARNING | 2019-04-09 10:00:03,544 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0012b38 with 29 unconstrained bytes
WARNING | 2019-04-09 10:00:07,612 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0012c6a with 29 unconstrained bytes
WARNING | 2019-04-09 10:03:06,081 | angr.state_plugins.symbolic_memory | Filling memory at 0xc00133f4 with 28 unconstrained bytes
WARNING | 2019-04-09 10:03:06,574 | angr.state_plugins.symbolic_memory | Filling memory at 0xc001344f with 27 unconstrained bytes
WARNING | 2019-04-09 10:03:07,001 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0013483 with 65 unconstrained bytes
b'flag{dr4g0n_or_p4tric1an_it5_LLVM}'
Time elapsed: 195.80076503753662
```

```shell
➜  csaw_wyvern git:(master) pypy3 solve.py
WARNING | 2019-04-09 00:50:54,196 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2019-04-09 00:50:54,196 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2019-04-09 00:50:54,196 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2019-04-09 00:50:54,196 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2019-04-09 00:50:54,197 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2019-04-09 00:50:54,197 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffeff00 with 8 unconstrained bytes referenced from 0x409dc70 (strlen+0x0 in libc.so.6 (0x9dc70))
WARNING | 2019-04-09 00:50:55,275 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0012b38 with 29 unconstrained bytes referenced from 0x40bb460 (memcpy+0x0 in libc.so.6 (0xbb460))
WARNING | 2019-04-09 00:50:59,297 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0012c6a with 29 unconstrained bytes referenced from 0x40bb460 (memcpy+0x0 in libc.so.6 (0xbb460))
WARNING | 2019-04-09 00:52:07,921 | angr.state_plugins.symbolic_memory | Filling memory at 0xc00133f4 with 28 unconstrained bytes referenced from 0x40bb460 (memcpy+0x0 in libc.so.6 (0xbb460))
WARNING | 2019-04-09 00:52:08,402 | angr.state_plugins.symbolic_memory | Filling memory at 0xc001344f with 27 unconstrained bytes referenced from 0x40bb460 (memcpy+0x0 in libc.so.6 (0xbb460))
WARNING | 2019-04-09 00:52:08,985 | angr.state_plugins.heap.heap_base | Allocation request of 155 bytes exceeded maximum of 128 bytes; allocating 155 bytes
WARNING | 2019-04-09 00:52:09,064 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0013483 with 65 unconstrained bytes referenced from 0x40bb460 (memcpy+0x0 in libc.so.6 (0xbb460))
b'flag{dr4g0n_or_p4tric1an_it5_LLVM}'
Time elapsed: 92.14751529693604
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>综上，遇到C++程序优化方法可以如下：</font></br>

- 使用`full_init_state(add_options=angr.options.unicorn)`装载程序；
- 使用pypy运行脚本