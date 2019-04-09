# bomb

## 常规hook

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这是一个二进制炸弹，一共有6个关卡加一个隐藏关卡，我们在这里用angr一层一层解，设计到了hook，堆栈操作，CFG，获取函数符号等。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>那么我们就从main函数开始看起：</font></br>

```C
// local variable allocation has failed, the output may be wrong!
int __cdecl main(int argc, const char **argv, const char **envp)
{
  const char **v3; // rbx
  const char *v4; // rcx
  __int64 v5; // rdi
  __int64 v6; // rdi
  __int64 v7; // rdi
  __int64 v8; // rdi
  __int64 v9; // rdi
  __int64 v10; // rdi

  if ( argc == 1 )
  {
    infile = (FILE *)stdin;
  }
  else
  {
    v3 = argv;
    if ( argc != 2 )
    {
      __printf_chk(1LL, "Usage: %s [<input_file>]\n", *argv);
      exit(8);
    }
    *(_QWORD *)&argc = argv[1];
    argv = (const char **)"r";
    infile = fopen(*(const char **)&argc, "r");
    if ( !infile )
    {
      v4 = v3[1];
      __printf_chk(1LL, "%s: Error: Couldn't open %s\n", *v3);
      exit(8);
    }
  }
  initialize_bomb(*(_QWORD *)&argc, argv, envp);
  puts("Welcome to my fiendish little bomb. You have 6 phases with");
  puts("which to blow yourself up. Have a nice day!");
  v5 = read_line("which to blow yourself up. Have a nice day!");
  phase_1(v5);
  phase_defused(v5);
  puts("Phase 1 defused. How about the next one?");
  v6 = read_line("Phase 1 defused. How about the next one?");
  phase_2(v6);
  phase_defused(v6);
  puts("That's number 2.  Keep going!");
  v7 = read_line("That's number 2.  Keep going!");
  phase_3(v7);
  phase_defused(v7);
  puts("Halfway there!");
  v8 = read_line("Halfway there!");
  phase_4(v8);
  phase_defused(v8);
  puts("So you got that one.  Try this one.");
  v9 = read_line("So you got that one.  Try this one.");
  phase_5(v9);
  phase_defused(v9);
  puts("Good work!  On to the next...");
  v10 = read_line("Good work!  On to the next...");
  phase_6(v10);
  phase_defused(v10);
  return 0;
}
```

**phase\_1**

```C
__int64 __fastcall phase_1(__int64 a1)
{
  __int64 result; // rax

  result = strings_not_equal((_BYTE *)a1, "Border relations with Canada have never been better.");
  if ( (_DWORD)result )
    explode_bomb(a1, "Border relations with Canada have never been better.");
  return result;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这个strings_not_equal实际上就是strcmp，里面还内置了一个strlen，只不过这两个函数都是自己实现的，那么我们用angr求解的时候可以直接hook strings_not_equal为libc标准函数strcmp来加快速度，（所以第一关其实就是一个非常简单的字符串相同的判断）。然后就是常规的explore：</font></br>

```python
import angr
import claripy

start=0x400EE0
end=0x400EF7
explode_bomb=0x40143A
strings_not_equal=0x401338
strings_addr=0x603780

p=angr.Project('./bomb')
# hook the strings_not_equal
p.hook(strings_not_equal,angr.SIM_PROCEDURES['libc']['strcmp']())

initial_state=p.factory.blank_state(addr=start)

flag1=claripy.BVS("flag1",128*8)
initial_state.memory.store(strings_addr,flag1)
initial_state.regs.rdi=strings_addr

sim=p.factory.simulation_manager(initial_state)
sim.explore(find=end,avoid=explode_bomb)

print(sim.found[0].solver.eval(flag1,cast_to=bytes).split(b'\x00')[0])
# Border relations with Canada have never been better.
```

**phase\_2**

```C
__int64 __fastcall phase_2(__int64 a1)
{
  __int64 result; // rax
  char *v2; // rbx
  int v3; // [rsp+0h] [rbp-38h]
  char v4; // [rsp+4h] [rbp-34h]
  char v5; // [rsp+18h] [rbp-20h]

  read_six_numbers(a1, &v3);
  if ( v3 != 1 )
    explode_bomb(a1, &v3);
  v2 = &v4;
  do
  {
    result = (unsigned int)(2 * *((_DWORD *)v2 - 1));
    if ( *(_DWORD *)v2 != (_DWORD)result )
      explode_bomb(a1, &v3);
    v2 += 4;
  }
  while ( v2 != &v5 );
  return result;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>那么第一关通过了，我们来看看第二关，这一关的read_six_numbers顾名思义，从a1（是之前read_line()得到的字符串）这个字符串里解析出六个数放在以v3起始的地址上，然后第一个数必须为1，剩下的数判断在do while循环里，可以很清楚的看到必须符合一个等式：input[n]==2**input[n-1]。稍微思考一下就知道输入序列是：1 2 4 8 16 32，接下来看看angr怎么解：</font></br>

```python
import angr
import claripy

start=0x400f0a
explode_bomb=0x40143a
end=0x400f3c

p=angr.Project('./bomb',auto_load_libs=False)
initial_state=p.factory.blank_state(addr=0x400f0a)

for i in range(6):
    initial_state.stack_push(initial_state.solver.BVS("int{}".format(i),32))

sim=p.factory.simulation_manager(initial_state)
sim.explore(find=end,avoid=explode_bomb)

found=sim.found[0]
flag2=[]

for i in range(3):
    cur_int=found.solver.eval(found.stack_pop())

    flag2.append(str(cur_int&0xFFFFFFFF))
    flag2.append(str(cur_int>>32&0xFFFFFFFF))


print(' '.join(flag2))
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>read_six_number之后六个数字以int类型保存在栈上，所以我们以blank_state加载到read函数后的地址上时可以手动push六个符号变量进去模拟之前读入的六个数字，然后常规explore之后可以再pop出来计算约束解。</font></br>

**phase\_3**

```C
signed __int64 __fastcall phase_3(__int64 a1)
{
  signed __int64 result; // rax
  int v2; // [rsp+8h] [rbp-10h]
  int v3; // [rsp+Ch] [rbp-Ch]

  if ( (signed int)__isoc99_sscanf(a1, "%d %d", &v2, &v3) <= 1 )
    explode_bomb(a1, "%d %d");
  switch ( v2 )
  {
    case 0:
      result = 207LL;
      break;
    case 1:
      result = 311LL;
      break;
    case 2:
      result = 707LL;
      break;
    case 3:
      result = 256LL;
      break;
    case 4:
      result = 389LL;
      break;
    case 5:
      result = 206LL;
      break;
    case 6:
      result = 682LL;
      break;
    case 7:
      result = 327LL;
      break;
    default:
      explode_bomb(a1, "%d %d");
      return result;
  }
  if ( (_DWORD)result != v3 )
    explode_bomb(a1, "%d %d");
  return result;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这题同样也是十分简单，只要输入case和result对应的数字就能过了这一关了，但是我们是出于学习angr的目的来做的，所以我们来看看angr的求解脚本：</font></br>

```python
import angr
import claripy

start=0x400f6a
end=0x400fc9
explode_bomb=0x40143a

p=angr.Project('./bomb')

initial_state=p.factory.blank_state(addr=start)

sm=p.factory.simulation_manager(initial_state)
sm.explore(find=end,avoid=explode_bomb)

flag={}

for i in sm.found:
    i.stack_pop()
    data=i.solver.eval(i.stack_pop(),cast_to=int)

    cmd=data&0xFFFFFFFF
    num=(data>>32)&0xFFFFFFFF
    flag[cmd]=num

for i in sm.active:
    if i.addr!=end:
        continue
    i.stack_pop()
    data=i.solver.eval(i.stack_pop(),cast_to=int)

    cmd=data&0xFFFFFFFF
    num=(data>>32)&0xFFFFFFFF
    flag[cmd]=num

for i in set(flag):
    print("{}:{} ".format(i,flag[i]))
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>因为我们的目的是要得到所有的解，所以简单的explore之后会有很多active路径，我们要遍历所有的路径然后把解都收集起来，至于如何取出我们想要的包含着解的符号变量就要因题目而异，在这里我们想要的两个4字节变量存放在rsp偏移8字节的地址上，所以只需要pop两次，第二次pop出来的8字节数据就存放着case和result。</font></br>

**phase\_4**

```C
__int64 __fastcall phase_4(__int64 a1)
{
  __int64 v1; // rdi
  __int64 result; // rax
  unsigned int v3; // [rsp+8h] [rbp-10h]
  int v4; // [rsp+Ch] [rbp-Ch]

  if ( (unsigned int)__isoc99_sscanf(a1, "%d %d", &v3, &v4) != 2 || v3 > 0xE )
    explode_bomb(a1, "%d %d");
  v1 = v3;
  result = func4(v3, 0LL, 14LL);
  if ( (_DWORD)result || v4 )
    explode_bomb(v1, 0LL);
  return result;
}


__int64 __fastcall func4(__int64 a1, __int64 a2, __int64 a3)
{
  signed int v3; // ecx
  __int64 result; // rax

  v3 = ((signed int)a3 - (signed int)a2) / 2 + a2;
  if ( v3 > (signed int)a1 )
    return 2 * (unsigned int)func4(a1, a2, (unsigned int)(v3 - 1));
  result = 0LL;
  if ( v3 < (signed int)a1 )
    result = 2 * (unsigned int)func4(a1, (unsigned int)(v3 + 1), a3) + 1;
  return result;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>第四关中如果想要避开explode_bomb只能让result与v4都为0，相当于输入的第二个数字必须为0，第一个数字会被送入递归的func4进行运算返回得到result，我们就得让func4返回0，让func返回0只需要让func里的两个if判断都不成立就行了，所以输入14即可。这一关比较简单，angr脚本也是非常简单：</font></br>

```python
import angr
import claripy

start=0x40102E
end=0x40105D
explode_bomb=0x40143a

p=angr.Project('./bomb')
initial_state=p.factory.blank_state(addr=start)

sm=p.factory.simulation_manager(initial_state)

sm.explore(find=end,avoid=explode_bomb)

found=sm.found[0]

found.stack_pop()
flag=found.stack_pop()

data=found.solver.eval(flag,cast_to=int)

input1=data&0xFFFFFFFF
input2=(data>>32)&0xFFFFFFFF

print('input1:{}\ninput2:{}'.format(input1,input2))
```

**phase\_5**

```C
unsigned __int64 __fastcall phase_5(_BYTE *a1, __int64 a2)
{
  __int64 v2; // rax
  char v4[6]; // [rsp+10h] [rbp-18h]
  char v5; // [rsp+16h] [rbp-12h]
  unsigned __int64 v6; // [rsp+18h] [rbp-10h]

  v6 = __readfsqword(0x28u);
  if ( (unsigned int)string_length(a1) != 6 )
    explode_bomb(a1, a2);
  v2 = 0LL;
  do
  {
    v4[v2] = array_3449[a1[v2] & 0xF];
    ++v2;
  }
  while ( v2 != 6 );
  v5 = 0;
  if ( (unsigned int)strings_not_equal(v4, "flyers") )
    explode_bomb(v4, "flyers");
  return __readfsqword(0x28u) ^ v6;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>a1就是我们输入的字符串，所以这题就是根据我们输入的字符串取末4个比特为索引，在置换表中得到一份映射，然后与flyers做比较，逻辑很简单，只要在array_3449里面对照着还原一下就行了，那么用angr如何求解呢？其实仍然是常规的explore，只是对输入的每个字节添加约束就行了（不然没法输入可见字符）：</font></br>

```python
import angr
import claripy

def is_alnum(state, c):
    is_num = state.solver.And(c >= ord("0"), c <= ord("9"))
    is_alpha_lower = state.solver.And(c >= ord("a"), c <= ord("z"))
    is_alpha_upper = state.solver.And(c >= ord("A"), c <= ord("Z"))
    is_zero = (c == ord('\x00'))
    isalphanum = state.solver.Or(
        is_num, is_alpha_lower, is_alpha_upper, is_zero)
    return isalphanum

p = angr.Project("./bomb", auto_load_libs=False)

p.hook(0x0000000000401338, angr.SIM_PROCEDURES['libc']['strcmp']())
p.hook(0x000000000040131B, angr.SIM_PROCEDURES['libc']['strlen']())

p.analyses.CFG()

start = p.kb.obj.get_symbol('phase_5').rebased_addr
avoid = p.kb.obj.get_symbol('explode_bomb').rebased_addr
find = p.kb.functions.get('phase_5').ret_sites[0].addr

state = p.factory.blank_state(addr=start)
state.regs.rdi = state.regs.rsp - 0x1000
string_addr = state.regs.rdi
sm = p.factory.simulation_manager(state)
sm.explore(find=find, avoid=avoid)
found = sm.found[0]

mem = found.memory.load(string_addr, 32)
for i in range(32):
    found.add_constraints(is_alnum(found, mem.get_byte(i)))
print(found.solver.eval(mem, cast_to=bytes).split(b'\x00')[0].decode())
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这题因为是带调试信息的，所以可以直接用`Project().kb.obj.get_symbol()`得到函数的符号表进而得到函数入口地址与返回地址，`Project().kb.functions.get().ret_sites`就是保存了一系列返回，事实上，不用这样直接用地址也能做，但是出于学习目的嘛，做题谁不会。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>做了这一关我才知道**angr是可以解置换表的，只是复杂度非常高**，置换的数量和置换表的长度都会影响angr的执行时间，比如一个非常简单的对输入进行一次无变化的置换（相当于1映射到1，2映射到2），也会产生十分大的时间消耗。**在我的环境中，对一个256字节大小的置换表（ascii码）置换5个字节需要超过146s，置换10个字节需要523s，可以说是指数性的**。</font></br>

**phase\_6**

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
  read_six_numbers(a1, (__int64)v15);
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

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这一关就比较复杂了，但是事实上经过前面几关，让你做你也可以做出来了，一个blank_state()再加上一个explore就能得到想要的路径并取得解，但是在这里我们要用一个比较复杂的方法来求解，然后借此学习angr的函数hook方法和路径优化方法，来看hook代码：</font></br>

```python
class read_6_ints(angr.SimProcedure):
    answer_ints = []  # class variable
    int_addrs = []

    def run(self, s1_addr, int_addr):
        print(int_addr)
        self.int_addrs.append(int_addr)
        for i in range(6):
            bvs = self.state.solver.BVS("phase6_int_%d" % i, 32)
            self.answer_ints.append(bvs)
            self.state.mem[int_addr].int.array(6)[i] = bvs

        return 6
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这就是hook函数的模版，你可以在angr.SimProcedure模拟例程类里定义自己的数据结构，被hook函数的执行类就是run类，其参数就是实际函数的参数，例如在这里hook的函数是read_six_numbers，其参数有两个，一个输入，一个输出，所以定义的run类也应当有这两个参数，然后我们就可以在类内部对两者进行修改。在这里就是得到输出的地址，然后在地址处插入自己的符号变量。`state[mem].int.array(6)`的作用类似`state.memory.load(mem)`，只是前者可以自定义取出的内存数量大小，由array()参数指定，后者一次只能取出一个，所以前者可以用数组访问。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>hook read_six_numbers之后，我们就可以用explore进行常规探索路径了，因为phase_6函数逻辑比较长，我们可以通过分成两段方式进行路径优化（**为什么？因为探索路径时可能会产生deadended或者avoid路径，取found有效路径后，在有效路径的基础上再次对以后的路径进行探索可以去除无效路径产生的无效时间复杂度**）。代码如下：</font></br>

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

**phase_secret**

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

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>虽然在这里触发这个隐藏关卡是有一个条件的，那就是我们的第三关的输入得带一个字符串“DrEvil“，因此第三关的输入可以为"7 0 DrEvil"，然后就能进入到这里了，在这里处于学习目的我们不用blank_state直接跳过，我们在这个隐藏关卡的开头执行，hook `read_line()`函数和`strtol(v1,0,10)`函数，对于read_line()函数我们不需要插入符号变量因为strtol函数还要再次加工，我们只需要在strtol的hook内部将返回地址修改为符号变量就能成功插入了。如下两个hook代码：</font></br>

```python
class readline_hook(angr.SimProcedure):
    def run(self):
        pass

class strtol_hook(angr.SimProcedure):
    def run(self, str, end, base):
        return self.state.solver.BVS("flag", 64, explicit_name=True)
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后就可以常规explore了，剩余代码如下：</font></br>

```python
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
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>所以最终flag如下，可以写入文件直接读取：</font></br>

```shell
➜  temp cat flag         
Border relations with Canada have never been better.
1 2 4 8 16 32
0 207
7 0 DrEvil
9?>567
4 3 2 1 6 5
22 2 DrEvil
➜  temp ./bomb flag       
Welcome to my fiendish little bomb. You have 6 phases with
which to blow yourself up. Have a nice day!
Phase 1 defused. How about the next one?
That's number 2.  Keep going!
Halfway there!
So you got that one.  Try this one.
Good work!  On to the next...
Curses, you've found the secret phase!
But finding it and solving it are quite different...
Wow! You've defused the secret stage!
Congratulations! You've defused the bomb!
➜  temp 
```

***

# counter

## UserHook

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>其实相比上面那个炸弹，这题更像是正文2333。这题用IDA打开可以看到是经过混淆的，反汇编指令达到了六十多万条，拿头逆当然不可能（虽然也不是不可以，因为大多都是垃圾代码），花那么多时间去做这个太可惜了，不如用来学习angr。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>除去main函数开头的一大堆垃圾代码，从0x43E099开始看（**可以给argv[1]下硬件断点得到从这里开始取出了我们的输入进行运算比较，奥对了0x43d2c6才是第一次比较输入的位置，但是这是直接比较的没有运算，比较简单所以跳过了**）,然后稍作分析就可以得出：程序对我们的输入每次取出一个字节进行各种计算，其中运算可能用到前一个输入的字节，反汇编如下：</font></br>

```assembly
.text:000000000043E099 ; ---------------------------------------------------------------------------
.text:000000000043E099
.text:000000000043E099 loc_43E099:                             ; CODE XREF: main+324D4↑j
.text:000000000043E099                 mov     eax, 8CF3CB57h
.text:000000000043E09E                 mov     ecx, 5F18CA7Ah
.text:000000000043E0A3                 mov     edx, 0FFFFFFFFh
.text:000000000043E0A8                 mov     rsi, [rbp+var_150]
.text:000000000043E0AF                 mov     rsi, [rsi]
.text:000000000043E0B2                 mov     rsi, [rsi+8]			; argv[1]
.text:000000000043E0B6                 movsx   edi, byte ptr [rsi+1]	; edi=(char)input[1]
.text:000000000043E0BA                 mov     r8d, edi
.text:000000000043E0BD                 xor     r8d, 0FFFFFFFFh
.text:000000000043E0C4                 and     r8d, 0CD378195h
.text:000000000043E0CB                 mov     r9d, edx
.text:000000000043E0CE                 xor     r9d, 0CD378195h
.text:000000000043E0D5                 and     edi, r9d
.text:000000000043E0D8                 mov     r10d, edx
.text:000000000043E0DB                 xor     r10d, 0BDh
.text:000000000043E0E2                 and     r10d, 0CD378195h
.text:000000000043E0E9                 and     r9d, 0BDh
.text:000000000043E0F0                 or      r8d, edi
.text:000000000043E0F3                 or      r10d, r9d
.text:000000000043E0F6                 xor     r8d, r10d
.text:000000000043E0F9                 mov     edi, edx
.text:000000000043E0FB                 xor     edi, 0FFh
.text:000000000043E101                 mov     r9d, r8d
.text:000000000043E104                 xor     r9d, edi
.text:000000000043E107                 and     r9d, r8d
.text:000000000043E10A                 mov     rsi, [rbp+var_150]
.text:000000000043E111                 mov     rsi, [rsi]
.text:000000000043E114                 mov     rsi, [rsi+8]
.text:000000000043E118                 movsx   edi, byte ptr [rsi]	; edi=(char)input[0]
.text:000000000043E11B                 sub     r9d, 8B5CB5DFh
.text:000000000043E122                 add     r9d, edi
.text:000000000043E125                 add     r9d, 8B5CB5DFh
.text:000000000043E12C                 xor     r9d, 0FFFFFFFFh
.text:000000000043E133                 mov     edi, edx
.text:000000000043E135                 xor     edi, 0FFh
.text:000000000043E13B                 xor     edx, 13E1F17Dh
.text:000000000043E141                 or      r9d, edi
.text:000000000043E144                 or      edx, 13E1F17Dh
.text:000000000043E14A                 xor     r9d, 0FFFFFFFFh
.text:000000000043E151                 and     r9d, edx
.text:000000000043E154                 mov     r11b, r9b
.text:000000000043E157                 mov     rsi, [rbp+var_148]
.text:000000000043E15E                 mov     [rsi], r11b
.text:000000000043E161                 mov     rsi, [rbp+var_148]
.text:000000000043E168                 movsx   edx, byte ptr [rsi]
.text:000000000043E16B                 cmp     edx, 1Ch				; 比较在这里
.text:000000000043E171                 setz    r11b
.text:000000000043E175                 and     r11b, 1
.text:000000000043E179                 mov     [rbp+var_4B], r11b
.text:000000000043E17D                 mov     edx, ds:dword_6A3B7C
.text:000000000043E184                 mov     edi, ds:dword_6A3B80
.text:000000000043E18B                 mov     r8d, edx
.text:000000000043E18E                 sub     r8d, 0F47F12B6h
.text:000000000043E195                 sub     r8d, 1
.text:000000000043E19C                 add     r8d, 0F47F12B6h
.text:000000000043E1A3                 imul    edx, r8d
.text:000000000043E1A7                 and     edx, 1
.text:000000000043E1AD                 cmp     edx, 0
.text:000000000043E1B3                 setz    r11b
.text:000000000043E1B7                 cmp     edi, 0Ah
.text:000000000043E1BD                 setl    bl
.text:000000000043E1C0                 mov     r14b, r11b
.text:000000000043E1C3                 and     r14b, bl
.text:000000000043E1C6                 xor     r11b, bl
.text:000000000043E1C9                 or      r14b, r11b
.text:000000000043E1CC                 test    r14b, 1
.text:000000000043E1D0                 cmovnz  eax, ecx
.text:000000000043E1D3                 mov     [rbp+var_160], eax
.text:000000000043E1D9                 jmp     loc_4A373E
.text:000000000043E1DE ; ---------------------------------------------------------------------------
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>经过前面那题bomb的学习我们都知道hook经常用来hook输入的函数，比如scanf等，那么这里我们的输入是命令行，不是函数，这可怎么hook呢？这里就要引出另一个hook办法：`angr.procedures.stubs.UserHook.UserHook`。其定义angr/procedures/stubs/userhook.py如下：</font></br>

```python
import angr

class UserHook(angr.SimProcedure):
    NO_RET = True

    # pylint: disable=arguments-differ
    def run(self, user_func=None, length=None):
        result = user_func(self.state)
        if result is None:
            jumpkind = 'Ijk_NoHook' if length == 0 else 'Ijk_Boring'
            self.successors.add_successor(self.state, self.state.addr+length, self.state.solver.true, jumpkind)
        else:
            for state in result:
                self.successors.add_successor(state, state.addr, state.scratch.guard, state.history.jumpkind)

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>其内部也定义了run函数，有两个参数，user_func就是我们的自定义函数，length就是跳过hook地址的字节数，用法与常规hook差不多，只是UserHook已经封装过了，我们基本只要实现好自定义函数就可以直接hook了，用法：`p.hook(addr, UserHook(user_func=hook_func, length=n))`。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>所以这题的思路就是：</font></br>

- hook从命令行取我们输入的相关指令，修改为取出符号变量；
- explore至flag判断的地址；
- eval得到flag；
- 重复以上直到获得所有flag。

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>还有一点要提一下可能有人会看不懂，那就是`sm.run(n=4)`，这条代码，先来看看run的官方文档：</font></br>

> `run`(*stash='active'*, *n=None*, *until=None*, ***kwargs*)
>
> Run until the SimulationManager has reached a completed state, according to the current exploration techniques. If no exploration techniques that define a completion state are being used, run until there is nothing left to run.
>
> | Parameters:  | **stash** – Operate on this stash<br />**n** – Step at most this many times<br />**until** – If provided, should be a function that takes a SimulationManager and returns True or False. Stepping will terminate when it is True. |
> | :----------- | ------------------------------------------------------------ |
> | Returns:     | The simulation manager, for chaining.                        |
> | Return type: | [SimulationManager](https://angr.io/api-doc/angr.html#angr.sim_manager.SimulationManager) |

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>意思就是根据目前设置的探索方法一直运行直到simulation_manager到达了一个完整的状态，比如这题就会一直run直到hook地址处以及hook返回处，hook了两次，所以run(n=4)后正好在第二次hook的结束地址处，然后只要运行到flag比较处设置条件约束就能计算正确的输入了。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>解释完了，接下来就直接放脚本了：</font></br>

```python
# This challenge is super big, and it's impossible to solve with IDA alone.
# However, we are sure that most of the code is just garbage - you can't have
# a 100-point challenge with that much non-garbage code. Therefore the idea is
# to use GDB along with hardware breakpoints to find out where each byte is
# verified, and then run that single part of code inside angr to solve the
# password.

from angr.procedures.stubs.UserHook import UserHook
import angr

def prepare_state(state, known_passwords):
    state = state.copy()
    password = [ ]
    for i in range(0, len(known_passwords) + 1):
        password.append(state.solver.BVS('password_%d' % i, 8))
        state.memory.store(0xd0000000 + i, password[-1])

    for i, char in enumerate(known_passwords):
        state.add_constraints(password[i] == ord(char))
    state.memory.store(0x6a3b7c, state.solver.BVV(0, 32))
    state.memory.store(0x6a3b80, state.solver.BVV(0, 32))

    state.regs.rbp = 0xffffffff00000000
    state.memory.store(state.regs.rbp-0x148, state.solver.BVV(0xd0000100, 64), endness=state.arch.memory_endness)
    state.memory.store(state.regs.rbp-0x140, state.solver.BVV(0xd0000100, 64), endness=state.arch.memory_endness)

    return state, password

#
# A bunch of hooks so that I don't have to take care of the following code snippet:
# .text:0000000000457294                 mov     r8, [rbp+var_150]
# .text:000000000045729B                 mov     r8, [r8]
# .text:000000000045729E                 mov     r8, [r8+8]
#
# I can definitely set it up easily with angr, but I was too lazy - which is proved to be
# a mistake soon after...

def hook_rsi(state):
    state.regs.rsi = 0xd0000000

def hook_r8(state):
    state.regs.r8 = 0xd0000000

def hook_rdi(state):
    state.regs.rdi = 0xd0000000

# Calculate the next byte of the password
def calc_one_byte(p, known_passwords, hook_func, start_addr, load_addr1, load_addr2, cmp_flag_reg, cmp_addr):
    byte_pos = len(known_passwords)

    p.hook(load_addr1, UserHook(user_func=hook_func, length=14))
    p.hook(load_addr2, UserHook(user_func=hook_func, length=14))
    state = p.factory.blank_state(addr=start_addr)
    state, password = prepare_state(state, known_passwords)
    sm = p.factory.simulation_manager(state)
    sm.run(n=4)
    sm.step(size=cmp_addr - load_addr2)

    s0 = sm.active[0].copy()
    s0.add_constraints(getattr(s0.regs, cmp_flag_reg) == 0x1)
    candidates = s0.solver.eval_upto(password[byte_pos], 256)
    # assert len(candidates) == 1

    return chr(candidates[0])

def main():
    p = angr.Project("counter", load_options={'auto_load_libs': False})

    # I got the first letter from gdb and IDA...
    # First letter is 'S'. I found it out at 0x43d2c6
    known_passwords = [ 'S' ]

    # Let's figure out the second letter

    # Get the second char
    c = calc_one_byte(p, known_passwords, hook_rsi, 0x43e099, 0x43e0a8, 0x43e10a, "r11", 0x43e175)
    # Second char: chr(116) == 't'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_r8, 0x43ee79, 0x43ee8c, 0x43eed3, "rbx", 0x43ef38)
    # Third char: chr(52) == '4'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x43fd06, 0x43fd17, 0x43fd6e, "r11", 0x43fde5)
    # Fourth char: chr(116) == 't'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_r8, 0x440a94, 0x440aa7, 0x440b0a, "rbx", 0x440b74)
    # Fifth char: chr(49) == '1'
    known_passwords += [ c ]

    # Why are there so many characters? I was expecting 5 at most...

    c = calc_one_byte(p, known_passwords, hook_rsi, 0x4418e2, 0x4418f1, 0x441942, "r10", 0x441994)
    # Sixth char: chr(99) == 'c'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x44268e, 0x44269f, 0x4426d2, "rbx", 0x44274e)
    # Seventh char: chr(95) == '_'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rsi, 0x4433a5, 0x4433b4, 0x4433eb, "r11", 0x443466)
    # Eighth char: chr(52) == '4'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x444194, 0x4441a5, 0x444208, "r11", 0x444260)
    # Ninth char: chr(110) == 'n'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x444f51, 0x444f62, 0x444fa9, "r11", 0x445001)
    # Tenth char: chr(52) == '4'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x445ddc, 0x445ded, 0x445e34, "rbx", 0x445e95)
    # 11th char: chr(108) == 'l'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_r8, 0x446bfa, 0x446c0d, 0x446c64, "rbx", 0x446cd6)
    # chr(121) == 'y'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rsi, 0x4479c4, 0x4479d3, 0x447a0a, "r10", 0x447a7a)
    # chr(83) == 'S'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_r8, 0x44877f, 0x448792, 0x4487cd, "rbx", 0x44883f)
    # chr(49) == '1'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x449513, 0x449524, 0x44957b, "r11", 0x4495ee)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_r8, 0x44a29d, 0x44a2b0, 0x44a2ff, "rbx", 0x44a357)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x44b0e8, 0x44b0f9, 0x44b140, "r11", 0x44b1b3)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rsi, 0x44bded, 0x44bdfc, 0x44be4d, "r10", 0x44bebb)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x44cc4f, 0x44cc60, 0x44ccaf, "r11", 0x44ccfb)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x44d99f, 0x44d9b0, 0x44da07, "r11", 0x44da72)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x44e89a, 0x44e8ab, 0x44e8f4, "r10", 0x44e94a)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x44f67e, 0x44f68f, 0x44f6f2, "r11", 0x44f765)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x4504fe, 0x45050f, 0x450566, "r11", 0x4505bf)
    known_passwords += [ c ]

    # So many letters!!!!!!!!
    c = calc_one_byte(p, known_passwords, hook_r8, 0x4511fe, 0x451211, 0x451268, "r14", 0x4512cd)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_r8, 0x4520d7, 0x4520ea, 0x452117, "r11", 0x45216f)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rsi, 0x452e82, 0x452e91, 0x452ed5, "r11", 0x452f50)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rsi, 0x453d28, 0x453d3a, 0x453d71, "r11", 0x453de6)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_r8, 0x454a39, 0x454a4c, 0x454a95, "r11", 0x454ae7)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x4557f9, 0x45580a, 0x455853, "r11", 0x4558c8)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x45660a, 0x45661b, 0x456648, "r11", 0x4566a3)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_r8, 0x457281, 0x457294, 0x4572cf, "rbx", 0x457314)
    known_passwords += [ c ]

    # The last one must be '4'...
    known_passwords += [ '4' ]
    password = "".join(known_passwords)
    print("Flag: EKO{%s}" % password)

    return password

def test():
    assert main() == 'St4t1c_4n4lyS1s_randomstring1234'

if __name__ == "__main__":
    main()
```

