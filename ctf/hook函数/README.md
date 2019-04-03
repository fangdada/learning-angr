# bomb

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

