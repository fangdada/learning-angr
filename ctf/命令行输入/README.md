# ais3_crackme

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这次咱们学学命令行输入下怎么用angr做一些简单的crackme，话不多说，看看IDA伪代码：</font></br>

**main**

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax

  if ( argc == 2 )
  {
    if ( (unsigned int)verify((__int64)argv[1]) )
      puts("Correct! that is the secret key!");
    else
      puts("I'm sorry, that's the wrong secret key!");
    result = 0;
  }
  else
  {
    puts("You need to enter the secret key!");
    result = -1;
  }
  return result;
}
```

**verify**

```C
_BOOL8 __fastcall verify(__int64 a1)
{
  int i; // [rsp+14h] [rbp-4h]

  for ( i = 0; *(_BYTE *)(i + a1); ++i )
  {
    if ( encrypted[i] != ((unsigned __int8)((unsigned __int8)(*(_BYTE *)(i + a1) ^ i) << ((i ^ 9) & 3)) | (unsigned __int8)((signed int)(unsigned __int8)(*(_BYTE *)(i + a1) ^ i) >> (8 - ((i ^ 9) & 3))))
                       + 8 )
      return 0LL;
  }
  return i == 23;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>其中的encrypted就是一个密文表，可以看到加密对比要求逆还是要花些功夫的，但是用angr可以很轻（wu）松（nao）的完成，构造命令行输入的话就要用到另一个库叫claripy，其他的都差不多：</font></br>

```python
import angr
import claripy

project = angr.Project("./ais3_crackme")
argv1 = claripy.BVS("argv1",100*8) #since we do not the length now, we just put 100 byte

initial_state = project.factory.entry_state(args=["./crackme1",argv1])

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>官方脚本里直接懒得猜flag多少字节，直接构造了100个字节，然后以args=[file,argv]的方式送入entry_state就行了，其他的都一样，只是约束器结果要转化为byte类型的字节流还要用到一个eval函数，看以下代码：</font><br>

```python
#create a path group using the created initial state 
sm = project.factory.simulation_manager(initial_state)

#symbolically execute the program until we reach the wanted value of the instruction pointer
sm.explore(find=0x400602) #at this instruction the binary will print(the "correct" message)

found = sm.found[0]
#ask to the symbolic solver to get the value of argv1 in the reached state as a string
solution = found.solver.eval(argv1, cast_to=bytes)

print solution.strip('\x00')
# ais3{I_tak3_g00d_n0t3s}
```

</br>

# asisctffinals2015_fake

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这题相比上面那个稍微复杂一些，但是基本一样，直接来看IDA main函数反编译：</font></br>

```C
__int64 __fastcall main(signed int a1, char **a2, char **a3)
{
  __int64 v3; // r8
  __int64 v5; // [rsp+0h] [rbp-38h]
  __int64 v6; // [rsp+8h] [rbp-30h]
  __int64 v7; // [rsp+10h] [rbp-28h]
  __int64 v8; // [rsp+18h] [rbp-20h]
  __int64 v9; // [rsp+20h] [rbp-18h]

  v3 = 0LL;
  if ( a1 > 1 )
    v3 = strtol(a2[1], 0LL, 10);
  v5 = 0x3CC6C7B7 * v3;
  v6 = 0x981DDEC9AB2D9LL
     * ((v3 >> 19)
      - 2837
      * (((signed __int64)((unsigned __int128)(6658253765061184651LL * (signed __int128)(v3 >> 19)) >> 64) >> 10)
       - (v3 >> 63)))
     * ((v3 >> 19)
      - 35
      * (((signed __int64)((unsigned __int128)(1054099661354831521LL * (signed __int128)(v3 >> 19)) >> 64) >> 1)
       - (v3 >> 63)))
     * ((v3 >> 19)
      - 33
      * (((signed __int64)((unsigned __int128)(1117984489315730401LL * (signed __int128)(v3 >> 19)) >> 64) >> 1)
       - (v3 >> 63)));
  v7 = ((v3 >> 19)
      - 9643
      * (((signed __int64)((unsigned __int128)(1958878557656183849LL * (signed __int128)(v3 >> 19)) >> 64) >> 10)
       - (v3 >> 63)))
     * 5785690976857702LL
     * ((v3 >> 19)
      - 167
      * (((signed __int64)((unsigned __int128)(7069410902499468883LL * (signed __int128)(v3 >> 19)) >> 64) >> 6)
       - (v3 >> 63)));
  v8 = ((v3 >> 19)
      - 257
      * (((signed __int64)((unsigned __int128)(9187483429707480961LL * (signed __int128)(v3 >> 19)) >> 64) >> 7)
       - (v3 >> 63)))
     * 668176625215826LL
     * ((v3 >> 19)
      - 55
      * (((signed __int64)((unsigned __int128)(5366325548715505925LL * (signed __int128)(v3 >> 19)) >> 64) >> 4)
       - (v3 >> 63)));
  v9 = ((v3 >> 19)
      - 48271
      * (((signed __int64)((unsigned __int128)(1565284823722614477LL * (signed __int128)(v3 >> 19)) >> 64) >> 12)
       - (v3 >> 63)))
     * 2503371776094LL
     * ((v3 >> 19)
      - 23
      * (((signed __int64)((v3 >> 19) + ((unsigned __int128)(-5614226457215950491LL * (signed __int128)(v3 >> 19)) >> 64)) >> 4)
       - (v3 >> 63)));
  puts((const char *)&v5);
  return 0LL;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>程序逻辑一目了然，只是单纯的命令行参数输入一串数字，然后经过一系列运算后就输出了，根据题目描述flag应当是"ASIS{xxxxx...xxxxx}"格式的，所以我们要做的就是：</font></br>

- 加载程序到strcol函数后，设置函数返回值rax为符号变量；
- 使用simulation manager的explore模拟执行完所有运算；
- 对运算后的符号变量添加约束；
- 求解得到flag。

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>所以还是比较好理解的，直接放脚本了：</font></br>

```shell
import angr
import binascii

def main():
    p = angr.Project("fake", auto_load_libs=False)

    state = p.factory.blank_state(addr=0x4004AC)
    inp = state.solver.BVS('inp', 8*8)
    state.regs.rax = inp

    simgr= p.factory.simulation_manager(state)
    simgr.explore(find=0x400684)
    found = simgr.found[0]

    # We know the flag starts with "ASIS{"
    flag_addr = found.regs.rdi
    found.add_constraints(found.memory.load(flag_addr, 5) == int(binascii.hexlify(b"ASIS{"), 16))

    # More constraints: the whole flag should be printable
    flag = found.memory.load(flag_addr, 40)
    for i in range(5, 5+32):
        cond_0 = flag.get_byte(i) >= ord('0')
        cond_1 = flag.get_byte(i) <= ord('9')
        cond_2 = flag.get_byte(i) >= ord('a')
        cond_3 = flag.get_byte(i) <= ord('f')
        cond_4 = found.solver.And(cond_0, cond_1)
        cond_5 = found.solver.And(cond_2, cond_3)
        found.add_constraints(found.solver.Or(cond_4, cond_5))

    # And it ends with a '}'
    found.add_constraints(flag.get_byte(32+5) == ord('}'))

    # In fact, putting less constraints (for example, only constraining the first
    # several characters) is enough to get the final flag, and Z3 runs much faster
    # if there are less constraints. I added all constraints just to stay on the
    # safe side.

    flag_str = found.solver.eval(flag, cast_to=bytes)
    return flag_str.rstrip(b'\0')

    #print("The number to input: ", found.solver.eval(inp))
    #print("Flag:", flag)

    # The number to input:  25313971399
    # Flag: ASIS{f5f7af556bd6973bd6f2687280a243d9}

def test():
    a = main()
    assert a == b'ASIS{f5f7af556bd6973bd6f2687280a243d9}'

if __name__ == '__main__':
    import logging
    logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)
    print(main())
```

