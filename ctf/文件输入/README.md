# asisctffinals2015 license

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这题需要存在一个特定名称与内容的文件，从中取出数据验证，成功就会打印flag。经过前面那么多节的学习，我们对各种输入插入符号变量已经有了一个差不多的掌握了，这次我们来学习一下如果是从文件中读取输入我们该怎么做（当然如果你实在不想学的话有一种奇技淫巧就是直接修改刚读完文件的缓冲区为符号变量，当然这是实战中的技巧，既然我们是来学习的就不考虑这种方式来）。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>老样子，我们还是从IDA开始看起吧，程序同样还是简单粗暴，直接就是一个main函数：</font></br>

```C
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  FILE *file; // rax
  FILE *file_ptr; // rbx
  unsigned int v5; // er12
  __int64 file_size; // rbp
  void *file_block; // rax
  __int64 v8; // r13
  __int64 v10; // rax
  _BYTE *v11; // rax
  signed int v12; // ecx
  signed __int64 v13; // rdx
  __int64 v14; // rax
  signed __int64 v15; // rbx
  __int64 v16; // rax
  __int64 v17; // rax
  __int64 v18; // rax
  __int64 v19; // rdx
  __int64 v20; // r15
  __int64 v21; // rcx
  __int64 v22; // r8
  __int64 v23; // rax
  __int64 v24; // r15
  __int64 v25; // rax
  __int64 v26; // rcx
  __int64 v27; // rax
  __int64 v28; // rax
  __int64 v29; // rax
  __int64 v30; // rax
  __int64 v31; // rax
  __int64 v32; // rax
  _BYTE *v33; // [rsp+8h] [rbp-270h]
  __int64 v34; // [rsp+10h] [rbp-268h]
  __int64 v35; // [rsp+18h] [rbp-260h]
  __int64 v36; // [rsp+20h] [rbp-258h]
  __int64 v37; // [rsp+28h] [rbp-250h]
  __int64 v38; // [rsp+30h] [rbp-248h]
  char v39; // [rsp+1A0h] [rbp-D8h]
  char v40; // [rsp+1A1h] [rbp-D7h]
  char v41; // [rsp+1A2h] [rbp-D6h]
  char v42; // [rsp+1A3h] [rbp-D5h]
  char v43; // [rsp+1A4h] [rbp-D4h]
  char v44; // [rsp+1A5h] [rbp-D3h]
  char v45; // [rsp+1A6h] [rbp-D2h]
  char v46; // [rsp+1A7h] [rbp-D1h]
  char v47; // [rsp+1A8h] [rbp-D0h]
  char v48; // [rsp+1A9h] [rbp-CFh]
  char v49; // [rsp+1AAh] [rbp-CEh]
  char v50; // [rsp+1ABh] [rbp-CDh]
  char v51; // [rsp+1ACh] [rbp-CCh]
  char v52; // [rsp+1ADh] [rbp-CBh]
  char v53; // [rsp+1AEh] [rbp-CAh]
  char v54; // [rsp+1AFh] [rbp-C9h]
  char v55; // [rsp+1B0h] [rbp-C8h]
  char v56; // [rsp+1B1h] [rbp-C7h]
  char v57; // [rsp+1B2h] [rbp-C6h]
  char v58; // [rsp+1B3h] [rbp-C5h]
  char v59; // [rsp+1B4h] [rbp-C4h]
  char v60; // [rsp+1B5h] [rbp-C3h]
  char v61; // [rsp+1B6h] [rbp-C2h]
  char v62; // [rsp+1B7h] [rbp-C1h]
  char v63; // [rsp+1B8h] [rbp-C0h]
  char v64; // [rsp+1B9h] [rbp-BFh]
  char v65; // [rsp+1BAh] [rbp-BEh]
  char v66; // [rsp+1BBh] [rbp-BDh]
  char v67; // [rsp+1BCh] [rbp-BCh]
  char v68; // [rsp+1BDh] [rbp-BBh]
  char v69; // [rsp+1BEh] [rbp-BAh]
  char v70; // [rsp+1BFh] [rbp-B9h]
  char v71; // [rsp+1C0h] [rbp-B8h]
  char v72; // [rsp+1C1h] [rbp-B7h]
  char v73; // [rsp+1C2h] [rbp-B6h]
  char v74; // [rsp+1C3h] [rbp-B5h]
  char v75; // [rsp+1C4h] [rbp-B4h]
  char v76; // [rsp+1C5h] [rbp-B3h]
  char s1[104]; // [rsp+1D0h] [rbp-A8h]
  unsigned __int64 v78; // [rsp+238h] [rbp-40h]

  v78 = __readfsqword(0x28u);
  file = fopen("_a\nb\tc_", "rb");
  file_ptr = file;
  if ( file )
  {
    fseek(file, 0LL, 2);
    v5 = 0x44;
    file_size = ftell(file_ptr);
    rewind(file_ptr);
    file_block = calloc(1uLL, file_size + 1);
    v8 = (__int64)file_block;
    if ( file_block )
    {
      LOBYTE(v5) = 0x3A;
      if ( fread(file_block, file_size, 1uLL, file_ptr) == 1 )
      {
        fclose(file_ptr);
        if ( -45235 * file_size * file_size * file_size * file_size
           + -1256 * file_size * file_size * file_size
           + 14392 * file_size * file_size
           + -59762 * file_size
           - 1949670109068LL
           + 44242 * file_size * file_size * file_size * file_size * file_size )
        {
          LOBYTE(v5) = 0;
          v18 = std::operator<<<std::char_traits<char>>(&std::cout, "wrong formatted key file");
          std::endl<char,std::char_traits<char>>(v18);
        }
        else
        {
          v34 = v8;
          v11 = (_BYTE *)v8;
          v12 = 1;
          while ( file_size > (signed __int64)&v11[-v8] )
          {
            v13 = (signed __int64)(v11 + 1);
            if ( *v11 == 10 )
            {
              v14 = v12++;
              *(&v34 + v14) = v13;
            }
            v11 = (_BYTE *)v13;
          }
          v15 = (file_size - (v12 - 1)) / v12;
          dword_6021E0 = v15;
          if ( (unsigned __int64)(5 * (signed int)v15) > 91 || (signed int)v15 <= 0 )
          {
            v5 = 32;
            v17 = std::operator<<<std::char_traits<char>>(&std::cout, "wrong formatted key file");
            std::endl<char,std::char_traits<char>>(v17);
          }
          else if ( v12 == 5 )
          {
            v39 = 53;
            v40 = 63;
            v19 = 0LL;
            v41 = 112;
            v42 = 20;
            v43 = 46;
            v44 = 121;
            v45 = 110;
            v46 = 47;
            v47 = 68;
            v48 = 13;
            v49 = 27;
            v50 = 63;
            v51 = 60;
            v52 = 62;
            v53 = 28;
            v54 = 45;
            v55 = 9;
            v56 = 36;
            v57 = 37;
            v58 = 11;
            v59 = 59;
            v60 = 14;
            v61 = 94;
            v62 = 77;
            v63 = 36;
            v64 = 26;
            v65 = 103;
            v66 = 63;
            v67 = 80;
            v68 = 90;
            v69 = 96;
            v70 = 4;
            v71 = 74;
            v72 = 22;
            v20 = v35;
            v21 = v34;
            v73 = 51;
            v74 = 101;
            v75 = 48;
            v76 = 125;
            do
            {
              s1[v19] = *(_BYTE *)(v21 + v19) ^ *(_BYTE *)(v20 + v19);
              ++v19;
            }
            while ( (signed int)v15 > (signed int)v19 );
            if ( memcmp(
                   s1,
                   "iKWoZLVc4LTyGrCRedPhfEnihgyGxWrCGjvi37pnPGh2f1DJKEcQZMDlVvZpEHHzUfd4VvlMzRDINqBk;1srRfRvvUW",
                   (signed int)v15) )
            {
              goto LABEL_41;
            }
            v22 = v37;
            v23 = 0LL;
            do
            {
              s1[v23] = *(_BYTE *)(v20 + v23) ^ *(_BYTE *)(v22 + v23) ^ 0x23;
              ++v23;
            }
            while ( (signed int)v15 > (signed int)v23 );
            v33 = (_BYTE *)v22;
            if ( memcmp(s1, &aIkwozlvc4ltygr[(signed int)v15], (signed int)v15) )
              goto LABEL_41;
            v24 = v36;
            v25 = 0LL;
            do
            {
              s1[v25] = v33[v25] ^ *(_BYTE *)(v24 + v25);
              ++v25;
            }
            while ( (signed int)v15 > (signed int)v25 );
            if ( memcmp(s1, (const void *)(2 * (signed int)v15 + 4198688LL), (signed int)v15) )
              goto LABEL_41;
            v26 = v38;
            v27 = 0LL;
            do
            {
              s1[v27] = v33[v27] ^ *(_BYTE *)(v26 + v27) ^ 0x23;
              ++v27;
            }
            while ( (signed int)v15 > (signed int)v27 );
            v28 = 0LL;
            do
            {
              s1[v28] ^= *(_BYTE *)(v24 + v28);
              ++v28;
            }
            while ( (signed int)v15 > (signed int)v28 );
            if ( !memcmp(s1, (const void *)(3 * (signed int)v15 + 4198688LL), (signed int)v15)
              && (v5 = memcmp(v33, (const void *)(4 * (signed int)v15 + 4198688LL), (signed int)v15)) == 0 )
            {
              v29 = 0LL;
              do
              {
                if ( file_size > v29 )
                  *(&v39 + v29) ^= *(_BYTE *)(v8 + v29);
                ++v29;
              }
              while ( v29 != 38 );
              v30 = std::operator<<<std::char_traits<char>>(&std::cout, "program successfully registered to ");
              v31 = std::operator<<<std::char_traits<char>>(v30, &v39);
              std::endl<char,std::char_traits<char>>(v31);
            }
            else
            {
LABEL_41:
              v5 = 0;
              v32 = std::operator<<<std::char_traits<char>>(&std::cout, "registration failed");
              std::endl<char,std::char_traits<char>>(v32);
            }
          }
          else
          {
            v5 = 23;
            v16 = std::operator<<<std::char_traits<char>>(&std::cout, "wrong formatted key file");
            std::endl<char,std::char_traits<char>>(v16);
          }
        }
      }
    }
  }
  else
  {
    v5 = 78;
    v10 = std::operator<<<std::char_traits<char>>(&std::cout, "key file not found!");
    std::endl<char,std::char_traits<char>>(v10);
  }
  return v5;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>其中fread后的if里的file_size可以用z3-solver求解得到：</font></br>

```python
In [2]: from z3 import *

In [3]: s=Solver()

In [4]: file_size=BitVec("file_size",32)

In [5]: s.add(-45235 * file_size * file_size * file_size * file_size
   ...:            + -1256 * file_size * file_size * file_size
   ...:            + 14392 * file_size * file_size
   ...:            + -59762 * file_size
   ...:            - 1949670109068
   ...:            + 44242 * file_size * file_size * file_size * file_size * file_size==0)

In [6]: s.check()
Out[6]: sat

In [7]: s.model()
Out[7]: [file_size = 34]

In [8]:
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>所以程序的逻辑如下：</font></br>

- 打开一个名称为"\_a\\nb\\tc\_"的文件；
- 验证文件大小为34个字节；
- 验证文件行数为5；
- 进行一系列与密文的比较，都正确即为flag（可以在最后的while看到flag为38个字节）。

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>因为文件字节包括行尾的"\\n"，所以实际上每行的字节是6个**(34-4)/5=6**，我们用angr先创建好符号变量：</font></br>

```python
bytestring = None
    for i in range(5):
        line = [ ]
        for j in range(6):
            line.append(state.solver.BVS('license_file_byte_%d_%d' % (i, j), 8))
            state.add_constraints(line[-1] != b'\n')
        if bytestring is None:
            bytestring = claripy.Concat(*line)
        else:
            bytestring = bytestring.concat(state.solver.BVV(b'\n'), *line)
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>接下来我们就到了新鲜的知识点了，创建文件并放入这些符号变量，先看代码：</font></br>

```python
state = p.factory.blank_state()
license_name = "_a\nb\tc_"

license_file = angr.storage.file.SimFile(license_name, bytestring)
state.fs.insert(license_name, license_file)
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>主要用到的就是上面这两行，来看看官方文档里的解释：</font></br>

> *class*`angr.storage.file.``SimFile`(*name*, *content=None*, *size=None*, *has_end=None*, *seekable=True*, *writable=True*, *ident=None*, *concrete=None*, ***kwargs*)
>
> Bases: [`angr.storage.file.SimFileBase`](https://angr.io/api-doc/angr.html#angr.storage.file.SimFileBase), [`angr.state_plugins.symbolic_memory.SimSymbolicMemory`](https://angr.io/api-doc/angr.html#angr.state_plugins.symbolic_memory.SimSymbolicMemory)
>
> The normal SimFile is meant to model files on disk. It subclasses SimSymbolicMemory so loads and stores to/from it are very simple.
>
> | Parameters: | **name** – The name of the file<br /><br />**content** – Optional initial content for the file as a string or bitvector<br /><br />**size** – Optional size of the file. If content is not specified, it defaults to zero<br /><br />**has_end** – Whether the size boundary is treated as the end of the file or a frontier at which new content will be generated. If unspecified, will pick its value based on options.FILES_HAVE_EOF. Another caveat is that if the size is also unspecified this value will default to False.<br /><br />**seekable** – Optional bool indicating whether seek operations on this file should succeed, default True.<br /><br />**writable** – Whether writing to this file is allowed<br /><br />**concrete** – Whether or not this file contains mostly concrete data. Will be used by some SimProcedures to choose how to handle variable-length operations like fgets. |
> | :---------: | ------------------------------------------------------------ |
> | Variables:  | **has_end** – Whether this file has an EOF                   |

</br>

> `insert`(*path*, *simfile*)
>
> ………………..
>
> `fs` – A dictionary of file names with associated preset SimFile objects.

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>其实看了这些也没卵用23333，我们只要知道是这么用的就行了，然后做完了上面这些工作后符号变量的事已经搞定了，接下来就是常规的explore：</font></br>

```python
simgr = p.factory.simulation_manager(state)

    simgr.explore(
                find=(0x400e93, ),
                avoid=(0x400bb1, 0x400b8f, 0x400b6d, 0x400a85,
                       0x400ebf, 0x400a59)
            )

    # One path will be found
    found = simgr.found[0]
    rsp = found.regs.rsp
    flag_addr = rsp + 0x278 - 0xd8 # Ripped from IDA
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>但是我们不能像往常的那样用found.posix.dumps(0)或者(1)来提取flag了，因为这里既没有标准输入也没有标准输出flag，我们要从内存里自己拿！取得一个rsp地址后，我们可以从栈上计算地址得到存放着flag的缓冲区的地址。然后可以直接这么做：</font></br>

```python
In [11]:found.solver.eval(found.memory.load(flag_addr,100),cast_to=bytes)
Out[11]: b'ASIS{8d2cc30143831881f94cb05dcf0b83e0}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00PhfEni\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>但是官方脚本比较强大，精确的解析了flag，不像我这么简单粗暴，来学学如何调用模拟器里的函数：</font></br>

```python
    FAKE_ADDR = 0x100000
    strlen = lambda state, arguments: \
        angr.SIM_PROCEDURES['libc']['strlen'](p, FAKE_ADDR, p.arch).execute(
            state, arguments=arguments
        )
    flag_length = strlen(found, arguments=[flag_addr]).ret_expr
    # In case it's not null-terminated, we get the least number as the length
    flag_length_int = min(found.solver.eval_upto(flag_length, 3))
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>`angr.SIM_PROCEDURES`是一个非常庞大全面的字典，其定义了字符串到模拟例程函数类的映射，没错是一个类，可以用execute方法来模拟执行这个函数，也就是说通过lambda设置一下后我们可以通过strlen(state,arguments).ret_expr执行strlen函数并取得其返回值，酷不酷？我们甚至可以重载其run()方法，hook函数就是这样搞的。</font></br>

```shell
In [21]: found.solver.eval_upto(flag_length,3)
Out[21]: [64, 38, 40]

In [22]: for i in angr.SIM_PROCEDURES:
    ...:     print(i)
    ...:
cgc
tracer
stubs
posix
libc
uclibc
ntdll
linux_kernel
testing
advapi32
msvcr
glibc
win32
linux_loader
win_user32

In [23]: for i in angr.SIM_PROCEDURES['libc']:
    ...:     print(i)
    ...:
    ...:
abort
access
atoi
calloc
exit
fclose
feof
fflush
fgetc
getc
fgets
fopen
FormatParser
fprintf
fputc
fputs
fread
free
fseek
ftell
fwrite
getchar
malloc
memcmp
memcpy
memset
perror
__printf_chk
printf
putc
putchar
puts
rand
realloc
rewind
scanf
setvbuf
__snprintf_chk
snprintf
sprintf
srand
sscanf
strcat
strchr
strcmp
strcpy
strlen
strncmp
strncpy
strstr
strtol
system
tmpnam
tolower
toupper
ungetc
vsnprintf
wcscasecmp
wcscmp

.......

In [45]: angr.SIM_PROCEDURES
Out[45]:
{'cgc': {'_terminate': angr.procedures.cgc._terminate._terminate,
  'allocate': angr.procedures.cgc.allocate.allocate,
  'deallocate': angr.procedures.cgc.deallocate.deallocate,
  'fdwait': angr.procedures.cgc.fdwait.fdwait,
  'random': angr.procedures.cgc.random.random,
  'receive': angr.procedures.cgc.receive.receive,
  'transmit': angr.procedures.cgc.transmit.transmit},
 'tracer': {'random': angr.procedures.tracer.random.random,
  'orig_receive': angr.procedures.cgc.receive.receive,
  'receive': angr.procedures.tracer.receive.receive,
 ..............
 }
 
```



&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>调用完了strlen计算来flag的长度后用flag_length接受了返回值，但是这不是int，也是一个符号变量，同样我们也是要通过solver计算得到的，我们不能直接用eval计算，而是要用eval_upto这个函数，这个函数跟eval有一个区别就是多了一个n参数，其代表了我们期望的解的个数。因为flag长度应当为38，所以用min得到最短的那个就可以了，剩下的就一样了：</font></br>

```python
    flag_int = found.solver.eval(found.memory.load(flag_addr, flag_length_int))
    flag = bytes.fromhex(hex(flag_int)[2:])
    return flag
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>完整脚本如下：</font></br>

```python
import angr
import claripy

def main():
    p = angr.Project("license", load_options={'auto_load_libs': False})

    # Create a blank state
    state = p.factory.blank_state()

    # Build the file whose name is weird
    license_name = "_a\nb\tc_"

    # This is the license file
    # From analyzing the binary, we know that the license file should have five
    # lines in total, and each line has 6 characters. Not setting file content
    # may also work, but in that case, angr will produce many more paths, and we
    # will spent much more time in path trimming.

    bytestring = None
    for i in range(5):
        line = [ ]
        for j in range(6):
            line.append(state.solver.BVS('license_file_byte_%d_%d' % (i, j), 8))
            state.add_constraints(line[-1] != b'\n')
        if bytestring is None:
            bytestring = claripy.Concat(*line)
        else:
            bytestring = bytestring.concat(state.solver.BVV(b'\n'), *line)

    license_file = angr.storage.file.SimFile(license_name, bytestring)
    state.fs.insert(license_name, license_file)

    simgr = p.factory.simulation_manager(state)

    simgr.explore(
                find=(0x400e93, ),
                avoid=(0x400bb1, 0x400b8f, 0x400b6d, 0x400a85,
                       0x400ebf, 0x400a59)
            )

    # One path will be found
    found = simgr.found[0]
    rsp = found.regs.rsp
    flag_addr = rsp + 0x278 - 0xd8 # Ripped from IDA
    # Perform an inline call to strlen() in order to determine the length of the
    # flag
    FAKE_ADDR = 0x100000
    strlen = lambda state, arguments: \
        angr.SIM_PROCEDURES['libc']['strlen'](p, FAKE_ADDR, p.arch).execute(
            state, arguments=arguments
        )
    flag_length = strlen(found, arguments=[flag_addr]).ret_expr
    # In case it's not null-terminated, we get the least number as the length
    flag_length_int = min(found.solver.eval_upto(flag_length, 3))
    # Read out the flag!
    flag_int = found.solver.eval(found.memory.load(flag_addr, flag_length_int))
    flag = bytes.fromhex(hex(flag_int)[2:])
    return flag

def test():
    assert main() == b'ASIS{8d2cc30143831881f94cb05dcf0b83e0}'

if __name__ == '__main__':
    print(main())

```

