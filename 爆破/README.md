# momo_3

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这是一个由mov obfuscation的程序，如果看过[常规解](https://github.com/fangdada/ctf/tree/master/0CTF2016/momo)的话就知道这题逻辑是逐字节判断输入是否为flag，用angr解的话或许可以同样用explore求到最终解？不行，因为逐字节比较时即使flag不对也不会马上报错，而是累计到最后才判断正确，这时我们就可以利用逐字节判断的特点进行爆破。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>那么如何利用angr进行爆破呢？主要就要靠simulation_manager这个模拟器执行来实现。首先还是要用angr.Project()加载二进制程序，然后新知识点来了：</font></br>

```python
p = angr.Project('./momo', auto_load_libs=False)

addr = after_fgets
size = mov_congrats - after_fgets

# let's disasm with capstone to search targets
insn_bytes = p.loader.memory.load(addr, size)

insns = []
for cs_insn in p.arch.capstone.disasm(insn_bytes, addr):
    insns.append(CapstoneInsn(cs_insn))
block = CapstoneBlock(addr, insns, 0, p.arch)

targets = []

# let's keep track of the state
state = 0
for ins in block.insns:
    if state == 0:
        if ins.op_str == 'edx, dword ptr [edx*4 + 0x81fe260]':
            state += 1
            continue
    if state == 1:
        if ins.op_str == 'al, byte ptr [0x81fe6e0]':
            state += 1
            continue
    if state == 2:
        if ins.op_str == 'dl, byte ptr [0x81fe6e4]':
            targets.append(ins.address + ins.size)
            state = 0

print("found {:d} targets".format(len(targets)))
assert len(targets) == 28

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>利用capstone反汇编引擎反汇编二进制程序，与我trace里写的disas.py不同，这题用的是angr.capstone，官方文档里写了angr.capstone其实就是capstone的深度复制，如上代码所示，ins为每条指令代码，ins.mnemonic为操作符，在这里为mov；ins.op_str是操作数；ins.address就是指令的地址。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>在上段代码中for循环中的if就是为了解析反汇编代码，目的是得到al,dl被赋值为密文和处理后的输入的指令地址，随后构造输入利用explorer find到上面的地址就可以得到模拟执行后的al和dl的值，根据程序逻辑只要他们相等就说明构造的输入是正确的，进而就能推出flag。然后我们继续往下看：</font></br>

```python
flag_arr = bytearray(b'0ctf{')

for target in targets[5:]:
    print(hex(target))
    print("\nexamining target {:#x}:".format(target))
    for trychar in string.printable:
        print("testing:"+trychar,)
        sys.stdout.flush()
        flag = bytes(flag_arr)+trychar.encode()
        state = p.factory.entry_state(stdin=flag + b"\n")

        e = p.factory.simulation_manager(state)
        e.explore(find=target)

        assert len(e.found) == 1
        np = e.found[0]

        while True:
            nb_size = target - np.addr
            if nb_size <= 0:
                break
            np = p.factory.successors(np, size=nb_size).flat_successors[0]
        assert nb_size == 0

        al = np.regs.eax[7:0]
        dl = np.regs.edx[7:0]
        al_val = al._model_concrete.value
        dl_val = dl._model_concrete.value

        if al_val == dl_val:
            flag_arr.append(ord(trychar))
            print("one flag_byte found:"+trychar)
            print("flag now:"+flag_arr.decode())
            sys.stdout.flush()
            break


return bytes(flag_arr)
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>上面这一段代码就是逐字节爆破了，由string.printable生成ascii字符串然后一个一个字节构造输入模拟执行，尝试al和dl相等的情况，若相等，就说明此字节是正确的，append此字节，然后迭代到下一个目标地址继续试探下一个字节，直到所有28个字节爆破完毕，就能得到flag了。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>（注：官方原脚本将run改为explore后运行正常）</font></br>