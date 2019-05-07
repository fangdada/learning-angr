# 0CTF2016 trace 

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这题就颇有难度了，知识点也比较多，首先我们来看看这题的[常规解](https://github.com/fangdada/ctf/tree/master/0CTF2016/trace)，我把反汇编脚本也放在这了。看懂了之后便思考如何用angr解决这个问题，因为这题是一个log和一个纯机器码文件，flag不作为输入而是在内存中，我们只能推测得到，所以不能用常规的exploror来求解，我们要用执行引擎模拟执行，先来看如下代码：</font></br>

```python
project = angr.Project("./data.bin", load_options={
    'main_opts': {
        'backend': 'blob',
        'base_addr': 0x400770,
        'arch': 'mipsel',
    },
})
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>跟常规的加载选项不同，这一次用了blob后端引擎使用mipsel架构来加载机器码文件，然后就可以模拟执行了。上一节讲了如何使用angr求解内存变量，所以这一次也是差不多：</font></br>

```python
    state = project.factory.blank_state(addr=MAIN_START)
    state.memory.store(FLAG_LOCATION, state.solver.BVS("flag", 8*32))
    state.memory.store(FLAG_PTR_LOCATION, struct.pack("<I", FLAG_LOCATION))

    sm = project.factory.simulation_manager(state)
    choices = [state]
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>因为是用机器码模拟执行所以要用空状态初始化，然后设置一下开始地址，再把solver的变量存储进入求解，跟第二节一样，最后同样作为参数传给simulation_manager就可以准备执行了，trace的代码如下：</font></br>

```python
def load_trace():
    res = []
    delay_slots = set()
    with open("./trace_8339a701aae26588966ad9efa0815a0a.log") as f:
        for line in f:
            if line.startswith('[INFO]'):
                addr = int(line[6:6+8], 16)

                res.append(addr)

                # every command like this is in delay slot
                # (in this particular binary)
                if ("move r1, r1" in line):
                    delay_slots.add(addr)

    return res, delay_slots

............
............

trace_log, delay_slots = load_trace()

............
............

print("Tracing...")
    for i, addr in enumerate(trace_log):
        if addr in delay_slots:
            continue

        for s in choices:
            if s.addr == addr:
                break

        else:
            raise ValueError("couldn't advance to %08x, line %d" % (addr, i+1))

        if s.addr == MAIN_END:
            break

        # if command is a jump, it's followed by a delay slot
        # we need to advance by two instructions
        # https://github.com/angr/angr/issues/71
        if s.addr + 4 in delay_slots:
            choices = project.factory.successors(s, num_inst=2).successors
        else:
            choices = project.factory.successors(s, num_inst=1).successors

    state = s
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>trace_log保存了trace的地址，delay_slots保存了适应处理器流水线设计的延迟指令。前半段都比较好理解，主要难点在于angr框架的这两句choices=project.factory.successors(s, num_inst=2).successors等。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>首先我们来看看官方文档里的解释：</font></br>

>`successors`(*simgr*, *state*, ***kwargs*)
>
>Perform the process of stepping a state forward, returning a SimSuccessors object.

>- **num_inst** – The maximum number of instructions.

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>successors会使用适合的模拟器（Simulation）执行，步进（step）一个状态（state），num_inst指定了最大的步进的语句数。num_inst=2就是为了跳过延迟指令（delay slots），否则会丢失状态分支，原因正如官方注释里的那个[issue](https://github.com/angr/angr/issues/71)。之前那个for s in choices....balabala的语句段就是让s指向最后的状态，而不会让s指向那个delay slot，不然脚本会出问题。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>好了，解释完了，等脚本最终慢慢trace完了之后state=s使state为最终状态，这时候之前保存的符号变量应当为flag了，将solver里的值取出转化为字符串就能得到flag了：</font></br>

```python
    print("Running solver...")

    solution = state.solver.eval(state.memory.load(FLAG_LOCATION, 32), cast_to=bytes).rstrip(b'\0').decode('ascii')
    print("The flag is", solution)

    return solution
```

