import angr
 
START_ADDR = 0x4007c2
 
p = angr.Project('angrybird')
state = p.factory.entry_state()
sm=p.factory.successors(state,num_inst=1)
sm=sm.successors[0]

while sm.addr!=0x400776:
    sm=p.factory.successors(sm,num_inst=1)
    sm=sm.successors[0]
# jump out the anti-run
sm.regs.rip=START_ADDR

# patch the stack
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

