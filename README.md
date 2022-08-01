# gqfi - gdb qemu fault injection
gqfi (gdb qemu fault injection) is a qemu based fault injection tool to simulate transient and permant memory faults in x86_64 intel systems.

### features
- transient memory faults (Single Event Upset, Single Bit Flip)
- permanent memory faults (Stuck to 0, Stuck to 1)
- time measurment in seconds (deterministic execution) or in cpu cycles
- unused memory regions can be detected during the golden run (see how to for more information)
- random bit and time 
