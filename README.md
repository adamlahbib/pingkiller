# Description
simple eBPF program that drops ICMP packets. It is written in C and uses the eBPF library and XDP to load the program into the kernel then outputs stats in the userspace program based on cilium-ebpf.

### Some details:

XDP allows for early packet interception at the network interface driver level.

The XDP eBPF program, implemented in C, hooks into the Linux kernel’s networking stack at an early stage to intercept packets and decide their fate.

The accompanying Golang application interacts with the XDP eBPF program, providing a user-friendly interface to monitor the packet drop behavior and visualize performance statistics.

Check out our explanation, installation guide, and environment setup at [https://admida0ui.tech/2023/08/11/ebpf/](https://admida0ui.tech/2023/08/11/ebpf/)