This program loads and attaches a BPF TC egress filter that sets the minor version of PTP v2 packets to 0.

The purpose of this is to work around a defect in the ethernet PHY used by the Raspberry Pi CM4,
which is that an outgoing PTP packet is only timestamped if its minor version is 0.
LinuxPTP 4.0 generates packets with a minor verson of 1, so it needs patching in order
to work on the Raspberry Pi CM4. This program allows LinuxPTP 4.0 to work on the Raspberry Pi CM4
without patches.

Currently this works only for UDP IPv4 PTP transport, which is the default for LinuxPTP.
Please file an issue if you would like support for other transports.

The program accepts a single argument, which is the name of the interface to attach to.
When the program receives a SIGINT (Ctrl-C), it detaches the filter and exits.

The program uses BPF CO-RE (Compile Once, Run Everywhere), so the binary is not tied
to a specific kernel version and does not need a compiler toolchain at runtime.

This has been tested only on Fedora 39, arm64 on the Raspberry Pi CM4.

Build prerequisites
* clang
* bpftool
* libbpf-devel

Build and install:

```
make
sudo make install
```

This also installs a systemd service `ptpver20@`, with the instance being the interface.
Just start the service to make sure ptp4l works.

```
sudo systemctl start ptpver20@end0
```

Here the interface name is `end0`.

If you have problems, make sure that you are allowing PTP packets through the firewall.

References:
* https://patchwork.kernel.org/project/netdevbpf/patch/20210512103451.989420-3-memxor@gmail.com/
* https://nakryiko.com/posts/bpf-core-reference-guide/
* https://github.com/libbpf/libbpf-bootstrap/ (specifically tc example)
* https://nakryiko.com/posts/libbpf-bootstrap/
* https://taoshu.in/unix/modify-udp-packet-using-ebpf.html

**Issues**

libbpf will display the following message:

```
libbpf: Kernel error message: Exclusivity flag on, cannot modify
```

if there is already a qdisc on the interface.  The message is harmless. You can also remove the

```
tc qdisc del dev end0 clsact
```

I should fix this filtering out the message with libbpf_set_print (level LIBBPF_WARN).