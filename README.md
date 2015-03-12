`mirage-net-pcap` is a module that satisfies Mirage's `V1.NETWORK` module type.  It reads from a pcap file (currently, provided by the Mirage crunch interface) and saves writes to memory.

An example unikernel using `mirage-net-pcap` is available at [https://github.com/yomimono/example-unikernels/] under the `arp_tester` directory.
