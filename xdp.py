from bcc import BPF
from ctypes import c_int
import sys
import time

def usage():
    print("Usage: {0} <ifdev> <port>".format(sys.argv[0]))
    print("e.g.: {0} ens160 8080\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 3:
    usage()

device = str(sys.argv[1])
port = int(sys.argv[2])

print("device: {}, port: {}".format(device, port))

b = BPF(text="""
  #include <uapi/linux/bpf.h>
  #include <linux/if_ether.h>
  #include <linux/tcp.h>
  #include <linux/ip.h>

  BPF_ARRAY(target_port, int, 1);

  static inline int get_port(struct iphdr *ip, void *data_end, int dst) {
    struct tcphdr *tcph = ((void*)ip) + sizeof(struct iphdr);

    if ((void*)&tcph[1] > data_end) {
      return 0;
    }

    if (dst == 0) {
      return ntohs(tcph->source);
    }
    return ntohs(tcph->dest);
  }

  int tcp_packet_filter(struct xdp_md *ctx) {
    void *data_end = (void*)(long)ctx->data_end;
    void *data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;

    uint64_t nh_off = sizeof(*eth);
    if (data + nh_off > data_end) {
      return XDP_DROP;
    }

    // get port condition
    uint32_t key = 0;
    int *port = target_port.lookup(&key);
    if (port == NULL) {
      return XDP_PASS;
    }

    if (*port == 0) {
      return XDP_PASS;
    }

    // protocol check
    struct iphdr *iph = data + sizeof(*eth);
    if ((void*)&iph[1] > data_end) {
      return XDP_DROP;
    }

    if (iph->protocol != IPPROTO_TCP) {
      return XDP_PASS;
    }

    int dport = get_port(iph, data_end, 1);

    // check port condition
    if (*port == dport) {
      bpf_trace_printk("block dport %d\\n", dport);
      return XDP_DROP;
    }

    return XDP_PASS;
  }
""", cflags=["-w"])

fn = b.load_func("tcp_packet_filter", BPF.XDP)

b["target_port"][c_int(0)] = c_int(port)
print("target_port: " + str(b["target_port"][c_int(0)].value))

try:
  b.attach_xdp(device, fn)
except Exception:
  print()
  usage()

try:
  b.trace_print()

except KeyboardInterrupt:
  print("Removing filter from device")

b.remove_xdp(device)
