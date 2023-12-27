#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define TC_ACT_UNSPEC -1

#define ETH_P_IP 0x0800
#define IP_OFFSET 0x1FFF /* mask for offset part of iphdr.frag_off */

struct ptphdr {
	__u8 messageType;
	__u8 versionPTP;
	__be16 messageLength; 
	__u8 domainNumber; 
	__u8 minorSdoId;
	__be16 flagField;
	__be64 correctionField;
	__be32 messageTypeSpecific;
	__u8 sourcePortIdentity[10];
	__be16 sequenceId;
	__u8 controlField;
	__u8 logMessageInterval;
};

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;
	struct ethhdr *eth = (void *)(__u64)skb->data;
	struct iphdr *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);
	struct ptphdr *ptp = (void *)(udp + 1);
	if ((void *)(ptp + 1) > (void *)(__u64)skb->data_end)
		return TC_ACT_OK;
	// cannot do anything with a fragment that isn't at the beginning of the packet
	if ((IP_OFFSET & bpf_ntohs(ip->frag_off)) != 0)
		return TC_ACT_OK;
	// only handle UDP at the moment
	if (ip->protocol != IPPROTO_UDP)
		return TC_ACT_OK;
	__u16 dport = bpf_ntohs(udp->dest);
	if (dport != 319 && dport != 320)
		return TC_ACT_OK;
	__u8 ver = ptp->versionPTP;
	__u8 major = ver & 0xF;
	__u8 minor = ver >> 4;
	if (major == 2 && minor != 0) {
		bpf_printk("Zeroed PTP minor version: dport=%d, messageType=%d, minor version=%d\n", dport, ptp->messageType & 0xF, minor);
		bpf_skb_store_bytes(skb, (void *)&ptp->versionPTP - (void *)eth, &major, 1, BPF_F_RECOMPUTE_CSUM);
	}
	return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
