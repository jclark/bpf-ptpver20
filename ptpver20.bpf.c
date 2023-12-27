#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define TC_ACT_UNSPEC -1

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/
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
	void *data = (void *)(__u64)skb->data;
	void *data_end = (void *)(__u64)skb->data_end;
	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;
	struct ethhdr *eth = data;
	void *p = eth + 1;
	struct iphdr *ip = p;
	if (p > data_end)
		return TC_ACT_OK;
	p = ip + 1;
	struct udphdr *udp = p;
	if (p > data_end)
		return TC_ACT_OK;
	// only handle UDP at the moment
	if (ip->protocol != IPPROTO_UDP)
		return TC_ACT_OK;
	// cannot do anything with a fragment that isn't at the beginning of the packet
	if ((IP_OFFSET & bpf_ntohs(ip->frag_off)) != 0)
		return TC_ACT_OK;
	p = udp + 1;
	struct ptphdr *ptp = p;
	if (p > data_end)
		return TC_ACT_OK;
	__u16 dport = bpf_ntohs(udp->dest);
	if (dport != 319 && dport != 320)
		return TC_ACT_OK;
	p = ptp + 1;
	if (p > data_end)
		return TC_ACT_OK;
	__u8 ver = ptp->versionPTP;
	__u8 major = ver & 0xF;
	__u8 minor = ver >> 4;
	if (major == 2 && minor != 0) {
		bpf_printk("Zeroed PTP minor version: dport=%d, messageType=%d, minor version=%d\n", dport, ptp->messageType & 0xF, minor);
		bpf_skb_store_bytes(skb, (void *)&ptp->versionPTP - data, &major, 1, BPF_F_RECOMPUTE_CSUM);
	}
	return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
