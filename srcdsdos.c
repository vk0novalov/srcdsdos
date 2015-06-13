#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/ip.h>

#define DNS_HEADER_SIZE 12

#define A2C_PRINT_REQUEST            "\xFF\xFF\xFF\xFF\x6C"
#define NULL_ENT_PACKET             "\xFF\xFF\xFF\xFF\x71\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x00"
#define STRANGE_BYTE_MARK_UDP_FLOOD    '\x20'

static int start_port = 27015;
static int end_port = 27030;

static struct nf_hook_ops bundle;

// based on https://github.com/dcherednik/kfdns4linux
static int kfdns_check_dns_header(unsigned char *data, uint len)
{
    if (len < DNS_HEADER_SIZE)
        return -1;
    if (*(data + sizeof(u16)) & 0x80)
        return 0;    /* response */
    return 1;        /* request */
}

static uint srcdsdos_packet_hook(uint hooknum,
                  struct sk_buff *skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn) (struct sk_buff *))
{
    struct iphdr *ip;
    struct udphdr *udp;
    unsigned char *data;
    unsigned int datalen;
    int i;
    int query;

    if (skb->protocol == htons(ETH_P_IP)) {
        ip = (struct iphdr *)skb_network_header(skb);
        if (ip->version == 4 && ip->protocol == IPPROTO_UDP) {
            skb_set_transport_header(skb, ip->ihl * 4);
            udp = (struct udphdr *)skb_transport_header(skb);
            if (udp->dest >= htons(start_port) && udp->dest <= htons(end_port)) {
                datalen =
                    skb->len - sizeof(struct iphdr) -
                    sizeof(struct udphdr);
                if (datalen == 0)
                {
                    return NF_DROP;
                }
                data =
                    skb->data + sizeof(struct udphdr) +
                    sizeof(struct iphdr);
                if (datalen >= 5 && !memcmp(data, A2C_PRINT_REQUEST, 5))
                {
                    return NF_DROP;
                }
                if (datalen >= 20 && !memcmp(data, NULL_ENT_PACKET, 20))
                {
                    return NF_DROP;
                }
                if (datalen > 40)
                {
                    for (i = 1; i < 20; i += 2)
                    {
                        if (data[i] != STRANGE_BYTE_MARK_UDP_FLOOD)
                            return NF_ACCEPT;
                    }
                    return NF_DROP;
                }
            } else if (udp->dest == htons(53)) {
                datalen =
                    skb->len - sizeof(struct iphdr) -
                    sizeof(struct udphdr);
                data =
                    skb->data + sizeof(struct udphdr) +
                    sizeof(struct iphdr);
                query = kfdns_check_dns_header(data, datalen);
                if (query <= 0)
                    return NF_DROP;
            }
        }
    }
    return NF_ACCEPT;
}

static int srcdsdos_init(void)
{
    bundle.hook = (nf_hookfn*)srcdsdos_packet_hook;
    bundle.owner = THIS_MODULE;
    bundle.pf = PF_INET;
    bundle.hooknum = 0; // NF_IP_PRE_ROUTING
    bundle.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&bundle);
    return 0;
}

static void srcdsdos_exit(void)
{
    nf_unregister_hook(&bundle);
}

module_init(srcdsdos_init);
module_exit(srcdsdos_exit);

module_param(start_port, int, 0);
module_param(end_port, int, 0);

MODULE_AUTHOR("victordoe");
MODULE_DESCRIPTION("Simple&stupid proposal of basic DoS protection for SRCDS");
MODULE_LICENSE("GPL");
