#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops nfho;

// function to be called by hook
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header;

    if (ip_header->protocol == IPPROTO_TCP) // use IPPROTO_TCP constant instead of a hardcoded value
    {
        printk(KERN_INFO "TCP Packet\n");

        // use tcp_hdr helper function to access the TCP header
        tcp_header = tcp_hdr(skb);

        // perform boundary checks before accessing fields in the TCP header
        if (skb->len >= (tcp_header->doff * 4)) // doff is the TCP data offset field
        {
            printk(KERN_INFO "Source Port: %u\n", ntohs(tcp_header->source));
        }
    }

    return NF_ACCEPT;
}

// Called when module loaded using 'insmod'
int init_module()
{
    nfho.hook = hook_func;
    nfho.priv = NULL;  // Set to NULL as we are not using private data
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    // Use nf_register_net_hook for recent kernels
    nf_register_net_hook(&init_net, &nfho);

    return 0;
}

// Called when module unloaded using 'rmmod'
void cleanup_module()
{
    // Use nf_unregister_net_hook for recent kernels
    nf_unregister_net_hook(&init_net, &nfho);
}

// Include the MODULE_LICENSE declaration
MODULE_LICENSE("GPL");
