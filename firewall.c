#include <linux/in.h>

#include <linux/ip.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

/**
 * Default to drop. A whitelist rule allows matched packets.
 */
struct firewall_whitelist_rule {
    const char * const source_ip;
    const u_int16_t source_port;
    const char * const dest_ip;
    const u_int16_t dest_port;
    const u_int8_t protocol;
};

typedef struct firewall_whitelist_rule whitelist_rule;

whitelist_rule whitelist[1] = {
    { "192.168.1.9", 0, "192.168.1.8", 0, IPPROTO_ICMP }
};

int matches_rule(const struct iphdr * iph,
        const unsigned char * transport_header,
        whitelist_rule rule) {
    // First check source and destination address

    return false;
}

int matches_whitelist(const struct iphdr * iph,
        const unsigned char * transport_header) {
    size_t i;
    size_t whitelist_size = sizeof(whitelist) / sizeof(whitelist_rule);
    for (i = 0; i < whitelist_size; i++){
        if (matches_rule(iph, transport_header, whitelist[i])) {
            return true;
        }
    }

    // No rules matched
    return false;
}

unsigned int drop_unless_whitelisted(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state) {
    struct iphdr * iph = (struct iphdr *) skb_network_header(skb);
    unsigned char * transport_header = skb_transport_header(skb);

    if (matches_whitelist(iph, transport_header)) {
        return NF_ACCEPT;
    } else {
        return NF_DROP;
    }
}

static struct nf_hook_ops inbound_hook;
static struct nf_hook_ops outbound_hook;

int init_module(void) {
    printk(KERN_INFO "Starting firewall.\n");

    inbound_hook.hook = drop_unless_whitelisted;
    inbound_hook.hooknum = NF_INET_PRE_ROUTING;
    inbound_hook.pf = PF_INET;
    inbound_hook.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&inbound_hook);

    outbound_hook.hook = drop_unless_whitelisted;
    outbound_hook.hooknum = NF_INET_LOCAL_OUT;
    outbound_hook.pf = PF_INET;
    outbound_hook.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&outbound_hook);

    return 0;
}

void cleanup_module(void) {
    printk(KERN_INFO "Turning off firewall.\n");
    nf_unregister_hook(&inbound_hook);
    nf_unregister_hook(&outbound_hook);
}