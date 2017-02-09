#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


unsigned int hook_func(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state) {
    return NF_DROP;
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