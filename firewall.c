#include <linux/in.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>

uint32_t ip_addr_from_string(const char * string_addr) {
    uint8_t octets[4];
    sscanf(string_addr, "%hhu.%hhu.%hhu.%hhu",
            &octets[0], &octets[1], &octets[2], &octets[3]);
    return *((int *)octets);
}

int protocol_uses_ports(uint8_t protocol) {
    return protocol == IPPROTO_TCP || protocol == IPPROTO_UDP;
}

/**
 * Default to drop. A whitelist rule allows matched packets.
 *
 * 0 for port-oriented protocols serves as a wildcard.
 */
struct firewall_whitelist_rule {
    const char * const source_ip;
    const uint16_t source_port;
    const char * const dest_ip;
    const uint16_t dest_port;
    const uint8_t protocol;
};

typedef struct firewall_whitelist_rule whitelist_rule;

whitelist_rule whitelist[6] = {
    { "192.168.1.8", 0, "192.168.1.9", 0, IPPROTO_ICMP },
    { "192.168.1.9", 0, "192.168.1.8", 0, IPPROTO_ICMP },
    { "192.168.1.8", 0, "192.168.1.9", 22, IPPROTO_TCP },
    { "192.168.1.9", 22, "192.168.1.8", 0, IPPROTO_TCP },
    { "192.168.1.8", 0, "128.230.18.198", 443, IPPROTO_TCP },
    { "128.230.18.198", 443, "192.168.1.8", 0, IPPROTO_TCP }
};

int matches_rule(const struct iphdr * iph,
        const unsigned char * transport_header,
        whitelist_rule rule) {
    // First check source and destination address
    if (iph->saddr != ip_addr_from_string(rule.source_ip)) {
        return false;
    }

    if (iph->daddr != ip_addr_from_string(rule.dest_ip)) {
        return false;
    }

    // Check protocol
    if (iph->protocol != rule.protocol) {
        return false;
    }

    // Check ports if port-oriented protocol
    if (protocol_uses_ports(iph->protocol)) {
        struct tcphdr * tcph = (struct tcphdr *) transport_header;

        // 0 is wildcard port
        if (rule.source_port != 0 && ntohs(tcph->source) != rule.source_port) {
            return false;
        }

        if (rule.dest_port != 0 && ntohs(tcph->dest) != rule.dest_port) {
            return false;
        }
    }

    // All checks passed
    return true;
}

void log_packet_info(const struct iphdr* iph, const unsigned char* transport_header){
    const char * proto;

    switch (iph->protocol) {
        case IPPROTO_TCP:
            proto = "TCP";
            break;
        case IPPROTO_UDP:
            proto = "UDP";
            break;
        case IPPROTO_ICMP:
            proto = "ICMP";
            break;
        default:
            proto = "IP";
            break;
    }

    if (protocol_uses_ports(iph->protocol)) {
        struct tcphdr * tcph = (struct tcphdr *) transport_header;

        printk(KERN_INFO "Checking %s packet %pI4:%hu->%pI4:%hu against whitelist.\n",
                proto,
                &iph->saddr, ntohs(tcph->source),
                &iph->daddr, ntohs(tcph->dest));
    } else {
        printk(KERN_INFO "Checking %s packet %pI4->%pI4 against whitelist.\n",
                proto, &iph->saddr, &iph->daddr);
    }
}

int matches_whitelist(const struct iphdr * iph,
        const unsigned char * transport_header) {
    size_t i;
    size_t whitelist_size = sizeof(whitelist) / sizeof(whitelist_rule);

    log_packet_info(iph, transport_header);

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