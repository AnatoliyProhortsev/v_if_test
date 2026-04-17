#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/inet.h>
#include <linux/if_arp.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <net/ip.h>

/// priv data
struct vnet_ping_priv
{
    /// dev address
    __be32 ipv4;

    /// lock for ip change
    spinlock_t procf_lock;
};

/// dev
static struct net_device *g_vnet_ping_dev = NULL;

/// procfs entry
static struct proc_dir_entry *g_vnet_ping_proc = NULL;

/// return ip to userspace
static int vnet_ping_proc_show(struct seq_file *m, void *v)
{
    struct vnet_ping_priv *priv;

    if (!g_vnet_ping_dev)
        return 0;

    priv = netdev_priv(g_vnet_ping_dev);

    seq_printf(m, "%pI4\n", &priv->ipv4);
    return 0;
}

/// open proc file
static int vnet_ping_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, vnet_ping_proc_show, NULL);
}

/// write handler
static ssize_t vnet_ping_proc_write(struct file *file,
                                const char __user *buffer,
                                size_t count,
                                loff_t *ppos)
{
    struct vnet_ping_priv *priv;

    char kbuf[64];
    __be32 new_ip;
    size_t len;

    if (!g_vnet_ping_dev)
        return -ENODEV;

    priv = netdev_priv(g_vnet_ping_dev);

    len = min(count, sizeof(kbuf) - 1);

    /// copy from userspace
    if (copy_from_user(kbuf, buffer, len))
        return -EFAULT;

    /// write nul-t
    kbuf[len] = '\0';

    // write nul-t to echo's esc-ch
    if (len > 0 && kbuf[len - 1] == '\n')
        kbuf[len - 1] = '\0';

    // parse ip from buff
    new_ip = in_aton(kbuf);
    if (new_ip == 0)
        return -EINVAL;

    // safe write
    spin_lock(&priv->procf_lock);
    priv->ipv4 = new_ip;
    spin_unlock(&priv->procf_lock);

    pr_info("vnet_ping0: new IPv4 = %pI4\n", &priv->ipv4);

    return count;
}

/// open op
static int vnet_ping_open(struct net_device *dev)
{
    netif_start_queue(dev);
    pr_info("%s: opened\n", dev->name);
    return 0;
}

/// stop op
static int vnet_ping_stop(struct net_device *dev)
{
    netif_stop_queue(dev);
    pr_info("%s: stopped\n", dev->name);
    return 0;
}

/// arp packet handle
static bool vnet_ping_handle_arp(struct sk_buff *skb, struct net_device *dev)
{
    struct vnet_ping_priv *priv = netdev_priv(dev);
    struct ethhdr *eth;
    struct arphdr *arp;

    unsigned int arp_len = sizeof(struct arphdr) +
                            2 * ETH_ALEN + 2 * sizeof(__be32);
    // write ptr
    unsigned char *arp_ptr;

    // addrs
    unsigned char *saddr;
    unsigned char *daddr;
    unsigned char old_saddr[ETH_ALEN];
    // ip
    __be32* sip;
    __be32* tip;
    __be32 old_sip;

    if (!pskb_may_pull(skb, sizeof(struct ethhdr) + arp_len))
        return false;

    eth = eth_hdr(skb);

    if (ntohs(eth->h_proto) != ETH_P_ARP)
        return false;

    arp = (struct arphdr *)(skb->data + sizeof(struct ethhdr));

    /// has valid header
    if (ntohs(arp->ar_hrd) != ARPHRD_ETHER ||
        ntohs(arp->ar_pro) != ETH_P_IP ||
        arp->ar_hln != ETH_ALEN ||
        arp->ar_pln != 4)
        return false;

    arp_ptr = (unsigned char *)(arp + 1);

    saddr = arp_ptr;
    arp_ptr += ETH_ALEN;

    sip = (__be32 *)arp_ptr;
    arp_ptr += sizeof(__be32);

    daddr = arp_ptr;
    arp_ptr += ETH_ALEN;

    tip = (__be32 *)arp_ptr;

    if (ntohs(arp->ar_op) != ARPOP_REQUEST)
        return false;

    if (*tip != priv->ipv4)
        return false;

    /// log
    pr_info("%s: ARP request who-has %pI4 from %pI4\n",
            dev->name, tip, sip);

    /// eth reply
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);

    /// arp request->reply op
    arp->ar_op = htons(ARPOP_REPLY);

    // set route
    /// swap haddr
    memcpy(old_saddr, saddr, ETH_ALEN);
    memcpy(daddr, old_saddr, ETH_ALEN);
    memcpy(saddr, dev->dev_addr, ETH_ALEN);
    /// reply with our ip
    old_sip = *sip;
    *tip = old_sip;
    *sip = priv->ipv4;

    // set rx packet
    skb->pkt_type = PACKET_HOST;
    skb->protocol = eth_type_trans(skb, dev);
    skb->ip_summed = CHECKSUM_UNNECESSARY;
    skb->dev = dev;

    /// send
    netif_rx(skb);
    return true;
}

// ndo_xmit
static netdev_tx_t vnet_ping_start_xmit(struct sk_buff *skb, struct net_device *dev)
{    
    struct vnet_ping_priv *priv = netdev_priv(dev);

    struct ethhdr *eth;
    struct iphdr *ip;
    struct icmphdr *icmp;

    unsigned int eth_hdr_len = sizeof(struct ethhdr);
    unsigned int min_ip_hdr_len = sizeof(struct iphdr);
    unsigned int icmp_hdr_len = sizeof(struct icmphdr);
    unsigned int ip_len;
    unsigned int icmp_len;

    unsigned char tmp_mac[ETH_ALEN];

    /// has skb
    if (!skb)
        return NETDEV_TX_OK;

    // handle arp
    if (vnet_ping_handle_arp(skb, dev)) 
    {
        dev->stats.tx_packets++;
        dev->stats.tx_bytes += skb->len;
        return NETDEV_TX_OK;
    }

    /// dev is up
    if (!(dev->flags & IFF_UP))
    {
        pr_info("%s: interface isn't up\n", dev->name);

        goto drop;
    }

    /// skb has eth header
    if (unlikely(!pskb_may_pull(skb, eth_hdr_len)))
        goto drop;
    /// get eth header
    eth = eth_hdr(skb);

    /// proto is IP
    if (ntohs(eth->h_proto) != ETH_P_IP)
        goto drop;

    // ip header
    /// skb has ip header
    if (unlikely(!pskb_may_pull(skb, eth_hdr_len + min_ip_hdr_len)))
        goto drop;
    /// get ip header
    ip = (struct iphdr *)(skb->data + eth_hdr_len);
    /// valid header len
    if (ip->ihl < 5)
        goto drop;
    /// ip header len
    ip_len = ip->ihl * 4;

    pr_info("%s: ip proto=%u src=%pI4 dst=%pI4 myip=%pI4\n",
        dev->name, ip->protocol, &ip->saddr, &ip->daddr, &priv->ipv4);

    /// ip proto is ICMP
    if (ip->protocol != IPPROTO_ICMP)
        goto drop;

    /// dest is our ip
    if (ip->daddr != priv->ipv4)
        goto drop;

    pr_info("%s: dst matches my ip %pI4\n", dev->name, &priv->ipv4);

    /// skb has icmp header
    if (unlikely(!pskb_may_pull(skb, eth_hdr_len + ip_len + icmp_hdr_len)))
        goto drop;
    /// get icmp header
    icmp = (struct icmphdr *)(skb->data + eth_hdr_len + ip_len);
    icmp_len = ntohs(ip->tot_len) - ip_len;

    pr_info("%s: icmp path src=%pI4 dst=%pI4 type=%u myip=%pI4\n",
        dev->name, &ip->saddr, &ip->daddr, icmp->type, &priv->ipv4);

    /// icmp has echo type
    if (icmp->type != ICMP_ECHO)
        goto drop;

    pr_info("%s: ICMP_ECHO detected\n", dev->name);

    /// replace with reply type
    icmp->type = ICMP_ECHOREPLY;
    icmp->code = 0;

    /// swap ip
    swap(ip->saddr, ip->daddr);

    /// swap MAC
    memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    // checksum
    /// icmp
    icmp->checksum = 0;
    icmp_len = ntohs(ip->tot_len) - ip_len;
    icmp->checksum = ip_compute_csum((void *)icmp, icmp_len);
    /// ip
    ip->check = 0;
    ip_send_check(ip);

    // skb
    skb->dev = dev;
    skb->pkt_type = PACKET_HOST;
    skb->protocol = htons(ETH_P_IP);
    /// send rx to kernel
    pr_info("%s sending ping response for %pI4\n", dev->name, &ip->daddr);
    netif_rx(skb);

    /// tx stat upd
    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;
    return NETDEV_TX_OK;

drop:
    dev->stats.tx_dropped++;
    dev_kfree_skb(skb);
    return NETDEV_TX_OK;
}

/// netdev ops contract
static const struct net_device_ops vnet_ping_netdev_ops = {
    .ndo_open       = vnet_ping_open,
    .ndo_stop       = vnet_ping_stop,
    .ndo_start_xmit = vnet_ping_start_xmit,
};

/// proc ops contract
static const struct proc_ops vnet_ping_proc_ops = {
    .proc_open    = vnet_ping_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
    .proc_write   = vnet_ping_proc_write,
};

/// setup func
static void vnet_ping_setup(struct net_device *dev)
{
    struct vnet_ping_priv *priv = netdev_priv(dev);

    ether_setup(dev);

    dev->netdev_ops = &vnet_ping_netdev_ops;
    dev->mtu = 1500;
    dev->tx_queue_len = 1000;

    // set default ip
    priv->ipv4 = in_aton("10.0.0.2");
    spin_lock_init(&priv->procf_lock);

    eth_hw_addr_random(dev);
}

/// alloc dev
static struct net_device *vnet_ping_create_dev(const char *name)
{
    struct net_device *dev;
    int ret;

    dev = alloc_netdev(sizeof(struct vnet_ping_priv),
                        name,
                        NET_NAME_UNKNOWN,
                        vnet_ping_setup);

    if (!dev)
    {
        return NULL;
    }

    ret = register_netdev(dev);
    if (ret)
    {
        free_netdev(dev);
        return NULL;
    }

    return dev;
}

static int __init vnet_ping_init(void)
{
    /// create vnet_ping dev
    g_vnet_ping_dev = vnet_ping_create_dev("vnet_ping0");
    if (!g_vnet_ping_dev)
    {
        return -ENOMEM;
    }
    pr_info("vnet_ping created {%s}\n", g_vnet_ping_dev->name);

    /// create proc
    g_vnet_ping_proc = proc_create("vnet_ping_ipv4", 0666, NULL, &vnet_ping_proc_ops);
    if (!g_vnet_ping_proc) 
    {
        pr_info("fail create proc {vnet_ping_ipv4}");
        unregister_netdev(g_vnet_ping_dev);
        free_netdev(g_vnet_ping_dev);
        g_vnet_ping_dev = NULL;
        return -ENOMEM;
    }
    pr_info("proc created {vnet_ping_ipv4}\n");

    return 0;
}

/// teardowm
static void __exit vnet_ping_exit(void)
{
    pr_info("vnet_ping deinit start\n");

    // remove proc
    if (g_vnet_ping_proc) 
    {
        pr_info("vnet_ping remove proc\n");
        proc_remove(g_vnet_ping_proc);
        g_vnet_ping_proc = NULL;
    }

    // remove dev
    if (g_vnet_ping_dev)
    {
        pr_info("vnet_ping remove dev\n");
        unregister_netdev(g_vnet_ping_dev);
        free_netdev(g_vnet_ping_dev);
        g_vnet_ping_dev = NULL;
    }

    pr_info("vnet_ping deinit end\n");
}

module_init(vnet_ping_init);
module_exit(vnet_ping_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anatoliy Prohorcev");
MODULE_DESCRIPTION("V_IF_TEST");