#ifndef VNF_H
#define VNF_H
#include <linux/netdevice.h>

#define OK 0
#define NOK -1
#define VNF_NAME "vnf%d"
#define DEBUG_SKB

struct vnf_priv
{
	struct net_device_stats stats;
};

static int vnf_dev_init(struct net_device *dev);
static int vnf_send(struct sk_buff *skb, struct net_device *dev);
static int vnf_open(struct net_device *dev);
static int vnf_stop(struct net_device *dev);

#ifdef DEBUG_SKB
void print_skb(struct sk_buff *skb);
#endif
#endif
