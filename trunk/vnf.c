#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/kernel.h> /* printk() */
#include <linux/slab.h>   /* kmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */
#include <linux/in.h>
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/skbuff.h>
#include <linux/in6.h>
#include <asm/checksum.h>
#include "vnf.h"

MODULE_DESCRIPTION ("Virtual Network interFace (VNF), a Linux network device module.");
MODULE_AUTHOR ("hongzhiyi <zhiyi.hong@gamil.com>");
MODULE_VERSION ("0.1");
MODULE_LICENSE ("GPL");

struct net_device *g_dev = NULL;

/*
 * Transmitter lockup simulation, normally disabled.
 */
static int lockup = 0;
module_param(lockup, int, 0);

static int timeout = VNF_TIMEOUT;
module_param(timeout, int, 0);

/*
 * Do we run in NAPI mode?
 */
static int use_napi = 0;
module_param(use_napi, int, 0);

int pool_size = 8;
module_param(pool_size, int, 0);

static void vnf_tx_timeout(struct net_device *dev);
static void (*vnf_interrupt)(int, void *, struct pt_regs *);

/*
 * Set up a device's packet pool.
 */
static void vnf_setup_pool(struct net_device *dev)
{
	struct vnf_priv *priv = netdev_priv(dev);
	int i;
	struct vnf_packet *pkt;

	priv->ppool = NULL;
	for (i = 0; i < pool_size; i++) {
		pkt = kmalloc(sizeof(struct vnf_packet), GFP_KERNEL);
		if (pkt == NULL) {
			printk (KERN_NOTICE "Ran out of memory allocating packet pool\n");
			return;
		}
		pkt->dev = dev;
		pkt->next = priv->ppool;
		priv->ppool = pkt;
	}
}

static void vnf_teardown_pool(struct net_device *dev)
{
	struct vnf_priv *priv = netdev_priv(dev);
	struct vnf_packet *pkt;
		    
	while ((pkt = priv->ppool)) {
		priv->ppool = pkt->next;
		kfree (pkt);
		/* FIXME - in-flight packets ? */
	}
} 

/*
 * Buffer/pool management.
 */
static struct vnf_packet *vnf_get_tx_buffer(struct net_device *dev)
{
	struct vnf_priv *priv = netdev_priv(dev);
	unsigned long flags;
	struct vnf_packet *pkt;

	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->ppool;
	if (priv->ppool == NULL) {
		printk(KERN_INFO "Pool empyt\n");
		netif_stop_queue(dev);
	}
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;
}

static void vnf_release_buffer(struct vnf_packet *pkt)
{
	unsigned long flags;
	struct vnf_priv *priv = netdev_priv(pkt->dev);

	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->ppool;
	priv->ppool = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
	if (netif_queue_stopped(pkt->dev) && pkt->next == NULL)
		netif_wake_queue(pkt->dev);
}

static void vnf_enqueue_buf(struct net_device *dev, struct vnf_packet *pkt)
{
	unsigned long flags;
	struct vnf_priv *priv = netdev_priv(dev);

	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->rx_queue; /* FIXME - misorders packets */
	priv->rx_queue = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
}

static struct vnf_packet *vnf_dequeue_buf(struct net_device *dev)
{
	struct vnf_priv *priv = netdev_priv(dev);
	struct vnf_packet *pkt;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->rx_queue;
	if (pkt != NULL)
		priv->rx_queue = pkt->next;
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;
}

/*
 * Enable and disable receive interrupts.
 */
static void vnf_rx_ints(struct net_device *dev, int enable)
{
	struct vnf_priv *priv = netdev_priv(dev);
	priv->rx_int_enabled = enable;
}

/* 
 * Open and close
 */
static int vnf_open(struct net_device *dev)
{
	/* 
	 * Assign the hardware address of the board: use "\0vnfx", where
	 * x is 0 or 1. The first byte is '\0' to avoid being a multicast
	 * address (the first byte of multicast addrs is odd).
	 */
	memcpy(dev->dev_addr, "\0vnf0", ETH_ALEN);
	if (dev == g_dev)
		dev->dev_addr[ETH_ALEN-1]++; /* \0vnf1 */
	netif_start_queue(dev);
	printk(KERN_DEBUG "net device %s opened\n", dev->name);
	return 0;
}

static int vnf_stop(struct net_device *dev)
{
	/* release ports, irq and such -- like fops->close */
	netif_stop_queue(dev);
	printk(KERN_DEBUG "net device %s stopped\n", dev->name);
	return 0;
}

/*
 * Configuration changes (passed on by ifconfig)
 */
static int vnf_config(struct net_device *dev, struct ifmap *map)
{
	if (dev->flags & IFF_UP)
		return -EBUSY;
	
	/* Don't allow changing the I/O address */
	if (map->base_addr != dev->base_addr) {
		printk(KERN_WARNING "vnf: Can't change I/O address\n");
		return -EOPNOTSUPP;
	}

	/* Allow changing the IRQ */
	if (map->irq != dev->irq) {
		dev->irq = map->irq;
		/* request_irq() is delayed to open-time */
	}

	/* ignore other fields */
	return 0;
}

/*
 * Receive a packet: retrieve, encapsulate and pass over to upper levels
 */
static void vnf_rx(struct net_device *dev, struct vnf_packet *pkt)
{
	struct sk_buff *skb;
	struct vnf_priv *priv = netdev_priv(dev);

	/*
	 * The packet has been retrieved from the transmission
	 * medium. Build an skb around it, so upper layers can handle it
	 */
	skb = dev_alloc_skb(pkt->datalen + 2);
	if (!skb) {
		if (printk_ratelimit())
			printk(KERN_NOTICE "vnf rx: low on mem - packet dropped\n");
		priv->stats.rx_dropped++;
		goto out;
	}
	skb_reserve(skb, 2); /* align IP on 16B boundary */
	memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);

#ifdef DEBUG_SKB
	print_skb(skb);
#endif	

	/* Write metadata, and then pass to the receive level */
	skb->dev = dev;
	skb->protocol = eth_type_trans(skb, dev);
	skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
	priv->stats.rx_packets++;
	priv->stats.rx_bytes += pkt->datalen;
	netif_rx(skb);

out:
	//kfree_skb(skb);
	return;
}

/*
 * The poll implementation.
 */
static int vnf_poll(struct net_device *dev, int *budget)
{

	/* We couldn't process everything. */
	return 1;
}

/*
 * The typical interrupt entry point
 */
static void vnf_regular_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	int statusword;
	struct vnf_priv *priv;
	struct vnf_packet *pkt = NULL;

	/*
	 * As usual, check the "device" pointer to be sure it is
	 * really interrupting.
	 * Then assign "struct device *dev"
	 */
	struct net_device *dev = (struct net_device *)dev_id;
	if (!dev)
		return;

	/* Lock the device */
	priv = netdev_priv(dev);
	spin_lock(&priv->lock);
	
	/* retrieve statusword: real netdevices use I/O instructions */
	statusword = priv->status;
	priv->status = 0;
	if (statusword & VNF_RX_INTR) {
		/* send it to vnf_rx for handling */
		pkt = priv->rx_queue;
		if (pkt) {
			priv->rx_queue = pkt->next;
			vnf_rx(dev, pkt);
		}
	}

	if (statusword & VNF_TX_INTR) {
		/* a transmission is over: free the skb */
		priv->stats.tx_packets++;
		priv->stats.tx_bytes += priv->tx_packetlen;
		dev_kfree_skb(priv->skb);
	}

	/* Unlock the device and we are done */
	spin_unlock(&priv->lock);
	if (pkt)
		vnf_release_buffer(pkt);
	return;
}

/*
 * A NAPI interrupt handler.
 */
static void vnf_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	return;
}

/*
 * Transmit a packet (low level interface)
 */
static void vnf_hw_tx(char *buf, int len, struct net_device *dev)
{
	/*
	 * This function deals with hw details. This interface loops
	 * back the packet to the other vnf interface (if any).
	 * In other words, this function implements the vnf behaviour,
	 * while all other procedures are rather device-independent
	 */
	struct iphdr *ih;
	struct net_device *dest;
	struct vnf_priv *priv;
	u32 *saddr, *daddr;
	struct vnf_packet *tx_buffer;

	if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
		printk("vnf: Hmm... packet too short (%i octets)\n", len);
		return;
	}

	if (0) {  /* enable this conditional to look at the data */
		int i;
		PDEBUG("len is %i\n" KERN_DEBUG "data:", len);
		for (i = 14; i < len; i++)
			printk(" %02x", buf[i] & 0xff);
		printk("\n");
	}

	/*
	 * Ethhdr is 14 bytes, but the kernel arranges for iphdr
	 * to be aligned (i.e., ethhdr is unaligned)
	 */
	ih = (struct iphdr *)(buf+sizeof(struct ethhdr));
	saddr = &ih->saddr;
	daddr = &ih->daddr;
	((u8 *)saddr)[2] ^= 1; /* change the third octet (class C) */
	((u8 *)daddr)[2] ^= 1;

	ih->check = 0;         /* and rebuild the checksum (ip needs it) */
	ih->check = ip_fast_csum((unsigned char *)ih,ih->ihl);

	if (dev == g_dev)
		PDEBUGG("%08x:%05i --> %08x:%05i\n",
			ntohl(ih->saddr),ntohs(((struct tcphdr *)(ih+1))->source),
			ntohl(ih->daddr),ntohs(((struct tcphdr *)(ih+1))->dest));
	else
		PDEBUGG("%08x:%05i <-- %08x:%05i\n",
			ntohl(ih->daddr),ntohs(((struct tcphdr *)(ih+1))->dest),
			ntohl(ih->saddr),ntohs(((struct tcphdr *)(ih+1))->source));

	/*
	 * Ok, now the packet is ready for transmission: first simulate a
	 * receive interrupt on the twin device, then  a
	 * transmission-done on the transmitting device
	 */
	/*FIXME
	 * dest = vnf_devs[dev == vnf_devs[0] ? 1 : 0];
	 * ...
	 */
}

/*
 * Transmit a packet (called by the kernel)
 */
static int vnf_tx(struct sk_buff *skb, struct net_device *dev)
{
	int len;
	char *data, shortpkt[ETH_ZLEN];
	struct vnf_priv *priv = netdev_priv(dev);
		
	data = skb->data;
	len = skb->len;
	if (len < ETH_ZLEN) {
		memset(shortpkt, 0, ETH_ZLEN);
		memcpy(shortpkt, skb->data, skb->len);
		len = ETH_ZLEN;
		data = shortpkt;
	}
	dev->trans_start = jiffies; /* save the timestamp */

	/* Remember the skb, so we can free it at interrupt time */
	priv->skb = skb;

	/* actual deliver of data is device-specific, and not shown here */
	vnf_hw_tx(data, len, dev);

	return 0; /* Our simple device can not fail */
}

/*
 * Deal with a transmit timeout.
 */
static void vnf_tx_timeout(struct net_device *dev)
{
	struct vnf_priv *priv = netdev_priv(dev);

	PDEBUG("Transmit timeout at %ld, latency %ld\n", jiffies,
		jiffies - dev->trans_start);

	/* Simulate a transmission interrupt to get things moving */
	priv->status = VNF_TX_INTR;
	vnf_interrupt(0, dev, NULL);
	priv->stats.tx_errors++;
	netif_wake_queue(dev);
	return;
}

/*
 * Ioctl commands
 */
static int vnf_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	PDEBUG("ioctl\n");
	return 0;
}

/*
 * Return statistics to the caller
 */
struct net_device_stats *vnf_stats(struct net_device *dev)
{
	struct vnf_priv *priv = netdev_priv(dev);
	return &priv->stats;
}

/*
 * This function is called to fill up an eth header, since arp is not
 * available on the interface
 */
static int vnf_rebuild_header(struct sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *)skb->data;
	struct net_device *dev = skb->dev;

	memcpy(eth->h_source, dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest, dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN - 1] ^= 0x01;  /* dest is us xor 1 */
	return 0;
}

static int vnf_header(struct sk_buff *skb, struct net_device *dev,
                      unsigned short type, void *daddr, void *saddr,
		              unsigned int len)
{
	struct ethhdr *eth = (struct ethhdr *)skb_push(skb, ETH_HLEN);

	eth->h_proto = htons(type);
	memcpy(eth->h_source, saddr ? saddr : dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest,   daddr ? daddr : dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN-1]   ^= 0x01;   /* dest is us xor 1 */
	return (dev->hard_header_len);
}

/*
 * The "change_mtu" method is usually not needed.
 * If you need it, it must be like this.
 */
static int vnf_change_mtu(struct net_device *dev, int new_mtu)
{

	return 0;
}

/* The init function (sometimes called probe).*/
static void vnf_dev_init(struct net_device *dev)
{
	struct vnf_priv *priv;

	ether_setup(dev); /* assign some of the fields */

	dev->open = vnf_open;
	dev->stop = vnf_stop;
	dev->set_config = vnf_config;
	dev->hard_start_xmit = vnf_rx;
	dev->do_ioctl = vnf_ioctl;
	dev->get_stats = vnf_stats;
	dev->change_mtu = vnf_change_mtu;
	dev->rebuild_header = vnf_rebuild_header;
	dev->hard_header = vnf_header;
	dev->tx_timeout = vnf_tx_timeout;
	dev->watchdog_timeo = timeout;
	if (use_napi) {
		dev->poll = vnf_poll;
		dev->weight = 2;
	}
	/* keep the default flags, just add -1ARP */
	dev->flags |= IFF_NOARP;
	dev->features |= NETIF_F_NO_CSUM;
	dev->hard_header_cache = NULL;      /* Disable caching */

	/*
	 * Then, initialize the priv field. This encloses the statistics
	 * and a few private fields.
	 */
	priv = netdev_priv(dev);
	memset(priv, 0, sizeof(struct vnf_priv));
	spin_lock_init(&priv->lock);
	vnf_rx_ints(dev, 1); /* enable receive interrupts */
	vnf_setup_pool(dev);
}


#ifdef DEBUG_SKB
void print_skb(struct sk_buff *skb)
{
	int i;
	
	printk(KERN_DEBUG "skb->length = %d", skb->len);
	for( i = 0; i < skb->len; i++ )
	{
		if( (i&0x0f) == 0)
		{
			printk("\n[%04x]", i);
		}
		printk("%2.2x ", skb->data[i]);
	}
	printk("\n");
}
#endif


static int __init vnf_module_init(void)
{
	int result, ret = -ENOMEM;
	printk(KERN_DEBUG "init module\n");
	vnf_interrupt = use_napi ? vnf_napi_interrupt : vnf_regular_interrupt;

	/* Allocate the devices */
	g_dev = alloc_netdev(sizeof(struct vnf_priv), "vnf%d",
		vnf_dev_init);
	if(!g_dev)
		goto out;

	ret = -ENODEV;
	if(result = register_netdev(g_dev)) {
		printk("vnf: error %i registering device \"%s\"\n",
			result, g_dev->name);
	} else 
		ret = 0;
out:
	if (ret) {
		free_netdev(g_dev);
	}
	return ret;
}

static void __exit vnf_module_exit(void)
{
	if(g_dev)
	{
		unregister_netdev(g_dev);
		vnf_teardown_pool(g_dev);
		free_netdev(g_dev);
	}
	printk(KERN_DEBUG "exit modules\n");
}

module_init(vnf_module_init);
module_exit(vnf_module_exit);
