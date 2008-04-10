#ifndef VNF_H
#define VNF_H
#include <linux/netdevice.h>

#define DEBUG_SKB
/* Default timeout period */
#define VNF_TIMEOUT 5   /* In jiffies */
/* These are the flags in the statusword */
#define VNF_RX_INTR 0x0001
#define VNF_TX_INTR 0x0002

#undef PDEBUG             /* undef it, just in case */
#ifdef VNF_DEBUG
#  ifdef __KERNEL__
     /* This one if debugging is on, and kernel space */
#    define PDEBUG(fmt, args...) printk( KERN_DEBUG "vnf: " fmt, ## args)
#  else
     /* This one for user space */
#    define PDEBUG(fmt, args...) fprintf(stderr, fmt, ## args)
#  endif
#else
#  define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif

#undef PDEBUGG
#define PDEBUGG(fmt, args...) /* nothing: it's a placeholder */


/*
 * A structure representing an in-flight packet.
 */
struct vnf_packet
{
	struct vnf_packet *next;
	struct net_device *dev;
	int	datalen;
	u8 data[ETH_DATA_LEN];
};

/*
 * This structure is private to each device. It is used to pass
 * packets in and out, so there is place for a packet
 */
struct vnf_priv
{
	struct net_device_stats stats;
	int status;
	struct vnf_packet *ppool;
	struct vnf_packet *rx_queue; /* List of incoming packets */
	int rx_int_enabled;
	int tx_packetlen;
	u8 *tx_packetdata;
	struct sk_buff *skb;
	spinlock_t lock;
};

static void vnf_dev_init(struct net_device *dev);
static int vnf_send(struct sk_buff *skb, struct net_device *dev);
static int vnf_open(struct net_device *dev);
static int vnf_stop(struct net_device *dev);

#ifdef DEBUG_SKB
void print_skb(struct sk_buff *skb);
#endif
#endif
