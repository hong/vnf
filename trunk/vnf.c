#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/if.h>
#include <linux/version.h>
#include "vnf.h"

extern struct net_device* alloc_etherdev(int sizeof_priv);
struct net_device *g_dev = NULL;

static int __init vnf_module_init(void)
{
	printk(KERN_DEBUG "init module\n");
	
	g_dev = alloc_etherdev(sizeof(struct vnf_priv));
	if(!g_dev)
		goto failed;
	
	memset((struct vnf_priv*)g_dev->priv, 0, sizeof(struct vnf_priv));
	strncpy(g_dev->name, VNF_NAME, IFNAMSIZ);

	g_dev->init = vnf_dev_init;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0))
	g_dev->destructor = free_netdev;
#else
	g_dev->features |= NETIF_F_DYNALLOC;
#endif
	if(register_netdev(g_dev))
		goto register_err;
	
	return OK;
register_err:
	kfree(g_dev);	
failed:
	return NOK;
}

static void __exit vnf_module_exit(void)
{
	if(g_dev)
	{
		unregister_netdev(g_dev);
		g_dev = NULL;
		printk("unregister netdev\n");
	}
	printk(KERN_DEBUG "exit modules\n");
}

static int vnf_dev_init(struct net_device *dev)
{
	printk(KERN_DEBUG "init net_dev\n");
	dev->hard_start_xmit = vnf_send;
	dev->open = vnf_open;
	dev->stop = vnf_stop;
	return OK;
}

/*ifconfig vnf0 up*/
static int vnf_open(struct net_device *dev)
{
	netif_start_queue(dev);
	printk(KERN_DEBUG "net device %s opened\n", dev->name);
	
	return OK;
}

/*ifconfig vnf0 down*/
static int vnf_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	printk(KERN_DEBUG "net device %s stopped\n", dev->name);

	return OK;
}

static int vnf_send(struct sk_buff *skb, struct net_device *dev)
{
	printk("vnf receive a skb\n");

#ifdef DEBUG_SKB
	print_skb(skb);
#endif	
	kfree_skb(skb);
	return 0;
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

module_init(vnf_module_init);
module_exit(vnf_module_exit);

MODULE_DESCRIPTION ("Virtual Network interFace (VNF), a Linux network device module.");
MODULE_AUTHOR ("hongzhiyi <zhiyi.hong@gamil.com>");
MODULE_VERSION ("0.1");
MODULE_LICENSE ("GPL");
