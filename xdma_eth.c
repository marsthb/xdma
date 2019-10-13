#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include "xdma-core.h"
#include "ps_pcie_dma_driver.h"
#include "ps_pcie_pf.h"
#include "xdma_eth.h"

/* Must be shorter than length of ethtool_drvinfo.driver field to fit */
#define DRIVER_NAME         "xxgbeth_driver"
#define DRIVER_DESCRIPTION  "Xilinx Gigabit Ethernet (XGEMAC) Linux driver"
#define DRIVER_VERSION      "1.0"
/*@}*/

#define XGMAC_TX_CHANNID 	0
#define XGMAC_RX_CHANNID 	1

#define ENABLE_JUMBO

#ifdef ENABLE_JUMBO    
#define XGMAC_RX_BUF_SIZE	XXGE_MAX_JUMBO_FRAME_SIZE
#else
#define XGMAC_RX_BUF_SIZE		1536
#endif

struct net_device *ndev = NULL;	    /* This networking device */

static struct net_device_ops xenet_netdev_ops;

/** @name Our private per-device data. When a net_device is allocated we 
 * will ask for enough extra space for this.
 * @{
 */
struct net_local {
	struct list_head rcv;
	struct list_head xmit;

	struct xdma_dev *lro;		/* parent device */

	struct net_device *ndev;	    /* This device instance */
	struct net_device_stats stats;	/* Statistics for this device */
	struct timer_list phy_timer;	/* PHY monitoring timer */

	u32 index;		                /* Which interface is this */
	u32 xgmii_addr;		            /* The XGMII address of the PHY */	

	void * TxHandle;                /* Handle of TX DMA engine */
	void * RxHandle;                /* Handle of RX DMA engine */

	/* The underlying OS independent code needs space as well.  A
	 * pointer to the following XXgEthernet structure will be passed to
	 * any XXgEthernet_ function that requires it.  However, we treat the
	 * data as an opaque object in this file (meaning that we never
	 * reference any of the fields inside this structure). */
	XXgEthernet Emac;

	unsigned int max_frame_size;
	/* buffer for one skb in case no room is available for transmission */
	struct sk_buff *deferred_skb;

	/* current sending skb, add by zkh */
	struct sk_buff *skb;

	/* add by zkh */
	struct napi_struct napi;

	/* Stats which could not fit in net_device_stats */
	int tx_pkts;
	int rx_pkts;
	int max_frags_in_a_packet;
	unsigned long realignments;
	unsigned long local_features;

	spinlock_t tx_lock;
};

int free_num_q_elements = 100;

extern int cyclic_transfer_setup(struct xdma_engine *engine);
extern int cyclic_transfer_teardown(struct xdma_engine *engine);
extern ssize_t eth_sgdma_write(struct xdma_dev *lro, char  *buf,
		size_t count, loff_t *pos, void *ptr_user_data);

int DmaMac_WriteReg(int offset, int data)
{
	return 0;
}
int DmaMac_ReadReg(int offset)
{
	int data = 0;

	return data;
}

void eth_tx_cbk(void *data)
{
	struct net_local *lp=netdev_priv(ndev);
	struct sk_buff *skb;
	unsigned int nfrags;

	/* for the multiple fragment packet, only last fragment deal with it. by zkh */
	if(data)
	{
		skb = (struct sk_buff*)data;
		nfrags = skb_shinfo(skb)->nr_frags +1;
		
		free_num_q_elements = free_num_q_elements + nfrags;	

		if (skb)
		{
			//need to increment stats and counters.
			
			lp->stats.tx_packets++;
			lp->stats.tx_bytes += skb->len;
			
			dev_kfree_skb(skb);
		}

		netif_wake_queue(lp->ndev);	
	}
}

void eth_rx_cbk(struct xdma_engine *engine, int length, int head)
{
	int ret;
	struct net_local *lp=netdev_priv(ndev);
	struct sk_buff *skb;
	unsigned char * phead;
	unsigned char *rx_buffer;
	int remaining = length;
	int copy;

	rx_buffer = engine->rx_buffer;

	skb = alloc_skb(length + 2, GFP_KERNEL);
//	skb = dev_alloc_skb(length + 2);
	if (skb == NULL) {
		printk("Alloc SKB failed for \n");    
		goto exit;
	}

	/* EOP found? Transfer anything from head to EOP */
	while (remaining) {
		copy = remaining > RX_BUF_BLOCK ? RX_BUF_BLOCK : remaining;

		dbg_tfr("head = %d, copy %d bytes from %p to skb\n", head,  copy,
			&rx_buffer[head * RX_BUF_BLOCK]);

//		skb_reserve(skb, 2); /* align IP on 16B boundary */  
		phead = skb_put(skb, copy);	/* Tell the skb how much data we got. */
		
		memcpy(phead, &rx_buffer[head * RX_BUF_BLOCK], copy);

		remaining -= copy;
		engine->user_buffer_index += copy;
		head = (head + 1) % RX_BUF_PAGES;
	}

	skb->dev = ndev;

	/* this routine adjusts skb->data to skip the header */
	skb->protocol = eth_type_trans(skb, ndev);
	skb->ip_summed = CHECKSUM_NONE;

	lp->stats.rx_packets++;
	lp->stats.rx_bytes += length;
	
	ret=netif_rx_ni(skb);	/* Send the packet upstream. */
//	ret = netif_receive_skb(skb);

	if(ret!=NET_RX_SUCCESS)
		printk(KERN_ERR "%s Rx Error %d\n", __FUNCTION__, ret);

exit:
	return;
}

#if 0    
/*
 * The poll implementation.
 */
static int zeth_poll(struct napi_struct *napi, int budget)
{
	int npackets = 0;
//	struct sk_buff *skb;
//	struct net_local *lp = container_of(napi, struct net_local, napi);
	int ret;
	struct net_local *lp=netdev_priv(ndev);
	struct sk_buff *skb;
	unsigned char * phead;
	unsigned char *rx_buffer;
	int remaining = length;
	int copy;

	struct snull_packet *pkt;

	while (npackets < budget && lp->rx_queue) {
		pkt = snull_dequeue_buf(dev);
		skb = dev_alloc_skb(pkt->datalen + 2);
		if (! skb) {
			if (printk_ratelimit())
				printk(KERN_NOTICE "snull: packet dropped\n");
			lp->stats.rx_dropped++;
			snull_release_buffer(pkt);
			continue;
		}
		skb_reserve(skb, 2); /* align IP on 16B boundary */  
		memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);
		skb->dev = dev;
		skb->protocol = eth_type_trans(skb, dev);
		skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
		netif_receive_skb(skb);
		
        	/* Maintain stats */
		npackets++;
		lp->stats.rx_packets++;
		lp->stats.rx_bytes += pkt->datalen;
		snull_release_buffer(pkt);
	}
	/* If we processed all packets, we're done; tell the kernel and reenable ints */
	if (! lp->rx_queue) {
		napi_complete(napi);
		snull_rx_ints(dev, 1);
		return 0;
	}

	/* We couldn't process everything. */
	return npackets;
}
#endif

static int xenet_send(struct sk_buff *skb, struct net_device *dev)
{
	int ret;
	struct net_local *lp;
	struct xdma_dev * lro;
//	unsigned long flags;
	unsigned int nfrags;
	skb_frag_t *frag;
	void *virt_addr;
	unsigned int len;
	loff_t pos = 0;

	lp = netdev_priv(dev);
	lro = lp->lro;
	
	/* Remember the skb, so we can free it at interrupt time */
	lp->skb = skb;

	spin_lock(&lp->tx_lock);
//	spin_lock_irqsave(&lp->tx_lock, flags);
	
	nfrags = skb_shinfo(skb)->nr_frags +1;

//	printk("%s fragment %d\n", __FUNCTION__, nfrags);

	if(nfrags > (free_num_q_elements - 1))
	{
		netif_stop_queue(dev);
		spin_unlock(&lp->tx_lock);
//		spin_unlock_irqrestore(&lp->tx_lock, flags);
		return NETDEV_TX_BUSY;
	}
	
	if(nfrags == 1)
	{
		ret = eth_sgdma_write(lro, skb->data, skb->len, &pos, (void *)skb);

		if(ret < XLNX_SUCCESS) 
		{
			printk(KERN_ERR"\n - Context Q saturated \n");
		}
	}
	else
	{
		int i=0; 
		frag = &skb_shinfo(skb)->frags[0];
		for(i=0;i< nfrags;i++)
		{
			if(i == 0)
			{
				len=skb_headlen(skb);

				printk(KERN_ERR"Eth Frag %d Length %d Data %x %x %x %x %x %x %x %x ",i,len,skb->data[0],skb->data[1],skb->data[2],skb->data[3],skb->data[4],skb->data[5],skb->data[6],skb->data[7]);

				ret = eth_sgdma_write(lro, skb->data, len, &pos, NULL);

				if(ret < XLNX_SUCCESS) 
				{
					printk(KERN_ERR"\n Context Q saturated Eth1\n");
				}
			}
			else
			{
				len =  skb_frag_size(frag);

				virt_addr = skb_frag_address(frag);

				printk(KERN_ERR"Eth Frag %d Length %d Data %x %x %x %x %x %x %x %x ",i,len,*((char *)(virt_addr)),*((char *)(virt_addr)+ 1),*((char *)(virt_addr)+ 2),*((char *)(virt_addr)+ 3),*((char *)(virt_addr)+4),*((char *)(virt_addr)+5 ),*((char *)(virt_addr)+6),*((char *)(virt_addr)+7 ));

				if(i== nfrags-1)
				{
					/* for the last fragment, record the skb buffer to free it. by zkh */
					ret = eth_sgdma_write(lro, virt_addr, len, &pos, (void *) skb);
				}
				else
				{
					ret = eth_sgdma_write(lro, virt_addr, len, &pos, NULL);
				}
				
				if(ret < XLNX_SUCCESS) 
				{
					printk(KERN_ERR"\n Context Q saturated Eth1\n");
				}

				frag++;				
			}

		}
	}

	spin_unlock(&lp->tx_lock);
//	spin_unlock_irqrestore(&lp->tx_lock, flags);

	return 0;
}

/*@}*/

/** @name For protection exclusion of all program flows
 * Calls from upper layer, and calls from DMA driver, and timer handlers.
 * Wrap certain temac routines with a lock, so access to the shared hard temac
 * interface is accessed mutually exclusive for dual channel temac support.
 * @{
 */
static inline void xenet_GetMacAddress(XXgEthernet *InstancePtr,
		void *AddressPtr)
{
	XXgEthernet_GetMacAddress(InstancePtr, AddressPtr);
}

static int xeth_setup_pool(struct net_device *dev)
{
	int rc = 0;
	struct xdma_engine *engine;
	struct net_local *lp = netdev_priv(dev);
	struct xdma_dev *lro;

	BUG_ON(!lp);
	lro = lp->lro;
	BUG_ON(!lro);
	engine = lro->engine[0][1];
	BUG_ON(!engine);
	BUG_ON(engine->magic != MAGIC_ENGINE);

	dbg_tfr("xeth_setup_pool(0x%p 0x%p %d %d)\n", dev, engine, 
			engine->streaming, engine->dir_to_dev);

	/* AXI ST C2H? Set up RX ring buffer on host with a cyclic transfer */
	if (engine->streaming && !engine->dir_to_dev)
		rc = cyclic_transfer_setup(engine);
	return rc;
}


/*
 * Called when the device goes from used to unused.
 */
static int xeth_free_pool(struct net_device *dev)
{
	int rc = 0;
	struct xdma_engine *engine;
	struct net_local *lp = netdev_priv(dev);
	struct xdma_dev *lro;

	BUG_ON(!lp);
	lro = lp->lro;
	BUG_ON(!lro);
	engine = lro->engine[0][1];
	BUG_ON(!engine);
	BUG_ON(engine->magic != MAGIC_ENGINE);

	dbg_tfr("%s (0x%p 0x%p %d %d)\n", __FUNCTION__, dev, engine, 
			engine->streaming, engine->dir_to_dev);

	if (engine->streaming && !engine->dir_to_dev)
		rc = cyclic_transfer_teardown(engine);

	return rc;
}

/* Gets called when ifconfig opens the interface */
static int xenet_open(struct net_device *dev)
{
	struct net_local *lp;
//	u32 Options;
	printk(KERN_INFO "calling xenet_open\n");

	/*
	 * Just to be safe, stop TX queue and the device first.  If the device is
	 * already stopped, an error will be returned.  In this case, we don't
	 * really care.
	 */
	netif_stop_queue(dev);
	lp = netdev_priv(dev);

	/* give the system enough time to establish a link */
	mdelay(2000);

	/* We're ready to go. */
	netif_start_queue(dev);

	spin_lock_init(&lp->tx_lock);

	return 0;
}

static int xenet_close(struct net_device *dev)
{
	struct net_local *lp;

	printk(KERN_INFO "xenet_close:\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)
	lp = netdev_priv(dev);
#else
	lp = (struct net_local *) dev->priv;	
#endif	

	/* Shut down the PHY monitoring timer. */
//	del_timer_sync(&lp->phy_timer);
	/* Stop Send queue */
	//   netif_carrier_off(dev); 
	netif_stop_queue(dev);
	/* Now we could stop the device */
//	_XXgEthernet_Stop(&lp->Emac);

	return 0;
}

static int xenet_set_mac_address(struct net_device *dev, void * ptr)
{
	return 0;
}

/*
 * Return statistics to the caller
 */
struct net_device_stats *xenet_get_stats(struct net_device *dev)
{
	struct net_local *lp;

//	printk("%s \n", __FUNCTION__);

	lp = netdev_priv(dev);

	return &lp->stats;
}

static void xenet_set_netdev_ops(struct net_device *ndev, struct net_device_ops *ndops)
{
	ndops->ndo_open = xenet_open;
	ndops->ndo_stop = xenet_close;
	ndops->ndo_start_xmit = xenet_send;
	ndops->ndo_set_mac_address = xenet_set_mac_address;
	//    ndops->ndo_do_ioctl = xenet_ioctl;
	//	ndops->ndo_change_mtu_rh74 = xenet_change_mtu;
	//    ndops->ndo_tx_timeout = xenet_tx_timeout;
	ndops->ndo_get_stats = xenet_get_stats;
	ndev->netdev_ops = ndops;
}

int xgenet_init(struct xdma_dev * lro)
{
	int retval = 0;
	struct net_local *lp = NULL;
	int rc=0;

	/*
	 * No kernel boot options used,
	 * so we just need to register the driver
	 */
	printk(KERN_INFO "Inserting Xilinx GigE driver in kernel.\n");

	ndev = alloc_etherdev(sizeof(struct net_local));
	if (!ndev) {
		printk(KERN_ERR "xgbeth_axi: Could not allocate net device.\n");
		retval= -ENOMEM;
		return retval;
	}

	/* Initialize the private data used by XEmac_LookupConfig().
	 * The private data are zeroed out by alloc_etherdev() already.
	 */

	lp = netdev_priv(ndev);

	lp->ndev = ndev;
	lp->lro = lro;

	xenet_GetMacAddress(&lp->Emac,ndev->dev_addr);

	printk("addr_len is %d, perm_addr[0] is %x, [1] = %x, [2] = %x, [3] = %x, perm_addr[4] is %x, [5] = %x\n", 
			ndev->addr_len, ndev->dev_addr[0], ndev->dev_addr[1], ndev->dev_addr[2],
			ndev->dev_addr[3], ndev->dev_addr[4], ndev->dev_addr[5]);

#ifdef ENABLE_JUMBO    
		lp->max_frame_size = XXGE_MAX_JUMBO_FRAME_SIZE;
#else
		lp->max_frame_size = 1600;
#endif

	ndev->mtu = XXGE_JUMBO_MTU;

	printk(KERN_INFO "MTU size is %d\n", ndev->mtu);

	/** Scan to find the PHY */
	lp->xgmii_addr = XXGE_PHY_ADDRESS;
	printk("xgmii_addr is %x\n", lp->xgmii_addr);

	xenet_set_netdev_ops(ndev, &xenet_netdev_ops);
	ndev->flags &= ~IFF_MULTICAST;
//	ndev->features = NETIF_F_SG | NETIF_F_FRAGLIST;
	ndev->features = 0;

	ndev->ifindex = 9;
	strcpy(ndev->name, "eth9");

	/* set up rx pool, init rx engine. by zkh */
	rc = xeth_setup_pool(ndev);

#if 0
	if (poll_mode) {
		netif_napi_add(ndev, &lp->napi, zeth_poll, 16);
	}
#endif

	rc = register_netdev(ndev);
	if (rc) {
		printk(KERN_ERR
				"%s: Cannot register net device, aborting.\n", ndev->name);
		goto error; /* rc is already set here... */
	} else {
		printk("%s:register net device, OK.\n", ndev->name);
	}

	return retval;
error:
	if (ndev) {
		free_netdev(ndev);
	}
	return -1;
}

void xgenet_cleanup(void)
{
	//Deregister Dma channels here 
	struct net_local *lp;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)
	lp = netdev_priv(ndev);
#else
	lp = (struct net_local *) ndev->priv;	
#endif	

	/* free rx pool. by zkh */
	xeth_free_pool(ndev);

	unregister_netdev(ndev);
	if(ndev != NULL)
		free_netdev(ndev);
}

