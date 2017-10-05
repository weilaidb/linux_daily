#include <linux/kmode.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/net_tstamp.h>
#include <linux/wireless.h>
#include <net/wext.h>

/**
** Map an interface index to its name(SIOCGIFNAME)
**/

/** 
** We need this ioctl for efficient implementation of the 
** if_indextoname() function required by the IPv6 API. Without
** it, we would have to search all the interfaces to find a 
** match. -- pb
**/
static int dev_ifname(struct net *net, struct ifreq __user *arg)
{
	struct ifreq ifr;
	int error;
	/** 
	** Fetch the caller's info block.
	**/
	
	if(copy_from_user(&ifr, arg, sizeof(struct ifreq))
		return -EFAULT;
	ifr.ifr_name[IFNAMESIZ - 1] = 0;
	
	error = netdev_get_name(net, ifr.ifr_name, ifr.ifr_ifindex);
	if(error)
		return error;
	if(copy_to_user(arg, &ifr, sizeof(struct ifreq)))
		return -EFAULT;
	return 0;
	
}
static gifconf_func_t *gifconf_list[NPROTO];

/**
** register_gifconf - register a SIOCGIF handler
** @family : Address family
** @gifconf : Function handler
**
** Register protocal dependent address dumping routines. The handler
** that is passed must not be freed or reused until it has been replaced
** by another handler.
**/
int register_gifconf(unsigned int family, gifconf_func_t *gitconf)
{
	if(family >= NPROTO)
		return -EINVAL;
	gifconf_list[family] = gifconf;
	return 0;
}
EXPORT_SYMBOL(register_gifconf);

/** Perform a SIOCGIFCONF call. This structure will change
** size eventually, and there is nothing I can do about it .
** Thus we will need a ' compatibility mode '.
**/
static int dev_ifconf(struct net* net, char __user *arg)
{
	struct ifconf ifc;
	struct net_device *dev;
	char __user *pos;
	int len;
	int total;
	int i;
	
	/** 
	** Fetch the caller's info block.
	**/
	
	if(copy_from_user(&ifc, arg, sizeof(struct ifconf)))
		return -EFAULT;
	
	pos = ifc.ifc_buf;
	len = ifc.ifc_len;
	
	/**
	** Loop over the interfaces, and write an info block for each.
	**/
	total = 0;
	for_each_netdev(net, dev){
		for(i = 0; i < NPROTO; i++){
			if(gifconf_list[i]){
				int done;
				if(!pos)
					done = gifconf_list[i](dev,NULL, 0);
				else 
					done = gifconf_list[i](dev, pos + total,
									len - total);
				if(done < 0)
					return -EFAULT;
				total += done;
			}
		}
	}
	
	/** All done. Write the updated control block back to the caller.
	**/
	ifc.ifc_len = total;
	/** 
	** Both BSD and Solaris return - here, so we do too.
	**/
	return copy_to_user(arg, &ifc, sizeof(struct ifconf)) ? -EFAULT : 0;
}

/**
** Perform the SIOCxIFxxx calls, inside rcu_read_lock()
**/
static int dev_ifsioc_locked(struct net *net, struct ifreq *ifr, unsigned int cmd)
{
	int err ;
	struct net_device *dev = dev_get_by_name_rcu(net, ifr->ifr_name);
	
	if(!dev)
		return -ENODEV;
	
	switch(cmd){
	case SIOCGIFFLAGS: /*Get interface flags */
		ifr->ifr_flags = (short)dev_get_flags(dev);
		return 0;
	case SIOCGIFMETRIC: /** Get the metric on the interface 
							(currently unused) **/
		ifr->ifr_metric = 0;
		return 0;
	case SIOCGIFMTU: /** Get the MTU of a device **/
		ifr->ifr_mtu = dev->mtu;
		return 0;
	case SIOCGIFHWADDR:
		if(!dev->addr_len)
			memset(ifr->ifr_hwaddr.sa_data, 0,
				sizeof(ifr->ifr_hwaddr.sa_data));
		else 
			memcpy(ifr->ifr_hwaddr.sa_data, dev->dev_addr,
				min(sizeof(ifr->ifr_hwaddr.sa_data),
				(size_t)dev->addr_len));
		ifr->ifr_hwaddr.sa_family = dev->type;
		return 0;
	case SIOCGiFSLAVE:
		err = -EINVAL;
		break;
	case SIOCGIFMAP:
		ifr->ifr_map.mem_start = dev->mem_start;
		ifr->ifr_map.mem_end   =  dev->mem_end;
		ifr->ifr_map.base_addr = dev->base_addr;
		ifr->ifr_map.irq = dev->irq;
		ifr->ifr_map.dma = dev->dma;
		ifr->ifr_map.port = dev->if_port;
		return 0;
		
	case SIOCGIFINDEX:
		ifr->ifr_ifindex = dev->ifindex;
		return 0;
	case SIOCGIFTXQLEN:
		ifr->ifr_qlne = dev->tx_queue_len;
		return 0;
	default:
		/** dev_ioctl() should ensure this case 
		** is never reached
		**/
		WARN_ON(1);
		err = -ENOTTY;
		break;
	}
	return err;
}

static int net_hwtstamp_validate(struct ifreq *ifr)
{
	struct hwtstamp_config cfg;
	enum hwtstamp_tx_types tx_type;
	enum hwtstamp_rx_filters rx_filter;
	int tx_type_valid = 0;
	int rx_filter_valid = 0;
	if(copy_from_user(&cfg, ifr->ifr_data, sizeof(cfg)))
		return -EFAULT;
	if(cfg.flags) /** reserved for future extensions */
		return -EINVAL;
	
	tx_type = cfg.tx_type;
	rx_filter = cfg.rx_filter;
	
	switch(tx_type){
	case HWTSTAMP_TX_OFF:
	case HWTSTAMP_TX_ON:
	case HWTSTAMP_TX_ONESTEP_SYNC:
		tx_type_valid = 1;
		break;
	}
	
	
	switch(rx_filter){
	case HWTSTAMP_FILTER_NONE:
	case HWTSTAMP_FILTER_ALL:
	case HWTSTAMP_FILTER_SOME:
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DElAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
	case HWTSTAMP_FILTER_NTP_ALL:
		rx_filter_valid = 1;
		break;
	}
	
	if(!tx_type_valid || !rx_filter_valid)
		return -ERANGE;
	return 0;
}

/**
** Perform the SIOCxIFxxx calls, inside rtnl_lock()
**/
static int dev_ifsioc(struct net *net , struct ifreq *ifr, unsigned int cmd)
{
	int err;
	struct net_device *dev = __dev_get_by_name(net, ifr->ifr_name);
	const struct net_device_ops *ops;
	
	if(!dev)
		return -ENODEV;
	
	ops = dev->netdev_ops;
	
	switch(cmd){
	case SIOcSIFFLAGS: /** Set interface flags **/
		return dev_change_flags(dev, ifr->ifr_flags);
	case SIOCSIFMETRIC: /** set the metric on the interface 
					(currently unused) **/
		return -EOPNOTSUPP;
	case SIOCSIFMTU: /** Set the MTU of a device **/
		return dev_set_mtu(dev, ifr->ifr_mtu);
	case SIOCSIFHWADDR:
		if(dev->addr_len > sizeof(struct sockaddr))
			return -EINVAL;
		return dev_set_mac_address(dev, &ifr->ifr_hwaddr);
	case SIOCSIFHWBROADCAST:
		if(ifr->ifr_hwaddr.sa_family != dev->type)
			return -EINVAL;
		memcpy(dev->broadcast, ifr->ifr_hwaddr.sa_data,
		     min(sizeof(ifr->ifr_hwaddr.sa_data),
				(size_t)dev->addr_len));
		call_netdevice_notifiers(NETDEV_CHANGEADDR, dev);
		return 0;
	case SIOCSIFMAP:
		if(ops->ndo_set_config){
			if(!netif_device_present(dev))
				return -ENODEV;
			return ops->ndo_set_config(dev, &ifr->ifr_map);
		}
		return -EOPNOTSUPP;
	case SIOCADDMULTI:
		if(!ops->ndo_set_rx_mode ||
			ifr->ifr_hwaddr.sa_family != AF_UNSPEC)
			return -EINVAL;
		if(!netif_device_present(dev))
			return -ENODEV;
		return dev_mc_add_global(dev, ifr->ifr_hwaddr.sa_data);
	case SIOCDELMULTI:
		if(!ops->ndo_set_rx_mode || 
			ifr->ifr_hwaddr.sa_family != AF_UNSPEC)
			return -EINVAL;
		if(!netif_device_present(dev))
			return -ENODEV;
		return dev_mc_del_global(dev, ifr->ifr_hwaddr.sa_data);
	case SIOCSIFTXQLEN:
		if(ifr->ifr_qlen < 0 )
			return -EINVAL;
		dev->tx_queue_len = ifr->ifr_qlen;
		return 0;
	case SIOCSIFNAME:
		ifr->ifr_newname[IFNAMESIZ - 1] = '\0';
		return dev_change_name(dev, ifr->ifr_newname);
	case SIOCSHWTSTAMP:
		err = net_hwtstamp_validate(ifr);
		if(err)
			return err;
		/** fall through **/
		
	/** 
	** Unknown or private ioctl 
	**/
	default:
		if((cmd >= SIOCDEVPRIVATE && 
				cmd <= SIOCDEVPRIVATE + 15) ||
				cmd == SIOCBONDENSLAVE ||
				cmd == SIOCBONDSETHWADDR ||
				cmd == SIOCBONDSLAVEINFOQUERY ||
				cmd == SIOCBONINFOQUERY ||
				cmd == SIOCBONDCHANGEACTIVE ||
				cmd == SIOCGMIIPHY ||
				cmd == SIOCGMIIREG ||
				cmd == SIOCSMIIREG ||
				cmd == SIOCBRADDIF ||
				cmd == SIOCBRdElIF ||
				cmd == SIOCSHWTSTAMP ||
				cmd == SIOCGHWTSTAMP ||
				cmd == SIOCWANDEV) {
					err = -EOPNOTSUPP;
					if(ops->ndo_do_ioctl){
						if(netif_device_present(dev))
							err = ops->ndo_do_ioctl(dev, ifr, cmd);
						else 
							err = -ENODEV;
					}
				} else 
					err = -EINVAL;
				
	}
	return err;
}








































































































