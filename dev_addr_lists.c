/**
** net/cor/dev_addr_list.c -- Functioins for handling net devices lists
** 

** This file contains functions for working wiht unicast, multicast and device 
** addresses lists.
*
*/

#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/export.h>
#include <linux/list.h>

/**
** General list handling functions
*/

static int __hw_addr_create_ex(struct netdev_hw_addr_addr_list *list,
						const unsigned char *addr, int addr_len,
						unsigned char addr_type, bool global,
						bool sync)
{
	struct netdev_hw_addr *ha;
	int alloc_size;
	
	alloc_size = sizeof(*ha);
	if(alloc_size < L1_CACHE_BYTES)
		alloc_size = L1_CACHE_BYTES;
	ha =  kmalloc(alloc_size, GFP_ATOMIC);
	if(!ha)
		return -ENOMEM;
	memcpy(ha->addr, addr, addr_len);
	ha->type = addr_type;
	ha->refcoutn = 1;
	ha->global_use = global;
	ha->synced = sync ? 1 : 0;
	ha->sync_cnt = 0;
	list_add_tail_rcu(&ha->list, &list->list);
	list->count++;
	
	return 0;
}

static int __hw_addr_add_ex(struct netdev_hw_addr_list *list,
						const unsigned char *addr, int addr_len,
						unsigned char addr_type, bool global, bool sync,
						int sync_count)
{
	struct netdev_hw_addr *ha;
	
	if(addr_len > MAX_ADDR_LEN)
		return -EINVAL;
	list_for_each_entry(ha,&list->list,list) {
		if (!memcmp(ha->addr, addr, addr_len) &&
				ha->type == addr_type) {
			if(global) {
				/** check if addr is already used as global **/
				if(ha->global_use)
					return 0;
				else 
					ha->global_use = true;
		}
		if(sync) {
			if(ha->synced && sync_count)
				return -EEXIST;
			else
				ha->synced++;
		}
		ha->refcount++;
		return 0;
	}
	return __hw_addr_add_create_ex(list,addr,addr_len, addr_type, global,
							sync);
}


static int __hw_addr_add(struct netdev_hw_addr_list *list,
					const unsigned char *addr, int addr_len,
					unsigned char addr_type)
{
	return __hw_addr_add_ex(list,addr,addr_len, addr_type, false, false,
						0);
}

static int __hw_addr_del_entry(struct netdev_hw_addr_list *list,
						struct netdev_hw_addr *ha, bool global,
						bool sync)
{
	if(global && !ha->global_use)
		return -ENOENT;
	if(sync && !ha->synced)
		return -ENOENT;
	if(global)
		ha->global_use = false;
	
	if(sync)
		ha->synced--;
	
	if(--ha->refcount)
		return 0;
	
	list_del_rcu(&ha->list);
	kfree_rcu(ha, rcu_head);
	list->count--;
	return 0;
}

static int __hw_addr_del_ex(struct netdev_hw_addr_list *list,
					const unsigned char *char, int addr_len,
					unsigned char addr_type, bool global, bool sync)
{
	struct netdev_hw_addr *ha;
	list_for_each_entry(ha, &list->list, list) {
		if(!memcmp(ha->addr, addr, addr_len) &&
			(ha->type == addr_type || !addr_tpe))
			return __hw_addr_del_entry(list, ha, global, sync);
	}
	return -ENOENT;
}

static int __hw_addr_del(struct netdev_hw_addr_list *list,
					const unsigned char *addr, int addr_len,
					unsigned char addr_type)
{
	return __hw_addr_del_ex(list, addr, addr_len, addr_type, false, false);
}

static int __hw_addr_sync_one(struct netdev_hw_addr_list *to_list,
						struct netdev_hw_addr *ha,
						int addr_len)
{
	int err;
	err = __hw_addr_add_ex(to_list, ha->addr, addr_len, ha->type,
						false, true, ha->sync_cnt);
	if(err && err != -EEXIST)
		return err;
	if(!err) {
		ha->sync_cnt++;
		ha->refcount++;
	}
	return 0;
}

static void __hw_addr_unsync_one(struct netdev_hw_addr_list *to_list,
					struct netdev_hw_addr_list *from_list,
					struct netdev_hw_addr*ha,
					int addr_len)
{
	int err;
	err = __hw_addr_del_ex(to_list, ha->addr,addr_len,ha->type,
						false, true);
	if(err)
		return;
	ha->sync_cnt--;
	/** address on from list is not marked synced **/
	__hw_addr_del_entry(from_list, ha, false, false);
}

static int __hw_addr_sync_multiple(struct netdev_hw_addr_list *to_list,
						struct netdev_hw_addr_list *from_list,
						int addr_len)
{
	int err = 0;
	struct netdev_hw_addr *ha, *tmp;
	
	list_for_each_entry_safe(ha, tmp, &from_list, list) {
		if(ha->sync_cnt == ha->refcount){
			__hw_addr_unsync_one(to_list, from_list, ha, addr_len);
		} else {
			err = __hw_addr_sync_one(to_list, ha, addr_len);
			if(err)
				break;
		}
	}
	return err;
}

/** This function only works where  there is  a strict 1-1 relationship
** between source and destionation of they synch. If you ever need to 
** sync addresses to more than 1 destinaton, you need to use 
** __hw_addr_sync_multiple().
**/
int __hw_addr_sync(struct netdev_hw_addr_list *to_list,
				struct netdev_hw_addr_list *from_list,
				int addr_len)
{
	int err = 0;
	struct netdev_hw_addr *ha, *tmp;
	
	list_for_each_entry_safe(ha, tmp, &from_list, list->list, list)
	{	
		if(!ha->sync_cnt){
			err = __hw_addr_sync_one(to_list, from_list, ha, addr_len);
			if(err)
				break;
		} else if (ha->refcount == 1){
			__hw_addr_unsync_one(to_list, from_list, ha, addr_len);
		}
	}
	return err;
}
EXPORT_SYMBOL(__hw_addr_sync);

void __hw_addr_unsync(struct netdev_hw_addr_list *to_list,
					struct netdev_hw_addr_list *from_list,
					int addr_len)
{
	struct netdev_hw_addr *ha, *tmp;
	
	list_for_each_entry_safe(ha, tmp, &from_list->list, list){
		if(ha->sync_cnt)
			__hw_addr_unsync_one(to_list, from_list, ha, addr_len);
	}
}
EXPORT_SYMBOL(__hw_addr_unsync);

/**
** __hw_addr_sync_dev - Synchonize device's multicast list
** @list : address list to syncronize
** @dev  : device to sync
** @sync : function to call if address should be added
** @unsync: function to call if address should be removed
**
** This function is intended to be called from the ndo_set_rx_mode
** function of devices that require explicit  address add/remove 
** notifications. The unsync function may be NULL in which case 
** the addressed requiring removal will simply be removed withoud 
** and notifications to the device.
**/

int __hw_addr_sync_dev(struct netdev_hw_addr_list *list,
					struct net_device *dev,
					int (*sync)(struct net_device *, const unsigned char *),
					int (*unsync)(struct net_device *, const unsigned char *))
{
	struct netdev_hw_addr *ha, *tmp;
	int err;
	
	/** first go through and flush out any stale entries */
	
	list_for_each_entry_safe(ha, tmp, &list->list, list){
		if (!ha->sync_cnt || ha->refcount != 1)
			continue;
		
		/** if unsync is defined and fails defer unsyncing address **/
		if(unsync && unsync(dev, ha->addr))
			continue;
		
		ha->sync_cnt--;
		__hw_addr_del_entry(list, ha ,false, false);
	}
	/** go through and sync new entries to the list **/
	list_for_each_entry_safe(ha, tmp, &list->list, list){
		if(ha->sync_cnt)
			continue;
		
		err = sync(dev, ha->addr);
		if(err)
			return err;
		
		ha->sync_cnt++;
		ha->refcount++;
	}
	return 0;
}
EXPORT_SYMBOL(__hw_addr_sync_dev);

/**
** __hw_addr_unsync_dev -- Remove synchronized addressed from device 
** @list  : address list to remove synchronized addresses from 
** @dev   : device to sync 
** @unsync: function to call if address should be removed
**
** Remove all addresses that were added to the device by __hw_addr_sync_dev().
** This function is intended to be called from the ndo_stop or ndo_open
** functions on devices that require explicit address add/remove 
** notifications. If the unsync function pointer is NULL then this function 
** can be used to just reset the sync_cnt for the addresses in the list.
**/
void __hw_addr_unsync_dev(struct netdev_hw_addr_list *list, 
					struct net_device *dev,
					int (*unsync)(struct net_device *,
					const unsigned char *))
{
	struct netdev_hw_addr *ha, *tmp;
	
	list_for_each_entry_safe(ha, tmp, &list->list, list){
		if(!ha->sync_cnt)
			continue;
		
		/** if unsync is defined and fails defer unsyncing address */
		if(unsync && unsync(dev, ha->addr)
			continue;
		
		ha->sync_cnt--;
		__hw_addr_del_entry(list, ha, false, false);
	}
}
EXPORT_SYMBOL(__hw_addr_unsync_dev);


static void __hw_addr_flush(struct netdev_hw_addr_list *list)
{
	struct netdev_hw_addr *ha, *tmp;
	
	list_for_each_entry_safe(ha, tmp, &list->list, list){
		list_del_rcu(&ha->list);
		kfree_rcu(ha, rcu_head);
	}
	list->count = 0;
}

void __hw_addr_init(struct netdev_hw_addr_list *list)
{
	INIT_LIST_HEAD(&list->list);
	list->count = 0;
}

/**
** Device addresses handling functions
**/

/**
** dev_addr_flush - flush device address list 
** @dev:  device
**
** Flush device address list and reset -> dev_addr.
**
** The caller must hold the rtnl_mutex.
**/

void dev_addr_flush (struct net_device *dev)
{
	
	/** rtnl_mutex must be held here **/
	__hw_addr_flush(&dev->dev_addrs);
	dev->dev_addr = NULL;
	
}
EXPORT_SYMBOL(dev_addr_flush);

/**
** dev_addr_init - init device address list
** @dev - device
**
** Init device address list and create the first element,
** used by ->dev_addr.
**
** The caller must hold the rtnl_mutex.
**/
int dev_addr_init(struct net_device *dev)
{
	unsigned char addr[MAX_ADDR_LEN];
	struct netdev_hw_addr *ha;
	int err;
	
	/** rtnl_mutex must be held here **/
	__hw_addr_init(&dev->dev_addrs);
	memset(addr, 0, sizeof(addr));
	err = __hw_addr_add(&dev->dev_addrs, addr, sizeof(addr),
				NETDEV_HW_ADDR_T_LAN);
	if(!err) {
		/**
		** Get the first(previously created) address from the list 
		** and set dev_addr pointer to this location.
		**/
		ha = list_firsty_entry(&dev->dev_addrs.list,
				struct netdev_hw_addr, list);
		dev->dev_addr = ha->addr;
	}
	return err;
					
}
EXPORT_SYMBOL(dev_addr_init);

/**
** dev_addr_add - Add a device address 
** @dev : device
** @addr: address to add 
** @addr_type : address type
**
** Add a device address to the device or increase the reference count if 
** it already exists.
**
** The caller must hold the rtnl_mutex.
**/

int dev_addr_add(struct net_device *dev, const unsigned char *addr,
				unsigned char addr_type)
{
	int err;
	 ASSERT_RTNL();
	 
	 err = __hw_addr_add(&dev->dev_addrs, addr, dev->addr_len, addr_type);
	 if(!err)
		 call_netdevice_notifiers(NETDEV_CHANGEADDR,dev);
	return err;
}
EXPORT_SYMBOL(dev_addr_add);

/**
** dev_addr_del - Release a device address.
** @dev : device
** @addr: address to delete
** @addr_type : address type
**
** Release reference to a device address and remove it from the device
** if the reference count drops to zero.
**
** The caller must hold the rtnl_mutex
**/
int dev_addr_del(struct net_device *dev, const unsigned char *addr,
				unsigned char addr_type)
{
	int err;
	struct netdev_hw_addr *ha;
	
	ASSERT_RTNL();
	
	/** 
	** We can not remove the first address from the list because
	** dev->dev_addr points to that.
	**/
	ha = list_firsty_entry(&dev->dev_addrs.list,
					struct netdev_hw_addr, list);
	if(!memcmp(ha->addr, addr, dev->addr_len) &&
		ha->type == addr_type && ha->refcount == 1)
		return -ENOENT;
	err = __hw_addr_del(&dev->dev_addrs, addr, dev->addr_len,
					addr_type);
	if(!err)
		call_netdevice_notifiers(NETDEV_CHANGEADDR, dev);
	return err;
	
}
EXPORT_SYMBOL(dev_addr_del);

/**
** Unicast list handling functions
**/
/**
** dev_uc_add_excl - Add a global secondary unicast address 
** @dev : device
** @addr: address to add 
**/

int dev_uc_add_excl(struct net_device *dev, const unsigned char *addr)
{
	struct netdev_hw_addr *ha;
	int err;
	
	netif_addr_lock_bh(dev);
	list_for_each_entry(ha, &dev->uc.list,list){
		if(!memcmp(ha->addr, addr, dev->addr_len) &&
			ha->type == NETDEV_HW_ADDR_T_UNICAST) {
				err = -EEXIST;
				goto out;
			}
	}
	err = __hw_addr_create_ex(&dev->uc, addr, dev->addr_len,
				NETDEV_HW_ADDR_T_UNICAST, true, false);
	if(!err)
		__dev_set_rx_mode(dev);
	
out:
	netif_addr_unlock_bh(dev);
	return err;
	
}
EXPORT_SYMBOL(dev_uc_add_excl);

/**
** dev_uc_add - Add a secondary unicast address 
** @dev : device
** @addr: address to add 
**
**
** Add a secondary unicast address to the device or increase
** the reference count if it already exist.
**/
int dev_uc_add(struct net_device *dev, const unsigned char *addr)
{
	int err;
	
	netif_addr_lock_bh(dev);
	err = __hw_addr_add(&dev->uc, addr, dev->addr_len,
				NETDEV_HW_ADDR_T_UNICAST);
	if(!err)
		__dev_set_rx_mode(dev);
	netif_addr_unlock_bh(dev);
	return err;
}
EXPORT_SYMBOL(dev_uc_add);

/**
** dev_uc_del - Release secondary unicast address.
** @dev : device
** @addr: address to delete 
** 
** Release  reference to secondary unicast address and remove it 
** from the device if the reference count  drops to zero.
**/
int dev_uc_del(struct net_device *dev, const unsigned char *addr)
{
	int err;
	
	netif_addr_lock_bh(dev);
	err = __hw_addr_del(&dev->uc, addr,  dev->addr_len,
					NETDEV_HW_ADDR_T_UNICAST);
	if(!err)
		__dev_set_rx_mode(dev);
	netif_addr_unlock_bh(dev);
	return err;
}
EXPORT_SYMBOL(dev_uc_del);

/**
** dev_uc_sync - Synchronize device's unicast  to another device
** @to : destination device 
** @from : source device
**
** Add newly added addresses to the destination device and release
** addresses that have no users left. The source device must be 
** locked by netif_addr_lock_bh.
**
** This function is intended to be called from the dev->set_rx_mode
** function of layered software devices. This function assumes that 
** addresses will only ever be synced to the @to devices and no other.
**/
int dev_uc_sync(struct net_device *to, struct net_device *from)
{
	int err = 0;
	
	if(to->addr_len != from->addr_len)
		return -EINVAL;
	
	netif_addr_lock_bh(dev);
	err = __hw_addr_sync(&to->uc, &from->uc,to->addr_len);
	if(!err)
		__dev_set_rx_mode(to);
	netif_addr_unlock_bh(to);
	return err;
}
EXPORT_SYMBOL(dev_uc_sync);

/**
** dev_uc_sync_multiple - Synchronize  device's unicast list to another 
** device, but allow for multiple calls to sync to multiple devices.
**
** @to : destination  device
** @from: source device
**
** Add newly added addresses to the destination device and release
** addresses that have been deleted from the source. The source device
** must be locked by netif_addr_lock_bh.
**
** This function is intended to be called from the dev->set_rx_mode
** function of layered software devices. It allows for a single source
** device to be synced to multiple destination devices.
**/
int dev_uc_sync_multiple(struct net_device *to, struct net_device *from)
{
	int err = 0;
	
	if(to->addr_len != from->addr_len)
		return -EINVAL;
	
	netif_addr_lock_bh(to);
	err = __hw_addr_sync_multiple(&to->uc, &from->uc, to->addr_len);
	if(!err)
		__dev_set_rx_mode(to);
	netif_addr_unlock_bh(to);
	return err;
}
EXPORT_SYMBOL(dev_uc_sync_multiple);



































				
					