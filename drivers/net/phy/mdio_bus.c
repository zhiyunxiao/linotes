// SPDX-License-Identifier: GPL-2.0+
/* MDIO Bus interface
 *
 * Author: Andy Fleming
 *
 * Copyright (c) 2004 Freescale Semiconductor, Inc.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/gpio/consumer.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mii.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of_device.h>
#include <linux/of_mdio.h>
#include <linux/phy.h>
#include <linux/reset.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>

#define CREATE_TRACE_POINTS
#include <trace/events/mdio.h>

static int mdiobus_register_gpiod(struct mdio_device *mdiodev)
{
	/* Deassert the optional reset signal */
	mdiodev->reset_gpio = gpiod_get_optional(&mdiodev->dev,
						 "reset", GPIOD_OUT_LOW);
	if (IS_ERR(mdiodev->reset_gpio))
		return PTR_ERR(mdiodev->reset_gpio);

	if (mdiodev->reset_gpio)
		gpiod_set_consumer_name(mdiodev->reset_gpio, "PHY reset");

	return 0;
}

static int mdiobus_register_reset(struct mdio_device *mdiodev)
{
	struct reset_control *reset;

	reset = reset_control_get_optional_exclusive(&mdiodev->dev, "phy");
	if (IS_ERR(reset))
		return PTR_ERR(reset);

	mdiodev->reset_ctrl = reset;

	return 0;
}

int mdiobus_register_device(struct mdio_device *mdiodev)
{
	int err;

	if (mdiodev->bus->mdio_map[mdiodev->addr])
		return -EBUSY;

	if (mdiodev->flags & MDIO_DEVICE_FLAG_PHY) {
		err = mdiobus_register_gpiod(mdiodev);
		if (err)
			return err;

		err = mdiobus_register_reset(mdiodev);
		if (err)
			return err;

		/* Assert the reset signal */
		mdio_device_reset(mdiodev, 1);
	}

	mdiodev->bus->mdio_map[mdiodev->addr] = mdiodev;

	return 0;
}
EXPORT_SYMBOL(mdiobus_register_device);

int mdiobus_unregister_device(struct mdio_device *mdiodev)
{
	if (mdiodev->bus->mdio_map[mdiodev->addr] != mdiodev)
		return -EINVAL;

	reset_control_put(mdiodev->reset_ctrl);

	mdiodev->bus->mdio_map[mdiodev->addr] = NULL;

	return 0;
}
EXPORT_SYMBOL(mdiobus_unregister_device);

static struct mdio_device *mdiobus_find_device(struct mii_bus *bus, int addr)
{
	bool addr_valid = addr >= 0 && addr < ARRAY_SIZE(bus->mdio_map);

	if (WARN_ONCE(!addr_valid, "addr %d out of range\n", addr))
		return NULL;

	return bus->mdio_map[addr];
}

struct phy_device *mdiobus_get_phy(struct mii_bus *bus, int addr)
{
	struct mdio_device *mdiodev;

	mdiodev = mdiobus_find_device(bus, addr);
	if (!mdiodev)
		return NULL;

	if (!(mdiodev->flags & MDIO_DEVICE_FLAG_PHY))
		return NULL;

	return container_of(mdiodev, struct phy_device, mdio);
}
EXPORT_SYMBOL(mdiobus_get_phy);

bool mdiobus_is_registered_device(struct mii_bus *bus, int addr)
{
	return mdiobus_find_device(bus, addr) != NULL;
}
EXPORT_SYMBOL(mdiobus_is_registered_device);

/**
 * mdiobus_release - mii_bus device release callback
 * @d: the target struct device that contains the mii_bus
 *
 * Description: called when the last reference to an mii_bus is
 * dropped, to free the underlying memory.
 */
static void mdiobus_release(struct device *d)
{
	struct mii_bus *bus = to_mii_bus(d);

	WARN(bus->state != MDIOBUS_RELEASED &&
	     /* for compatibility with error handling in drivers */
	     bus->state != MDIOBUS_ALLOCATED,
	     "%s: not in RELEASED or ALLOCATED state\n",
	     bus->id);

	if (bus->state == MDIOBUS_RELEASED)
		fwnode_handle_put(dev_fwnode(d));

	kfree(bus);
}

struct mdio_bus_stat_attr {
	int addr;
	unsigned int field_offset;
};

static u64 mdio_bus_get_stat(struct mdio_bus_stats *s, unsigned int offset)
{
	const char *p = (const char *)s + offset;
	unsigned int start;
	u64 val = 0;

	do {
		start = u64_stats_fetch_begin(&s->syncp);
		val = u64_stats_read((const u64_stats_t *)p);
	} while (u64_stats_fetch_retry(&s->syncp, start));

	return val;
}

static u64 mdio_bus_get_global_stat(struct mii_bus *bus, unsigned int offset)
{
	unsigned int i;
	u64 val = 0;

	for (i = 0; i < PHY_MAX_ADDR; i++)
		val += mdio_bus_get_stat(&bus->stats[i], offset);

	return val;
}

static ssize_t mdio_bus_stat_field_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct mii_bus *bus = to_mii_bus(dev);
	struct mdio_bus_stat_attr *sattr;
	struct dev_ext_attribute *eattr;
	u64 val;

	eattr = container_of(attr, struct dev_ext_attribute, attr);
	sattr = eattr->var;

	if (sattr->addr < 0)
		val = mdio_bus_get_global_stat(bus, sattr->field_offset);
	else
		val = mdio_bus_get_stat(&bus->stats[sattr->addr],
					sattr->field_offset);

	return sysfs_emit(buf, "%llu\n", val);
}

static ssize_t mdio_bus_device_stat_field_show(struct device *dev,
					       struct device_attribute *attr,
					       char *buf)
{
	struct mdio_device *mdiodev = to_mdio_device(dev);
	struct mii_bus *bus = mdiodev->bus;
	struct mdio_bus_stat_attr *sattr;
	struct dev_ext_attribute *eattr;
	int addr = mdiodev->addr;
	u64 val;

	eattr = container_of(attr, struct dev_ext_attribute, attr);
	sattr = eattr->var;

	val = mdio_bus_get_stat(&bus->stats[addr], sattr->field_offset);

	return sysfs_emit(buf, "%llu\n", val);
}

#define MDIO_BUS_STATS_ATTR_DECL(field, file)				\
static struct dev_ext_attribute dev_attr_mdio_bus_##field = {		\
	.attr = { .attr = { .name = file, .mode = 0444 },		\
		     .show = mdio_bus_stat_field_show,			\
	},								\
	.var = &((struct mdio_bus_stat_attr) {				\
		-1, offsetof(struct mdio_bus_stats, field)		\
	}),								\
};									\
static struct dev_ext_attribute dev_attr_mdio_bus_device_##field = {	\
	.attr = { .attr = { .name = file, .mode = 0444 },		\
		     .show = mdio_bus_device_stat_field_show,		\
	},								\
	.var = &((struct mdio_bus_stat_attr) {				\
		-1, offsetof(struct mdio_bus_stats, field)		\
	}),								\
};

#define MDIO_BUS_STATS_ATTR(field)					\
	MDIO_BUS_STATS_ATTR_DECL(field, __stringify(field))

MDIO_BUS_STATS_ATTR(transfers);
MDIO_BUS_STATS_ATTR(errors);
MDIO_BUS_STATS_ATTR(writes);
MDIO_BUS_STATS_ATTR(reads);

#define MDIO_BUS_STATS_ADDR_ATTR_DECL(field, addr, file)		\
static struct dev_ext_attribute dev_attr_mdio_bus_addr_##field##_##addr = { \
	.attr = { .attr = { .name = file, .mode = 0444 },		\
		     .show = mdio_bus_stat_field_show,			\
	},								\
	.var = &((struct mdio_bus_stat_attr) {				\
		addr, offsetof(struct mdio_bus_stats, field)		\
	}),								\
}

#define MDIO_BUS_STATS_ADDR_ATTR(field, addr)				\
	MDIO_BUS_STATS_ADDR_ATTR_DECL(field, addr,			\
				 __stringify(field) "_" __stringify(addr))

#define MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(addr)			\
	MDIO_BUS_STATS_ADDR_ATTR(transfers, addr);			\
	MDIO_BUS_STATS_ADDR_ATTR(errors, addr);				\
	MDIO_BUS_STATS_ADDR_ATTR(writes, addr);				\
	MDIO_BUS_STATS_ADDR_ATTR(reads, addr)				\

MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(0);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(1);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(2);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(3);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(4);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(5);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(6);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(7);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(8);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(9);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(10);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(11);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(12);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(13);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(14);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(15);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(16);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(17);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(18);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(19);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(20);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(21);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(22);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(23);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(24);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(25);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(26);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(27);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(28);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(29);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(30);
MDIO_BUS_STATS_ADDR_ATTR_GROUP_DECL(31);

#define MDIO_BUS_STATS_ADDR_ATTR_GROUP(addr)				\
	&dev_attr_mdio_bus_addr_transfers_##addr.attr.attr,		\
	&dev_attr_mdio_bus_addr_errors_##addr.attr.attr,		\
	&dev_attr_mdio_bus_addr_writes_##addr.attr.attr,		\
	&dev_attr_mdio_bus_addr_reads_##addr.attr.attr			\

static struct attribute *mdio_bus_statistics_attrs[] = {
	&dev_attr_mdio_bus_transfers.attr.attr,
	&dev_attr_mdio_bus_errors.attr.attr,
	&dev_attr_mdio_bus_writes.attr.attr,
	&dev_attr_mdio_bus_reads.attr.attr,
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(0),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(1),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(2),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(3),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(4),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(5),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(6),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(7),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(8),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(9),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(10),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(11),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(12),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(13),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(14),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(15),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(16),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(17),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(18),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(19),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(20),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(21),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(22),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(23),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(24),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(25),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(26),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(27),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(28),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(29),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(30),
	MDIO_BUS_STATS_ADDR_ATTR_GROUP(31),
	NULL,
};

static const struct attribute_group mdio_bus_statistics_group = {
	.name	= "statistics",
	.attrs	= mdio_bus_statistics_attrs,
};

static const struct attribute_group *mdio_bus_groups[] = {
	&mdio_bus_statistics_group,
	NULL,
};

const struct class mdio_bus_class = {
	.name		= "mdio_bus",
	.dev_release	= mdiobus_release,
	.dev_groups	= mdio_bus_groups,
};
EXPORT_SYMBOL_GPL(mdio_bus_class);

/**
 * mdio_find_bus - Given the name of a mdiobus, find the mii_bus.
 * @mdio_name: The name of a mdiobus.
 *
 * Returns a reference to the mii_bus, or NULL if none found.  The
 * embedded struct device will have its reference count incremented,
 * and this must be put_deviced'ed once the bus is finished with.
 */
struct mii_bus *mdio_find_bus(const char *mdio_name)
{
	struct device *d;

	d = class_find_device_by_name(&mdio_bus_class, mdio_name);
	return d ? to_mii_bus(d) : NULL;
}
EXPORT_SYMBOL(mdio_find_bus);

#if IS_ENABLED(CONFIG_OF_MDIO)
/**
 * of_mdio_find_bus - Given an mii_bus node, find the mii_bus.
 * @mdio_bus_np: Pointer to the mii_bus.
 *
 * Returns a reference to the mii_bus, or NULL if none found.  The
 * embedded struct device will have its reference count incremented,
 * and this must be put once the bus is finished with.
 *
 * Because the association of a device_node and mii_bus is made via
 * of_mdiobus_register(), the mii_bus cannot be found before it is
 * registered with of_mdiobus_register().
 *
 */
struct mii_bus *of_mdio_find_bus(struct device_node *mdio_bus_np)
{
	struct device *d;

	if (!mdio_bus_np)
		return NULL;

	d = class_find_device_by_of_node(&mdio_bus_class, mdio_bus_np);
	return d ? to_mii_bus(d) : NULL;
}
EXPORT_SYMBOL(of_mdio_find_bus);
#endif

static void mdiobus_stats_acct(struct mdio_bus_stats *stats, bool op, int ret)
{
	preempt_disable();
	u64_stats_update_begin(&stats->syncp);

	u64_stats_inc(&stats->transfers);
	if (ret < 0) {
		u64_stats_inc(&stats->errors);
		goto out;
	}

	if (op)
		u64_stats_inc(&stats->reads);
	else
		u64_stats_inc(&stats->writes);
out:
	u64_stats_update_end(&stats->syncp);
	preempt_enable();
}

/**
 * __mdiobus_read - Unlocked version of the mdiobus_read function
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @regnum: register number to read
 *
 * Read a MDIO bus register. Caller must hold the mdio bus lock.
 *
 * NOTE: MUST NOT be called from interrupt context.
 */
int __mdiobus_read(struct mii_bus *bus, int addr, u32 regnum)
{
	int retval;

	lockdep_assert_held_once(&bus->mdio_lock);

	if (addr >= PHY_MAX_ADDR)
		return -ENXIO;

	if (bus->read)
		retval = bus->read(bus, addr, regnum);
	else
		retval = -EOPNOTSUPP;

	trace_mdio_access(bus, 1, addr, regnum, retval, retval);
	mdiobus_stats_acct(&bus->stats[addr], true, retval);

	return retval;
}
EXPORT_SYMBOL(__mdiobus_read);

/**
 * __mdiobus_write - Unlocked version of the mdiobus_write function
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @regnum: register number to write
 * @val: value to write to @regnum
 *
 * Write a MDIO bus register. Caller must hold the mdio bus lock.
 *
 * NOTE: MUST NOT be called from interrupt context.
 */
int __mdiobus_write(struct mii_bus *bus, int addr, u32 regnum, u16 val)
{
	int err;

	lockdep_assert_held_once(&bus->mdio_lock);

	if (addr >= PHY_MAX_ADDR)
		return -ENXIO;

	if (bus->write)
		err = bus->write(bus, addr, regnum, val);
	else
		err = -EOPNOTSUPP;

	trace_mdio_access(bus, 0, addr, regnum, val, err);
	mdiobus_stats_acct(&bus->stats[addr], false, err);

	return err;
}
EXPORT_SYMBOL(__mdiobus_write);

/**
 * __mdiobus_modify_changed - Unlocked version of the mdiobus_modify function
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @regnum: register number to modify
 * @mask: bit mask of bits to clear
 * @set: bit mask of bits to set
 *
 * Read, modify, and if any change, write the register value back to the
 * device. Any error returns a negative number.
 *
 * NOTE: MUST NOT be called from interrupt context.
 */
int __mdiobus_modify_changed(struct mii_bus *bus, int addr, u32 regnum,
			     u16 mask, u16 set)
{
	int new, ret;

	ret = __mdiobus_read(bus, addr, regnum);
	if (ret < 0)
		return ret;

	new = (ret & ~mask) | set;
	if (new == ret)
		return 0;

	ret = __mdiobus_write(bus, addr, regnum, new);

	return ret < 0 ? ret : 1;
}
EXPORT_SYMBOL_GPL(__mdiobus_modify_changed);

/**
 * __mdiobus_c45_read - Unlocked version of the mdiobus_c45_read function
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @devad: device address to read
 * @regnum: register number to read
 *
 * Read a MDIO bus register. Caller must hold the mdio bus lock.
 *
 * NOTE: MUST NOT be called from interrupt context.
 */
int __mdiobus_c45_read(struct mii_bus *bus, int addr, int devad, u32 regnum)
{
	int retval;

	lockdep_assert_held_once(&bus->mdio_lock);

	if (addr >= PHY_MAX_ADDR)
		return -ENXIO;

	if (bus->read_c45)
		retval = bus->read_c45(bus, addr, devad, regnum);
	else
		retval = -EOPNOTSUPP;

	trace_mdio_access(bus, 1, addr, regnum, retval, retval);
	mdiobus_stats_acct(&bus->stats[addr], true, retval);

	return retval;
}
EXPORT_SYMBOL(__mdiobus_c45_read);

/**
 * __mdiobus_c45_write - Unlocked version of the mdiobus_write function
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @devad: device address to read
 * @regnum: register number to write
 * @val: value to write to @regnum
 *
 * Write a MDIO bus register. Caller must hold the mdio bus lock.
 *
 * NOTE: MUST NOT be called from interrupt context.
 */
int __mdiobus_c45_write(struct mii_bus *bus, int addr, int devad, u32 regnum,
			u16 val)
{
	int err;

	lockdep_assert_held_once(&bus->mdio_lock);

	if (addr >= PHY_MAX_ADDR)
		return -ENXIO;

	if (bus->write_c45)
		err = bus->write_c45(bus, addr, devad, regnum, val);
	else
		err = -EOPNOTSUPP;

	trace_mdio_access(bus, 0, addr, regnum, val, err);
	mdiobus_stats_acct(&bus->stats[addr], false, err);

	return err;
}
EXPORT_SYMBOL(__mdiobus_c45_write);

/**
 * __mdiobus_c45_modify_changed - Unlocked version of the mdiobus_modify function
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @devad: device address to read
 * @regnum: register number to modify
 * @mask: bit mask of bits to clear
 * @set: bit mask of bits to set
 *
 * Read, modify, and if any change, write the register value back to the
 * device. Any error returns a negative number.
 *
 * NOTE: MUST NOT be called from interrupt context.
 */
static int __mdiobus_c45_modify_changed(struct mii_bus *bus, int addr,
					int devad, u32 regnum, u16 mask,
					u16 set)
{
	int new, ret;

	ret = __mdiobus_c45_read(bus, addr, devad, regnum);
	if (ret < 0)
		return ret;

	new = (ret & ~mask) | set;
	if (new == ret)
		return 0;

	ret = __mdiobus_c45_write(bus, addr, devad, regnum, new);

	return ret < 0 ? ret : 1;
}

/**
 * mdiobus_read_nested - Nested version of the mdiobus_read function
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @regnum: register number to read
 *
 * In case of nested MDIO bus access avoid lockdep false positives by
 * using mutex_lock_nested().
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 */
int mdiobus_read_nested(struct mii_bus *bus, int addr, u32 regnum)
{
	int retval;

	mutex_lock_nested(&bus->mdio_lock, MDIO_MUTEX_NESTED);
	retval = __mdiobus_read(bus, addr, regnum);
	mutex_unlock(&bus->mdio_lock);

	return retval;
}
EXPORT_SYMBOL(mdiobus_read_nested);

/**
 * mdiobus_read - Convenience function for reading a given MII mgmt register
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @regnum: register number to read
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 */
int mdiobus_read(struct mii_bus *bus, int addr, u32 regnum)
{
	int retval;

	mutex_lock(&bus->mdio_lock);
	retval = __mdiobus_read(bus, addr, regnum);
	mutex_unlock(&bus->mdio_lock);

	return retval;
}
EXPORT_SYMBOL(mdiobus_read);

/**
 * mdiobus_c45_read - Convenience function for reading a given MII mgmt register
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @devad: device address to read
 * @regnum: register number to read
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 */
int mdiobus_c45_read(struct mii_bus *bus, int addr, int devad, u32 regnum)
{
	int retval;

	mutex_lock(&bus->mdio_lock);
	retval = __mdiobus_c45_read(bus, addr, devad, regnum);
	mutex_unlock(&bus->mdio_lock);

	return retval;
}
EXPORT_SYMBOL(mdiobus_c45_read);

/**
 * mdiobus_c45_read_nested - Nested version of the mdiobus_c45_read function
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @devad: device address to read
 * @regnum: register number to read
 *
 * In case of nested MDIO bus access avoid lockdep false positives by
 * using mutex_lock_nested().
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 */
int mdiobus_c45_read_nested(struct mii_bus *bus, int addr, int devad,
			    u32 regnum)
{
	int retval;

	mutex_lock_nested(&bus->mdio_lock, MDIO_MUTEX_NESTED);
	retval = __mdiobus_c45_read(bus, addr, devad, regnum);
	mutex_unlock(&bus->mdio_lock);

	return retval;
}
EXPORT_SYMBOL(mdiobus_c45_read_nested);

/**
 * mdiobus_write_nested - Nested version of the mdiobus_write function
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @regnum: register number to write
 * @val: value to write to @regnum
 *
 * In case of nested MDIO bus access avoid lockdep false positives by
 * using mutex_lock_nested().
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 */
int mdiobus_write_nested(struct mii_bus *bus, int addr, u32 regnum, u16 val)
{
	int err;

	mutex_lock_nested(&bus->mdio_lock, MDIO_MUTEX_NESTED);
	err = __mdiobus_write(bus, addr, regnum, val);
	mutex_unlock(&bus->mdio_lock);

	return err;
}
EXPORT_SYMBOL(mdiobus_write_nested);

/**
 * mdiobus_write - Convenience function for writing a given MII mgmt register
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @regnum: register number to write
 * @val: value to write to @regnum
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 */
int mdiobus_write(struct mii_bus *bus, int addr, u32 regnum, u16 val)
{
	int err;

	mutex_lock(&bus->mdio_lock);
	err = __mdiobus_write(bus, addr, regnum, val);
	mutex_unlock(&bus->mdio_lock);

	return err;
}
EXPORT_SYMBOL(mdiobus_write);

/**
 * mdiobus_c45_write - Convenience function for writing a given MII mgmt register
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @devad: device address to read
 * @regnum: register number to write
 * @val: value to write to @regnum
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 */
int mdiobus_c45_write(struct mii_bus *bus, int addr, int devad, u32 regnum,
		      u16 val)
{
	int err;

	mutex_lock(&bus->mdio_lock);
	err = __mdiobus_c45_write(bus, addr, devad, regnum, val);
	mutex_unlock(&bus->mdio_lock);

	return err;
}
EXPORT_SYMBOL(mdiobus_c45_write);

/**
 * mdiobus_c45_write_nested - Nested version of the mdiobus_c45_write function
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @devad: device address to read
 * @regnum: register number to write
 * @val: value to write to @regnum
 *
 * In case of nested MDIO bus access avoid lockdep false positives by
 * using mutex_lock_nested().
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 */
int mdiobus_c45_write_nested(struct mii_bus *bus, int addr, int devad,
			     u32 regnum, u16 val)
{
	int err;

	mutex_lock_nested(&bus->mdio_lock, MDIO_MUTEX_NESTED);
	err = __mdiobus_c45_write(bus, addr, devad, regnum, val);
	mutex_unlock(&bus->mdio_lock);

	return err;
}
EXPORT_SYMBOL(mdiobus_c45_write_nested);

/*
 * __mdiobus_modify - Convenience function for modifying a given mdio device
 *	register
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @regnum: register number to write
 * @mask: bit mask of bits to clear
 * @set: bit mask of bits to set
 */
int __mdiobus_modify(struct mii_bus *bus, int addr, u32 regnum, u16 mask,
		     u16 set)
{
	int err;

	err = __mdiobus_modify_changed(bus, addr, regnum, mask, set);

	return err < 0 ? err : 0;
}
EXPORT_SYMBOL_GPL(__mdiobus_modify);

/**
 * mdiobus_modify - Convenience function for modifying a given mdio device
 *	register
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @regnum: register number to write
 * @mask: bit mask of bits to clear
 * @set: bit mask of bits to set
 */
int mdiobus_modify(struct mii_bus *bus, int addr, u32 regnum, u16 mask, u16 set)
{
	int err;

	mutex_lock(&bus->mdio_lock);
	err = __mdiobus_modify(bus, addr, regnum, mask, set);
	mutex_unlock(&bus->mdio_lock);

	return err;
}
EXPORT_SYMBOL_GPL(mdiobus_modify);

/**
 * mdiobus_c45_modify - Convenience function for modifying a given mdio device
 *	register
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @devad: device address to read
 * @regnum: register number to write
 * @mask: bit mask of bits to clear
 * @set: bit mask of bits to set
 */
int mdiobus_c45_modify(struct mii_bus *bus, int addr, int devad, u32 regnum,
		       u16 mask, u16 set)
{
	int err;

	mutex_lock(&bus->mdio_lock);
	err = __mdiobus_c45_modify_changed(bus, addr, devad, regnum,
					   mask, set);
	mutex_unlock(&bus->mdio_lock);

	return err < 0 ? err : 0;
}
EXPORT_SYMBOL_GPL(mdiobus_c45_modify);

/**
 * mdiobus_modify_changed - Convenience function for modifying a given mdio
 *	device register and returning if it changed
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @regnum: register number to write
 * @mask: bit mask of bits to clear
 * @set: bit mask of bits to set
 */
int mdiobus_modify_changed(struct mii_bus *bus, int addr, u32 regnum,
			   u16 mask, u16 set)
{
	int err;

	mutex_lock(&bus->mdio_lock);
	err = __mdiobus_modify_changed(bus, addr, regnum, mask, set);
	mutex_unlock(&bus->mdio_lock);

	return err;
}
EXPORT_SYMBOL_GPL(mdiobus_modify_changed);

/**
 * mdiobus_c45_modify_changed - Convenience function for modifying a given mdio
 *	device register and returning if it changed
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @devad: device address to read
 * @regnum: register number to write
 * @mask: bit mask of bits to clear
 * @set: bit mask of bits to set
 */
int mdiobus_c45_modify_changed(struct mii_bus *bus, int addr, int devad,
			       u32 regnum, u16 mask, u16 set)
{
	int err;

	mutex_lock(&bus->mdio_lock);
	err = __mdiobus_c45_modify_changed(bus, addr, devad, regnum, mask, set);
	mutex_unlock(&bus->mdio_lock);

	return err;
}
EXPORT_SYMBOL_GPL(mdiobus_c45_modify_changed);

/**
 * mdio_bus_match - determine if given MDIO driver supports the given
 *		    MDIO device
 * @dev: target MDIO device
 * @drv: given MDIO driver
 *
 * Description: Given a MDIO device, and a MDIO driver, return 1 if
 *   the driver supports the device.  Otherwise, return 0. This may
 *   require calling the devices own match function, since different classes
 *   of MDIO devices have different match criteria.
 */
static int mdio_bus_match(struct device *dev, const struct device_driver *drv)
{
	const struct mdio_driver *mdiodrv = to_mdio_driver(drv);
	struct mdio_device *mdio = to_mdio_device(dev);

	/* Both the driver and device must type-match */
	if (!(mdiodrv->mdiodrv.flags & MDIO_DEVICE_IS_PHY) !=
	    !(mdio->flags & MDIO_DEVICE_FLAG_PHY))
		return 0;

	if (of_driver_match_device(dev, drv))
		return 1;

	if (mdio->bus_match)
		return mdio->bus_match(dev, drv);

	return 0;
}

static int mdio_uevent(const struct device *dev, struct kobj_uevent_env *env)
{
	int rc;

	/* Some devices have extra OF data and an OF-style MODALIAS */
	rc = of_device_uevent_modalias(dev, env);
	if (rc != -ENODEV)
		return rc;

	return 0;
}

static struct attribute *mdio_bus_device_statistics_attrs[] = {
	&dev_attr_mdio_bus_device_transfers.attr.attr,
	&dev_attr_mdio_bus_device_errors.attr.attr,
	&dev_attr_mdio_bus_device_writes.attr.attr,
	&dev_attr_mdio_bus_device_reads.attr.attr,
	NULL,
};

static const struct attribute_group mdio_bus_device_statistics_group = {
	.name	= "statistics",
	.attrs	= mdio_bus_device_statistics_attrs,
};

static const struct attribute_group *mdio_bus_dev_groups[] = {
	&mdio_bus_device_statistics_group,
	NULL,
};

const struct bus_type mdio_bus_type = {
	.name		= "mdio_bus",
	.dev_groups	= mdio_bus_dev_groups,
	.match		= mdio_bus_match,
	.uevent		= mdio_uevent,
};
EXPORT_SYMBOL(mdio_bus_type);

static int __init mdio_bus_init(void)
{
	int ret;

	ret = class_register(&mdio_bus_class);
	if (!ret) {
		ret = bus_register(&mdio_bus_type);
		if (ret)
			class_unregister(&mdio_bus_class);
	}

	return ret;
}

static void __exit mdio_bus_exit(void)
{
	class_unregister(&mdio_bus_class);
	bus_unregister(&mdio_bus_type);
}

subsys_initcall(mdio_bus_init);
module_exit(mdio_bus_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MDIO bus/device layer");
