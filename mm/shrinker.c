// SPDX-License-Identifier: GPL-2.0
#include <linux/memcontrol.h>
#include <linux/rwsem.h>
#include <linux/shrinker.h>
#include <linux/rculist.h>
#include <trace/events/vmscan.h>

#include "internal.h"

LIST_HEAD(shrinker_list);
DEFINE_MUTEX(shrinker_mutex);

#ifdef CONFIG_MEMCG
static int shrinker_nr_max;

static inline int shrinker_unit_size(int nr_items)
{
	return (DIV_ROUND_UP(nr_items, SHRINKER_UNIT_BITS) * sizeof(struct shrinker_info_unit *));
}

static inline void shrinker_unit_free(struct shrinker_info *info, int start)
{
	struct shrinker_info_unit **unit;
	int nr, i;

	if (!info)
		return;

	unit = info->unit;
	nr = DIV_ROUND_UP(info->map_nr_max, SHRINKER_UNIT_BITS);

	for (i = start; i < nr; i++) {
		if (!unit[i])
			break;

		kfree(unit[i]);
		unit[i] = NULL;
	}
}

static inline int shrinker_unit_alloc(struct shrinker_info *new,
				       struct shrinker_info *old, int nid)
{
	struct shrinker_info_unit *unit;
	int nr = DIV_ROUND_UP(new->map_nr_max, SHRINKER_UNIT_BITS);
	int start = old ? DIV_ROUND_UP(old->map_nr_max, SHRINKER_UNIT_BITS) : 0;
	int i;

	for (i = start; i < nr; i++) {
		unit = kzalloc_node(sizeof(*unit), GFP_KERNEL, nid);
		if (!unit) {
			shrinker_unit_free(new, start);
			return -ENOMEM;
		}

		new->unit[i] = unit;
	}

	return 0;
}

void free_shrinker_info(struct mem_cgroup *memcg)
{
	struct mem_cgroup_per_node *pn;
	struct shrinker_info *info;
	int nid;

	for_each_node(nid) {
		pn = memcg->nodeinfo[nid];
		info = rcu_dereference_protected(pn->shrinker_info, true);
		shrinker_unit_free(info, 0);
		kvfree(info);
		rcu_assign_pointer(pn->shrinker_info, NULL);
	}
}

int alloc_shrinker_info(struct mem_cgroup *memcg)
{
	int nid, ret = 0;
	int array_size = 0;

	mutex_lock(&shrinker_mutex);
	array_size = shrinker_unit_size(shrinker_nr_max);
	for_each_node(nid) {
		struct shrinker_info *info = kvzalloc_node(sizeof(*info) + array_size,
							   GFP_KERNEL, nid);
		if (!info)
			goto err;
		info->map_nr_max = shrinker_nr_max;
		if (shrinker_unit_alloc(info, NULL, nid)) {
			kvfree(info);
			goto err;
		}
		rcu_assign_pointer(memcg->nodeinfo[nid]->shrinker_info, info);
	}
	mutex_unlock(&shrinker_mutex);

	return ret;

err:
	mutex_unlock(&shrinker_mutex);
	free_shrinker_info(memcg);
	return -ENOMEM;
}

static struct shrinker_info *shrinker_info_protected(struct mem_cgroup *memcg,
						     int nid)
{
	return rcu_dereference_protected(memcg->nodeinfo[nid]->shrinker_info,
					 lockdep_is_held(&shrinker_mutex));
}

static int expand_one_shrinker_info(struct mem_cgroup *memcg, int new_size,
				    int old_size, int new_nr_max)
{
	struct shrinker_info *new, *old;
	struct mem_cgroup_per_node *pn;
	int nid;

	for_each_node(nid) {
		pn = memcg->nodeinfo[nid];
		old = shrinker_info_protected(memcg, nid);
		/* Not yet online memcg */
		if (!old)
			return 0;

		/* Already expanded this shrinker_info */
		if (new_nr_max <= old->map_nr_max)
			continue;

		new = kvzalloc_node(sizeof(*new) + new_size, GFP_KERNEL, nid);
		if (!new)
			return -ENOMEM;

		new->map_nr_max = new_nr_max;

		memcpy(new->unit, old->unit, old_size);
		if (shrinker_unit_alloc(new, old, nid)) {
			kvfree(new);
			return -ENOMEM;
		}

		rcu_assign_pointer(pn->shrinker_info, new);
		kvfree_rcu(old, rcu);
	}

	return 0;
}

static int expand_shrinker_info(int new_id)
{
	int ret = 0;
	int new_nr_max = round_up(new_id + 1, SHRINKER_UNIT_BITS);
	int new_size, old_size = 0;
	struct mem_cgroup *memcg;

	if (!root_mem_cgroup)
		goto out;

	lockdep_assert_held(&shrinker_mutex);

	new_size = shrinker_unit_size(new_nr_max);
	old_size = shrinker_unit_size(shrinker_nr_max);

	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		ret = expand_one_shrinker_info(memcg, new_size, old_size,
					       new_nr_max);
		if (ret) {
			mem_cgroup_iter_break(NULL, memcg);
			goto out;
		}
	} while ((memcg = mem_cgroup_iter(NULL, memcg, NULL)) != NULL);
out:
	if (!ret)
		shrinker_nr_max = new_nr_max;

	return ret;
}

static inline int shrinker_id_to_index(int shrinker_id)
{
	return shrinker_id / SHRINKER_UNIT_BITS;
}

static inline int shrinker_id_to_offset(int shrinker_id)
{
	return shrinker_id % SHRINKER_UNIT_BITS;
}

static inline int calc_shrinker_id(int index, int offset)
{
	return index * SHRINKER_UNIT_BITS + offset;
}

void set_shrinker_bit(struct mem_cgroup *memcg, int nid, int shrinker_id)
{
	if (shrinker_id >= 0 && memcg && !mem_cgroup_is_root(memcg)) {
		struct shrinker_info *info;
		struct shrinker_info_unit *unit;

		rcu_read_lock();
		info = rcu_dereference(memcg->nodeinfo[nid]->shrinker_info);
		unit = info->unit[shrinker_id_to_index(shrinker_id)];
		if (!WARN_ON_ONCE(shrinker_id >= info->map_nr_max)) {
			/* Pairs with smp mb in shrink_slab() */
			smp_mb__before_atomic();
			set_bit(shrinker_id_to_offset(shrinker_id), unit->map);
		}
		rcu_read_unlock();
	}
}

static DEFINE_IDR(shrinker_idr);

static int shrinker_memcg_alloc(struct shrinker *shrinker)
{
	int id, ret = -ENOMEM;

	if (mem_cgroup_disabled())
		return -ENOSYS;

	mutex_lock(&shrinker_mutex);
	id = idr_alloc(&shrinker_idr, shrinker, 0, 0, GFP_KERNEL);
	if (id < 0)
		goto unlock;

	if (id >= shrinker_nr_max) {
		if (expand_shrinker_info(id)) {
			idr_remove(&shrinker_idr, id);
			goto unlock;
		}
	}
	shrinker->id = id;
	ret = 0;
unlock:
	mutex_unlock(&shrinker_mutex);
	return ret;
}

static void shrinker_memcg_remove(struct shrinker *shrinker)
{
	int id = shrinker->id;

	BUG_ON(id < 0);

	lockdep_assert_held(&shrinker_mutex);

	idr_remove(&shrinker_idr, id);
}

static long xchg_nr_deferred_memcg(int nid, struct shrinker *shrinker,
				   struct mem_cgroup *memcg)
{
	struct shrinker_info *info;
	struct shrinker_info_unit *unit;
	long nr_deferred;

	rcu_read_lock();
	info = rcu_dereference(memcg->nodeinfo[nid]->shrinker_info);
	unit = info->unit[shrinker_id_to_index(shrinker->id)];
	nr_deferred = atomic_long_xchg(&unit->nr_deferred[shrinker_id_to_offset(shrinker->id)], 0);
	rcu_read_unlock();

	return nr_deferred;
}

static long add_nr_deferred_memcg(long nr, int nid, struct shrinker *shrinker,
				  struct mem_cgroup *memcg)
{
	struct shrinker_info *info;
	struct shrinker_info_unit *unit;
	long nr_deferred;

	rcu_read_lock();
	info = rcu_dereference(memcg->nodeinfo[nid]->shrinker_info);
	unit = info->unit[shrinker_id_to_index(shrinker->id)];
	nr_deferred =
		atomic_long_add_return(nr, &unit->nr_deferred[shrinker_id_to_offset(shrinker->id)]);
	rcu_read_unlock();

	return nr_deferred;
}

void reparent_shrinker_deferred(struct mem_cgroup *memcg)
{
	int nid, index, offset;
	long nr;
	struct mem_cgroup *parent;
	struct shrinker_info *child_info, *parent_info;
	struct shrinker_info_unit *child_unit, *parent_unit;

	parent = parent_mem_cgroup(memcg);
	if (!parent)
		parent = root_mem_cgroup;

	/* Prevent from concurrent shrinker_info expand */
	mutex_lock(&shrinker_mutex);
	for_each_node(nid) {
		child_info = shrinker_info_protected(memcg, nid);
		parent_info = shrinker_info_protected(parent, nid);
		for (index = 0; index < shrinker_id_to_index(child_info->map_nr_max); index++) {
			child_unit = child_info->unit[index];
			parent_unit = parent_info->unit[index];
			for (offset = 0; offset < SHRINKER_UNIT_BITS; offset++) {
				nr = atomic_long_read(&child_unit->nr_deferred[offset]);
				atomic_long_add(nr, &parent_unit->nr_deferred[offset]);
			}
		}
	}
	mutex_unlock(&shrinker_mutex);
}
#else
static int shrinker_memcg_alloc(struct shrinker *shrinker)
{
	return -ENOSYS;
}

static void shrinker_memcg_remove(struct shrinker *shrinker)
{
}

static long xchg_nr_deferred_memcg(int nid, struct shrinker *shrinker,
				   struct mem_cgroup *memcg)
{
	return 0;
}

static long add_nr_deferred_memcg(long nr, int nid, struct shrinker *shrinker,
				  struct mem_cgroup *memcg)
{
	return 0;
}
#endif /* CONFIG_MEMCG */

static long xchg_nr_deferred(struct shrinker *shrinker,
			     struct shrink_control *sc)
{
	int nid = sc->nid;

	if (!(shrinker->flags & SHRINKER_NUMA_AWARE))
		nid = 0;

	if (sc->memcg &&
	    (shrinker->flags & SHRINKER_MEMCG_AWARE))
		return xchg_nr_deferred_memcg(nid, shrinker,
					      sc->memcg);

	return atomic_long_xchg(&shrinker->nr_deferred[nid], 0);
}


static long add_nr_deferred(long nr, struct shrinker *shrinker,
			    struct shrink_control *sc)
{
	int nid = sc->nid;

	if (!(shrinker->flags & SHRINKER_NUMA_AWARE))
		nid = 0;

	if (sc->memcg &&
	    (shrinker->flags & SHRINKER_MEMCG_AWARE))
		return add_nr_deferred_memcg(nr, nid, shrinker,
					     sc->memcg);

	return atomic_long_add_return(nr, &shrinker->nr_deferred[nid]);
}

#define SHRINK_BATCH 128

// 执行实际的 slab 收缩操作
// shrinkctl：包含回收控制信息（gfp_mask、nid、memcg）
// shrinker：具体的收缩器对象（包含回收方法）
// priority：回收优先级（值越小表示压力越大）
static unsigned long do_shrink_slab(struct shrink_control *shrinkctl,
				    struct shrinker *shrinker, int priority)
{
	unsigned long freed = 0;          // 已释放的页数
	unsigned long long delta;         // 本次回收应扫描的增量
	long total_scan;                  // 本次总共需扫描的对象数
	long freeable;                    // 可回收的对象总数
	long nr;                          // 延迟计数值
	long new_nr;                      // 新的延迟计数值
	long batch_size = shrinker->batch ? shrinker->batch
					  : SHRINK_BATCH;  // 每次扫描的批次大小
	long scanned = 0, next_deferred;  // 已扫描对象数，延迟计数器

	// 调用 shrinker 的 count_objects 方法获取可回收对象总数
	// 实际执行如：super_cache_count（文件系统缓存），inode_lru_isolate（inode 缓存）
	freeable = shrinker->count_objects(shrinker, shrinkctl);
	// 如果没有可回收对象或特殊标记，直接返回
	if (freeable == 0 || freeable == SHRINK_EMPTY)
		return freeable;

	// 原子交换获取并重置 per-node/memcg 的延迟计数
	// 统计上次回收未完成的扫描量，确保公平扫描
	// nr_deferred 数组存储在 shrinker 结构中（per-node）
	nr = xchg_nr_deferred(shrinker, shrinkctl);

	// seeks 机制：评估对象回收成本（如磁盘I/O成本）
	// 对于低I/O开销的缓存（如inode），积极回收
	// 对于高I/O开销的缓存（如dentry），保守回收
	// 计算方法：delta = (freeable/2^priority * 4) / seeks
	if (shrinker->seeks) {
		delta = freeable >> priority;  // 压力越大扫描越多
		delta *= 4;
		do_div(delta, shrinker->seeks);  // 除以"查找成本"
	} else {
		delta = freeable / 2;  // 无成本对象直接扫描半数
	}

	// 平衡扫描量和回收效率
	// 压力大时（priority小）：
	// 1. 扫描更多延迟对象
	// 2. 扫描更大的增量
	// 保护机制：扫描量不超过对象总量的2倍
	total_scan = nr >> priority;  // 延迟计数按优先级折算
	total_scan += delta;          // 加上本次增量
	total_scan = min(total_scan, (2 * freeable));  // 不超过两倍对象数

	// 调试追踪：记录回收开始前的状态
	trace_mm_shrink_slab_start(shrinker, shrinkctl, nr,
				   freeable, delta, total_scan, priority);

	// 当待扫描量 ≥ 批次大小，或待扫描量 ≥ 可回收量（内存极紧张）
	while (total_scan >= batch_size ||
	       total_scan >= freeable) {
		unsigned long ret;
		// 批处理优化：每次扫描不超过批次大小（默认128）
		// 避免单次回收时间过长
		unsigned long nr_to_scan = min(batch_size, total_scan);

		// 准备扫描控制参数
		shrinkctl->nr_to_scan = nr_to_scan;
		shrinkctl->nr_scanned = nr_to_scan;

		// 核心操作：调用 shrinker 的具体扫描方法
		// 示例文件系统扫描器：super_cache_scan()，inode_lru_isolate()
		ret = shrinker->scan_objects(shrinker, shrinkctl);
		if (ret == SHRINK_STOP)
			break;  // 提前终止扫描

		// 扫描过程中主动调度，避免卡顿
		// 熔断机制：当扫描器遇到问题时可提前终止
		freed += ret;  // 累计回收页数

		count_vm_events(SLABS_SCANNED, shrinkctl->nr_scanned);  // 更新统计
		total_scan -= shrinkctl->nr_scanned;  // 更新剩余扫描量
		scanned += shrinkctl->nr_scanned;  // 累计实际扫描量

		cond_resched();  // 主动让出CPU
	}

	// 延迟计算算法：
	// 1. 新延迟 = 旧延迟 + 本次增量 - 已扫描量
	// 2. 保证非负且不超过对象总量的两倍
	next_deferred = max_t(long, (nr + delta - scanned), 0);
	next_deferred = min(next_deferred, (2 * freeable));

	// 原子更新：将新延迟值写回 shrinker 结构
	// 保障跨CPU核心的一致性
	new_nr = add_nr_deferred(next_deferred, shrinker, shrinkctl);

	// 记录回收结束事件（用于ftrace调试）
	// 返回实际释放的内存页数
	trace_mm_shrink_slab_end(shrinker, shrinkctl->nid, freed, nr, new_nr, total_scan);
	return freed;
}

#ifdef CONFIG_MEMCG
static unsigned long shrink_slab_memcg(gfp_t gfp_mask, int nid,
			struct mem_cgroup *memcg, int priority)
{
	struct shrinker_info *info;
	unsigned long ret, freed = 0;
	int offset, index = 0;

	if (!mem_cgroup_online(memcg))
		return 0;

	/*
	 * lockless algorithm of memcg shrink.
	 *
	 * The shrinker_info may be freed asynchronously via RCU in the
	 * expand_one_shrinker_info(), so the rcu_read_lock() needs to be used
	 * to ensure the existence of the shrinker_info.
	 *
	 * The shrinker_info_unit is never freed unless its corresponding memcg
	 * is destroyed. Here we already hold the refcount of memcg, so the
	 * memcg will not be destroyed, and of course shrinker_info_unit will
	 * not be freed.
	 *
	 * So in the memcg shrink:
	 *  step 1: use rcu_read_lock() to guarantee existence of the
	 *          shrinker_info.
	 *  step 2: after getting shrinker_info_unit we can safely release the
	 *          RCU lock.
	 *  step 3: traverse the bitmap and calculate shrinker_id
	 *  step 4: use rcu_read_lock() to guarantee existence of the shrinker.
	 *  step 5: use shrinker_id to find the shrinker, then use
	 *          shrinker_try_get() to guarantee existence of the shrinker,
	 *          then we can release the RCU lock to do do_shrink_slab() that
	 *          may sleep.
	 *  step 6: do shrinker_put() paired with step 5 to put the refcount,
	 *          if the refcount reaches 0, then wake up the waiter in
	 *          shrinker_free() by calling complete().
	 *          Note: here is different from the global shrink, we don't
	 *                need to acquire the RCU lock to guarantee existence of
	 *                the shrinker, because we don't need to use this
	 *                shrinker to traverse the next shrinker in the bitmap.
	 *  step 7: we have already exited the read-side of rcu critical section
	 *          before calling do_shrink_slab(), the shrinker_info may be
	 *          released in expand_one_shrinker_info(), so go back to step 1
	 *          to reacquire the shrinker_info.
	 */
again:
	rcu_read_lock();
	info = rcu_dereference(memcg->nodeinfo[nid]->shrinker_info);
	if (unlikely(!info))
		goto unlock;

	if (index < shrinker_id_to_index(info->map_nr_max)) {
		struct shrinker_info_unit *unit;

		unit = info->unit[index];

		rcu_read_unlock();

		for_each_set_bit(offset, unit->map, SHRINKER_UNIT_BITS) {
			struct shrink_control sc = {
				.gfp_mask = gfp_mask,
				.nid = nid,
				.memcg = memcg,
			};
			struct shrinker *shrinker;
			int shrinker_id = calc_shrinker_id(index, offset);

			rcu_read_lock();
			shrinker = idr_find(&shrinker_idr, shrinker_id);
			if (unlikely(!shrinker || !shrinker_try_get(shrinker))) {
				clear_bit(offset, unit->map);
				rcu_read_unlock();
				continue;
			}
			rcu_read_unlock();

			/* Call non-slab shrinkers even though kmem is disabled */
			if (!memcg_kmem_online() &&
			    !(shrinker->flags & SHRINKER_NONSLAB))
				continue;

			ret = do_shrink_slab(&sc, shrinker, priority);
			if (ret == SHRINK_EMPTY) {
				clear_bit(offset, unit->map);
				/*
				 * After the shrinker reported that it had no objects to
				 * free, but before we cleared the corresponding bit in
				 * the memcg shrinker map, a new object might have been
				 * added. To make sure, we have the bit set in this
				 * case, we invoke the shrinker one more time and reset
				 * the bit if it reports that it is not empty anymore.
				 * The memory barrier here pairs with the barrier in
				 * set_shrinker_bit():
				 *
				 * list_lru_add()     shrink_slab_memcg()
				 *   list_add_tail()    clear_bit()
				 *   <MB>               <MB>
				 *   set_bit()          do_shrink_slab()
				 */
				smp_mb__after_atomic();
				ret = do_shrink_slab(&sc, shrinker, priority);
				if (ret == SHRINK_EMPTY)
					ret = 0;
				else
					set_shrinker_bit(memcg, nid, shrinker_id);
			}
			freed += ret;
			shrinker_put(shrinker);
		}

		index++;
		goto again;
	}
unlock:
	rcu_read_unlock();
	return freed;
}
#else /* !CONFIG_MEMCG */
static unsigned long shrink_slab_memcg(gfp_t gfp_mask, int nid,
			struct mem_cgroup *memcg, int priority)
{
	return 0;
}
#endif /* CONFIG_MEMCG */

/**
 * shrink_slab - shrink slab caches
 * @gfp_mask: allocation context
 * @nid: node whose slab caches to target
 * @memcg: memory cgroup whose slab caches to target
 * @priority: the reclaim priority
 *
 * Call the shrink functions to age shrinkable caches.
 *
 * @nid is passed along to shrinkers with SHRINKER_NUMA_AWARE set,
 * unaware shrinkers will receive a node id of 0 instead.
 *
 * @memcg specifies the memory cgroup to target. Unaware shrinkers
 * are called only if it is the root cgroup.
 *
 * @priority is sc->priority, we take the number of objects and >> by priority
 * in order to get the scan target.
 *
 * Returns the number of reclaimed slab objects.
 */
// 入口函数，用于收缩所有注册的 shrinker 管理的 slab 缓存
// gfp_mask: 内存分配标志，指定回收行为
// nid: NUMA 节点 ID
// memcg: 内存控制组指针
// priority: 回收优先级 (值越小表示压力越大)
// 返回值: 总共释放的内存量
unsigned long shrink_slab(gfp_t gfp_mask, int nid, struct mem_cgroup *memcg,
			  int priority)
{
	// ret: 单次 shrinker 收缩的返回值
	// freed: 累计释放的页数
	unsigned long ret, freed = 0;
	// shrinker: 遍历 shrinker 列表的指针
	struct shrinker *shrinker;

	// 处理 memcg 禁用时的特殊情况,当通过启动参数禁用 memcg 时，根 memcg 可能仍存在,避免跳过全局回收导致过早 OOM
	// 如果 memcg 启用且不是根 memcg
	// 则调用 memcg 专用的收缩函数
	// 直接返回不再执行全局收缩
	if (!mem_cgroup_disabled() && !mem_cgroup_is_root(memcg))
		return shrink_slab_memcg(gfp_mask, nid, memcg, priority);

	// 开始受 RCU 保护的临界区, 保证 shrinker 列表遍历期间不会被释放
	rcu_read_lock();
	// 遍历所有 shrinkers:
	// 1. 使用 RCU-safe 方式遍历全局 shrinker_list
	// 2. 处理每个注册的内存回收器
	list_for_each_entry_rcu(shrinker, &shrinker_list, list) {
		// 准备控制结构:
		// 1. 创建传递参数的 shrink_control
		// 2. 包含内存标志、节点 ID 和内存控制组
		struct shrink_control sc = {
			.gfp_mask = gfp_mask,
			.nid = nid,
			.memcg = memcg,
		};

		// 获取 shrinker 引用:
		// 1. 尝试增加 shrinker 的引用计数
		// 2. 如果失败(可能正在注销)，跳过此 shrinker
		// 3. 保证后续操作期间 shrinker 不会被释放
		if (!shrinker_try_get(shrinker))
			continue;

		// 释放 RCU 锁:
		// 1. 允许在 do_shrink_slab 中睡眠
		// 2. 因为已通过引用计数保护 shrinker
		rcu_read_unlock();

		// 执行实际收缩:
		// 1. 调用 shrinker 的扫描函数
		// 2. 可能阻塞/睡眠，因为已释放 RCU 锁
		ret = do_shrink_slab(&sc, shrinker, priority);
		// 处理特殊返回值:
		// 1. SHRINK_EMPTY: 没有可回收对象
		// 转换为 0 避免干扰统计
		if (ret == SHRINK_EMPTY)
			ret = 0;
		// 累计释放量:统计所有 shrinker 释放的总页数
		freed += ret;

		// 重新加 RCU 锁:为下一轮遍历和 put 操作准备
		rcu_read_lock();
		// 释放 shrinker 引用:
		// 1. 减少引用计数
		// 2. 若计数归零则唤醒等待注销的进程
		// 3. 与前面的 try_get 配对使用
		shrinker_put(shrinker);
	}

	rcu_read_unlock();
	// 避免长时间占用 CPU, 保证其他进程有机会运行
	cond_resched();
	return freed;
}

struct shrinker *shrinker_alloc(unsigned int flags, const char *fmt, ...)
{
	struct shrinker *shrinker;
	unsigned int size;
	va_list ap;
	int err;

	shrinker = kzalloc(sizeof(struct shrinker), GFP_KERNEL);
	if (!shrinker)
		return NULL;

	va_start(ap, fmt);
	err = shrinker_debugfs_name_alloc(shrinker, fmt, ap);
	va_end(ap);
	if (err)
		goto err_name;

	shrinker->flags = flags | SHRINKER_ALLOCATED;
	shrinker->seeks = DEFAULT_SEEKS;

	if (flags & SHRINKER_MEMCG_AWARE) {
		err = shrinker_memcg_alloc(shrinker);
		if (err == -ENOSYS) {
			/* Memcg is not supported, fallback to non-memcg-aware shrinker. */
			shrinker->flags &= ~SHRINKER_MEMCG_AWARE;
			goto non_memcg;
		}

		if (err)
			goto err_flags;

		return shrinker;
	}

non_memcg:
	/*
	 * The nr_deferred is available on per memcg level for memcg aware
	 * shrinkers, so only allocate nr_deferred in the following cases:
	 *  - non-memcg-aware shrinkers
	 *  - !CONFIG_MEMCG
	 *  - memcg is disabled by kernel command line
	 */
	size = sizeof(*shrinker->nr_deferred);
	if (flags & SHRINKER_NUMA_AWARE)
		size *= nr_node_ids;

	shrinker->nr_deferred = kzalloc(size, GFP_KERNEL);
	if (!shrinker->nr_deferred)
		goto err_flags;

	return shrinker;

err_flags:
	shrinker_debugfs_name_free(shrinker);
err_name:
	kfree(shrinker);
	return NULL;
}
EXPORT_SYMBOL_GPL(shrinker_alloc);

void shrinker_register(struct shrinker *shrinker)
{
	if (unlikely(!(shrinker->flags & SHRINKER_ALLOCATED))) {
		pr_warn("Must use shrinker_alloc() to dynamically allocate the shrinker");
		return;
	}

	mutex_lock(&shrinker_mutex);
	list_add_tail_rcu(&shrinker->list, &shrinker_list);
	shrinker->flags |= SHRINKER_REGISTERED;
	shrinker_debugfs_add(shrinker);
	mutex_unlock(&shrinker_mutex);

	init_completion(&shrinker->done);
	/*
	 * Now the shrinker is fully set up, take the first reference to it to
	 * indicate that lookup operations are now allowed to use it via
	 * shrinker_try_get().
	 */
	refcount_set(&shrinker->refcount, 1);
}
EXPORT_SYMBOL_GPL(shrinker_register);

static void shrinker_free_rcu_cb(struct rcu_head *head)
{
	struct shrinker *shrinker = container_of(head, struct shrinker, rcu);

	kfree(shrinker->nr_deferred);
	kfree(shrinker);
}

void shrinker_free(struct shrinker *shrinker)
{
	struct dentry *debugfs_entry = NULL;
	int debugfs_id;

	if (!shrinker)
		return;

	if (shrinker->flags & SHRINKER_REGISTERED) {
		/* drop the initial refcount */
		shrinker_put(shrinker);
		/*
		 * Wait for all lookups of the shrinker to complete, after that,
		 * no shrinker is running or will run again, then we can safely
		 * free it asynchronously via RCU and safely free the structure
		 * where the shrinker is located, such as super_block etc.
		 */
		wait_for_completion(&shrinker->done);
	}

	mutex_lock(&shrinker_mutex);
	if (shrinker->flags & SHRINKER_REGISTERED) {
		/*
		 * Now we can safely remove it from the shrinker_list and then
		 * free it.
		 */
		list_del_rcu(&shrinker->list);
		debugfs_entry = shrinker_debugfs_detach(shrinker, &debugfs_id);
		shrinker->flags &= ~SHRINKER_REGISTERED;
	}

	shrinker_debugfs_name_free(shrinker);

	if (shrinker->flags & SHRINKER_MEMCG_AWARE)
		shrinker_memcg_remove(shrinker);
	mutex_unlock(&shrinker_mutex);

	if (debugfs_entry)
		shrinker_debugfs_remove(debugfs_entry, debugfs_id);

	call_rcu(&shrinker->rcu, shrinker_free_rcu_cb);
}
EXPORT_SYMBOL_GPL(shrinker_free);
