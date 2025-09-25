// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *
 *  Swap reorganised 29.12.95, Stephen Tweedie.
 *  kswapd added: 7.1.96  sct
 *  Removed kswapd_ctl limits, and swap out as many pages as needed
 *  to bring the system back to freepages.high: 2.4.97, Rik van Riel.
 *  Zone aware kswapd started 02/00, Kanoj Sarcar (kanoj@sgi.com).
 *  Multiqueue VM started 5.8.00, Rik van Riel.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/vmpressure.h>
#include <linux/vmstat.h>
#include <linux/file.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>	/* for buffer_heads_over_limit */
#include <linux/mm_inline.h>
#include <linux/backing-dev.h>
#include <linux/rmap.h>
#include <linux/topology.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/compaction.h>
#include <linux/notifier.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/memcontrol.h>
#include <linux/migrate.h>
#include <linux/delayacct.h>
#include <linux/sysctl.h>
#include <linux/memory-tiers.h>
#include <linux/oom.h>
#include <linux/pagevec.h>
#include <linux/prefetch.h>
#include <linux/printk.h>
#include <linux/dax.h>
#include <linux/psi.h>
#include <linux/pagewalk.h>
#include <linux/shmem_fs.h>
#include <linux/ctype.h>
#include <linux/debugfs.h>
#include <linux/khugepaged.h>
#include <linux/rculist_nulls.h>
#include <linux/random.h>
#include <linux/mmu_notifier.h>

#include <asm/tlbflush.h>
#include <asm/div64.h>

#include <linux/swapops.h>
#include <linux/balloon_compaction.h>
#include <linux/sched/sysctl.h>

#include "internal.h"
#include "swap.h"

#define CREATE_TRACE_POINTS
#include <trace/events/vmscan.h>

struct scan_control {
	/* How many pages shrink_list() should reclaim */
	unsigned long nr_to_reclaim;

	/*
	 * Nodemask of nodes allowed by the caller. If NULL, all nodes
	 * are scanned.
	 */
	nodemask_t	*nodemask;

	/*
	 * The memory cgroup that hit its limit and as a result is the
	 * primary target of this reclaim invocation.
	 */
	struct mem_cgroup *target_mem_cgroup;

	/*
	 * Scan pressure balancing between anon and file LRUs
	 */
	unsigned long	anon_cost;
	unsigned long	file_cost;

#ifdef CONFIG_MEMCG
	/* Swappiness value for proactive reclaim. Always use sc_swappiness()! */
	int *proactive_swappiness;
#endif

	/* Can active folios be deactivated as part of reclaim? */
#define DEACTIVATE_ANON 1
#define DEACTIVATE_FILE 2
	unsigned int may_deactivate:2;
	unsigned int force_deactivate:1;
	unsigned int skipped_deactivate:1;

	/* Writepage batching in laptop mode; RECLAIM_WRITE */
	unsigned int may_writepage:1;

	/* Can mapped folios be reclaimed? */
	unsigned int may_unmap:1;

	/* Can folios be swapped as part of reclaim? */
	unsigned int may_swap:1;

	/* Not allow cache_trim_mode to be turned on as part of reclaim? */
	unsigned int no_cache_trim_mode:1;

	/* Has cache_trim_mode failed at least once? */
	unsigned int cache_trim_mode_failed:1;

	/* Proactive reclaim invoked by userspace through memory.reclaim */
	unsigned int proactive:1;

	/*
	 * Cgroup memory below memory.low is protected as long as we
	 * don't threaten to OOM. If any cgroup is reclaimed at
	 * reduced force or passed over entirely due to its memory.low
	 * setting (memcg_low_skipped), and nothing is reclaimed as a
	 * result, then go back for one more cycle that reclaims the protected
	 * memory (memcg_low_reclaim) to avert OOM.
	 */
	unsigned int memcg_low_reclaim:1;
	unsigned int memcg_low_skipped:1;

	/* Shared cgroup tree walk failed, rescan the whole tree */
	unsigned int memcg_full_walk:1;

	unsigned int hibernation_mode:1;

	/* One of the zones is ready for compaction */
	unsigned int compaction_ready:1;

	/* There is easily reclaimable cold cache in the current node */
	unsigned int cache_trim_mode:1;

	/* The file folios on the current node are dangerously low */
	unsigned int file_is_tiny:1;

	/* Always discard instead of demoting to lower tier memory */
	unsigned int no_demotion:1;

	/* Allocation order */
	s8 order;

	/* Scan (total_size >> priority) pages at once */
	s8 priority;

	/* The highest zone to isolate folios for reclaim from */
	s8 reclaim_idx;

	/* This context's GFP mask */
	gfp_t gfp_mask;

	/* Incremented by the number of inactive pages that were scanned */
	unsigned long nr_scanned;

	/* Number of pages freed so far during a call to shrink_zones() */
	unsigned long nr_reclaimed;

	struct {
		unsigned int dirty;
		unsigned int unqueued_dirty;
		unsigned int congested;
		unsigned int writeback;
		unsigned int immediate;
		unsigned int file_taken;
		unsigned int taken;
	} nr;

	/* for recording the reclaimed slab by now */
	struct reclaim_state reclaim_state;
};

#ifdef ARCH_HAS_PREFETCHW
#define prefetchw_prev_lru_folio(_folio, _base, _field)			\
	do {								\
		if ((_folio)->lru.prev != _base) {			\
			struct folio *prev;				\
									\
			prev = lru_to_folio(&(_folio->lru));		\
			prefetchw(&prev->_field);			\
		}							\
	} while (0)
#else
#define prefetchw_prev_lru_folio(_folio, _base, _field) do { } while (0)
#endif

/*
 * From 0 .. MAX_SWAPPINESS.  Higher means more swappy.
 */
int vm_swappiness = 60;

#ifdef CONFIG_MEMCG

/* Returns true for reclaim through cgroup limits or cgroup interfaces. */
static bool cgroup_reclaim(struct scan_control *sc)
{
	return sc->target_mem_cgroup;
}

/*
 * Returns true for reclaim on the root cgroup. This is true for direct
 * allocator reclaim and reclaim through cgroup interfaces on the root cgroup.
 */
static bool root_reclaim(struct scan_control *sc)
{
	return !sc->target_mem_cgroup || mem_cgroup_is_root(sc->target_mem_cgroup);
}

/**
 * writeback_throttling_sane - is the usual dirty throttling mechanism available?
 * @sc: scan_control in question
 *
 * The normal page dirty throttling mechanism in balance_dirty_pages() is
 * completely broken with the legacy memcg and direct stalling in
 * shrink_folio_list() is used for throttling instead, which lacks all the
 * niceties such as fairness, adaptive pausing, bandwidth proportional
 * allocation and configurability.
 *
 * This function tests whether the vmscan currently in progress can assume
 * that the normal dirty throttling mechanism is operational.
 */
static bool writeback_throttling_sane(struct scan_control *sc)
{
	if (!cgroup_reclaim(sc))
		return true;
#ifdef CONFIG_CGROUP_WRITEBACK
	if (cgroup_subsys_on_dfl(memory_cgrp_subsys))
		return true;
#endif
	return false;
}

static int sc_swappiness(struct scan_control *sc, struct mem_cgroup *memcg)
{
	if (sc->proactive && sc->proactive_swappiness)
		return *sc->proactive_swappiness;
	return mem_cgroup_swappiness(memcg);
}
#else
static bool cgroup_reclaim(struct scan_control *sc)
{
	return false;
}

static bool root_reclaim(struct scan_control *sc)
{
	return true;
}

static bool writeback_throttling_sane(struct scan_control *sc)
{
	return true;
}

static int sc_swappiness(struct scan_control *sc, struct mem_cgroup *memcg)
{
	return READ_ONCE(vm_swappiness);
}
#endif

/* for_each_managed_zone_pgdat - helper macro to iterate over all managed zones in a pgdat up to
 * and including the specified highidx
 * @zone: The current zone in the iterator
 * @pgdat: The pgdat which node_zones are being iterated
 * @idx: The index variable
 * @highidx: The index of the highest zone to return
 *
 * This macro iterates through all managed zones up to and including the specified highidx.
 * The zone iterator enters an invalid state after macro call and must be reinitialized
 * before it can be used again.
 */
#define for_each_managed_zone_pgdat(zone, pgdat, idx, highidx)	\
	for ((idx) = 0, (zone) = (pgdat)->node_zones;		\
	    (idx) <= (highidx);					\
	    (idx)++, (zone)++)					\
		if (!managed_zone(zone))			\
			continue;				\
		else

static void set_task_reclaim_state(struct task_struct *task,
				   struct reclaim_state *rs)
{
	/* Check for an overwrite */
	WARN_ON_ONCE(rs && task->reclaim_state);

	/* Check for the nulling of an already-nulled member */
	WARN_ON_ONCE(!rs && !task->reclaim_state);

	task->reclaim_state = rs;
}

/*
 * flush_reclaim_state(): add pages reclaimed outside of LRU-based reclaim to
 * scan_control->nr_reclaimed.
 */
static void flush_reclaim_state(struct scan_control *sc)
{
	/*
	 * Currently, reclaim_state->reclaimed includes three types of pages
	 * freed outside of vmscan:
	 * (1) Slab pages.
	 * (2) Clean file pages from pruned inodes (on highmem systems).
	 * (3) XFS freed buffer pages.
	 *
	 * For all of these cases, we cannot universally link the pages to a
	 * single memcg. For example, a memcg-aware shrinker can free one object
	 * charged to the target memcg, causing an entire page to be freed.
	 * If we count the entire page as reclaimed from the memcg, we end up
	 * overestimating the reclaimed amount (potentially under-reclaiming).
	 *
	 * Only count such pages for global reclaim to prevent under-reclaiming
	 * from the target memcg; preventing unnecessary retries during memcg
	 * charging and false positives from proactive reclaim.
	 *
	 * For uncommon cases where the freed pages were actually mostly
	 * charged to the target memcg, we end up underestimating the reclaimed
	 * amount. This should be fine. The freed pages will be uncharged
	 * anyway, even if they are not counted here properly, and we will be
	 * able to make forward progress in charging (which is usually in a
	 * retry loop).
	 *
	 * We can go one step further, and report the uncharged objcg pages in
	 * memcg reclaim, to make reporting more accurate and reduce
	 * underestimation, but it's probably not worth the complexity for now.
	 */
	if (current->reclaim_state && root_reclaim(sc)) {
		sc->nr_reclaimed += current->reclaim_state->reclaimed;
		current->reclaim_state->reclaimed = 0;
	}
}

static bool can_demote(int nid, struct scan_control *sc,
		       struct mem_cgroup *memcg)
{
	int demotion_nid;

	if (!numa_demotion_enabled)
		return false;
	if (sc && sc->no_demotion)
		return false;

	demotion_nid = next_demotion_node(nid);
	if (demotion_nid == NUMA_NO_NODE)
		return false;

	/* If demotion node isn't in the cgroup's mems_allowed, fall back */
	return mem_cgroup_node_allowed(memcg, demotion_nid);
}

static inline bool can_reclaim_anon_pages(struct mem_cgroup *memcg,
					  int nid,
					  struct scan_control *sc)
{
	if (memcg == NULL) {
		/*
		 * For non-memcg reclaim, is there
		 * space in any swap device?
		 */
		if (get_nr_swap_pages() > 0)
			return true;
	} else {
		/* Is the memcg below its swap limit? */
		if (mem_cgroup_get_nr_swap_pages(memcg) > 0)
			return true;
	}

	/*
	 * The page can not be swapped.
	 *
	 * Can it be reclaimed from this node via demotion?
	 */
	return can_demote(nid, sc, memcg);
}

/*
 * This misses isolated folios which are not accounted for to save counters.
 * As the data only determines if reclaim or compaction continues, it is
 * not expected that isolated folios will be a dominating factor.
 */
unsigned long zone_reclaimable_pages(struct zone *zone)
{
	unsigned long nr;

	nr = zone_page_state_snapshot(zone, NR_ZONE_INACTIVE_FILE) +
		zone_page_state_snapshot(zone, NR_ZONE_ACTIVE_FILE);
	if (can_reclaim_anon_pages(NULL, zone_to_nid(zone), NULL))
		nr += zone_page_state_snapshot(zone, NR_ZONE_INACTIVE_ANON) +
			zone_page_state_snapshot(zone, NR_ZONE_ACTIVE_ANON);
	/*
	 * If there are no reclaimable file-backed or anonymous pages,
	 * ensure zones with sufficient free pages are not skipped.
	 * This prevents zones like DMA32 from being ignored in reclaim
	 * scenarios where they can still help alleviate memory pressure.
	 */
	if (nr == 0)
		nr = zone_page_state_snapshot(zone, NR_FREE_PAGES);
	return nr;
}

/**
 * lruvec_lru_size -  Returns the number of pages on the given LRU list.
 * @lruvec: lru vector
 * @lru: lru to use
 * @zone_idx: zones to consider (use MAX_NR_ZONES - 1 for the whole LRU list)
 */
static unsigned long lruvec_lru_size(struct lruvec *lruvec, enum lru_list lru,
				     int zone_idx)
{
	unsigned long size = 0;
	int zid;
	struct zone *zone;

	for_each_managed_zone_pgdat(zone, lruvec_pgdat(lruvec), zid, zone_idx) {
		if (!mem_cgroup_disabled())
			size += mem_cgroup_get_zone_lru_size(lruvec, lru, zid);
		else
			size += zone_page_state(zone, NR_ZONE_LRU_BASE + lru);
	}
	return size;
}

static unsigned long drop_slab_node(int nid)
{
	unsigned long freed = 0;
	struct mem_cgroup *memcg = NULL;

	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		freed += shrink_slab(GFP_KERNEL, nid, memcg, 0);
	} while ((memcg = mem_cgroup_iter(NULL, memcg, NULL)) != NULL);

	return freed;
}

void drop_slab(void)
{
	int nid;
	int shift = 0;
	unsigned long freed;

	do {
		freed = 0;
		for_each_online_node(nid) {
			if (fatal_signal_pending(current))
				return;

			freed += drop_slab_node(nid);
		}
	} while ((freed >> shift++) > 1);
}

#define CHECK_RECLAIMER_OFFSET(type)					\
	do {								\
		BUILD_BUG_ON(PGSTEAL_##type - PGSTEAL_KSWAPD !=		\
			     PGDEMOTE_##type - PGDEMOTE_KSWAPD);	\
		BUILD_BUG_ON(PGSTEAL_##type - PGSTEAL_KSWAPD !=		\
			     PGSCAN_##type - PGSCAN_KSWAPD);		\
	} while (0)

static int reclaimer_offset(struct scan_control *sc)
{
	CHECK_RECLAIMER_OFFSET(DIRECT);
	CHECK_RECLAIMER_OFFSET(KHUGEPAGED);
	CHECK_RECLAIMER_OFFSET(PROACTIVE);

	if (current_is_kswapd())
		return 0;
	if (current_is_khugepaged())
		return PGSTEAL_KHUGEPAGED - PGSTEAL_KSWAPD;
	if (sc->proactive)
		return PGSTEAL_PROACTIVE - PGSTEAL_KSWAPD;
	return PGSTEAL_DIRECT - PGSTEAL_KSWAPD;
}

static inline int is_page_cache_freeable(struct folio *folio)
{
	/*
	 * A freeable page cache folio is referenced only by the caller
	 * that isolated the folio, the page cache and optional filesystem
	 * private data at folio->private.
	 */
	return folio_ref_count(folio) - folio_test_private(folio) ==
		1 + folio_nr_pages(folio);
}

/*
 * We detected a synchronous write error writing a folio out.  Probably
 * -ENOSPC.  We need to propagate that into the address_space for a subsequent
 * fsync(), msync() or close().
 *
 * The tricky part is that after writepage we cannot touch the mapping: nothing
 * prevents it from being freed up.  But we have a ref on the folio and once
 * that folio is locked, the mapping is pinned.
 *
 * We're allowed to run sleeping folio_lock() here because we know the caller has
 * __GFP_FS.
 */
static void handle_write_error(struct address_space *mapping,
				struct folio *folio, int error)
{
	folio_lock(folio);
	if (folio_mapping(folio) == mapping)
		mapping_set_error(mapping, error);
	folio_unlock(folio);
}

static bool skip_throttle_noprogress(pg_data_t *pgdat)
{
	int reclaimable = 0, write_pending = 0;
	int i;
	struct zone *zone;
	/*
	 * If kswapd is disabled, reschedule if necessary but do not
	 * throttle as the system is likely near OOM.
	 */
	if (pgdat->kswapd_failures >= MAX_RECLAIM_RETRIES)
		return true;

	/*
	 * If there are a lot of dirty/writeback folios then do not
	 * throttle as throttling will occur when the folios cycle
	 * towards the end of the LRU if still under writeback.
	 */
	for_each_managed_zone_pgdat(zone, pgdat, i, MAX_NR_ZONES - 1) {
		reclaimable += zone_reclaimable_pages(zone);
		write_pending += zone_page_state_snapshot(zone,
						  NR_ZONE_WRITE_PENDING);
	}
	if (2 * write_pending <= reclaimable)
		return true;

	return false;
}

void reclaim_throttle(pg_data_t *pgdat, enum vmscan_throttle_state reason)
{
	wait_queue_head_t *wqh = &pgdat->reclaim_wait[reason];
	long timeout, ret;
	DEFINE_WAIT(wait);

	/*
	 * Do not throttle user workers, kthreads other than kswapd or
	 * workqueues. They may be required for reclaim to make
	 * forward progress (e.g. journalling workqueues or kthreads).
	 */
	if (!current_is_kswapd() &&
	    current->flags & (PF_USER_WORKER|PF_KTHREAD)) {
		cond_resched();
		return;
	}

	/*
	 * These figures are pulled out of thin air.
	 * VMSCAN_THROTTLE_ISOLATED is a transient condition based on too many
	 * parallel reclaimers which is a short-lived event so the timeout is
	 * short. Failing to make progress or waiting on writeback are
	 * potentially long-lived events so use a longer timeout. This is shaky
	 * logic as a failure to make progress could be due to anything from
	 * writeback to a slow device to excessive referenced folios at the tail
	 * of the inactive LRU.
	 */
	switch(reason) {
	case VMSCAN_THROTTLE_WRITEBACK:
		timeout = HZ/10;

		if (atomic_inc_return(&pgdat->nr_writeback_throttled) == 1) {
			WRITE_ONCE(pgdat->nr_reclaim_start,
				node_page_state(pgdat, NR_THROTTLED_WRITTEN));
		}

		break;
	case VMSCAN_THROTTLE_CONGESTED:
		fallthrough;
	case VMSCAN_THROTTLE_NOPROGRESS:
		if (skip_throttle_noprogress(pgdat)) {
			cond_resched();
			return;
		}

		timeout = 1;

		break;
	case VMSCAN_THROTTLE_ISOLATED:
		timeout = HZ/50;
		break;
	default:
		WARN_ON_ONCE(1);
		timeout = HZ;
		break;
	}

	prepare_to_wait(wqh, &wait, TASK_UNINTERRUPTIBLE);
	ret = schedule_timeout(timeout);
	finish_wait(wqh, &wait);

	if (reason == VMSCAN_THROTTLE_WRITEBACK)
		atomic_dec(&pgdat->nr_writeback_throttled);

	trace_mm_vmscan_throttled(pgdat->node_id, jiffies_to_usecs(timeout),
				jiffies_to_usecs(timeout - ret),
				reason);
}

/*
 * Account for folios written if tasks are throttled waiting on dirty
 * folios to clean. If enough folios have been cleaned since throttling
 * started then wakeup the throttled tasks.
 */
void __acct_reclaim_writeback(pg_data_t *pgdat, struct folio *folio,
							int nr_throttled)
{
	unsigned long nr_written;

	node_stat_add_folio(folio, NR_THROTTLED_WRITTEN);

	/*
	 * This is an inaccurate read as the per-cpu deltas may not
	 * be synchronised. However, given that the system is
	 * writeback throttled, it is not worth taking the penalty
	 * of getting an accurate count. At worst, the throttle
	 * timeout guarantees forward progress.
	 */
	nr_written = node_page_state(pgdat, NR_THROTTLED_WRITTEN) -
		READ_ONCE(pgdat->nr_reclaim_start);

	if (nr_written > SWAP_CLUSTER_MAX * nr_throttled)
		wake_up(&pgdat->reclaim_wait[VMSCAN_THROTTLE_WRITEBACK]);
}

/* possible outcome of pageout() */
typedef enum {
	/* failed to write folio out, folio is locked */
	PAGE_KEEP,
	/* move folio to the active list, folio is locked */
	PAGE_ACTIVATE,
	/* folio has been sent to the disk successfully, folio is unlocked */
	PAGE_SUCCESS,
	/* folio is clean and locked */
	PAGE_CLEAN,
} pageout_t;

/*
 * pageout is called by shrink_folio_list() for each dirty folio.
 */
static pageout_t pageout(struct folio *folio, struct address_space *mapping,
			 struct swap_iocb **plug, struct list_head *folio_list)
{
	int (*writeout)(struct folio *, struct writeback_control *);

	/*
	 * We no longer attempt to writeback filesystem folios here, other
	 * than tmpfs/shmem.  That's taken care of in page-writeback.
	 * If we find a dirty filesystem folio at the end of the LRU list,
	 * typically that means the filesystem is saturating the storage
	 * with contiguous writes and telling it to write a folio here
	 * would only make the situation worse by injecting an element
	 * of random access.
	 *
	 * If the folio is swapcache, write it back even if that would
	 * block, for some throttling. This happens by accident, because
	 * swap_backing_dev_info is bust: it doesn't reflect the
	 * congestion state of the swapdevs.  Easy to fix, if needed.
	 */
	if (!is_page_cache_freeable(folio))
		return PAGE_KEEP;
	if (!mapping) {
		/*
		 * Some data journaling orphaned folios can have
		 * folio->mapping == NULL while being dirty with clean buffers.
		 */
		if (folio_test_private(folio)) {
			if (try_to_free_buffers(folio)) {
				folio_clear_dirty(folio);
				pr_info("%s: orphaned folio\n", __func__);
				return PAGE_CLEAN;
			}
		}
		return PAGE_KEEP;
	}
	if (shmem_mapping(mapping))
		writeout = shmem_writeout;
	else if (folio_test_anon(folio))
		writeout = swap_writeout;
	else
		return PAGE_ACTIVATE;

	if (folio_clear_dirty_for_io(folio)) {
		int res;
		struct writeback_control wbc = {
			.sync_mode = WB_SYNC_NONE,
			.nr_to_write = SWAP_CLUSTER_MAX,
			.range_start = 0,
			.range_end = LLONG_MAX,
			.for_reclaim = 1,
			.swap_plug = plug,
		};

		/*
		 * The large shmem folio can be split if CONFIG_THP_SWAP is
		 * not enabled or contiguous swap entries are failed to
		 * allocate.
		 */
		if (shmem_mapping(mapping) && folio_test_large(folio))
			wbc.list = folio_list;

		folio_set_reclaim(folio);
		res = writeout(folio, &wbc);
		if (res < 0)
			handle_write_error(mapping, folio, res);
		if (res == AOP_WRITEPAGE_ACTIVATE) {
			folio_clear_reclaim(folio);
			return PAGE_ACTIVATE;
		}

		if (!folio_test_writeback(folio)) {
			/* synchronous write? */
			folio_clear_reclaim(folio);
		}
		trace_mm_vmscan_write_folio(folio);
		node_stat_add_folio(folio, NR_VMSCAN_WRITE);
		return PAGE_SUCCESS;
	}

	return PAGE_CLEAN;
}

/*
 * Same as remove_mapping, but if the folio is removed from the mapping, it
 * gets returned with a refcount of 0.
 */
static int __remove_mapping(struct address_space *mapping, struct folio *folio,
			    bool reclaimed, struct mem_cgroup *target_memcg)
{
	int refcount;
	void *shadow = NULL;

	BUG_ON(!folio_test_locked(folio));
	BUG_ON(mapping != folio_mapping(folio));

	if (!folio_test_swapcache(folio))
		spin_lock(&mapping->host->i_lock);
	xa_lock_irq(&mapping->i_pages);
	/*
	 * The non racy check for a busy folio.
	 *
	 * Must be careful with the order of the tests. When someone has
	 * a ref to the folio, it may be possible that they dirty it then
	 * drop the reference. So if the dirty flag is tested before the
	 * refcount here, then the following race may occur:
	 *
	 * get_user_pages(&page);
	 * [user mapping goes away]
	 * write_to(page);
	 *				!folio_test_dirty(folio)    [good]
	 * folio_set_dirty(folio);
	 * folio_put(folio);
	 *				!refcount(folio)   [good, discard it]
	 *
	 * [oops, our write_to data is lost]
	 *
	 * Reversing the order of the tests ensures such a situation cannot
	 * escape unnoticed. The smp_rmb is needed to ensure the folio->flags
	 * load is not satisfied before that of folio->_refcount.
	 *
	 * Note that if the dirty flag is always set via folio_mark_dirty,
	 * and thus under the i_pages lock, then this ordering is not required.
	 */
	refcount = 1 + folio_nr_pages(folio);
	if (!folio_ref_freeze(folio, refcount))
		goto cannot_free;
	/* note: atomic_cmpxchg in folio_ref_freeze provides the smp_rmb */
	if (unlikely(folio_test_dirty(folio))) {
		folio_ref_unfreeze(folio, refcount);
		goto cannot_free;
	}

	if (folio_test_swapcache(folio)) {
		swp_entry_t swap = folio->swap;

		if (reclaimed && !mapping_exiting(mapping))
			shadow = workingset_eviction(folio, target_memcg);
		__delete_from_swap_cache(folio, swap, shadow);
		memcg1_swapout(folio, swap);
		xa_unlock_irq(&mapping->i_pages);
		put_swap_folio(folio, swap);
	} else {
		void (*free_folio)(struct folio *);

		free_folio = mapping->a_ops->free_folio;
		/*
		 * Remember a shadow entry for reclaimed file cache in
		 * order to detect refaults, thus thrashing, later on.
		 *
		 * But don't store shadows in an address space that is
		 * already exiting.  This is not just an optimization,
		 * inode reclaim needs to empty out the radix tree or
		 * the nodes are lost.  Don't plant shadows behind its
		 * back.
		 *
		 * We also don't store shadows for DAX mappings because the
		 * only page cache folios found in these are zero pages
		 * covering holes, and because we don't want to mix DAX
		 * exceptional entries and shadow exceptional entries in the
		 * same address_space.
		 */
		if (reclaimed && folio_is_file_lru(folio) &&
		    !mapping_exiting(mapping) && !dax_mapping(mapping))
			shadow = workingset_eviction(folio, target_memcg);
		__filemap_remove_folio(folio, shadow);
		xa_unlock_irq(&mapping->i_pages);
		if (mapping_shrinkable(mapping))
			inode_add_lru(mapping->host);
		spin_unlock(&mapping->host->i_lock);

		if (free_folio)
			free_folio(folio);
	}

	return 1;

cannot_free:
	xa_unlock_irq(&mapping->i_pages);
	if (!folio_test_swapcache(folio))
		spin_unlock(&mapping->host->i_lock);
	return 0;
}

/**
 * remove_mapping() - Attempt to remove a folio from its mapping.
 * @mapping: The address space.
 * @folio: The folio to remove.
 *
 * If the folio is dirty, under writeback or if someone else has a ref
 * on it, removal will fail.
 * Return: The number of pages removed from the mapping.  0 if the folio
 * could not be removed.
 * Context: The caller should have a single refcount on the folio and
 * hold its lock.
 */
long remove_mapping(struct address_space *mapping, struct folio *folio)
{
	if (__remove_mapping(mapping, folio, false, NULL)) {
		/*
		 * Unfreezing the refcount with 1 effectively
		 * drops the pagecache ref for us without requiring another
		 * atomic operation.
		 */
		folio_ref_unfreeze(folio, 1);
		return folio_nr_pages(folio);
	}
	return 0;
}

/**
 * folio_putback_lru - Put previously isolated folio onto appropriate LRU list.
 * @folio: Folio to be returned to an LRU list.
 *
 * Add previously isolated @folio to appropriate LRU list.
 * The folio may still be unevictable for other reasons.
 *
 * Context: lru_lock must not be held, interrupts must be enabled.
 */
void folio_putback_lru(struct folio *folio)
{
	folio_add_lru(folio);
	folio_put(folio);		/* drop ref from isolate */
}

enum folio_references {
	FOLIOREF_RECLAIM,
	FOLIOREF_RECLAIM_CLEAN,
	FOLIOREF_KEEP,
	FOLIOREF_ACTIVATE,
};

#ifdef CONFIG_LRU_GEN
/*
 * Only used on a mapped folio in the eviction (rmap walk) path, where promotion
 * needs to be done by taking the folio off the LRU list and then adding it back
 * with PG_active set. In contrast, the aging (page table walk) path uses
 * folio_update_gen().
 */
static bool lru_gen_set_refs(struct folio *folio)
{
	/* see the comment on LRU_REFS_FLAGS */
	if (!folio_test_referenced(folio) && !folio_test_workingset(folio)) {
		set_mask_bits(&folio->flags, LRU_REFS_MASK, BIT(PG_referenced));
		return false;
	}

	set_mask_bits(&folio->flags, LRU_REFS_FLAGS, BIT(PG_workingset));
	return true;
}
#else
static bool lru_gen_set_refs(struct folio *folio)
{
	return false;
}
#endif /* CONFIG_LRU_GEN */

static enum folio_references folio_check_references(struct folio *folio,
						  struct scan_control *sc)
{
	int referenced_ptes, referenced_folio;
	unsigned long vm_flags;

	/* 步骤1：获取反向映射统计 */
	referenced_ptes = folio_referenced(folio, 1, sc->target_mem_cgroup,   // PTE级访问次数
					   &vm_flags);

	/*
	 * The supposedly reclaimable folio was found to be in a VM_LOCKED vma.
	 * Let the folio, now marked Mlocked, be moved to the unevictable list.
	 */
	/* 步骤2：处理锁定的内存页 */
	if (vm_flags & VM_LOCKED)
		return FOLIOREF_ACTIVATE;  // 激活锁定页

	/*
	 * There are two cases to consider.
	 * 1) Rmap lock contention: rotate.
	 * 2) Skip the non-shared swapbacked folio mapped solely by
	 *    the exiting or OOM-reaped process.
	 */
	/* 步骤3：处理锁争用或特殊僵尸页 */
	if (referenced_ptes == -1)     // 竞争或僵尸页
		return FOLIOREF_KEEP;      // 保留不处理

	/* 步骤4：多代LRU处理 */
	if (lru_gen_enabled()) {
		if (!referenced_ptes)      // 无访问
			return FOLIOREF_RECLAIM;

		// 有访问则用新型策略
		return lru_gen_set_refs(folio) ? FOLIOREF_ACTIVATE : FOLIOREF_KEEP;
	}

	/* 步骤5：传统回收决策 */
	referenced_folio = folio_test_clear_referenced(folio); // 读取PG_referenced位

	if (referenced_ptes) {         // 有PTE级访问
		/*
		 * All mapped folios start out with page table
		 * references from the instantiating fault, so we need
		 * to look twice if a mapped file/anon folio is used more
		 * than once.
		 *
		 * Mark it and spare it for another trip around the
		 * inactive list.  Another page table reference will
		 * lead to its activation.
		 *
		 * Note: the mark is set for activated folios as well
		 * so that recently deactivated but used folios are
		 * quickly recovered.
		 */
		folio_set_referenced(folio); // 标记页面为被引用

		// 复合热点条件
		if (referenced_folio || referenced_ptes > 1)
			return FOLIOREF_ACTIVATE;

		/*
		 * Activate file-backed executable folios after first usage.
		 */
		// 特殊处理可执行文件页
		if ((vm_flags & VM_EXEC) && folio_is_file_lru(folio))
			return FOLIOREF_ACTIVATE;

		return FOLIOREF_KEEP;      // 单次引用暂缓回收
	}

	/* Reclaim if clean, defer dirty folios to writeback */
	/* 步骤6：无访问的页面处理 */
	if (referenced_folio && folio_is_file_lru(folio))
		return FOLIOREF_RECLAIM_CLEAN; // 干净文件页优先回收

	return FOLIOREF_RECLAIM;       // 其余情况直接回收
}

/* Check if a folio is dirty or under writeback */
static void folio_check_dirty_writeback(struct folio *folio,
				       bool *dirty, bool *writeback)
{
	struct address_space *mapping;

	/*
	 * Anonymous folios are not handled by flushers and must be written
	 * from reclaim context. Do not stall reclaim based on them.
	 * MADV_FREE anonymous folios are put into inactive file list too.
	 * They could be mistakenly treated as file lru. So further anon
	 * test is needed.
	 */
	if (!folio_is_file_lru(folio) ||
	    (folio_test_anon(folio) && !folio_test_swapbacked(folio))) {
		*dirty = false;
		*writeback = false;
		return;
	}

	/* By default assume that the folio flags are accurate */
	*dirty = folio_test_dirty(folio);
	*writeback = folio_test_writeback(folio);

	/* Verify dirty/writeback state if the filesystem supports it */
	if (!folio_test_private(folio))
		return;

	mapping = folio_mapping(folio);
	if (mapping && mapping->a_ops->is_dirty_writeback)
		mapping->a_ops->is_dirty_writeback(folio, dirty, writeback);
}

struct folio *alloc_migrate_folio(struct folio *src, unsigned long private)
{
	struct folio *dst;
	nodemask_t *allowed_mask;
	struct migration_target_control *mtc;

	mtc = (struct migration_target_control *)private;

	allowed_mask = mtc->nmask;
	/*
	 * make sure we allocate from the target node first also trying to
	 * demote or reclaim pages from the target node via kswapd if we are
	 * low on free memory on target node. If we don't do this and if
	 * we have free memory on the slower(lower) memtier, we would start
	 * allocating pages from slower(lower) memory tiers without even forcing
	 * a demotion of cold pages from the target memtier. This can result
	 * in the kernel placing hot pages in slower(lower) memory tiers.
	 */
	mtc->nmask = NULL;
	mtc->gfp_mask |= __GFP_THISNODE;
	dst = alloc_migration_target(src, (unsigned long)mtc);
	if (dst)
		return dst;

	mtc->gfp_mask &= ~__GFP_THISNODE;
	mtc->nmask = allowed_mask;

	return alloc_migration_target(src, (unsigned long)mtc);
}

/*
 * Take folios on @demote_folios and attempt to demote them to another node.
 * Folios which are not demoted are left on @demote_folios.
 */
static unsigned int demote_folio_list(struct list_head *demote_folios,
				     struct pglist_data *pgdat)
{
	int target_nid = next_demotion_node(pgdat->node_id);
	unsigned int nr_succeeded;
	nodemask_t allowed_mask;

	struct migration_target_control mtc = {
		/*
		 * Allocate from 'node', or fail quickly and quietly.
		 * When this happens, 'page' will likely just be discarded
		 * instead of migrated.
		 */
		.gfp_mask = (GFP_HIGHUSER_MOVABLE & ~__GFP_RECLAIM) | __GFP_NOWARN |
			__GFP_NOMEMALLOC | GFP_NOWAIT,
		.nid = target_nid,
		.nmask = &allowed_mask,
		.reason = MR_DEMOTION,
	};

	if (list_empty(demote_folios))
		return 0;

	if (target_nid == NUMA_NO_NODE)
		return 0;

	node_get_allowed_targets(pgdat, &allowed_mask);

	/* Demotion ignores all cpuset and mempolicy settings */
	migrate_pages(demote_folios, alloc_migrate_folio, NULL,
		      (unsigned long)&mtc, MIGRATE_ASYNC, MR_DEMOTION,
		      &nr_succeeded);

	return nr_succeeded;
}

static bool may_enter_fs(struct folio *folio, gfp_t gfp_mask)
{
	if (gfp_mask & __GFP_FS)
		return true;
	if (!folio_test_swapcache(folio) || !(gfp_mask & __GFP_IO))
		return false;
	/*
	 * We can "enter_fs" for swap-cache with only __GFP_IO
	 * providing this isn't SWP_FS_OPS.
	 * ->flags can be updated non-atomicially (scan_swap_map_slots),
	 * but that will never affect SWP_FS_OPS, so the data_race
	 * is safe.
	 */
	return !data_race(folio_swap_flags(folio) & SWP_FS_OPS);
}

/*
 * shrink_folio_list() returns the number of reclaimed pages
 */
// 该函数是 Linux 内存回收的核心逻辑，处理从 LRU 链表分离的 Folio 页帧，
// 通过页面回写、解映射等操作回收内存。返回成功回收的页数。
static unsigned int shrink_folio_list(struct list_head *folio_list,
		struct pglist_data *pgdat, struct scan_control *sc,
		struct reclaim_stat *stat, bool ignore_references,
		struct mem_cgroup *memcg)
{
	struct folio_batch free_folios;          // 缓存待释放的 Folio 批次
	LIST_HEAD(ret_folios);                   // 需放回 LRU 的 Folio 链表
	LIST_HEAD(demote_folios);                // 需降级迁移的 Folio 链表
	unsigned int nr_reclaimed = 0, nr_demoted = 0; // 已回收/降级的页数
	unsigned int pgactivate = 0;             // 激活的页数统计
	bool do_demote_pass;                     // 是否执行降级迁移
	struct swap_iocb *plug = NULL;           // Swap I/O 聚合插槽

	// folio_batch_init(&free_folios)：初始化批量释放结构。
	folio_batch_init(&free_folios);
	// memset(stat, 0, sizeof(*stat))：清零回收统计。
	memset(stat, 0, sizeof(*stat));
	// 在不需要紧急处理时，主动检查并自愿让出 CPU，为其他任务提供运行机会，从而避免内核代码路径过长导致系统无响应。
	cond_resched();
	// do_demote_pass = can_demote(...)：检查是否允许降级迁移。
	do_demote_pass = can_demote(pgdat->node_id, sc, memcg);

retry:
	// 主循环：遍历 Folio 链表
	while (!list_empty(folio_list)) {
		struct address_space *mapping;
		struct folio *folio;
		enum folio_references references = FOLIOREF_RECLAIM;
		bool dirty, writeback;
		unsigned int nr_pages;

		// 每处理一个 Folio 前调用 cond_resched() 避免占用 CPU 过久。
		cond_resched();

		folio = lru_to_folio(folio_list);    // 获取链表首个 Folio
		list_del(&folio->lru);               // 从链表移除

		// 1. Folio 锁定与基础检查
		if (!folio_trylock(folio))
			goto keep;     // 尝试加锁，失败则暂不处理

		// “硬件中毒”是一个状态标志，由内核的内存错误检测机制（如通过 EDAC - Error Detection and Correction）设置。
		// 当内存控制器或内核检测到无法纠正的物理内存错误（Uncorrectable Error）时，就会将对应的页面标记为 PG_hwpoison。
		if (folio_contain_hwpoisoned_page(folio)) { // 跳过硬件损坏页
			// 这个函数会遍历所有映射了此坏页的进程的页表（Page Tables），并解除（Unmap） 这些虚拟地址到损坏物理页的映射关系。
			// 这是最关键的一步，它确保了未来任何进程都无法再访问到这块损坏的内存，从而阻止了错误的传播。访问已解除映射的地址会触发页错误（Page Fault）
			unmap_poisoned_folio(folio, folio_pfn(folio), false);
			folio_unlock(folio);
			folio_put(folio);
			continue;
		}

		VM_BUG_ON_FOLIO(folio_test_active(folio), folio); // 确保非活跃状态

		nr_pages = folio_nr_pages(folio);

		/* Account the number of base pages */
		sc->nr_scanned += nr_pages;

		// evictable:可驱逐，如果页面不可回收（例如，被 mlock 锁定），则跳转到 activate_locked 标签处的代码
		if (unlikely(!folio_evictable(folio)))
			goto activate_locked;

		// sc->may_unmap : 如果为 true，允许回收器解除页面的映射（这是正常回收的必要步骤）
		// 检查该 folio 是否仍然被进程映射，即是否还有页表项（Page Table Entry, PTE）指向这个物理页面
		// keep_locked 会做什么？ 它会保留页面的锁，并将其直接放回它原来所在的非活跃 LRU 链表的尾部。
		// 这意味着回收器放弃了本次回收尝试，但页面依然在回收队列中，可能会在下次扫描时再次被尝试
		if (!sc->may_unmap && folio_mapped(folio))
			goto keep_locked;

		// 用于获取页面的两个关键状态：是否是脏页（Dirty）和是否正在回写（Under Writeback）
		folio_check_dirty_writeback(folio, &dirty, &writeback); // 检查脏页/回写状态

		// 统计脏页信息（nr_dirty, nr_unqueued_dirty, nr_congested）。
		if (dirty || writeback)
			stat->nr_dirty += nr_pages;

		if (dirty && !writeback)
			stat->nr_unqueued_dirty += nr_pages;

		// 这行代码的目的不是改变程序行为，而是为了监控和诊断:当前这个页面是否既正在被回写到磁盘，又曾经被标记为回收候选者
		// 如果这个页面同时满足上述两个条件，那么就将这个页面的大小（以页数为单位）加到‘拥堵页面’的总数上去。
		if (writeback && folio_test_reclaim(folio))
			stat->nr_congested += nr_pages; // congested：拥挤，记录 因 I/O 阻塞而无法回收的页面数量

		// 条件入口：检查当前folio是否正处于回写（Writeback） 状态。如果是，则进入这个复杂的处理分支。
		if (folio_test_writeback(folio)) {
			// 获取地址空间：获取该folio所属的地址空间（address_space），即它属于哪个文件。这对于后续判断是否需要防止死锁至关重要。
			mapping = folio_mapping(folio);

			/*
				设计意图：这是一种乐观策略。kswapd 发现系统已经有很多回写I/O（节点标志 PGDAT_WRITEBACK），并且这个folio自己
				也正在回写且之前就被标记过（说明可能等了很久了）。为了避免 kswapd 被阻塞并能够继续扫描其他folio，它选择立即
				放弃这个folio，相信在未来的某个周期，回写会完成，届时再回收它。这保证了 kswapd 的流畅性。
			*/
			if (current_is_kswapd() &&						// 当前执行上下文是 kswapd 内核线程（后台回收）
			    folio_test_reclaim(folio) &&				// 该folio已经被标记为 回收候选（PG_reclaim）
			    test_bit(PGDAT_WRITEBACK, &pgdat->flags)) { // folio所在的NUMA节点已经被标记为有回写活动（PGDAT_WRITEBACK）
				stat->nr_immediate += nr_pages;				// 将folio的页数计入“立即处理”的统计项
				goto activate_locked;						// 跳转到 activate_locked 标签，将folio置为活跃并放回活跃LRU链表

			/*
				设计意图：这是一个安全与效率兼顾的策略。当遇到可能死锁、不允许等待或首次冲突的情况时，回收器选择“撤退”。它标记该folio（PG_reclaim）
				并激活它，目的是在下一个回收周期中，这个folio很可能已经完成了回写，可以安全回收。这避免了潜在的死锁和性能延迟。
			*/
			} else if (writeback_throttling_sane(sc) ||		// 回写节制机制是“正常”的。这通常指在cgroup v1环境下，其回写节制逻辑可能产生问题，所以需要特殊处理。
			    !folio_test_reclaim(folio) ||				// 该folio尚未被标记为回收候选。这意味着它是第一次遇到回写冲突。
			    !may_enter_fs(folio, sc->gfp_mask) ||		// 当前回收上下文不允许执行文件系统操作（例如，在原子上下文中）。等待回写可能需要进入FS层，这是被禁止的。
			    (mapping &&
				// 最关键的条件。内核判断，如果等待这个folio的回写完成，可能会导致死锁。这通常发生在需要为回写分配内存（如申请request结构），
				// 而回收器又正在等待该回写完成才能释放内存的循环依赖场景。
			     mapping_writeback_may_deadlock_on_reclaim(mapping))) {
				folio_set_reclaim(folio);					// 确保设置 PG_reclaim 标志，标记该folio为回收候选
				stat->nr_writeback += nr_pages;				// 将folio的页数计入“回写”统计项
				goto activate_locked;						// 跳转到 activate_locked 标签，将folio置为活跃并放回活跃LRU链表。

			/*
				设计意图：这是一种积极阻塞的策略。当回收器判断没有死锁风险（不满足分支二的条件）且自己不是kswapd（或节点压力不大，不满足分支一的条件）时，
				它选择“坚持到底”。它愿意花费一点时间等待I/O完成，以便在当前回收周期内就完成对这个folio的回收，从而更高效地释放内存。
			*/
			} else {
				folio_unlock(folio);						// 解锁folio。这是关键一步，允许其他线程（比如处理回写完成的I/O中断）访问该folio
				folio_wait_writeback(folio);				// 同步等待，直到该folio的回写操作完成
				/* then go back and try same folio again */
				list_add_tail(&folio->lru, folio_list);		// 等待完成后，将folio重新加回当前回收列表的末尾
				continue;	// 跳过本轮循环后续代码，立即开始下一轮循环。这样，在下一轮循环中，这个刚刚完成回写的folio将被再次处理，此时它应该已经变成一个干净的folio，可以被顺利回收
			}
		}

		if (!ignore_references)
			references = folio_check_references(folio, sc);  // 检查引用次数

		// 引用检查是决定回收/激活的关键（通过反向映射计算）。
		switch (references) {
		case FOLIOREF_ACTIVATE:  // 激活
			goto activate_locked;
		case FOLIOREF_KEEP:      // 保留
			stat->nr_ref_keep += nr_pages;
			goto keep_locked;
		case FOLIOREF_RECLAIM:   // 尝试回收
		case FOLIOREF_RECLAIM_CLEAN:
			; /* try to reclaim the folio below */
		}

		// 将冷页迁移到低速内存层级（如 DRAM → CXL）。
		if (do_demote_pass &&	// 系统是否支持降级功能
			// thp_migration_supported(): 检查系统内核是否支持透明大页（Transparent Huge Page, THP）的迁移
			// !folio_test_large(folio): 如果当前处理的 folio 不是一个大页（即它是一个标准的 4KB 或类似大小的基础页面），那么这个条件也为真。
		    (thp_migration_supported() || !folio_test_large(folio))) {
			list_add(&folio->lru, &demote_folios); // 加入降级链表
			folio_unlock(folio);
			continue;
		}

		// 匿名页交换空间分配：为匿名页分配 Swap 条目，处理大页分裂等特殊情况。
		// 是匿名页
		// 有交换支持
		if (folio_test_anon(folio) && folio_test_swapbacked(folio)) {
			if (!folio_test_swapcache(folio)) {
				// __GFP_IO 标志表示允许进行I/O操作，如果不允许I/O（!(__GFP_IO)）意味着不能交换，则跳转到 keep_locked
				if (!(sc->gfp_mask & __GFP_IO))
					goto keep_locked;
				// 检查这个folio是否可能被DMA操作固定在内存中。DMA操作是设备直接访问内存，如果页面被固定，则不能被移走（包括交换），
				// 否则会导致DMA访问失败。如果可能被固定，则跳转到 keep_locked，保留页面
				if (folio_maybe_dma_pinned(folio))
					goto keep_locked;
				// 如果folio是大页（例如2MB的透明大页THP），需要特殊处理，因为交换子系统通常只处理4KB大小的页面。
				if (folio_test_large(folio)) {
					// 检查这个大页是否可以被拆分。如果不能拆分（例如，有无法处理的映射），则跳转到 activate_locked，激活并保留它。
					if (!can_split_folio(folio, 1, NULL))
						goto activate_locked;

					// 这是一个针对一种特殊竞争条件的检查。如果folio的延迟列表不为空且页面被部分映射，则尝试立即拆分它。如果拆分失败，也跳转到 activate_locked。
					if (data_race(!list_empty(&folio->_deferred_list) &&
					    folio_test_partially_mapped(folio)) &&
					    split_folio_to_list(folio, folio_list))
						goto activate_locked;
				}
				// 调用 folio_alloc_swap 为这个folio分配一个交换槽, 如果分配失败（返回值非零），则进入if语句块处理失败情况
				if (folio_alloc_swap(folio, __GFP_HIGH | __GFP_NOWARN)) {
					int __maybe_unused order = folio_order(folio);

					// 处理普通页失败：如果不是大页，直接跳转到 activate_locked_split
					if (!folio_test_large(folio))
						goto activate_locked_split;
					// 大页的回退策略：分配大页的交换槽失败，尝试将大页拆分成普通的4KB小页。如果拆分失败，跳转到 activate_locked
					if (split_folio_to_list(folio, folio_list))
						goto activate_locked;
					// 透明大页：它自动地将许多普通的小页（通常为 4KB）合并成一个巨大的页（通常为 2MB 甚至 1GB），从而提升系统性能，而无需应用程序做任何修改
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
					// folio的大小是PMD级别的（例如2MB），则记录统计事件 THP_SWPOUT_FALLBACK。这表明一次大页交换因为分配失败而回退到了拆分模式
					if (nr_pages >= HPAGE_PMD_NR) {
						count_memcg_folio_events(folio,
							THP_SWPOUT_FALLBACK, 1);
						count_vm_event(THP_SWPOUT_FALLBACK);
					}
#endif
					// 记录更详细的大页统计信息
					count_mthp_stat(order, MTHP_STAT_SWPOUT_FALLBACK);
					// 再次尝试分配：在拆分成功后，再次尝试为拆分后的单个小页分配交换槽。如果这次还失败，跳转到 activate_locked_split。
					if (folio_alloc_swap(folio, __GFP_HIGH | __GFP_NOWARN))
						goto activate_locked_split;
				}

				/*
					标记为脏：如果 folio_alloc_swap 成功（或者回退成功后），调用 folio_mark_dirty 将页面标记为脏。
					为什么？ 虽然这是一个匿名页，内容来自内存而非文件，但一旦它被成功分配了交换槽，它就被视为“交换缓存”中的一员。将其标记为脏，
					是为了确保后续的代码（如 shrink_folio_list 的后面部分）会将其加入到脏页回写队列，最终将其内容写入交换分区。
				*/
				folio_mark_dirty(folio);
			}
		}

		// 如果当前处理的 folio 包含了多个基础页面，但它又不是一个大页（复合页）
		// 对于复合页来说，回收器可以一次性处理多个基础页面，这样效率更高，但是在处理的过程中，仅统计了一次，因此在这里，需要补上缺失的部分
		// 值为nr_pages - 1
		if ((nr_pages > 1) && !folio_test_large(folio)) {
			// 记录了本次回收操作已经扫描了多少个基础页面
			sc->nr_scanned -= (nr_pages - 1);
			nr_pages = 1;
		}

		/*
			条件检查：首先检查该folio是否仍然被映射（folio_mapped(folio)）。这是通过检查folio的_mapcount或_entire_mapcount来实现的。
			如果folio没有被任何进程的页表映射，则跳过整个解除映射块。只有当folio还被映射时，才需要执行后续复杂的解除操作。
		*/
		if (folio_mapped(folio)) {
			/*
				初始化参数：
				flags: 声明并初始化一个名为 flags 的枚举变量，用于控制 try_to_unmap 函数的行为。初始设置为 TTU_BATCH_FLUSH。这个标志告诉 try_to_unmap
				使用批处理模式（效率更高），并在处理完成后刷新TLB（Translation Lookaside Buffer，页表缓存）。
				was_swapbacked: 保存当前folio的swapbacked状态。这个状态表示folio在分配时是否被标记为“将来可能需要交换”。这个值会在后面用于诊断。
			*/
			enum ttu_flags flags = TTU_BATCH_FLUSH;
			bool was_swapbacked = folio_test_swapbacked(folio);

			/*
				大页处理准备 1：检查folio是否可以被PMD（Page Middle Directory，中间页目录）级别的大页映射（例如，2MB的透明大页THP）。如果是，
				则在 flags 中增加 TTU_SPLIT_HUGE_PMD 标志。这个标志指示 try_to_unmap 在解除映射前，先尝试拆分这个大页映射。因为处理一个巨大的
				PMD映射可能比处理多个PTE（Page Table Entry，页表项）映射更复杂，有时拆分后逐个处理更简单可靠。
			*/
			if (folio_test_pmd_mappable(folio))
				flags |= TTU_SPLIT_HUGE_PMD;

			/*
				大页处理准备 2：检查folio是否是一个大页。如果是，则增加 TTU_SYNC 标志。这个标志要求 try_to_unmap 进行同步的（阻塞的）操作。
				对于大页，同步操作可以避免复杂的竞态条件，确保操作的原子性和正确性。
			*/
			if (folio_test_large(folio))
				flags |= TTU_SYNC;

			/*
				核心调用：调用 try_to_unmap 函数，传入folio和前面设置好的标志位。这个函数是内存管理中最复杂的函数之一。它的作用是：
				遍历所有映射了该folio的进程的页表。
				根据标志位，可能先拆分大页映射。
				将找到的每个页表项（PTE）都替换为一个特殊的迁移条目或交换条目，或者直接置为空。
				在这个过程中，它会刷新TLB和CPU缓存以确保一致性。
				简单来说，它让所有曾经能访问这块物理内存的进程，下次访问时都会触发一个页错误（Page Fault）。
			*/
			try_to_unmap(folio, flags); // 解除物理内存映射
			/*
				结果验证：再次检查folio是否还被映射。如果 try_to_unmap 函数成功解除了所有映射，那么 folio_mapped(folio) 应该返回false。
				如果仍然为true，说明解除映射失败了。
			*/
			if (folio_mapped(folio)) {
				// 统计失败：如果解除映射失败，将失败的页面数（nr_pages）加到 stat->nr_unmap_fail 计数器中。这个统计信息对于监控和调试内存回收问题非常重要。
				stat->nr_unmap_fail += nr_pages;
				/*
					诊断特定失败：这是一个更细致的诊断。它检查folio的 swapbacked 状态是否在本次操作中发生了变化。具体来说，如果folio之前没有交换支持
					（!was_swapbacked），但现在有了（folio_test_swapbacked(folio)），这通常意味着有一个叫做 lazyfree 的机制尝试在解除映射的过程中
					“偷懒”地给folio添加交换支持，但这个操作最终也失败了。这种特殊的失败会被记录到 nr_lazyfree_fail 中。
				*/
				if (!was_swapbacked &&
				    folio_test_swapbacked(folio))
					stat->nr_lazyfree_fail += nr_pages;
				/*
					失败处理：如果解除映射失败，使用 goto 语句跳转到 activate_locked 标签。activate_locked 处的代码会：
					将folio的 PG_active 标志置位。
					将folio放回活跃LRU链表。
					解锁folio。
					这意味着回收器放弃了回收这个folio的尝试。 因为它仍然被映射，强行回收会导致使用它的进程发生错误。
					将其激活可以防止回收器在短时间内再次尝试扫描它，从而避免无谓的消耗。
				*/
				goto activate_locked; // 失败则激活
			}
		}

		if (folio_maybe_dma_pinned(folio))
			goto activate_locked;

		// 获取地址空间：获取该folio所属的address_space，即它属于哪个文件。这是后续执行回写操作所必需的
		mapping = folio_mapping(folio);
		
		if (folio_test_dirty(folio)) {					// 脏页检查：确认folio是脏的（内容已被修改，与磁盘不一致）
			if (folio_is_file_lru(folio) &&				// 对于文件脏页
			    (!current_is_kswapd() ||				// 当前执行者不是后台回收线程kswapd（即是在直接回收路径中）
			     !folio_test_reclaim(folio) ||			// 该folio没有被标记为回收候选（PG_reclaim）
			     !test_bit(PGDAT_DIRTY, &pgdat->flags))) {		// Folio所在的NUMA节点没有处于全局脏页压力状态（PGDAT_DIRTY）
				// 如果满足，则记录统计信息NR_VMSCAN_IMMEDIATE，标记folio为PG_reclaim，然后跳转到activate_locked将其激活并放回活跃链表。
				// 这意味着内核认为在当前上下文中回写这个页面的代价太高或是不必要的，不如直接放弃。
				node_stat_mod_folio(folio, NR_VMSCAN_IMMEDIATE,
						nr_pages);
				folio_set_reclaim(folio);

				goto activate_locked;
			}

			// 检查1 - 只回收干净页：如果之前的引用检查（folio_check_references）返回FOLIOREF_RECLAIM_CLEAN，这意味着只允许回收干净的页面。
			// 对于脏页，只能选择保留。跳转到keep_locked。
			if (references == FOLIOREF_RECLAIM_CLEAN)
				goto keep_locked;
			// 检查2 - 文件系统许可：may_enter_fs检查当前回收上下文（sc->gfp_mask）是否被允许进入文件系统层。回写操作必然需要调用文件系统代码，
			// 如果不允许（例如在原子上下文中），则无法进行回写。跳转到keep_locked。
			if (!may_enter_fs(folio, sc->gfp_mask))
				goto keep_locked;
			// 检查3 - 回写许可：检查扫描控制结构sc中的may_writepage标志。这是一个总开关，如果明确禁止回写，则跳转到keep_locked。
			if (!sc->may_writepage)
				goto keep_locked;

			// 刷新TLB：这是一个重要的同步点。它在尝试回写之前，确保所有针对该folio的解除映射操作（unmap） 已经在所有CPU上完成并被看到。这保证了数据的正确性。
			try_to_unmap_flush_dirty();
			// 核心回写函数：调用pageout函数，尝试将folio的内容写回其对应的后端存储（文件或交换区）。这个函数是实际发起I/O操作的地方。它的返回值决定了后续的处理路径。
			switch (pageout(folio, mapping, &plug, folio_list)) {
			case PAGE_KEEP:    		// 回写层（如文件系统）认为这个页面应该被保留（例如，它可能已经被其他方式处理了）。跳转到keep_locked。
				goto keep_locked;
			case PAGE_ACTIVATE:		// 激活：回写失败或发生其他错误（例如，I/O错误）。内核决定不回收这个页面，而是将其激活。
									// 注意这里也有之前提到的公平性修正代码，在激活前修正扫描计数。
				if (nr_pages > 1 && !folio_test_large(folio)) {
					sc->nr_scanned -= (nr_pages - 1);
					nr_pages = 1;
				}
				goto activate_locked;
			case PAGE_SUCCESS: 		// 成功：回写I/O被成功发起。但这并不代表回写已经完成！代码会进行一系列非常严谨的检查，以确保页面状态稳定：
				if (nr_pages > 1 && !folio_test_large(folio)) {
					sc->nr_scanned -= (nr_pages - 1);
					nr_pages = 1;
				}
				stat->nr_pageout += nr_pages;

				// 只有所有这些检查都通过，页面才是真正干净且稳定的，可以继续向下执行到PAGE_CLEAN case尝试回收。否则，会通过各种goto保持页面状态。
				if (folio_test_writeback(folio)) // 检查是否还在回写中
					goto keep;                   // 是，则保持原状，等待I/O完成
				if (folio_test_dirty(folio))     // 检查是否又变脏了
					goto keep;                   // 是，需要再次回写，保持原状

				if (!folio_trylock(folio))       // 尝试重新获取锁（因为I/O完成会解锁？）
					goto keep;                   // 获取失败，保持原状
				if (folio_test_dirty(folio) ||   // 再次检查脏和回写状态（状态可能又变了）
				    folio_test_writeback(folio))
					goto keep_locked;            // 状态有变，保持并锁定
				mapping = folio_mapping(folio);
				fallthrough;
			case PAGE_CLEAN:					 // 干净：页面已经是干净的（可能pageout发现它不需要回写就变干净了）。程序会继续向下执行，
												 // 后续代码会尝试回收这个干净的页面。
				; /* try to free the folio below */
			}
		}

		/**这里要释放的元数据，指的是进程无关的文件系统元数据，因为脏数据会写，可能会导致磁盘的目录/结构发生变化，因此需要回写这部分数据
		 * 需要注意的是，由于数据更为重要且更容易发生变化，因此需要先确保数据的回写完成，不然完成了元数据的会写，但是脏数据因为某些原因回写失败
		 * 那么元数据又需要恢复，逻辑会更为混乱
		 */

		// 在回收一个页面之前，尝试释放其关联的底层缓冲区缓存，如果成功并且页面再无其他引用，则直接将其释放。
		// 一个folio即将被回收，但它可能仍然与块设备上的缓冲区（buffer_head） 相关联。这些缓冲区是文件系统
		// 用于缓存磁盘块元数据的结构。为了安全地回收folio，内核需要先尝试解除这种关联。
		if (folio_needs_release(folio)) {						// 检查这个folio是否需要执行release操作。
																// 这通常意味着folio包含缓冲区头（buffer heads），
																// 即folio_test_private(folio)为真。缓冲区头是旧版
																// 内核用于将页面缓存与磁盘块映射起来的数据结构，在现代
																// 文件系统中仍然用于元数据（如inode、位图）的缓存。
			/*
				核心操作 - 释放缓冲区：调用filemap_release_folio函数。
				参数：folio和分配掩码sc->gfp_mask。
				作用：这个函数会调用folio所属地址空间（address_space）的release_folio方法（通常由具体的文件系统，如ext4, XFS实现）。
				文件系统会尝试解除所有关联的缓冲区头（buffer_head）。这可能涉及等待正在进行的I/O完成或丢弃干净的缓冲区。
				返回值：如果释放成功，返回true；如果由于某些原因无法释放（例如，有缓冲区正在被使用或被锁定），返回false。
				失败处理：如果释放失败（!filemap_release_folio），则跳转到activate_locked。这意味着回收无法继续，folio将被重新激活并放回活跃LRU链表。
			*/
			if (!filemap_release_folio(folio, sc->gfp_mask))
				goto activate_locked;
			/*
				黄金回收机会检查：这是一个优化路径。它检查两个条件同时满足：
				!mapping：folio没有所属的地址空间（address_space）。这意味着它已经不再属于任何文件的页缓存。
				folio_ref_count(folio) == 1：folio的引用计数为1。这个唯一的引用很可能就是当前回收线程所持有的。
				这两个条件同时成立，意味着：这个folio曾经是页缓存的一部分，但现在已经被完全剥离（无mapping），并且
				除了回收器之外，没有任何其他地方在使用它（引用为1）。这是一个绝佳的、可以立即释放的候选者。
			*/
			if (!mapping && folio_ref_count(folio) == 1) {
				folio_unlock(folio);				// 解锁：因为folio的引用计数是1，解锁是安全的。解锁后，其他线程就无法再获取到它了。
				/*
					尝试释放：folio_put_testzero(folio)做两件事：
					将folio的引用计数减1。
					检查减1后引用计数是否变为0。
					由于我们检查了引用计数原来是1，所以减1后必定为0。因此，folio_put_testzero(folio)总是返回true。
					操作：如果返回true（确实为0），则跳转到free_it标签。free_it处的代码会直接将folio的物理内存释放回伙伴分配器（Buddy Allocator）。
				*/
				if (folio_put_testzero(folio))
					goto free_it;
				/*
					不可能的分支：这个else分支在逻辑上永远不会被执行。因为我们在前面已经确定了folio_ref_count(folio) == 1，所以folio_put_testzero(folio)必定返回true。
					代码意义：这里可能是一种防御性编程，或者是为了代码的对称性和未来可能的扩展。理论上，如果引用减1后不为0，它会统计回收的页面数并继续循环处理下一个folio。
				*/
				else {
					nr_reclaimed += nr_pages;
					continue;
				}
			}
		}

		/*
			条件判断：检查当前folio是否同时满足两个条件：
			folio_test_anon(folio)：它是一个匿名页（如进程的堆、栈内存）。
			!folio_test_swapbacked(folio)：它没有交换支持（swapbacked）。
			这是什么页面？ 通常，一个匿名页在分配时就会被标记为 swapbacked，表明它将来需要被交换。如果一个匿名页没有这个标志，
			它很可能是在启用 CONFIG_Lazyfree 机制下，通过 madvise(MADV_FREE) 等操作标记为“延迟释放（Lazyfree）”的页面。这种
			页面的特点是：内核可以在内存压力下直接丢弃它们，而无需交换到磁盘。如果进程之后又访问它，内核会自动用零填充一个新的页面。
		*/
		if (folio_test_anon(folio) && !folio_test_swapbacked(folio)) {
			/*
				引用计数冻结（Refcount Freezing）：这是极其重要的一步，是一种并发安全技术。
				folio_ref_freeze(folio, 1) 在一个原子操作中完成两件事：
				检查：当前folio的引用计数（_refcount）是否正好等于1。
				冻结：如果等于1，则将其“冻结”，防止后续的任何 get_page()/folio_get() 操作成功（它们会失败），同时保持引用计数为1。
				为什么？ 回收器持有最后一个引用。这个操作确保了在当前瞬间，没有任何其他线程能够再获得对这个folio的引用。这就安全地
				“锁定”了folio的状态，避免了在后续操作中发生竞态条件（例如，另一个线程突然又映射了这个folio）。
				失败处理：如果冻结失败（引用计数不等于1），说明有另一个线程在我们不知情的情况下获取了该folio的引用。此时不能继续回收，必须跳转到 keep_locked 保留页面。
			*/
			if (!folio_ref_freeze(folio, 1))
				goto keep_locked;
			// 记录统计信息：如果冻结成功，记录 PGLAZYFREED 事件。这表明一个Lazyfree页面被成功释放。这个统计信息对于监控系统内存行为和调试非常有用。
			count_vm_events(PGLAZYFREED, nr_pages);
			count_memcg_folio_events(folio, PGLAZYFREED, nr_pages);
		/*
			条件判断与函数调用：
				!mapping：首先检查folio是否没有地址空间（mapping）。这可能发生在一些特殊的folio上。
				!__remove_mapping(...)：如果folio有地址空间，则调用 __remove_mapping 这个核心函数来尝试移除它。这个函数也内部实现了引用计数检查和冻结逻辑，
				与上面的 folio_ref_freeze 类似，但更复杂，因为它需要处理页缓存中的folio。
			__remove_mapping 的工作：
				再次检查folio的引用计数是否为预期值（并冻结）。
				将folio从它的页缓存（address_space）的基数树（radix tree）或XArray中移除。
				如果folio是匿名页，还会将其从交换缓存（swap cache）中移除。
			失败处理：如果 __remove_mapping 返回 false（失败），或者folio根本没有 mapping，则跳转到 keep_locked。失败的原因通常也是在最后时刻引用计数发生了变化。
		*/
		} else if (!mapping || !__remove_mapping(mapping, folio, true,
							 sc->target_mem_cgroup))
			goto keep_locked;

		// 解锁：只有在前面的所有步骤都成功之后，才会执行到这行代码。
		// 意义：此时，folio已经成功地从所有管理数据结构中移除（页缓存、交换缓存），并且其引用计数被“冻结”为1（且无人能再获取引用）。
		// 解锁是这个folio生命周期的转折点。解锁之后，这个folio就不再被任何锁保护，但因为引用计数为1且被冻结，唯一的引用持有者就是
		// 本回收线程，因此它现在是一个“僵尸”页面，等待最后的释放。
		folio_unlock(folio);

// 这段代码是 Linux 内核内存回收的最终步骤，也是整个漫长回收过程的收获时刻。
// 它的核心功能是：将已经成功解除所有关联的folio，安全、高效地批量释放回系统的空闲内存池（伙伴系统）。
free_it:
		/*
			这是回收器的“功劳簿”。它将本次成功释放的页面数（nr_pages，对于复合页可能大于1）累加到总回收计数（nr_reclaimed）中。
			这个计数器至关重要，它决定了本次回收循环是否已经完成了目标（例如 sc->nr_to_reclaim），从而决定是否应该停止回收。
		*/
		nr_reclaimed += nr_pages;      // 更新回收计数

		/*
			移除延迟拆分队列：如果这个folio之前因为某些原因（例如，是透明大页THP）被放入了延迟拆分队列，那么现在既然它
			马上就要被释放了，拆分自然就没有必要了。这个函数将其从该队列中移除，避免内核在未来执行不必要的拆分操作。
		*/
		folio_unqueue_deferred_split(folio);
		/*
			批量添加：这是性能优化的关键。folio_batch_add 函数尝试将当前folio添加到一个名为 free_folios 的本地批次数组中
			（这个数组通常在函数开头声明为 struct folio_batch free_folios）。
			== 0 的条件：folio_batch_add 函数在批次已满时会返回 0。一个 folio_batch 通常可以容纳15或16个folio（例如 PAGE_FOLIO_BATCH）。
			如果返回 0，表示批次已满，需要立即处理这个批次的释放。如果返回非零，则只是成功添加，循环继续，等待批次被填满。
		*/
		if (folio_batch_add(&free_folios, folio) == 0) {
			/*
				内存控制组卸载：在释放物理内存之前，必须先更新内存控制组（memcg） 的统计信息。这个函数遍历批次中的所有folio，
				从它们所属的memcg中减去这些页面所占用的内存计数。这是内存资源隔离和计费的关键步骤。
			*/
			mem_cgroup_uncharge_folios(&free_folios);
			/*
				刷新TLB：这是一个非常重要的内存屏障操作。它确保在释放这些页面之前，所有CPU上可能残留的、与这些页面相关的旧页表项
				（TLB条目） 都被彻底清空（flush）。这是因为：
				之前的 try_to_unmap 是批量进行的，可能有些TLB刷新是延迟的。
				确保在物理页面被重新分配给他用之前，绝不会有任何一个CPU因为旧的TLB缓存而访问到错误的数据。这是防止数据损坏和系统不稳定性的关键安全措施。
			*/
			try_to_unmap_flush();
			/*
				核心释放函数：这是最终执行释放操作的函数。它接收整个要释放的folio批次。
				unref 的含义：这里的“unref”指的是这些folio的引用计数都已经降为0（“unreferenced”）。该函数会：
				遍历批次中的每个folio。
				根据folio的顺序（order），调用伙伴系统的释放接口（如 __free_pages），将物理内存归还到对应的空闲链表中。
				更新zone的统计信息。
				至此，这些物理页面正式成为空闲内存，可以被分配给任何需要它的进程或内核组件。
			*/
			free_unref_folios(&free_folios);
		}
		continue;

activate_locked_split:
		/*
			这个条件检查和处理逻辑与我们之前讨论的完全一样。它判断当前处理的folio是否是一个复合页（Compound Page），
			但不是透明大页（THP）（即 !folio_test_large(folio) 为真）。
		*/
		if (nr_pages > 1) {
			sc->nr_scanned -= (nr_pages - 1);
			nr_pages = 1;
		}
/*
	设计意图：既然决定不回收这个folio了（要激活它），而交换空间又很紧张（或者folio被锁定根本不能交换），
	那么占着这个交换槽就是一种浪费。释放它可以让其他更需要交换的页面使用。这是一种资源的回收和再利用。
*/
activate_locked:
		/* Not a candidate for swapping, so reclaim swap space. */
		if (folio_test_swapcache(folio) &&			// folio_test_swapcache(folio)：该folio在交换缓存（swap cache） 中。
													// 这意味着它是一个匿名页，并且已经被分配了交换空间（一个swap entry）。
		    (mem_cgroup_swap_full(folio) || folio_test_mlocked(folio)))		// 其所属的内存控制组（memcg）的交换空间已满，或者该folio被 mlock() 锁定了。
			folio_free_swap(folio);					// 如果上述条件满足，则调用此函数释放为该folio分配的交换槽（swap slot）
		VM_BUG_ON_FOLIO(folio_test_active(folio), folio);
		if (!folio_test_mlocked(folio)) {			// 检查folio没有被 mlock() 系统调用锁定。被锁定的页面不能换出，也不需要改变其活跃状态。
			int type = folio_is_file_lru(folio);	// 判断folio类型（0代表匿名页，1代表文件页）
			folio_set_active(folio);				// 设置folio的 PG_active 标志。这是最关键的一步，标志着folio状态的改变
			stat->nr_activate[type] += nr_pages;	// 更新统计信息，记录本次激活了多少页（区分类型）
			count_memcg_folio_events(folio, PGACTIVATE, nr_pages);	// 记录内存控制组级别的事件计数。
		}
keep_locked:
		folio_unlock(folio);
keep:
		list_add(&folio->lru, &ret_folios);				// 将folio添加到 ret_folios 链表中。这个链表专门用于收集所有在本轮回收中未被成功回收或释放的folio。
		VM_BUG_ON_FOLIO(folio_test_lru(folio) ||
				folio_test_unevictable(folio), folio);
	}
	/* 'folio_list' is always empty here */

	/* Migrate folios selected for demotion */
	nr_demoted = demote_folio_list(&demote_folios, pgdat); // 这是执行内存降级（Demotion） 的核心函数。它接收之前收集的、准备迁移到慢速内存的folio列表
															// （demote_folios），并尝试实际迁移它们
	// 将成功降级的页面数也算作本次回收的成功成果。因为虽然物理内存没有被释放，但宝贵的高速内存空间已经被腾出来了
	nr_reclaimed += nr_demoted;								// 返回成功降级的folio数量
	stat->nr_demoted += nr_demoted;							// 更新统计信息，记录降级的页面数。
	// 降级失败且非主动回收时，重试回收而非降级。
	if (!list_empty(&demote_folios)) {						// 如果降级操作完成后，demote_folios 列表不为空，说明有些folio降级失败了
		list_splice_init(&demote_folios, folio_list);		// 将这些降级失败的folio重新移回最初的回收列表（folio_list）中

		if (!sc->proactive) {								// 如果当前回收是直接回收（!sc->proactive），则采取更激进的策略
			do_demote_pass = false;							// 禁用降级功能。既然降级失败了，就不再尝试。
			goto retry;            							// 跳转回函数开头的 retry: 标签。这意味着这些降级失败的folio将在禁用降级的情况下，
															// 重新经历一遍回收流程，这次内核会尝试用传统的回收方法（如交换或丢弃）来处理它们。
		}
	}

	// 计算总激活数：将匿名页（index 0）和文件页（index 1）的激活数量相加，得到总共激活的页面数（pgactivate），用于后续的事件计数
	pgactivate = stat->nr_activate[0] + stat->nr_activate[1];

	// 释放批处理：这是回收的最终步骤，处理的是那些已经成功解除所有关联、可以释放的folio（free_folios 列表）。
	mem_cgroup_uncharge_folios(&free_folios); // 从内存控制组（memcg）中解除这些页面的计数（“充能”的逆操作）。
	try_to_unmap_flush();					  // 执行最后的TLB刷新，确保所有CPU都不会再访问这些即将被释放的页面。
	free_unref_folios(&free_folios);          // 最终调用伙伴系统（Buddy System），将这些folio的物理内存释放回空闲页列表。这是真正释放内存的地方。

	// 处理保留页：将之前收集的、所有未成功回收的folio（ret_folios）重新拼接回原始的回收列表（folio_list）中。调用这个函数的上级逻辑会
	// 负责将这些folio重新放回它们合适的LRU链表。
	list_splice(&ret_folios, folio_list);     // 剩余页放回 LRU
	// 记录激活事件：向全局虚拟机统计中记录 PGACTIVATE 事件，表示本次回收过程中激活了多少页面
	count_vm_events(PGACTIVATE, pgactivate);

	// 清理交换插件：如果在回收过程中使用了交换写的聚合插件（plugging）来优化I/O，这里要卸载（unplug）它，以确保所有缓存的写操作都被刷新到磁盘。
	if (plug)
		swap_write_unplug(plug);
	/*
		返回结果：函数最终返回 nr_reclaimed。这个数值包含了：
		成功释放的页数（free_folios）。
		成功降级的页数（nr_demoted）。
		（可能还有其他的，如惰性释放等）。
		这个返回值告诉调用者：“我这次一共帮你腾出了这么多页的内存”。
	*/
	return nr_reclaimed;                      // 返回回收页数
}

unsigned int reclaim_clean_pages_from_list(struct zone *zone,
					   struct list_head *folio_list)
{
	struct scan_control sc = {
		.gfp_mask = GFP_KERNEL,
		.may_unmap = 1,
	};
	struct reclaim_stat stat;
	unsigned int nr_reclaimed;
	struct folio *folio, *next;
	LIST_HEAD(clean_folios);
	unsigned int noreclaim_flag;

	list_for_each_entry_safe(folio, next, folio_list, lru) {
		if (!folio_test_hugetlb(folio) && folio_is_file_lru(folio) &&
		    !folio_test_dirty(folio) && !__folio_test_movable(folio) &&
		    !folio_test_unevictable(folio)) {
			folio_clear_active(folio);
			list_move(&folio->lru, &clean_folios);
		}
	}

	/*
	 * We should be safe here since we are only dealing with file pages and
	 * we are not kswapd and therefore cannot write dirty file pages. But
	 * call memalloc_noreclaim_save() anyway, just in case these conditions
	 * change in the future.
	 */
	noreclaim_flag = memalloc_noreclaim_save();
	nr_reclaimed = shrink_folio_list(&clean_folios, zone->zone_pgdat, &sc,
					&stat, true, NULL);
	memalloc_noreclaim_restore(noreclaim_flag);

	list_splice(&clean_folios, folio_list);
	mod_node_page_state(zone->zone_pgdat, NR_ISOLATED_FILE,
			    -(long)nr_reclaimed);
	/*
	 * Since lazyfree pages are isolated from file LRU from the beginning,
	 * they will rotate back to anonymous LRU in the end if it failed to
	 * discard so isolated count will be mismatched.
	 * Compensate the isolated count for both LRU lists.
	 */
	mod_node_page_state(zone->zone_pgdat, NR_ISOLATED_ANON,
			    stat.nr_lazyfree_fail);
	mod_node_page_state(zone->zone_pgdat, NR_ISOLATED_FILE,
			    -(long)stat.nr_lazyfree_fail);
	return nr_reclaimed;
}

/*
 * Update LRU sizes after isolating pages. The LRU size updates must
 * be complete before mem_cgroup_update_lru_size due to a sanity check.
 */
static __always_inline void update_lru_sizes(struct lruvec *lruvec,
			enum lru_list lru, unsigned long *nr_zone_taken)
{
	int zid;

	for (zid = 0; zid < MAX_NR_ZONES; zid++) {
		if (!nr_zone_taken[zid])
			continue;

		update_lru_size(lruvec, lru, zid, -nr_zone_taken[zid]);
	}

}

/*
 * Isolating page from the lruvec to fill in @dst list by nr_to_scan times.
 *
 * lruvec->lru_lock is heavily contended.  Some of the functions that
 * shrink the lists perform better by taking out a batch of pages
 * and working on them outside the LRU lock.
 *
 * For pagecache intensive workloads, this function is the hottest
 * spot in the kernel (apart from copy_*_user functions).
 *
 * Lru_lock must be held before calling this function.
 *
 * @nr_to_scan:	The number of eligible pages to look through on the list.
 * @lruvec:	The LRU vector to pull pages from.
 * @dst:	The temp list to put pages on to.
 * @nr_scanned:	The number of pages that were scanned.
 * @sc:		The scan_control struct for this reclaim session
 * @lru:	LRU list id for isolating
 *
 * returns how many pages were moved onto *@dst.
 */
static unsigned long isolate_lru_folios(unsigned long nr_to_scan,
		struct lruvec *lruvec, struct list_head *dst,
		unsigned long *nr_scanned, struct scan_control *sc,
		enum lru_list lru)
{
	struct list_head *src = &lruvec->lists[lru];
	unsigned long nr_taken = 0;
	unsigned long nr_zone_taken[MAX_NR_ZONES] = { 0 };
	unsigned long nr_skipped[MAX_NR_ZONES] = { 0, };
	unsigned long skipped = 0, total_scan = 0, scan = 0;
	unsigned long nr_pages;
	unsigned long max_nr_skipped = 0;
	LIST_HEAD(folios_skipped);

	while (scan < nr_to_scan && !list_empty(src)) {
		struct list_head *move_to = src;
		struct folio *folio;

		folio = lru_to_folio(src);
		prefetchw_prev_lru_folio(folio, src, flags);

		nr_pages = folio_nr_pages(folio);
		total_scan += nr_pages;

		/* Using max_nr_skipped to prevent hard LOCKUP*/
		if (max_nr_skipped < SWAP_CLUSTER_MAX_SKIPPED &&
		    (folio_zonenum(folio) > sc->reclaim_idx)) {
			nr_skipped[folio_zonenum(folio)] += nr_pages;
			move_to = &folios_skipped;
			max_nr_skipped++;
			goto move;
		}

		/*
		 * Do not count skipped folios because that makes the function
		 * return with no isolated folios if the LRU mostly contains
		 * ineligible folios.  This causes the VM to not reclaim any
		 * folios, triggering a premature OOM.
		 * Account all pages in a folio.
		 */
		scan += nr_pages;

		if (!folio_test_lru(folio))
			goto move;
		if (!sc->may_unmap && folio_mapped(folio))
			goto move;

		/*
		 * Be careful not to clear the lru flag until after we're
		 * sure the folio is not being freed elsewhere -- the
		 * folio release code relies on it.
		 */
		if (unlikely(!folio_try_get(folio)))
			goto move;

		if (!folio_test_clear_lru(folio)) {
			/* Another thread is already isolating this folio */
			folio_put(folio);
			goto move;
		}

		nr_taken += nr_pages;
		nr_zone_taken[folio_zonenum(folio)] += nr_pages;
		move_to = dst;
move:
		list_move(&folio->lru, move_to);
	}

	/*
	 * Splice any skipped folios to the start of the LRU list. Note that
	 * this disrupts the LRU order when reclaiming for lower zones but
	 * we cannot splice to the tail. If we did then the SWAP_CLUSTER_MAX
	 * scanning would soon rescan the same folios to skip and waste lots
	 * of cpu cycles.
	 */
	if (!list_empty(&folios_skipped)) {
		int zid;

		list_splice(&folios_skipped, src);
		for (zid = 0; zid < MAX_NR_ZONES; zid++) {
			if (!nr_skipped[zid])
				continue;

			__count_zid_vm_events(PGSCAN_SKIP, zid, nr_skipped[zid]);
			skipped += nr_skipped[zid];
		}
	}
	*nr_scanned = total_scan;
	trace_mm_vmscan_lru_isolate(sc->reclaim_idx, sc->order, nr_to_scan,
				    total_scan, skipped, nr_taken, lru);
	update_lru_sizes(lruvec, lru, nr_zone_taken);
	return nr_taken;
}

/**
 * folio_isolate_lru() - Try to isolate a folio from its LRU list.
 * @folio: Folio to isolate from its LRU list.
 *
 * Isolate a @folio from an LRU list and adjust the vmstat statistic
 * corresponding to whatever LRU list the folio was on.
 *
 * The folio will have its LRU flag cleared.  If it was found on the
 * active list, it will have the Active flag set.  If it was found on the
 * unevictable list, it will have the Unevictable flag set.  These flags
 * may need to be cleared by the caller before letting the page go.
 *
 * Context:
 *
 * (1) Must be called with an elevated refcount on the folio. This is a
 *     fundamental difference from isolate_lru_folios() (which is called
 *     without a stable reference).
 * (2) The lru_lock must not be held.
 * (3) Interrupts must be enabled.
 *
 * Return: true if the folio was removed from an LRU list.
 * false if the folio was not on an LRU list.
 */
bool folio_isolate_lru(struct folio *folio)
{
	bool ret = false;

	VM_BUG_ON_FOLIO(!folio_ref_count(folio), folio);

	if (folio_test_clear_lru(folio)) {
		struct lruvec *lruvec;

		folio_get(folio);
		lruvec = folio_lruvec_lock_irq(folio);
		lruvec_del_folio(lruvec, folio);
		unlock_page_lruvec_irq(lruvec);
		ret = true;
	}

	return ret;
}

/*
 * A direct reclaimer may isolate SWAP_CLUSTER_MAX pages from the LRU list and
 * then get rescheduled. When there are massive number of tasks doing page
 * allocation, such sleeping direct reclaimers may keep piling up on each CPU,
 * the LRU list will go small and be scanned faster than necessary, leading to
 * unnecessary swapping, thrashing and OOM.
 */
static bool too_many_isolated(struct pglist_data *pgdat, int file,
		struct scan_control *sc)
{
	unsigned long inactive, isolated;
	bool too_many;

	if (current_is_kswapd())
		return false;

	if (!writeback_throttling_sane(sc))
		return false;

	if (file) {
		inactive = node_page_state(pgdat, NR_INACTIVE_FILE);
		isolated = node_page_state(pgdat, NR_ISOLATED_FILE);
	} else {
		inactive = node_page_state(pgdat, NR_INACTIVE_ANON);
		isolated = node_page_state(pgdat, NR_ISOLATED_ANON);
	}

	/*
	 * GFP_NOIO/GFP_NOFS callers are allowed to isolate more pages, so they
	 * won't get blocked by normal direct-reclaimers, forming a circular
	 * deadlock.
	 */
	if (gfp_has_io_fs(sc->gfp_mask))
		inactive >>= 3;

	too_many = isolated > inactive;

	/* Wake up tasks throttled due to too_many_isolated. */
	if (!too_many)
		wake_throttle_isolated(pgdat);

	return too_many;
}

/*
 * move_folios_to_lru() moves folios from private @list to appropriate LRU list.
 *
 * Returns the number of pages moved to the given lruvec.
 */
static unsigned int move_folios_to_lru(struct lruvec *lruvec,
		struct list_head *list)
{
	int nr_pages, nr_moved = 0;
	struct folio_batch free_folios;

	folio_batch_init(&free_folios);
	while (!list_empty(list)) {
		struct folio *folio = lru_to_folio(list);

		VM_BUG_ON_FOLIO(folio_test_lru(folio), folio);
		list_del(&folio->lru);
		if (unlikely(!folio_evictable(folio))) {
			spin_unlock_irq(&lruvec->lru_lock);
			folio_putback_lru(folio);
			spin_lock_irq(&lruvec->lru_lock);
			continue;
		}

		/*
		 * The folio_set_lru needs to be kept here for list integrity.
		 * Otherwise:
		 *   #0 move_folios_to_lru             #1 release_pages
		 *   if (!folio_put_testzero())
		 *				      if (folio_put_testzero())
		 *				        !lru //skip lru_lock
		 *     folio_set_lru()
		 *     list_add(&folio->lru,)
		 *                                        list_add(&folio->lru,)
		 */
		folio_set_lru(folio);

		if (unlikely(folio_put_testzero(folio))) {
			__folio_clear_lru_flags(folio);

			folio_unqueue_deferred_split(folio);
			if (folio_batch_add(&free_folios, folio) == 0) {
				spin_unlock_irq(&lruvec->lru_lock);
				mem_cgroup_uncharge_folios(&free_folios);
				free_unref_folios(&free_folios);
				spin_lock_irq(&lruvec->lru_lock);
			}

			continue;
		}

		/*
		 * All pages were isolated from the same lruvec (and isolation
		 * inhibits memcg migration).
		 */
		VM_BUG_ON_FOLIO(!folio_matches_lruvec(folio, lruvec), folio);
		lruvec_add_folio(lruvec, folio);
		nr_pages = folio_nr_pages(folio);
		nr_moved += nr_pages;
		if (folio_test_active(folio))
			workingset_age_nonresident(lruvec, nr_pages);
	}

	if (free_folios.nr) {
		spin_unlock_irq(&lruvec->lru_lock);
		mem_cgroup_uncharge_folios(&free_folios);
		free_unref_folios(&free_folios);
		spin_lock_irq(&lruvec->lru_lock);
	}

	return nr_moved;
}

/*
 * If a kernel thread (such as nfsd for loop-back mounts) services a backing
 * device by writing to the page cache it sets PF_LOCAL_THROTTLE. In this case
 * we should not throttle.  Otherwise it is safe to do so.
 */
static int current_may_throttle(void)
{
	return !(current->flags & PF_LOCAL_THROTTLE);
}

/*
 * shrink_inactive_list() is a helper for shrink_node().  It returns the number
 * of reclaimed pages
 */
// 从非活动 LRU 链表 (INACTIVE_ANON/INACTIVE_FILE) 扫描并回收页面，返回实际回收的页面数。
// nr_to_scan：目标扫描的页面数。
// lruvec：LRU 链表管理单元。
// sc：内存回收控制参数。
// lru：指定操作的非活动链表类型（文件页/匿名页）。
// 返回值：成功回收的页面数。
static unsigned long shrink_inactive_list(unsigned long nr_to_scan,
		struct lruvec *lruvec, struct scan_control *sc,
		enum lru_list lru)
{
	LIST_HEAD(folio_list);           // 临时链表：存放待处理的页面
	unsigned long nr_scanned;        // 实际扫描的页面数
	unsigned int nr_reclaimed = 0;   // 成功回收的页面数（初始为0）
	unsigned long nr_taken;          // 从LRU取出的页面数
	struct reclaim_stat stat;        // 记录回收统计信息
	bool file = is_file_lru(lru);    // 文件页（true）或匿名页（false）
	enum vm_event_item item;         // 事件类型（PGSCAN_KSWAPD等）
	struct pglist_data *pgdat = lruvec_pgdat(lruvec); // 关联的NUMA节点
	bool stalled = false;            // 是否因拥塞而阻塞

	// 拥塞控制（防止过多隔离页面）
	// 作用：确保系统中隔离页面（正在回收）的数量不超过阈值，避免过度占用内存。
	while (unlikely(too_many_isolated(pgdat, file, sc))) {
		if (stalled)
			// 若阻塞过一次 (stalled=true)，直接返回 0。
			return 0;          // 已阻塞过则放弃回收

		stalled = true;
		// 首次阻塞时调用 reclaim_throttle()，让出 CPU 并等待其他回收线程完成。
		reclaim_throttle(pgdat, VMSCAN_THROTTLE_ISOLATED); // 主动阻塞等待

		// 若进程收到终止信号 (如 kill -9)，返回最大回收值（SWAP_CLUSTER_MAX）
		// 以便快速退出。
		if (fatal_signal_pending(current)) // 收到终止信号则强制返回
			return SWAP_CLUSTER_MAX;
	}

	// 提取非活动页面
	lru_add_drain();  // 确保LRU缓存中的页面已加入链表

	spin_lock_irq(&lruvec->lru_lock); // 禁用中断并加锁

	// isolate_lru_folios()：从非活动链表批量取出页面（持有锁时操作）
	// 到临时链表
	nr_taken = isolate_lru_folios(nr_to_scan, lruvec, &folio_list,
				     &nr_scanned, sc, lru);
	
	// 更新节点隔离页面计数（NR_ISOLATED_ANON/FILE）
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
	// 记录页面扫描事件（区分kswapd/直接回收）
	item = PGSCAN_KSWAPD + reclaimer_offset(sc);
	if (!cgroup_reclaim(sc))
		__count_vm_events(item, nr_scanned);  // 全局事件
	count_memcg_events(lruvec_memcg(lruvec), item, nr_scanned); // CGroup事件
	// 记录扫描事件 PGSCAN_*（区分回收器类型）
	__count_vm_events(PGSCAN_ANON + file, nr_scanned); // 匿名/文件页事件

	spin_unlock_irq(&lruvec->lru_lock); // 解锁并恢复中断

	// 回收页面核心逻辑
	if (nr_taken == 0) // 未取出页面则直接退出
		return 0;

	// shrink_folio_list() 是回收页面的核心函数：
	// 1. 对临时链表中的每个页面执行回收（如：写回磁盘、释放内存、加入交换区等）。
	// 2. 返回实际回收的页面数 nr_reclaimed。
	// 3. 填充回收统计 stat（例如：脏页/写回页数量）。
	// 尝试回收页面！核心函数返回实际回收数量
	nr_reclaimed = shrink_folio_list(&folio_list, pgdat, sc, &stat, false,
					 lruvec_memcg(lruvec));

	spin_lock_irq(&lruvec->lru_lock);
	// move_folios_to_lru()：将未被回收的页面放回 LRU 链表（可能因状态变化
	// 进入活动或非活动链表）。
	move_folios_to_lru(lruvec, &folio_list); // 将未回收的页面放回LRU链表

	// 记录降级事件（PGDEMOTE_*：活跃→非活跃）
	__mod_lruvec_state(lruvec, PGDEMOTE_KSWAPD + reclaimer_offset(sc),
					stat.nr_demoted);
	// 解除页面的隔离状态
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
	// 记录页面窃取事件（PGSTEAL_*：成功回收）
	item = PGSTEAL_KSWAPD + reclaimer_offset(sc);
	if (!cgroup_reclaim(sc))
		__count_vm_events(item, nr_reclaimed);
	count_memcg_events(lruvec_memcg(lruvec), item, nr_reclaimed);
	// 记录成功回收的页面数。
	__count_vm_events(PGSTEAL_ANON + file, nr_reclaimed);
	spin_unlock_irq(&lruvec->lru_lock);

	// 反馈机制与延迟控制
	// 记录回收成本，动态调整未来扫描压力
	// stat.nr_pageout：需写回磁盘的页面数（高开销操作）。
	// nr_scanned - nr_reclaimed：扫描但未回收的页面数（无效扫描）。
	// 这些信息用于调整未来扫描的优先级和频率（避免高开销操作）。
	lru_note_cost(lruvec, file, stat.nr_pageout, nr_scanned - nr_reclaimed);

	// 脏页写回优化
	// 唤醒回写线程处理未排队的脏页
	// 当所有取出的页面都是未排队的脏页（nr_unqueued_dirty == nr_taken）
	// ，说明回写线程未及时工作。
	if (stat.nr_unqueued_dirty == nr_taken) {
		// 唤醒回写线程：调用 wakeup_flusher_threads() 强制启动脏页写回。
		wakeup_flusher_threads(WB_REASON_VMSCAN);
		// CGroup v1 回写限流优化
		// 限流优化：针对 CGroup v1 的特殊处理，避免回写线程无法跟上内存分配速度。
		if (!writeback_throttling_sane(sc))
			reclaim_throttle(pgdat, VMSCAN_THROTTLE_WRITEBACK);
	}

	// 更新控制参数与跟踪
	// 将统计信息汇总到 scan_control
	// sc->nr 字段用于全局跟踪回收状态（如回写压力、拥塞情况）。
	// 文件页回收数单独记录（因文件页回收通常更高效）。
	sc->nr.dirty += stat.nr_dirty;
	sc->nr.congested += stat.nr_congested;
	sc->nr.unqueued_dirty += stat.nr_unqueued_dirty;
	sc->nr.writeback += stat.nr_writeback;
	sc->nr.immediate += stat.nr_immediate;
	sc->nr.taken += nr_taken; // 文件页单独计数
	if (file)
		sc->nr.file_taken += nr_taken;

	// 调试跟踪：记录详细回收信息
	trace_mm_vmscan_lru_shrink_inactive(pgdat->node_id,
			nr_scanned, nr_reclaimed, &stat, sc->priority, file);
	return nr_reclaimed; // 返回实际回收的页面数
}

// 目的：从活动 LRU 链表 (ACTIVE_ANON 或 ACTIVE_FILE) 中扫描并尝试
// 将页面降级到非活动链表 (INACTIVE_ANON 或 INACTIVE_FILE)。
// 参数：
// nr_to_scan：目标扫描的页面数。
// lruvec：管理 LRU 链表的逻辑单元（通常按 NUMA 节点或内存组划分）。
// sc：内存回收的控制参数（如优先级、目标内存组）。
// lru：指定操作的活动 LRU 类型（文件页或匿名页）。
static void shrink_active_list(unsigned long nr_to_scan,
			       struct lruvec *lruvec,
			       struct scan_control *sc,
			       enum lru_list lru)
{
	unsigned long nr_taken;          // 从 LRU 链表成功取出的页面数
	unsigned long nr_scanned;         // 实际扫描的页面数
	unsigned long vm_flags;           // 页面的 VM 访问标志（如是否可执行）
	LIST_HEAD(l_hold);               // 临时链表：存储从 LRU 取出的所有页面
	LIST_HEAD(l_active);             // 临时链表：继续保留在活动链表的页面
	LIST_HEAD(l_inactive);           // 临时链表：待降级到非活动链表的页面
	unsigned nr_deactivate, nr_activate; // 实际降级/激活的页面数
	unsigned nr_rotated = 0;         // 因访问被“旋转”回活动链表的页面数
	bool file = is_file_lru(lru);     // 当前操作的文件页 (true) 或匿名页 (false)
	struct pglist_data *pgdat = lruvec_pgdat(lruvec); // 关联的 NUMA 节点

	// LRU 缓存预热
	// 作用：清空当前 CPU 的 LRU 页面缓存（lru_pvecs），确保之后的操作基于最新状态。
	lru_add_drain();

	// 锁定 LRU 并提取页面
	// 锁定：禁用中断并获取 lruvec->lru_lock，防止并发访问。
	spin_lock_irq(&lruvec->lru_lock);
	// 提取页面：从活动链表中分离 nr_to_scan 个页面到临时链表 l_hold，返回实际取出
	// 的页面数 (nr_taken) 和扫描数 (nr_scanned)。
	nr_taken = isolate_lru_folios(nr_to_scan, lruvec, &l_hold,
				     &nr_scanned, sc, lru);

	// 更新内存统计
	// 记录隔离页面：更新节点统计，标记页面处于隔离状态 (NR_ISOLATED_ANON/FILE)。
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);

	// 记录填充事件：全局事件 PGREFILL：非 CGroup 回收时记录扫描量。
	if (!cgroup_reclaim(sc))
		__count_vm_events(PGREFILL, nr_scanned);
	// 记录填充事件：CGroup 事件：记录内存组的扫描量。
	count_memcg_events(lruvec_memcg(lruvec), PGREFILL, nr_scanned);
	// 解锁：释放 LRU 锁，允许中断和其他操作。
	spin_unlock_irq(&lruvec->lru_lock);

	// 逐页检查并分类
	while (!list_empty(&l_hold)) {
		struct folio *folio;

		cond_resched(); // 主动让出 CPU，避免长时间占用
		folio = lru_to_folio(&l_hold);
		list_del(&folio->lru); // 从临时链表移除

		// 不可回收处理：若页面被锁定（如 mlock），直接放回原链表。
		if (unlikely(!folio_evictable(folio))) {
			folio_putback_lru(folio); // 放回原 LRU 链表
			continue;
		}

		// 缓冲区超限处理：当系统文件缓存过大时，尝试释放页面的缓冲区头。
		if (unlikely(buffer_heads_over_limit)) {
			if (folio_needs_release(folio) &&
			    folio_trylock(folio)) {
				filemap_release_folio(folio, 0); // 尝试释放缓存
				folio_unlock(folio);
			}
		}

		// 页面引用检查：
		// 关键逻辑：通过 folio_referenced 检测页面近期是否被访问：
		//     可执行文件页：若被访问（VM_EXEC），视为活跃页面，
		//     加入 l_active 并计数 (nr_rotated)。
		//     匿名页：即使被访问也不保留（避免 JVM 等大量临时匿名页
		//     影响回收效率）。
		if (folio_referenced(folio, 0, sc->target_mem_cgroup,
				     &vm_flags) != 0) {
			if ((vm_flags & VM_EXEC) && folio_is_file_lru(folio)) {
				nr_rotated += folio_nr_pages(folio);
				list_add(&folio->lru, &l_active); // 保留在活动链表
				continue;
			}
		}

		// 降级到非活动链表：
		folio_clear_active(folio);     // 清除活动标志
		folio_set_workingset(folio);   // 标记为工作集（参与第二次机会）
		list_add(&folio->lru, &l_inactive); // 加入待降级链表
	}

	// 移动页面回 LRU, 锁定并移动：
	spin_lock_irq(&lruvec->lru_lock);

	// 将 l_active 放回活动链表，更新 nr_activate。
	nr_activate = move_folios_to_lru(lruvec, &l_active);
	// 将 l_inactive 移到非活动链表，更新 nr_deactivate。
	nr_deactivate = move_folios_to_lru(lruvec, &l_inactive);

	// 更新统计：记录全局和 CGroup 的降级事件 (PGDEACTIVATE)。
	__count_vm_events(PGDEACTIVATE, nr_deactivate);
	count_memcg_events(lruvec_memcg(lruvec), PGDEACTIVATE, nr_deactivate);

	// 更新统计：解除页面的隔离状态（减少 NR_ISOLATED_* 计数）。
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
	spin_unlock_irq(&lruvec->lru_lock);

	// 后期处理与跟踪
	if (nr_rotated)
		// 成本反馈：lru_note_cost 根据 nr_rotated 调整未来扫描优先级
		// （避免频繁扫描活跃页面）。
		lru_note_cost(lruvec, file, 0, nr_rotated); // 记录旋转成本，平衡后续扫描压力
	// 调试信息：记录详细参数供内存回收跟踪器分析。
	trace_mm_vmscan_lru_shrink_active(pgdat->node_id, nr_taken, nr_activate,
			nr_deactivate, nr_rotated, sc->priority, file); // 调试跟踪
}

static unsigned int reclaim_folio_list(struct list_head *folio_list,
				      struct pglist_data *pgdat)
{
	struct reclaim_stat stat;
	unsigned int nr_reclaimed;
	struct folio *folio;
	struct scan_control sc = {
		.gfp_mask = GFP_KERNEL,
		.may_writepage = 1,
		.may_unmap = 1,
		.may_swap = 1,
		.no_demotion = 1,
	};

	nr_reclaimed = shrink_folio_list(folio_list, pgdat, &sc, &stat, true, NULL);
	while (!list_empty(folio_list)) {
		folio = lru_to_folio(folio_list);
		list_del(&folio->lru);
		folio_putback_lru(folio);
	}
	trace_mm_vmscan_reclaim_pages(pgdat->node_id, sc.nr_scanned, nr_reclaimed, &stat);

	return nr_reclaimed;
}

unsigned long reclaim_pages(struct list_head *folio_list)
{
	int nid;
	unsigned int nr_reclaimed = 0;
	LIST_HEAD(node_folio_list);
	unsigned int noreclaim_flag;

	if (list_empty(folio_list))
		return nr_reclaimed;

	noreclaim_flag = memalloc_noreclaim_save();

	nid = folio_nid(lru_to_folio(folio_list));
	do {
		struct folio *folio = lru_to_folio(folio_list);

		if (nid == folio_nid(folio)) {
			folio_clear_active(folio);
			list_move(&folio->lru, &node_folio_list);
			continue;
		}

		nr_reclaimed += reclaim_folio_list(&node_folio_list, NODE_DATA(nid));
		nid = folio_nid(lru_to_folio(folio_list));
	} while (!list_empty(folio_list));

	nr_reclaimed += reclaim_folio_list(&node_folio_list, NODE_DATA(nid));

	memalloc_noreclaim_restore(noreclaim_flag);

	return nr_reclaimed;
}

static unsigned long shrink_list(enum lru_list lru, unsigned long nr_to_scan,
				 struct lruvec *lruvec, struct scan_control *sc)
{
	if (is_active_lru(lru)) {
		if (sc->may_deactivate & (1 << is_file_lru(lru)))
			shrink_active_list(nr_to_scan, lruvec, sc, lru);
		else
			sc->skipped_deactivate = 1;
		return 0;
	}

	return shrink_inactive_list(nr_to_scan, lruvec, sc, lru);
}

/*
 * The inactive anon list should be small enough that the VM never has
 * to do too much work.
 *
 * The inactive file list should be small enough to leave most memory
 * to the established workingset on the scan-resistant active list,
 * but large enough to avoid thrashing the aggregate readahead window.
 *
 * Both inactive lists should also be large enough that each inactive
 * folio has a chance to be referenced again before it is reclaimed.
 *
 * If that fails and refaulting is observed, the inactive list grows.
 *
 * The inactive_ratio is the target ratio of ACTIVE to INACTIVE folios
 * on this LRU, maintained by the pageout code. An inactive_ratio
 * of 3 means 3:1 or 25% of the folios are kept on the inactive list.
 *
 * total     target    max
 * memory    ratio     inactive
 * -------------------------------------
 *   10MB       1         5MB
 *  100MB       1        50MB
 *    1GB       3       250MB
 *   10GB      10       0.9GB
 *  100GB      31         3GB
 *    1TB     101        10GB
 *   10TB     320        32GB
 */
static bool inactive_is_low(struct lruvec *lruvec, enum lru_list inactive_lru)
{
	enum lru_list active_lru = inactive_lru + LRU_ACTIVE;
	unsigned long inactive, active;
	unsigned long inactive_ratio;
	unsigned long gb;

	inactive = lruvec_page_state(lruvec, NR_LRU_BASE + inactive_lru);
	active = lruvec_page_state(lruvec, NR_LRU_BASE + active_lru);

	gb = (inactive + active) >> (30 - PAGE_SHIFT);
	if (gb)
		inactive_ratio = int_sqrt(10 * gb);
	else
		inactive_ratio = 1;

	return inactive * inactive_ratio < active;
}

enum scan_balance {
	SCAN_EQUAL,
	SCAN_FRACT,
	SCAN_ANON,
	SCAN_FILE,
};

static void prepare_scan_control(pg_data_t *pgdat, struct scan_control *sc)
{
	unsigned long file;
	struct lruvec *target_lruvec;

	if (lru_gen_enabled())
		return;

	target_lruvec = mem_cgroup_lruvec(sc->target_mem_cgroup, pgdat);

	/*
	 * Flush the memory cgroup stats in rate-limited way as we don't need
	 * most accurate stats here. We may switch to regular stats flushing
	 * in the future once it is cheap enough.
	 */
	mem_cgroup_flush_stats_ratelimited(sc->target_mem_cgroup);

	/*
	 * Determine the scan balance between anon and file LRUs.
	 */
	spin_lock_irq(&target_lruvec->lru_lock);
	sc->anon_cost = target_lruvec->anon_cost;
	sc->file_cost = target_lruvec->file_cost;
	spin_unlock_irq(&target_lruvec->lru_lock);

	/*
	 * Target desirable inactive:active list ratios for the anon
	 * and file LRU lists.
	 */
	if (!sc->force_deactivate) {
		unsigned long refaults;

		/*
		 * When refaults are being observed, it means a new
		 * workingset is being established. Deactivate to get
		 * rid of any stale active pages quickly.
		 */
		refaults = lruvec_page_state(target_lruvec,
				WORKINGSET_ACTIVATE_ANON);
		if (refaults != target_lruvec->refaults[WORKINGSET_ANON] ||
			inactive_is_low(target_lruvec, LRU_INACTIVE_ANON))
			sc->may_deactivate |= DEACTIVATE_ANON;
		else
			sc->may_deactivate &= ~DEACTIVATE_ANON;

		refaults = lruvec_page_state(target_lruvec,
				WORKINGSET_ACTIVATE_FILE);
		if (refaults != target_lruvec->refaults[WORKINGSET_FILE] ||
		    inactive_is_low(target_lruvec, LRU_INACTIVE_FILE))
			sc->may_deactivate |= DEACTIVATE_FILE;
		else
			sc->may_deactivate &= ~DEACTIVATE_FILE;
	} else
		sc->may_deactivate = DEACTIVATE_ANON | DEACTIVATE_FILE;

	/*
	 * If we have plenty of inactive file pages that aren't
	 * thrashing, try to reclaim those first before touching
	 * anonymous pages.
	 */
	file = lruvec_page_state(target_lruvec, NR_INACTIVE_FILE);
	if (file >> sc->priority && !(sc->may_deactivate & DEACTIVATE_FILE) &&
	    !sc->no_cache_trim_mode)
		sc->cache_trim_mode = 1;
	else
		sc->cache_trim_mode = 0;

	/*
	 * Prevent the reclaimer from falling into the cache trap: as
	 * cache pages start out inactive, every cache fault will tip
	 * the scan balance towards the file LRU.  And as the file LRU
	 * shrinks, so does the window for rotation from references.
	 * This means we have a runaway feedback loop where a tiny
	 * thrashing file LRU becomes infinitely more attractive than
	 * anon pages.  Try to detect this based on file LRU size.
	 */
	if (!cgroup_reclaim(sc)) {
		unsigned long total_high_wmark = 0;
		unsigned long free, anon;
		int z;
		struct zone *zone;

		free = sum_zone_node_page_state(pgdat->node_id, NR_FREE_PAGES);
		file = node_page_state(pgdat, NR_ACTIVE_FILE) +
			   node_page_state(pgdat, NR_INACTIVE_FILE);

		for_each_managed_zone_pgdat(zone, pgdat, z, MAX_NR_ZONES - 1) {
			total_high_wmark += high_wmark_pages(zone);
		}

		/*
		 * Consider anon: if that's low too, this isn't a
		 * runaway file reclaim problem, but rather just
		 * extreme pressure. Reclaim as per usual then.
		 */
		anon = node_page_state(pgdat, NR_INACTIVE_ANON);

		sc->file_is_tiny =
			file + free <= total_high_wmark &&
			!(sc->may_deactivate & DEACTIVATE_ANON) &&
			anon >> sc->priority;
	}
}

static inline void calculate_pressure_balance(struct scan_control *sc,
			int swappiness, u64 *fraction, u64 *denominator)
{
	unsigned long anon_cost, file_cost, total_cost;
	unsigned long ap, fp;

	/*
	 * Calculate the pressure balance between anon and file pages.
	 *
	 * The amount of pressure we put on each LRU is inversely
	 * proportional to the cost of reclaiming each list, as
	 * determined by the share of pages that are refaulting, times
	 * the relative IO cost of bringing back a swapped out
	 * anonymous page vs reloading a filesystem page (swappiness).
	 *
	 * Although we limit that influence to ensure no list gets
	 * left behind completely: at least a third of the pressure is
	 * applied, before swappiness.
	 *
	 * With swappiness at 100, anon and file have equal IO cost.
	 */
	total_cost = sc->anon_cost + sc->file_cost;
	anon_cost = total_cost + sc->anon_cost;
	file_cost = total_cost + sc->file_cost;
	total_cost = anon_cost + file_cost;

	ap = swappiness * (total_cost + 1);
	ap /= anon_cost + 1;

	fp = (MAX_SWAPPINESS - swappiness) * (total_cost + 1);
	fp /= file_cost + 1;

	fraction[WORKINGSET_ANON] = ap;
	fraction[WORKINGSET_FILE] = fp;
	*denominator = ap + fp;
}

/*
 * Determine how aggressively the anon and file LRU lists should be
 * scanned.
 *
 * nr[0] = anon inactive folios to scan; nr[1] = anon active folios to scan
 * nr[2] = file inactive folios to scan; nr[3] = file active folios to scan
 */
static void get_scan_count(struct lruvec *lruvec, struct scan_control *sc,
			   unsigned long *nr)
{
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	int swappiness = sc_swappiness(sc, memcg);
	u64 fraction[ANON_AND_FILE];
	u64 denominator = 0;	/* gcc */
	enum scan_balance scan_balance;
	enum lru_list lru;

	/* If we have no swap space, do not bother scanning anon folios. */
	if (!sc->may_swap || !can_reclaim_anon_pages(memcg, pgdat->node_id, sc)) {
		scan_balance = SCAN_FILE;
		goto out;
	}

	/*
	 * Global reclaim will swap to prevent OOM even with no
	 * swappiness, but memcg users want to use this knob to
	 * disable swapping for individual groups completely when
	 * using the memory controller's swap limit feature would be
	 * too expensive.
	 */
	if (cgroup_reclaim(sc) && !swappiness) {
		scan_balance = SCAN_FILE;
		goto out;
	}

	/* Proactive reclaim initiated by userspace for anonymous memory only */
	if (swappiness == SWAPPINESS_ANON_ONLY) {
		WARN_ON_ONCE(!sc->proactive);
		scan_balance = SCAN_ANON;
		goto out;
	}

	/*
	 * Do not apply any pressure balancing cleverness when the
	 * system is close to OOM, scan both anon and file equally
	 * (unless the swappiness setting disagrees with swapping).
	 */
	if (!sc->priority && swappiness) {
		scan_balance = SCAN_EQUAL;
		goto out;
	}

	/*
	 * If the system is almost out of file pages, force-scan anon.
	 */
	if (sc->file_is_tiny) {
		scan_balance = SCAN_ANON;
		goto out;
	}

	/*
	 * If there is enough inactive page cache, we do not reclaim
	 * anything from the anonymous working right now to make sure
         * a streaming file access pattern doesn't cause swapping.
	 */
	if (sc->cache_trim_mode) {
		scan_balance = SCAN_FILE;
		goto out;
	}

	scan_balance = SCAN_FRACT;
	calculate_pressure_balance(sc, swappiness, fraction, &denominator);

out:
	for_each_evictable_lru(lru) {
		bool file = is_file_lru(lru);
		unsigned long lruvec_size;
		unsigned long low, min;
		unsigned long scan;

		lruvec_size = lruvec_lru_size(lruvec, lru, sc->reclaim_idx);
		mem_cgroup_protection(sc->target_mem_cgroup, memcg,
				      &min, &low);

		if (min || low) {
			/*
			 * Scale a cgroup's reclaim pressure by proportioning
			 * its current usage to its memory.low or memory.min
			 * setting.
			 *
			 * This is important, as otherwise scanning aggression
			 * becomes extremely binary -- from nothing as we
			 * approach the memory protection threshold, to totally
			 * nominal as we exceed it.  This results in requiring
			 * setting extremely liberal protection thresholds. It
			 * also means we simply get no protection at all if we
			 * set it too low, which is not ideal.
			 *
			 * If there is any protection in place, we reduce scan
			 * pressure by how much of the total memory used is
			 * within protection thresholds.
			 *
			 * There is one special case: in the first reclaim pass,
			 * we skip over all groups that are within their low
			 * protection. If that fails to reclaim enough pages to
			 * satisfy the reclaim goal, we come back and override
			 * the best-effort low protection. However, we still
			 * ideally want to honor how well-behaved groups are in
			 * that case instead of simply punishing them all
			 * equally. As such, we reclaim them based on how much
			 * memory they are using, reducing the scan pressure
			 * again by how much of the total memory used is under
			 * hard protection.
			 */
			unsigned long cgroup_size = mem_cgroup_size(memcg);
			unsigned long protection;

			/* memory.low scaling, make sure we retry before OOM */
			if (!sc->memcg_low_reclaim && low > min) {
				protection = low;
				sc->memcg_low_skipped = 1;
			} else {
				protection = min;
			}

			/* Avoid TOCTOU with earlier protection check */
			cgroup_size = max(cgroup_size, protection);

			scan = lruvec_size - lruvec_size * protection /
				(cgroup_size + 1);

			/*
			 * Minimally target SWAP_CLUSTER_MAX pages to keep
			 * reclaim moving forwards, avoiding decrementing
			 * sc->priority further than desirable.
			 */
			scan = max(scan, SWAP_CLUSTER_MAX);
		} else {
			scan = lruvec_size;
		}

		scan >>= sc->priority;

		/*
		 * If the cgroup's already been deleted, make sure to
		 * scrape out the remaining cache.
		 */
		if (!scan && !mem_cgroup_online(memcg))
			scan = min(lruvec_size, SWAP_CLUSTER_MAX);

		switch (scan_balance) {
		case SCAN_EQUAL:
			/* Scan lists relative to size */
			break;
		case SCAN_FRACT:
			/*
			 * Scan types proportional to swappiness and
			 * their relative recent reclaim efficiency.
			 * Make sure we don't miss the last page on
			 * the offlined memory cgroups because of a
			 * round-off error.
			 */
			scan = mem_cgroup_online(memcg) ?
			       div64_u64(scan * fraction[file], denominator) :
			       DIV64_U64_ROUND_UP(scan * fraction[file],
						  denominator);
			break;
		case SCAN_FILE:
		case SCAN_ANON:
			/* Scan one type exclusively */
			if ((scan_balance == SCAN_FILE) != file)
				scan = 0;
			break;
		default:
			/* Look ma, no brain */
			BUG();
		}

		nr[lru] = scan;
	}
}

/*
 * Anonymous LRU management is a waste if there is
 * ultimately no way to reclaim the memory.
 */
static bool can_age_anon_pages(struct lruvec *lruvec,
			       struct scan_control *sc)
{
	/* Aging the anon LRU is valuable if swap is present: */
	if (total_swap_pages > 0)
		return true;

	/* Also valuable if anon pages can be demoted: */
	return can_demote(lruvec_pgdat(lruvec)->node_id, sc,
			  lruvec_memcg(lruvec));
}

#ifdef CONFIG_LRU_GEN

#ifdef CONFIG_LRU_GEN_ENABLED
DEFINE_STATIC_KEY_ARRAY_TRUE(lru_gen_caps, NR_LRU_GEN_CAPS);
#define get_cap(cap)	static_branch_likely(&lru_gen_caps[cap])
#else
DEFINE_STATIC_KEY_ARRAY_FALSE(lru_gen_caps, NR_LRU_GEN_CAPS);
#define get_cap(cap)	static_branch_unlikely(&lru_gen_caps[cap])
#endif

static bool should_walk_mmu(void)
{
	return arch_has_hw_pte_young() && get_cap(LRU_GEN_MM_WALK);
}

static bool should_clear_pmd_young(void)
{
	return arch_has_hw_nonleaf_pmd_young() && get_cap(LRU_GEN_NONLEAF_YOUNG);
}

/******************************************************************************
 *                          shorthand helpers
 ******************************************************************************/

#define DEFINE_MAX_SEQ(lruvec)						\
	unsigned long max_seq = READ_ONCE((lruvec)->lrugen.max_seq)

#define DEFINE_MIN_SEQ(lruvec)						\
	unsigned long min_seq[ANON_AND_FILE] = {			\
		READ_ONCE((lruvec)->lrugen.min_seq[LRU_GEN_ANON]),	\
		READ_ONCE((lruvec)->lrugen.min_seq[LRU_GEN_FILE]),	\
	}

/* Get the min/max evictable type based on swappiness */
#define min_type(swappiness) (!(swappiness))
#define max_type(swappiness) ((swappiness) < SWAPPINESS_ANON_ONLY)

#define evictable_min_seq(min_seq, swappiness)				\
	min((min_seq)[min_type(swappiness)], (min_seq)[max_type(swappiness)])

#define for_each_gen_type_zone(gen, type, zone)				\
	for ((gen) = 0; (gen) < MAX_NR_GENS; (gen)++)			\
		for ((type) = 0; (type) < ANON_AND_FILE; (type)++)	\
			for ((zone) = 0; (zone) < MAX_NR_ZONES; (zone)++)

#define for_each_evictable_type(type, swappiness)			\
	for ((type) = min_type(swappiness); (type) <= max_type(swappiness); (type)++)

#define get_memcg_gen(seq)	((seq) % MEMCG_NR_GENS)
#define get_memcg_bin(bin)	((bin) % MEMCG_NR_BINS)

static struct lruvec *get_lruvec(struct mem_cgroup *memcg, int nid)
{
	struct pglist_data *pgdat = NODE_DATA(nid);

#ifdef CONFIG_MEMCG
	if (memcg) {
		struct lruvec *lruvec = &memcg->nodeinfo[nid]->lruvec;

		/* see the comment in mem_cgroup_lruvec() */
		if (!lruvec->pgdat)
			lruvec->pgdat = pgdat;

		return lruvec;
	}
#endif
	VM_WARN_ON_ONCE(!mem_cgroup_disabled());

	return &pgdat->__lruvec;
}

static int get_swappiness(struct lruvec *lruvec, struct scan_control *sc)
{
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);

	if (!sc->may_swap)
		return 0;

	if (!can_demote(pgdat->node_id, sc, memcg) &&
	    mem_cgroup_get_nr_swap_pages(memcg) < MIN_LRU_BATCH)
		return 0;

	return sc_swappiness(sc, memcg);
}

static int get_nr_gens(struct lruvec *lruvec, int type)
{
	return lruvec->lrugen.max_seq - lruvec->lrugen.min_seq[type] + 1;
}

static bool __maybe_unused seq_is_valid(struct lruvec *lruvec)
{
	int type;

	for (type = 0; type < ANON_AND_FILE; type++) {
		int n = get_nr_gens(lruvec, type);

		if (n < MIN_NR_GENS || n > MAX_NR_GENS)
			return false;
	}

	return true;
}

/******************************************************************************
 *                          Bloom filters
 ******************************************************************************/

/*
 * Bloom filters with m=1<<15, k=2 and the false positive rates of ~1/5 when
 * n=10,000 and ~1/2 when n=20,000, where, conventionally, m is the number of
 * bits in a bitmap, k is the number of hash functions and n is the number of
 * inserted items.
 *
 * Page table walkers use one of the two filters to reduce their search space.
 * To get rid of non-leaf entries that no longer have enough leaf entries, the
 * aging uses the double-buffering technique to flip to the other filter each
 * time it produces a new generation. For non-leaf entries that have enough
 * leaf entries, the aging carries them over to the next generation in
 * walk_pmd_range(); the eviction also report them when walking the rmap
 * in lru_gen_look_around().
 *
 * For future optimizations:
 * 1. It's not necessary to keep both filters all the time. The spare one can be
 *    freed after the RCU grace period and reallocated if needed again.
 * 2. And when reallocating, it's worth scaling its size according to the number
 *    of inserted entries in the other filter, to reduce the memory overhead on
 *    small systems and false positives on large systems.
 * 3. Jenkins' hash function is an alternative to Knuth's.
 */
#define BLOOM_FILTER_SHIFT	15

static inline int filter_gen_from_seq(unsigned long seq)
{
	return seq % NR_BLOOM_FILTERS;
}

static void get_item_key(void *item, int *key)
{
	u32 hash = hash_ptr(item, BLOOM_FILTER_SHIFT * 2);

	BUILD_BUG_ON(BLOOM_FILTER_SHIFT * 2 > BITS_PER_TYPE(u32));

	key[0] = hash & (BIT(BLOOM_FILTER_SHIFT) - 1);
	key[1] = hash >> BLOOM_FILTER_SHIFT;
}

static bool test_bloom_filter(struct lru_gen_mm_state *mm_state, unsigned long seq,
			      void *item)
{
	int key[2];
	unsigned long *filter;
	int gen = filter_gen_from_seq(seq);

	filter = READ_ONCE(mm_state->filters[gen]);
	if (!filter)
		return true;

	get_item_key(item, key);

	return test_bit(key[0], filter) && test_bit(key[1], filter);
}

static void update_bloom_filter(struct lru_gen_mm_state *mm_state, unsigned long seq,
				void *item)
{
	int key[2];
	unsigned long *filter;
	int gen = filter_gen_from_seq(seq);

	filter = READ_ONCE(mm_state->filters[gen]);
	if (!filter)
		return;

	get_item_key(item, key);

	if (!test_bit(key[0], filter))
		set_bit(key[0], filter);
	if (!test_bit(key[1], filter))
		set_bit(key[1], filter);
}

static void reset_bloom_filter(struct lru_gen_mm_state *mm_state, unsigned long seq)
{
	unsigned long *filter;
	int gen = filter_gen_from_seq(seq);

	filter = mm_state->filters[gen];
	if (filter) {
		bitmap_clear(filter, 0, BIT(BLOOM_FILTER_SHIFT));
		return;
	}

	filter = bitmap_zalloc(BIT(BLOOM_FILTER_SHIFT),
			       __GFP_HIGH | __GFP_NOMEMALLOC | __GFP_NOWARN);
	WRITE_ONCE(mm_state->filters[gen], filter);
}

/******************************************************************************
 *                          mm_struct list
 ******************************************************************************/

#ifdef CONFIG_LRU_GEN_WALKS_MMU

static struct lru_gen_mm_list *get_mm_list(struct mem_cgroup *memcg)
{
	static struct lru_gen_mm_list mm_list = {
		.fifo = LIST_HEAD_INIT(mm_list.fifo),
		.lock = __SPIN_LOCK_UNLOCKED(mm_list.lock),
	};

#ifdef CONFIG_MEMCG
	if (memcg)
		return &memcg->mm_list;
#endif
	VM_WARN_ON_ONCE(!mem_cgroup_disabled());

	return &mm_list;
}

static struct lru_gen_mm_state *get_mm_state(struct lruvec *lruvec)
{
	return &lruvec->mm_state;
}

static struct mm_struct *get_next_mm(struct lru_gen_mm_walk *walk)
{
	int key;
	struct mm_struct *mm;
	struct pglist_data *pgdat = lruvec_pgdat(walk->lruvec);
	struct lru_gen_mm_state *mm_state = get_mm_state(walk->lruvec);

	mm = list_entry(mm_state->head, struct mm_struct, lru_gen.list);
	key = pgdat->node_id % BITS_PER_TYPE(mm->lru_gen.bitmap);

	if (!walk->force_scan && !test_bit(key, &mm->lru_gen.bitmap))
		return NULL;

	clear_bit(key, &mm->lru_gen.bitmap);

	return mmget_not_zero(mm) ? mm : NULL;
}

void lru_gen_add_mm(struct mm_struct *mm)
{
	int nid;
	struct mem_cgroup *memcg = get_mem_cgroup_from_mm(mm);
	struct lru_gen_mm_list *mm_list = get_mm_list(memcg);

	VM_WARN_ON_ONCE(!list_empty(&mm->lru_gen.list));
#ifdef CONFIG_MEMCG
	VM_WARN_ON_ONCE(mm->lru_gen.memcg);
	mm->lru_gen.memcg = memcg;
#endif
	spin_lock(&mm_list->lock);

	for_each_node_state(nid, N_MEMORY) {
		struct lruvec *lruvec = get_lruvec(memcg, nid);
		struct lru_gen_mm_state *mm_state = get_mm_state(lruvec);

		/* the first addition since the last iteration */
		if (mm_state->tail == &mm_list->fifo)
			mm_state->tail = &mm->lru_gen.list;
	}

	list_add_tail(&mm->lru_gen.list, &mm_list->fifo);

	spin_unlock(&mm_list->lock);
}

void lru_gen_del_mm(struct mm_struct *mm)
{
	int nid;
	struct lru_gen_mm_list *mm_list;
	struct mem_cgroup *memcg = NULL;

	if (list_empty(&mm->lru_gen.list))
		return;

#ifdef CONFIG_MEMCG
	memcg = mm->lru_gen.memcg;
#endif
	mm_list = get_mm_list(memcg);

	spin_lock(&mm_list->lock);

	for_each_node(nid) {
		struct lruvec *lruvec = get_lruvec(memcg, nid);
		struct lru_gen_mm_state *mm_state = get_mm_state(lruvec);

		/* where the current iteration continues after */
		if (mm_state->head == &mm->lru_gen.list)
			mm_state->head = mm_state->head->prev;

		/* where the last iteration ended before */
		if (mm_state->tail == &mm->lru_gen.list)
			mm_state->tail = mm_state->tail->next;
	}

	list_del_init(&mm->lru_gen.list);

	spin_unlock(&mm_list->lock);

#ifdef CONFIG_MEMCG
	mem_cgroup_put(mm->lru_gen.memcg);
	mm->lru_gen.memcg = NULL;
#endif
}

#ifdef CONFIG_MEMCG
void lru_gen_migrate_mm(struct mm_struct *mm)
{
	struct mem_cgroup *memcg;
	struct task_struct *task = rcu_dereference_protected(mm->owner, true);

	VM_WARN_ON_ONCE(task->mm != mm);
	lockdep_assert_held(&task->alloc_lock);

	/* for mm_update_next_owner() */
	if (mem_cgroup_disabled())
		return;

	/* migration can happen before addition */
	if (!mm->lru_gen.memcg)
		return;

	rcu_read_lock();
	memcg = mem_cgroup_from_task(task);
	rcu_read_unlock();
	if (memcg == mm->lru_gen.memcg)
		return;

	VM_WARN_ON_ONCE(list_empty(&mm->lru_gen.list));

	lru_gen_del_mm(mm);
	lru_gen_add_mm(mm);
}
#endif

#else /* !CONFIG_LRU_GEN_WALKS_MMU */

static struct lru_gen_mm_list *get_mm_list(struct mem_cgroup *memcg)
{
	return NULL;
}

static struct lru_gen_mm_state *get_mm_state(struct lruvec *lruvec)
{
	return NULL;
}

static struct mm_struct *get_next_mm(struct lru_gen_mm_walk *walk)
{
	return NULL;
}

#endif

static void reset_mm_stats(struct lru_gen_mm_walk *walk, bool last)
{
	int i;
	int hist;
	struct lruvec *lruvec = walk->lruvec;
	struct lru_gen_mm_state *mm_state = get_mm_state(lruvec);

	lockdep_assert_held(&get_mm_list(lruvec_memcg(lruvec))->lock);

	hist = lru_hist_from_seq(walk->seq);

	for (i = 0; i < NR_MM_STATS; i++) {
		WRITE_ONCE(mm_state->stats[hist][i],
			   mm_state->stats[hist][i] + walk->mm_stats[i]);
		walk->mm_stats[i] = 0;
	}

	if (NR_HIST_GENS > 1 && last) {
		hist = lru_hist_from_seq(walk->seq + 1);

		for (i = 0; i < NR_MM_STATS; i++)
			WRITE_ONCE(mm_state->stats[hist][i], 0);
	}
}

static bool iterate_mm_list(struct lru_gen_mm_walk *walk, struct mm_struct **iter)
{
	bool first = false;
	bool last = false;
	struct mm_struct *mm = NULL;
	struct lruvec *lruvec = walk->lruvec;
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	struct lru_gen_mm_list *mm_list = get_mm_list(memcg);
	struct lru_gen_mm_state *mm_state = get_mm_state(lruvec);

	/*
	 * mm_state->seq is incremented after each iteration of mm_list. There
	 * are three interesting cases for this page table walker:
	 * 1. It tries to start a new iteration with a stale max_seq: there is
	 *    nothing left to do.
	 * 2. It started the next iteration: it needs to reset the Bloom filter
	 *    so that a fresh set of PTE tables can be recorded.
	 * 3. It ended the current iteration: it needs to reset the mm stats
	 *    counters and tell its caller to increment max_seq.
	 */
	spin_lock(&mm_list->lock);

	VM_WARN_ON_ONCE(mm_state->seq + 1 < walk->seq);

	if (walk->seq <= mm_state->seq)
		goto done;

	if (!mm_state->head)
		mm_state->head = &mm_list->fifo;

	if (mm_state->head == &mm_list->fifo)
		first = true;

	do {
		mm_state->head = mm_state->head->next;
		if (mm_state->head == &mm_list->fifo) {
			WRITE_ONCE(mm_state->seq, mm_state->seq + 1);
			last = true;
			break;
		}

		/* force scan for those added after the last iteration */
		if (!mm_state->tail || mm_state->tail == mm_state->head) {
			mm_state->tail = mm_state->head->next;
			walk->force_scan = true;
		}
	} while (!(mm = get_next_mm(walk)));
done:
	if (*iter || last)
		reset_mm_stats(walk, last);

	spin_unlock(&mm_list->lock);

	if (mm && first)
		reset_bloom_filter(mm_state, walk->seq + 1);

	if (*iter)
		mmput_async(*iter);

	*iter = mm;

	return last;
}

static bool iterate_mm_list_nowalk(struct lruvec *lruvec, unsigned long seq)
{
	bool success = false;
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	struct lru_gen_mm_list *mm_list = get_mm_list(memcg);
	struct lru_gen_mm_state *mm_state = get_mm_state(lruvec);

	spin_lock(&mm_list->lock);

	VM_WARN_ON_ONCE(mm_state->seq + 1 < seq);

	if (seq > mm_state->seq) {
		mm_state->head = NULL;
		mm_state->tail = NULL;
		WRITE_ONCE(mm_state->seq, mm_state->seq + 1);
		success = true;
	}

	spin_unlock(&mm_list->lock);

	return success;
}

/******************************************************************************
 *                          PID controller
 ******************************************************************************/

/*
 * A feedback loop based on Proportional-Integral-Derivative (PID) controller.
 *
 * The P term is refaulted/(evicted+protected) from a tier in the generation
 * currently being evicted; the I term is the exponential moving average of the
 * P term over the generations previously evicted, using the smoothing factor
 * 1/2; the D term isn't supported.
 *
 * The setpoint (SP) is always the first tier of one type; the process variable
 * (PV) is either any tier of the other type or any other tier of the same
 * type.
 *
 * The error is the difference between the SP and the PV; the correction is to
 * turn off protection when SP>PV or turn on protection when SP<PV.
 *
 * For future optimizations:
 * 1. The D term may discount the other two terms over time so that long-lived
 *    generations can resist stale information.
 */
struct ctrl_pos {
	unsigned long refaulted;
	unsigned long total;
	int gain;
};

static void read_ctrl_pos(struct lruvec *lruvec, int type, int tier, int gain,
			  struct ctrl_pos *pos)
{
	int i;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	int hist = lru_hist_from_seq(lrugen->min_seq[type]);

	pos->gain = gain;
	pos->refaulted = pos->total = 0;

	for (i = tier % MAX_NR_TIERS; i <= min(tier, MAX_NR_TIERS - 1); i++) {
		pos->refaulted += lrugen->avg_refaulted[type][i] +
				  atomic_long_read(&lrugen->refaulted[hist][type][i]);
		pos->total += lrugen->avg_total[type][i] +
			      lrugen->protected[hist][type][i] +
			      atomic_long_read(&lrugen->evicted[hist][type][i]);
	}
}

static void reset_ctrl_pos(struct lruvec *lruvec, int type, bool carryover)
{
	int hist, tier;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	bool clear = carryover ? NR_HIST_GENS == 1 : NR_HIST_GENS > 1;
	unsigned long seq = carryover ? lrugen->min_seq[type] : lrugen->max_seq + 1;

	lockdep_assert_held(&lruvec->lru_lock);

	if (!carryover && !clear)
		return;

	hist = lru_hist_from_seq(seq);

	for (tier = 0; tier < MAX_NR_TIERS; tier++) {
		if (carryover) {
			unsigned long sum;

			sum = lrugen->avg_refaulted[type][tier] +
			      atomic_long_read(&lrugen->refaulted[hist][type][tier]);
			WRITE_ONCE(lrugen->avg_refaulted[type][tier], sum / 2);

			sum = lrugen->avg_total[type][tier] +
			      lrugen->protected[hist][type][tier] +
			      atomic_long_read(&lrugen->evicted[hist][type][tier]);
			WRITE_ONCE(lrugen->avg_total[type][tier], sum / 2);
		}

		if (clear) {
			atomic_long_set(&lrugen->refaulted[hist][type][tier], 0);
			atomic_long_set(&lrugen->evicted[hist][type][tier], 0);
			WRITE_ONCE(lrugen->protected[hist][type][tier], 0);
		}
	}
}

static bool positive_ctrl_err(struct ctrl_pos *sp, struct ctrl_pos *pv)
{
	/*
	 * Return true if the PV has a limited number of refaults or a lower
	 * refaulted/total than the SP.
	 */
	return pv->refaulted < MIN_LRU_BATCH ||
	       pv->refaulted * (sp->total + MIN_LRU_BATCH) * sp->gain <=
	       (sp->refaulted + 1) * pv->total * pv->gain;
}

/******************************************************************************
 *                          the aging
 ******************************************************************************/

/* promote pages accessed through page tables */
static int folio_update_gen(struct folio *folio, int gen)
{
	unsigned long new_flags, old_flags = READ_ONCE(folio->flags);

	VM_WARN_ON_ONCE(gen >= MAX_NR_GENS);

	/* see the comment on LRU_REFS_FLAGS */
	if (!folio_test_referenced(folio) && !folio_test_workingset(folio)) {
		set_mask_bits(&folio->flags, LRU_REFS_MASK, BIT(PG_referenced));
		return -1;
	}

	do {
		/* lru_gen_del_folio() has isolated this page? */
		if (!(old_flags & LRU_GEN_MASK))
			return -1;

		new_flags = old_flags & ~(LRU_GEN_MASK | LRU_REFS_FLAGS);
		new_flags |= ((gen + 1UL) << LRU_GEN_PGOFF) | BIT(PG_workingset);
	} while (!try_cmpxchg(&folio->flags, &old_flags, new_flags));

	return ((old_flags & LRU_GEN_MASK) >> LRU_GEN_PGOFF) - 1;
}

/* protect pages accessed multiple times through file descriptors */
static int folio_inc_gen(struct lruvec *lruvec, struct folio *folio, bool reclaiming)
{
	int type = folio_is_file_lru(folio);          // 0=匿名页,1=文件页
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	int new_gen, old_gen = lru_gen_from_seq(lrugen->min_seq[type]); // 计算旧代索引
	unsigned long new_flags, old_flags = READ_ONCE(folio->flags); // 原子读取页面标志

	// 确保页面已经有有效的代信息
	VM_WARN_ON_ONCE_FOLIO(!(old_flags & LRU_GEN_MASK), folio);

	do {
		// 从页面标志中提取当前代
		new_gen = ((old_flags & LRU_GEN_MASK) >> LRU_GEN_PGOFF) - 1;
		/* folio_update_gen() has promoted this page? */
		// 如果其他线程已更新页面代，直接返回新代
		if (new_gen >= 0 && new_gen != old_gen)
			return new_gen;

		// 计算新代：(旧代+1) % 最大代数
		new_gen = (old_gen + 1) % MAX_NR_GENS;

		// 准备新标志位：清除旧代和引用标志
		new_flags = old_flags & ~(LRU_GEN_MASK | LRU_REFS_FLAGS);
		new_flags |= (new_gen + 1UL) << LRU_GEN_PGOFF;  // 设置新代标志,gen从0开始，flag从1开始？
		/* for folio_end_writeback() */
		// 回收中标记：设置PG_reclaim标志
		if (reclaiming)
			new_flags |= BIT(PG_reclaim);
	} while (!try_cmpxchg(&folio->flags, &old_flags, new_flags)); // 原子比较交换

	// 更新LRU链表中页面大小统计
	lru_gen_update_size(lruvec, folio, old_gen, new_gen);

	return new_gen;
}

static void update_batch_size(struct lru_gen_mm_walk *walk, struct folio *folio,
			      int old_gen, int new_gen)
{
	int type = folio_is_file_lru(folio);
	int zone = folio_zonenum(folio);
	int delta = folio_nr_pages(folio);

	VM_WARN_ON_ONCE(old_gen >= MAX_NR_GENS);
	VM_WARN_ON_ONCE(new_gen >= MAX_NR_GENS);

	walk->batched++;

	walk->nr_pages[old_gen][type][zone] -= delta;
	walk->nr_pages[new_gen][type][zone] += delta;
}

static void reset_batch_size(struct lru_gen_mm_walk *walk)
{
	int gen, type, zone;
	struct lruvec *lruvec = walk->lruvec;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;

	walk->batched = 0;

	for_each_gen_type_zone(gen, type, zone) {
		enum lru_list lru = type * LRU_INACTIVE_FILE;
		int delta = walk->nr_pages[gen][type][zone];

		if (!delta)
			continue;

		walk->nr_pages[gen][type][zone] = 0;
		WRITE_ONCE(lrugen->nr_pages[gen][type][zone],
			   lrugen->nr_pages[gen][type][zone] + delta);

		if (lru_gen_is_active(lruvec, gen))
			lru += LRU_ACTIVE;
		__update_lru_size(lruvec, lru, zone, delta);
	}
}

static int should_skip_vma(unsigned long start, unsigned long end, struct mm_walk *args)
{
	struct address_space *mapping;
	struct vm_area_struct *vma = args->vma;
	struct lru_gen_mm_walk *walk = args->private;

	if (!vma_is_accessible(vma))
		return true;

	if (is_vm_hugetlb_page(vma))
		return true;

	if (!vma_has_recency(vma))
		return true;

	if (vma->vm_flags & (VM_LOCKED | VM_SPECIAL))
		return true;

	if (vma == get_gate_vma(vma->vm_mm))
		return true;

	if (vma_is_anonymous(vma))
		return !walk->swappiness;

	if (WARN_ON_ONCE(!vma->vm_file || !vma->vm_file->f_mapping))
		return true;

	mapping = vma->vm_file->f_mapping;
	if (mapping_unevictable(mapping))
		return true;

	if (shmem_mapping(mapping))
		return !walk->swappiness;

	if (walk->swappiness > MAX_SWAPPINESS)
		return true;

	/* to exclude special mappings like dax, etc. */
	return !mapping->a_ops->read_folio;
}

/*
 * Some userspace memory allocators map many single-page VMAs. Instead of
 * returning back to the PGD table for each of such VMAs, finish an entire PMD
 * table to reduce zigzags and improve cache performance.
 */
static bool get_next_vma(unsigned long mask, unsigned long size, struct mm_walk *args,
			 unsigned long *vm_start, unsigned long *vm_end)
{
	unsigned long start = round_up(*vm_end, size);
	unsigned long end = (start | ~mask) + 1;
	VMA_ITERATOR(vmi, args->mm, start);

	VM_WARN_ON_ONCE(mask & size);
	VM_WARN_ON_ONCE((start & mask) != (*vm_start & mask));

	for_each_vma(vmi, args->vma) {
		if (end && end <= args->vma->vm_start)
			return false;

		if (should_skip_vma(args->vma->vm_start, args->vma->vm_end, args))
			continue;

		*vm_start = max(start, args->vma->vm_start);
		*vm_end = min(end - 1, args->vma->vm_end - 1) + 1;

		return true;
	}

	return false;
}

static unsigned long get_pte_pfn(pte_t pte, struct vm_area_struct *vma, unsigned long addr,
				 struct pglist_data *pgdat)
{
	unsigned long pfn = pte_pfn(pte);

	VM_WARN_ON_ONCE(addr < vma->vm_start || addr >= vma->vm_end);

	if (!pte_present(pte) || is_zero_pfn(pfn))
		return -1;

	if (WARN_ON_ONCE(pte_devmap(pte) || pte_special(pte)))
		return -1;

	if (!pte_young(pte) && !mm_has_notifiers(vma->vm_mm))
		return -1;

	if (WARN_ON_ONCE(!pfn_valid(pfn)))
		return -1;

	if (pfn < pgdat->node_start_pfn || pfn >= pgdat_end_pfn(pgdat))
		return -1;

	return pfn;
}

static unsigned long get_pmd_pfn(pmd_t pmd, struct vm_area_struct *vma, unsigned long addr,
				 struct pglist_data *pgdat)
{
	unsigned long pfn = pmd_pfn(pmd);

	VM_WARN_ON_ONCE(addr < vma->vm_start || addr >= vma->vm_end);

	if (!pmd_present(pmd) || is_huge_zero_pmd(pmd))
		return -1;

	if (WARN_ON_ONCE(pmd_devmap(pmd)))
		return -1;

	if (!pmd_young(pmd) && !mm_has_notifiers(vma->vm_mm))
		return -1;

	if (WARN_ON_ONCE(!pfn_valid(pfn)))
		return -1;

	if (pfn < pgdat->node_start_pfn || pfn >= pgdat_end_pfn(pgdat))
		return -1;

	return pfn;
}

static struct folio *get_pfn_folio(unsigned long pfn, struct mem_cgroup *memcg,
				   struct pglist_data *pgdat)
{
	struct folio *folio = pfn_folio(pfn);

	if (folio_lru_gen(folio) < 0)
		return NULL;

	if (folio_nid(folio) != pgdat->node_id)
		return NULL;

	if (folio_memcg(folio) != memcg)
		return NULL;

	return folio;
}

static bool suitable_to_scan(int total, int young)
{
	int n = clamp_t(int, cache_line_size() / sizeof(pte_t), 2, 8);

	/* suitable if the average number of young PTEs per cacheline is >=1 */
	return young * n >= total;
}

static void walk_update_folio(struct lru_gen_mm_walk *walk, struct folio *folio,
			      int new_gen, bool dirty)
{
	int old_gen;

	if (!folio)
		return;

	if (dirty && !folio_test_dirty(folio) &&
	    !(folio_test_anon(folio) && folio_test_swapbacked(folio) &&
	      !folio_test_swapcache(folio)))
		folio_mark_dirty(folio);

	if (walk) {
		old_gen = folio_update_gen(folio, new_gen);
		if (old_gen >= 0 && old_gen != new_gen)
			update_batch_size(walk, folio, old_gen, new_gen);
	} else if (lru_gen_set_refs(folio)) {
		old_gen = folio_lru_gen(folio);
		if (old_gen >= 0 && old_gen != new_gen)
			folio_activate(folio);
	}
}

static bool walk_pte_range(pmd_t *pmd, unsigned long start, unsigned long end,
			   struct mm_walk *args)
{
	int i;
	bool dirty;
	pte_t *pte;
	spinlock_t *ptl;
	unsigned long addr;
	int total = 0;
	int young = 0;
	struct folio *last = NULL;
	struct lru_gen_mm_walk *walk = args->private;
	struct mem_cgroup *memcg = lruvec_memcg(walk->lruvec);
	struct pglist_data *pgdat = lruvec_pgdat(walk->lruvec);
	DEFINE_MAX_SEQ(walk->lruvec);
	int gen = lru_gen_from_seq(max_seq);
	pmd_t pmdval;

	pte = pte_offset_map_rw_nolock(args->mm, pmd, start & PMD_MASK, &pmdval, &ptl);
	if (!pte)
		return false;

	if (!spin_trylock(ptl)) {
		pte_unmap(pte);
		return true;
	}

	if (unlikely(!pmd_same(pmdval, pmdp_get_lockless(pmd)))) {
		pte_unmap_unlock(pte, ptl);
		return false;
	}

	arch_enter_lazy_mmu_mode();
restart:
	for (i = pte_index(start), addr = start; addr != end; i++, addr += PAGE_SIZE) {
		unsigned long pfn;
		struct folio *folio;
		pte_t ptent = ptep_get(pte + i);

		total++;
		walk->mm_stats[MM_LEAF_TOTAL]++;

		pfn = get_pte_pfn(ptent, args->vma, addr, pgdat);
		if (pfn == -1)
			continue;

		folio = get_pfn_folio(pfn, memcg, pgdat);
		if (!folio)
			continue;

		if (!ptep_clear_young_notify(args->vma, addr, pte + i))
			continue;

		if (last != folio) {
			walk_update_folio(walk, last, gen, dirty);

			last = folio;
			dirty = false;
		}

		if (pte_dirty(ptent))
			dirty = true;

		young++;
		walk->mm_stats[MM_LEAF_YOUNG]++;
	}

	walk_update_folio(walk, last, gen, dirty);
	last = NULL;

	if (i < PTRS_PER_PTE && get_next_vma(PMD_MASK, PAGE_SIZE, args, &start, &end))
		goto restart;

	arch_leave_lazy_mmu_mode();
	pte_unmap_unlock(pte, ptl);

	return suitable_to_scan(total, young);
}

static void walk_pmd_range_locked(pud_t *pud, unsigned long addr, struct vm_area_struct *vma,
				  struct mm_walk *args, unsigned long *bitmap, unsigned long *first)
{
	int i;
	bool dirty;
	pmd_t *pmd;
	spinlock_t *ptl;
	struct folio *last = NULL;
	struct lru_gen_mm_walk *walk = args->private;
	struct mem_cgroup *memcg = lruvec_memcg(walk->lruvec);
	struct pglist_data *pgdat = lruvec_pgdat(walk->lruvec);
	DEFINE_MAX_SEQ(walk->lruvec);
	int gen = lru_gen_from_seq(max_seq);

	VM_WARN_ON_ONCE(pud_leaf(*pud));

	/* try to batch at most 1+MIN_LRU_BATCH+1 entries */
	if (*first == -1) {
		*first = addr;
		bitmap_zero(bitmap, MIN_LRU_BATCH);
		return;
	}

	i = addr == -1 ? 0 : pmd_index(addr) - pmd_index(*first);
	if (i && i <= MIN_LRU_BATCH) {
		__set_bit(i - 1, bitmap);
		return;
	}

	pmd = pmd_offset(pud, *first);

	ptl = pmd_lockptr(args->mm, pmd);
	if (!spin_trylock(ptl))
		goto done;

	arch_enter_lazy_mmu_mode();

	do {
		unsigned long pfn;
		struct folio *folio;

		/* don't round down the first address */
		addr = i ? (*first & PMD_MASK) + i * PMD_SIZE : *first;

		if (!pmd_present(pmd[i]))
			goto next;

		if (!pmd_trans_huge(pmd[i])) {
			if (!walk->force_scan && should_clear_pmd_young() &&
			    !mm_has_notifiers(args->mm))
				pmdp_test_and_clear_young(vma, addr, pmd + i);
			goto next;
		}

		pfn = get_pmd_pfn(pmd[i], vma, addr, pgdat);
		if (pfn == -1)
			goto next;

		folio = get_pfn_folio(pfn, memcg, pgdat);
		if (!folio)
			goto next;

		if (!pmdp_clear_young_notify(vma, addr, pmd + i))
			goto next;

		if (last != folio) {
			walk_update_folio(walk, last, gen, dirty);

			last = folio;
			dirty = false;
		}

		if (pmd_dirty(pmd[i]))
			dirty = true;

		walk->mm_stats[MM_LEAF_YOUNG]++;
next:
		i = i > MIN_LRU_BATCH ? 0 : find_next_bit(bitmap, MIN_LRU_BATCH, i) + 1;
	} while (i <= MIN_LRU_BATCH);

	walk_update_folio(walk, last, gen, dirty);

	arch_leave_lazy_mmu_mode();
	spin_unlock(ptl);
done:
	*first = -1;
}

static void walk_pmd_range(pud_t *pud, unsigned long start, unsigned long end,
			   struct mm_walk *args)
{
	int i;
	pmd_t *pmd;
	unsigned long next;
	unsigned long addr;
	struct vm_area_struct *vma;
	DECLARE_BITMAP(bitmap, MIN_LRU_BATCH);
	unsigned long first = -1;
	struct lru_gen_mm_walk *walk = args->private;
	struct lru_gen_mm_state *mm_state = get_mm_state(walk->lruvec);

	VM_WARN_ON_ONCE(pud_leaf(*pud));

	/*
	 * Finish an entire PMD in two passes: the first only reaches to PTE
	 * tables to avoid taking the PMD lock; the second, if necessary, takes
	 * the PMD lock to clear the accessed bit in PMD entries.
	 */
	pmd = pmd_offset(pud, start & PUD_MASK);
restart:
	/* walk_pte_range() may call get_next_vma() */
	vma = args->vma;
	for (i = pmd_index(start), addr = start; addr != end; i++, addr = next) {
		pmd_t val = pmdp_get_lockless(pmd + i);

		next = pmd_addr_end(addr, end);

		if (!pmd_present(val) || is_huge_zero_pmd(val)) {
			walk->mm_stats[MM_LEAF_TOTAL]++;
			continue;
		}

		if (pmd_trans_huge(val)) {
			struct pglist_data *pgdat = lruvec_pgdat(walk->lruvec);
			unsigned long pfn = get_pmd_pfn(val, vma, addr, pgdat);

			walk->mm_stats[MM_LEAF_TOTAL]++;

			if (pfn != -1)
				walk_pmd_range_locked(pud, addr, vma, args, bitmap, &first);
			continue;
		}

		if (!walk->force_scan && should_clear_pmd_young() &&
		    !mm_has_notifiers(args->mm)) {
			if (!pmd_young(val))
				continue;

			walk_pmd_range_locked(pud, addr, vma, args, bitmap, &first);
		}

		if (!walk->force_scan && !test_bloom_filter(mm_state, walk->seq, pmd + i))
			continue;

		walk->mm_stats[MM_NONLEAF_FOUND]++;

		if (!walk_pte_range(&val, addr, next, args))
			continue;

		walk->mm_stats[MM_NONLEAF_ADDED]++;

		/* carry over to the next generation */
		update_bloom_filter(mm_state, walk->seq + 1, pmd + i);
	}

	walk_pmd_range_locked(pud, -1, vma, args, bitmap, &first);

	if (i < PTRS_PER_PMD && get_next_vma(PUD_MASK, PMD_SIZE, args, &start, &end))
		goto restart;
}

static int walk_pud_range(p4d_t *p4d, unsigned long start, unsigned long end,
			  struct mm_walk *args)
{
	int i;
	pud_t *pud;
	unsigned long addr;
	unsigned long next;
	struct lru_gen_mm_walk *walk = args->private;

	VM_WARN_ON_ONCE(p4d_leaf(*p4d));

	pud = pud_offset(p4d, start & P4D_MASK);
restart:
	for (i = pud_index(start), addr = start; addr != end; i++, addr = next) {
		pud_t val = READ_ONCE(pud[i]);

		next = pud_addr_end(addr, end);

		if (!pud_present(val) || WARN_ON_ONCE(pud_leaf(val)))
			continue;

		walk_pmd_range(&val, addr, next, args);

		if (need_resched() || walk->batched >= MAX_LRU_BATCH) {
			end = (addr | ~PUD_MASK) + 1;
			goto done;
		}
	}

	if (i < PTRS_PER_PUD && get_next_vma(P4D_MASK, PUD_SIZE, args, &start, &end))
		goto restart;

	end = round_up(end, P4D_SIZE);
done:
	if (!end || !args->vma)
		return 1;

	walk->next_addr = max(end, args->vma->vm_start);

	return -EAGAIN;
}

static void walk_mm(struct mm_struct *mm, struct lru_gen_mm_walk *walk)
{
	static const struct mm_walk_ops mm_walk_ops = {
		.test_walk = should_skip_vma,
		.p4d_entry = walk_pud_range,
		.walk_lock = PGWALK_RDLOCK,
	};
	int err;
	struct lruvec *lruvec = walk->lruvec;

	walk->next_addr = FIRST_USER_ADDRESS;

	do {
		DEFINE_MAX_SEQ(lruvec);

		err = -EBUSY;

		/* another thread might have called inc_max_seq() */
		if (walk->seq != max_seq)
			break;

		/* the caller might be holding the lock for write */
		if (mmap_read_trylock(mm)) {
			err = walk_page_range(mm, walk->next_addr, ULONG_MAX, &mm_walk_ops, walk);

			mmap_read_unlock(mm);
		}

		if (walk->batched) {
			spin_lock_irq(&lruvec->lru_lock);
			reset_batch_size(walk);
			spin_unlock_irq(&lruvec->lru_lock);
		}

		cond_resched();
	} while (err == -EAGAIN);
}

static struct lru_gen_mm_walk *set_mm_walk(struct pglist_data *pgdat, bool force_alloc)
{
	struct lru_gen_mm_walk *walk = current->reclaim_state->mm_walk;

	if (pgdat && current_is_kswapd()) {
		VM_WARN_ON_ONCE(walk);

		walk = &pgdat->mm_walk;
	} else if (!walk && force_alloc) {
		VM_WARN_ON_ONCE(current_is_kswapd());

		walk = kzalloc(sizeof(*walk), __GFP_HIGH | __GFP_NOMEMALLOC | __GFP_NOWARN);
	}

	current->reclaim_state->mm_walk = walk;

	return walk;
}

static void clear_mm_walk(void)
{
	struct lru_gen_mm_walk *walk = current->reclaim_state->mm_walk;

	VM_WARN_ON_ONCE(walk && memchr_inv(walk->nr_pages, 0, sizeof(walk->nr_pages)));
	VM_WARN_ON_ONCE(walk && memchr_inv(walk->mm_stats, 0, sizeof(walk->mm_stats)));

	current->reclaim_state->mm_walk = NULL;

	if (!current_is_kswapd())
		kfree(walk);
}

static bool inc_min_seq(struct lruvec *lruvec, int type, int swappiness)
{
	int zone;
	int remaining = MAX_LRU_BATCH; // 批量处理控制 (通常=256)
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	int hist = lru_hist_from_seq(lrugen->min_seq[type]); // 历史索引
	int new_gen, old_gen = lru_gen_from_seq(lrugen->min_seq[type]); // 当前代索引

	/* For file type, skip the check if swappiness is anon only */
	/* 文件页且只交换匿名页时跳过 */
	if (type && (swappiness == SWAPPINESS_ANON_ONLY))
		goto done;

	/* For anon type, skip the check if swappiness is zero (file only) */
	/* 匿名页且禁止交换时跳过 */
	if (!type && !swappiness)
		goto done;

	/* prevent cold/hot inversion if the type is evictable */
	for (zone = 0; zone < MAX_NR_ZONES; zone++) {
		struct list_head *head = &lrugen->folios[old_gen][type][zone];

		while (!list_empty(head)) {
			struct folio *folio = lru_to_folio(head);
			int refs = folio_lru_refs(folio);
			bool workingset = folio_test_workingset(folio);

			VM_WARN_ON_ONCE_FOLIO(folio_test_unevictable(folio), folio);
			VM_WARN_ON_ONCE_FOLIO(folio_test_active(folio), folio);
			VM_WARN_ON_ONCE_FOLIO(folio_is_file_lru(folio) != type, folio);
			VM_WARN_ON_ONCE_FOLIO(folio_zonenum(folio) != zone, folio);

			// 提升页面代（不处于回收上下文中）
			new_gen = folio_inc_gen(lruvec, folio, false);
			// 移动到新代链表尾部
			list_move_tail(&folio->lru, &lrugen->folios[new_gen][type][zone]);

			/* don't count the workingset being lazily promoted */
			 // 处理非初始状态页面（有引用历史）
			// refs = ((flags & LRU_REFS_MASK) >> LRU_REFS_PGOFF) + 1，也就是refs对应的标记位处的值+1
			// BIT(LRU_REFS_WIDTH) = 1 << 2，两者想等时，表示flags在LRU_REFS_MASK处全是1，不想等，则只要REFS不全为1即可
			if (refs + workingset != BIT(LRU_REFS_WIDTH) + 1) {
				int tier = lru_tier_from_refs(refs, workingset);
				int delta = folio_nr_pages(folio);

				WRITE_ONCE(lrugen->protected[hist][type][tier],
					   lrugen->protected[hist][type][tier] + delta);
			}

			if (!--remaining)
				return false;
		}
	}
done:
	reset_ctrl_pos(lruvec, type, true);
	WRITE_ONCE(lrugen->min_seq[type], lrugen->min_seq[type] + 1);

	return true;
}

static bool try_to_inc_min_seq(struct lruvec *lruvec, int swappiness)
{
	int gen, type, zone;
	bool success = false;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	DEFINE_MIN_SEQ(lruvec);

	VM_WARN_ON_ONCE(!seq_is_valid(lruvec));

	/* find the oldest populated generation */
	for_each_evictable_type(type, swappiness) {
		while (min_seq[type] + MIN_NR_GENS <= lrugen->max_seq) {
			gen = lru_gen_from_seq(min_seq[type]);

			for (zone = 0; zone < MAX_NR_ZONES; zone++) {
				if (!list_empty(&lrugen->folios[gen][type][zone]))
					goto next;
			}

			min_seq[type]++;
		}
next:
		;
	}

	/* see the comment on lru_gen_folio */
	if (swappiness && swappiness <= MAX_SWAPPINESS) {
		unsigned long seq = lrugen->max_seq - MIN_NR_GENS;

		if (min_seq[LRU_GEN_ANON] > seq && min_seq[LRU_GEN_FILE] < seq)
			min_seq[LRU_GEN_ANON] = seq;
		else if (min_seq[LRU_GEN_FILE] > seq && min_seq[LRU_GEN_ANON] < seq)
			min_seq[LRU_GEN_FILE] = seq;
	}

	for_each_evictable_type(type, swappiness) {
		if (min_seq[type] <= lrugen->min_seq[type])
			continue;

		reset_ctrl_pos(lruvec, type, true);
		WRITE_ONCE(lrugen->min_seq[type], min_seq[type]);
		success = true;
	}

	return success;
}

static bool inc_max_seq(struct lruvec *lruvec, unsigned long seq, int swappiness)
{
	bool success;
	int prev, next;
	int type, zone;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
restart:
	if (seq < READ_ONCE(lrugen->max_seq))
		return false;

	spin_lock_irq(&lruvec->lru_lock);

	VM_WARN_ON_ONCE(!seq_is_valid(lruvec));

	success = seq == lrugen->max_seq;
	if (!success)
		goto unlock;

	for (type = 0; type < ANON_AND_FILE; type++) {
		if (get_nr_gens(lruvec, type) != MAX_NR_GENS)
			continue;

		if (inc_min_seq(lruvec, type, swappiness))
			continue;

		spin_unlock_irq(&lruvec->lru_lock);
		cond_resched();
		goto restart;
	}

	/*
	 * Update the active/inactive LRU sizes for compatibility. Both sides of
	 * the current max_seq need to be covered, since max_seq+1 can overlap
	 * with min_seq[LRU_GEN_ANON] if swapping is constrained. And if they do
	 * overlap, cold/hot inversion happens.
	 */
	prev = lru_gen_from_seq(lrugen->max_seq - 1);
	next = lru_gen_from_seq(lrugen->max_seq + 1);

	for (type = 0; type < ANON_AND_FILE; type++) {
		for (zone = 0; zone < MAX_NR_ZONES; zone++) {
			enum lru_list lru = type * LRU_INACTIVE_FILE;
			long delta = lrugen->nr_pages[prev][type][zone] -
				     lrugen->nr_pages[next][type][zone];

			if (!delta)
				continue;

			__update_lru_size(lruvec, lru, zone, delta);
			__update_lru_size(lruvec, lru + LRU_ACTIVE, zone, -delta);
		}
	}

	for (type = 0; type < ANON_AND_FILE; type++)
		reset_ctrl_pos(lruvec, type, false);

	WRITE_ONCE(lrugen->timestamps[next], jiffies);
	/* make sure preceding modifications appear */
	smp_store_release(&lrugen->max_seq, lrugen->max_seq + 1);
unlock:
	spin_unlock_irq(&lruvec->lru_lock);

	return success;
}

static bool try_to_inc_max_seq(struct lruvec *lruvec, unsigned long seq,
			       int swappiness, bool force_scan)
{
	bool success;
	struct lru_gen_mm_walk *walk;
	struct mm_struct *mm = NULL;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	struct lru_gen_mm_state *mm_state = get_mm_state(lruvec);

	VM_WARN_ON_ONCE(seq > READ_ONCE(lrugen->max_seq));

	if (!mm_state)
		return inc_max_seq(lruvec, seq, swappiness);

	/* see the comment in iterate_mm_list() */
	if (seq <= READ_ONCE(mm_state->seq))
		return false;

	/*
	 * If the hardware doesn't automatically set the accessed bit, fallback
	 * to lru_gen_look_around(), which only clears the accessed bit in a
	 * handful of PTEs. Spreading the work out over a period of time usually
	 * is less efficient, but it avoids bursty page faults.
	 */
	if (!should_walk_mmu()) {
		success = iterate_mm_list_nowalk(lruvec, seq);
		goto done;
	}

	walk = set_mm_walk(NULL, true);
	if (!walk) {
		success = iterate_mm_list_nowalk(lruvec, seq);
		goto done;
	}

	walk->lruvec = lruvec;
	walk->seq = seq;
	walk->swappiness = swappiness;
	walk->force_scan = force_scan;

	do {
		success = iterate_mm_list(walk, &mm);
		if (mm)
			walk_mm(mm, walk);
	} while (mm);
done:
	if (success) {
		success = inc_max_seq(lruvec, seq, swappiness);
		WARN_ON_ONCE(!success);
	}

	return success;
}

/******************************************************************************
 *                          working set protection
 ******************************************************************************/

static void set_initial_priority(struct pglist_data *pgdat, struct scan_control *sc)
{
	int priority;
	unsigned long reclaimable;

	if (sc->priority != DEF_PRIORITY || sc->nr_to_reclaim < MIN_LRU_BATCH)
		return;
	/*
	 * Determine the initial priority based on
	 * (total >> priority) * reclaimed_to_scanned_ratio = nr_to_reclaim,
	 * where reclaimed_to_scanned_ratio = inactive / total.
	 */
	reclaimable = node_page_state(pgdat, NR_INACTIVE_FILE);
	if (can_reclaim_anon_pages(NULL, pgdat->node_id, sc))
		reclaimable += node_page_state(pgdat, NR_INACTIVE_ANON);

	/* round down reclaimable and round up sc->nr_to_reclaim */
	priority = fls_long(reclaimable) - 1 - fls_long(sc->nr_to_reclaim - 1);

	/*
	 * The estimation is based on LRU pages only, so cap it to prevent
	 * overshoots of shrinker objects by large margins.
	 */
	sc->priority = clamp(priority, DEF_PRIORITY / 2, DEF_PRIORITY);
}

static bool lruvec_is_sizable(struct lruvec *lruvec, struct scan_control *sc)
{
	int gen, type, zone;
	unsigned long total = 0;
	int swappiness = get_swappiness(lruvec, sc);
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	DEFINE_MAX_SEQ(lruvec);
	DEFINE_MIN_SEQ(lruvec);

	for_each_evictable_type(type, swappiness) {
		unsigned long seq;

		for (seq = min_seq[type]; seq <= max_seq; seq++) {
			gen = lru_gen_from_seq(seq);

			for (zone = 0; zone < MAX_NR_ZONES; zone++)
				total += max(READ_ONCE(lrugen->nr_pages[gen][type][zone]), 0L);
		}
	}

	/* whether the size is big enough to be helpful */
	return mem_cgroup_online(memcg) ? (total >> sc->priority) : total;
}

static bool lruvec_is_reclaimable(struct lruvec *lruvec, struct scan_control *sc,
				  unsigned long min_ttl)
{
	int gen;
	unsigned long birth;
	int swappiness = get_swappiness(lruvec, sc);
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	DEFINE_MIN_SEQ(lruvec);

	if (mem_cgroup_below_min(NULL, memcg))
		return false;

	if (!lruvec_is_sizable(lruvec, sc))
		return false;

	gen = lru_gen_from_seq(evictable_min_seq(min_seq, swappiness));
	birth = READ_ONCE(lruvec->lrugen.timestamps[gen]);

	return time_is_before_jiffies(birth + min_ttl);
}

/* to protect the working set of the last N jiffies */
static unsigned long lru_gen_min_ttl __read_mostly;

static void lru_gen_age_node(struct pglist_data *pgdat, struct scan_control *sc)
{
	struct mem_cgroup *memcg;
	// 从全局变量lru_gen_min_ttl读取最小TTL(Time-To-Live)值
	unsigned long min_ttl = READ_ONCE(lru_gen_min_ttl);
	// 如果min_ttl为0，则reclaimable初始化为true，否则为false
	bool reclaimable = !min_ttl;

	// 内核警告：确保当前进程是kswapd(内核交换守护进程)
	VM_WARN_ON_ONCE(!current_is_kswapd());

	// 设置初始扫描优先级，基于内存压力和其他因素
	set_initial_priority(pgdat, sc);

	// 开始迭代所有内存控制组(memcg)，从根开始
	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		// 获取当前memcg在指定内存节点上的lruvec(LRU向量)
		struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);

		// 计算当前memcg的内存保护值
		mem_cgroup_calculate_protection(NULL, memcg);

		// 如果之前认为不可回收，检查当前memcg是否有可回收页面
		if (!reclaimable)
			reclaimable = lruvec_is_reclaimable(lruvec, sc, min_ttl);
			/*
				它获取传入的 min_ttl（最小存活时间，单位是秒）。
				它检查指定的 lruvec（一个内存控制组在一个内存节点上的所有LRU列表）中，是否存在任何一个世代，其年龄（创建时间到现在的时间差）大于 min_ttl。
				如果存在这样的世代，说明这个 lruvec 里肯定有“足够老”的、可以安全回收的页面。函数返回 true。
				如果不存在，说明这个 lruvec 里所有页面都“太年轻”了，最近都被访问过。函数返回 false。
				所以，lru_gen_age_node 通过遍历所有 memcg，并调用 lruvec_is_reclaimable 来询问每个 memcg：”你手下有没有老了可以回收的页面？
				“ 只要有一个 memcg 回答“有”，reclaimable 就会变为 true
			*/
	} while ((memcg = mem_cgroup_iter(NULL, memcg, NULL))); // 继续迭代下一个memcg

	/*
     * 主要目标：如果所有memcg的所有代都比min_ttl年轻，则触发OOM kill
     * 但另一种可能是所有memcg都太小或低于最小值
     */
    // 如果未找到可回收页面且成功获取OOM锁(避免并发OOM)
	/*
		它是一个安全阀或最终检查。它在 shrink_node 等函数尝试回收之后被调用。它的逻辑是：
		“我已经让 shrink_node 尽力去回收了。现在让我检查一下，是不是因为所有页面都太年轻（!reclaimable）导致它什么都没回收到？
		如果是这样，并且内存压力依然巨大，那说明我们遇到了极端情况，只能启动终极手段——OOM Killer来杀死进程释放内存了。”
	*/
	if (!reclaimable && mutex_trylock(&oom_lock)) {
		// 准备OOM控制结构
		struct oom_control oc = {
			.gfp_mask = sc->gfp_mask,  // 传递分配掩码
		};

		// 触发Out-of-Memory killer选择进程终止
		out_of_memory(&oc);

		// 释放OOM锁
		mutex_unlock(&oom_lock);
	}
}

/******************************************************************************
 *                          rmap/PT walk feedback
 ******************************************************************************/

/*
 * This function exploits spatial locality when shrink_folio_list() walks the
 * rmap. It scans the adjacent PTEs of a young PTE and promotes hot pages. If
 * the scan was done cacheline efficiently, it adds the PMD entry pointing to
 * the PTE table to the Bloom filter. This forms a feedback loop between the
 * eviction and the aging.
 */
bool lru_gen_look_around(struct page_vma_mapped_walk *pvmw)
{
	int i;
	bool dirty;
	unsigned long start;
	unsigned long end;
	struct lru_gen_mm_walk *walk;
	struct folio *last = NULL;
	int young = 1;
	pte_t *pte = pvmw->pte;
	unsigned long addr = pvmw->address;
	struct vm_area_struct *vma = pvmw->vma;
	struct folio *folio = pfn_folio(pvmw->pfn);
	struct mem_cgroup *memcg = folio_memcg(folio);
	struct pglist_data *pgdat = folio_pgdat(folio);
	struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
	struct lru_gen_mm_state *mm_state = get_mm_state(lruvec);
	DEFINE_MAX_SEQ(lruvec);
	int gen = lru_gen_from_seq(max_seq);

	lockdep_assert_held(pvmw->ptl);
	VM_WARN_ON_ONCE_FOLIO(folio_test_lru(folio), folio);

	if (!ptep_clear_young_notify(vma, addr, pte))
		return false;

	if (spin_is_contended(pvmw->ptl))
		return true;

	/* exclude special VMAs containing anon pages from COW */
	if (vma->vm_flags & VM_SPECIAL)
		return true;

	/* avoid taking the LRU lock under the PTL when possible */
	walk = current->reclaim_state ? current->reclaim_state->mm_walk : NULL;

	start = max(addr & PMD_MASK, vma->vm_start);
	end = min(addr | ~PMD_MASK, vma->vm_end - 1) + 1;

	if (end - start == PAGE_SIZE)
		return true;

	if (end - start > MIN_LRU_BATCH * PAGE_SIZE) {
		if (addr - start < MIN_LRU_BATCH * PAGE_SIZE / 2)
			end = start + MIN_LRU_BATCH * PAGE_SIZE;
		else if (end - addr < MIN_LRU_BATCH * PAGE_SIZE / 2)
			start = end - MIN_LRU_BATCH * PAGE_SIZE;
		else {
			start = addr - MIN_LRU_BATCH * PAGE_SIZE / 2;
			end = addr + MIN_LRU_BATCH * PAGE_SIZE / 2;
		}
	}

	arch_enter_lazy_mmu_mode();

	pte -= (addr - start) / PAGE_SIZE;

	for (i = 0, addr = start; addr != end; i++, addr += PAGE_SIZE) {
		unsigned long pfn;
		pte_t ptent = ptep_get(pte + i);

		pfn = get_pte_pfn(ptent, vma, addr, pgdat);
		if (pfn == -1)
			continue;

		folio = get_pfn_folio(pfn, memcg, pgdat);
		if (!folio)
			continue;

		if (!ptep_clear_young_notify(vma, addr, pte + i))
			continue;

		if (last != folio) {
			walk_update_folio(walk, last, gen, dirty);

			last = folio;
			dirty = false;
		}

		if (pte_dirty(ptent))
			dirty = true;

		young++;
	}

	walk_update_folio(walk, last, gen, dirty);

	arch_leave_lazy_mmu_mode();

	/* feedback from rmap walkers to page table walkers */
	if (mm_state && suitable_to_scan(i, young))
		update_bloom_filter(mm_state, max_seq, pvmw->pmd);

	return true;
}

/******************************************************************************
 *                          memcg LRU
 ******************************************************************************/

/* see the comment on MEMCG_NR_GENS */
enum {
	MEMCG_LRU_NOP,		// 回收操作无实质结果
	MEMCG_LRU_HEAD,		// 回收困难，需持续关注
	MEMCG_LRU_TAIL,		// 回收成功，让其“休息”
	MEMCG_LRU_OLD,		// 内存访问频率低
	MEMCG_LRU_YOUNG,	// 内存访问频率高
};

static void lru_gen_rotate_memcg(struct lruvec *lruvec, int op)
{
	int seg;
	int old, new;
	unsigned long flags;
	int bin = get_random_u32_below(MEMCG_NR_BINS);
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);

	spin_lock_irqsave(&pgdat->memcg_lru.lock, flags);

	VM_WARN_ON_ONCE(hlist_nulls_unhashed(&lruvec->lrugen.list));

	seg = 0;
	new = old = lruvec->lrugen.gen;

	/* see the comment on MEMCG_NR_GENS */
	if (op == MEMCG_LRU_HEAD)
		seg = MEMCG_LRU_HEAD;
	else if (op == MEMCG_LRU_TAIL)
		seg = MEMCG_LRU_TAIL;
	else if (op == MEMCG_LRU_OLD)
		new = get_memcg_gen(pgdat->memcg_lru.seq);
	else if (op == MEMCG_LRU_YOUNG)
		new = get_memcg_gen(pgdat->memcg_lru.seq + 1);
	else
		VM_WARN_ON_ONCE(true);

	WRITE_ONCE(lruvec->lrugen.seg, seg);
	WRITE_ONCE(lruvec->lrugen.gen, new);

	hlist_nulls_del_rcu(&lruvec->lrugen.list);

	if (op == MEMCG_LRU_HEAD || op == MEMCG_LRU_OLD)
		hlist_nulls_add_head_rcu(&lruvec->lrugen.list, &pgdat->memcg_lru.fifo[new][bin]);
	else
		hlist_nulls_add_tail_rcu(&lruvec->lrugen.list, &pgdat->memcg_lru.fifo[new][bin]);

	pgdat->memcg_lru.nr_memcgs[old]--;
	pgdat->memcg_lru.nr_memcgs[new]++;

	if (!pgdat->memcg_lru.nr_memcgs[old] && old == get_memcg_gen(pgdat->memcg_lru.seq))
		WRITE_ONCE(pgdat->memcg_lru.seq, pgdat->memcg_lru.seq + 1);

	spin_unlock_irqrestore(&pgdat->memcg_lru.lock, flags);
}

#ifdef CONFIG_MEMCG

void lru_gen_online_memcg(struct mem_cgroup *memcg)
{
	int gen;
	int nid;
	int bin = get_random_u32_below(MEMCG_NR_BINS);

	for_each_node(nid) {
		struct pglist_data *pgdat = NODE_DATA(nid);
		struct lruvec *lruvec = get_lruvec(memcg, nid);

		spin_lock_irq(&pgdat->memcg_lru.lock);

		VM_WARN_ON_ONCE(!hlist_nulls_unhashed(&lruvec->lrugen.list));

		gen = get_memcg_gen(pgdat->memcg_lru.seq);

		lruvec->lrugen.gen = gen;

		hlist_nulls_add_tail_rcu(&lruvec->lrugen.list, &pgdat->memcg_lru.fifo[gen][bin]);
		pgdat->memcg_lru.nr_memcgs[gen]++;

		spin_unlock_irq(&pgdat->memcg_lru.lock);
	}
}

void lru_gen_offline_memcg(struct mem_cgroup *memcg)
{
	int nid;

	for_each_node(nid) {
		struct lruvec *lruvec = get_lruvec(memcg, nid);

		lru_gen_rotate_memcg(lruvec, MEMCG_LRU_OLD);
	}
}

void lru_gen_release_memcg(struct mem_cgroup *memcg)
{
	int gen;
	int nid;

	for_each_node(nid) {
		struct pglist_data *pgdat = NODE_DATA(nid);
		struct lruvec *lruvec = get_lruvec(memcg, nid);

		spin_lock_irq(&pgdat->memcg_lru.lock);

		if (hlist_nulls_unhashed(&lruvec->lrugen.list))
			goto unlock;

		gen = lruvec->lrugen.gen;

		hlist_nulls_del_init_rcu(&lruvec->lrugen.list);
		pgdat->memcg_lru.nr_memcgs[gen]--;

		if (!pgdat->memcg_lru.nr_memcgs[gen] && gen == get_memcg_gen(pgdat->memcg_lru.seq))
			WRITE_ONCE(pgdat->memcg_lru.seq, pgdat->memcg_lru.seq + 1);
unlock:
		spin_unlock_irq(&pgdat->memcg_lru.lock);
	}
}

void lru_gen_soft_reclaim(struct mem_cgroup *memcg, int nid)
{
	struct lruvec *lruvec = get_lruvec(memcg, nid);

	/* see the comment on MEMCG_NR_GENS */
	if (READ_ONCE(lruvec->lrugen.seg) != MEMCG_LRU_HEAD)
		lru_gen_rotate_memcg(lruvec, MEMCG_LRU_HEAD);
}

#endif /* CONFIG_MEMCG */

/******************************************************************************
 *                          the eviction
 ******************************************************************************/

static bool sort_folio(struct lruvec *lruvec, struct folio *folio, struct scan_control *sc,
		       int tier_idx)
{
	bool success;
	bool dirty, writeback;
	int gen = folio_lru_gen(folio);
	int type = folio_is_file_lru(folio);
	int zone = folio_zonenum(folio);
	int delta = folio_nr_pages(folio);
	int refs = folio_lru_refs(folio);
	bool workingset = folio_test_workingset(folio);
	int tier = lru_tier_from_refs(refs, workingset);
	struct lru_gen_folio *lrugen = &lruvec->lrugen;

	VM_WARN_ON_ONCE_FOLIO(gen >= MAX_NR_GENS, folio);

	/* unevictable */
	if (!folio_evictable(folio)) {
		success = lru_gen_del_folio(lruvec, folio, true);
		VM_WARN_ON_ONCE_FOLIO(!success, folio);
		folio_set_unevictable(folio);
		lruvec_add_folio(lruvec, folio);
		__count_vm_events(UNEVICTABLE_PGCULLED, delta);
		return true;
	}

	/* promoted */
	if (gen != lru_gen_from_seq(lrugen->min_seq[type])) {
		list_move(&folio->lru, &lrugen->folios[gen][type][zone]);
		return true;
	}

	/* protected */
	if (tier > tier_idx || refs + workingset == BIT(LRU_REFS_WIDTH) + 1) {
		gen = folio_inc_gen(lruvec, folio, false);
		list_move(&folio->lru, &lrugen->folios[gen][type][zone]);

		/* don't count the workingset being lazily promoted */
		if (refs + workingset != BIT(LRU_REFS_WIDTH) + 1) {
			int hist = lru_hist_from_seq(lrugen->min_seq[type]);

			WRITE_ONCE(lrugen->protected[hist][type][tier],
				   lrugen->protected[hist][type][tier] + delta);
		}
		return true;
	}

	/* ineligible */
	if (!folio_test_lru(folio) || zone > sc->reclaim_idx) {
		gen = folio_inc_gen(lruvec, folio, false);
		list_move_tail(&folio->lru, &lrugen->folios[gen][type][zone]);
		return true;
	}

	dirty = folio_test_dirty(folio);
	writeback = folio_test_writeback(folio);
	if (type == LRU_GEN_FILE && dirty) {
		sc->nr.file_taken += delta;
		if (!writeback)
			sc->nr.unqueued_dirty += delta;
	}

	/* waiting for writeback */
	if (writeback || (type == LRU_GEN_FILE && dirty)) {
		gen = folio_inc_gen(lruvec, folio, true);
		list_move(&folio->lru, &lrugen->folios[gen][type][zone]);
		return true;
	}

	return false;
}

static bool isolate_folio(struct lruvec *lruvec, struct folio *folio, struct scan_control *sc)
{
	bool success;

	/* swap constrained */
	if (!(sc->gfp_mask & __GFP_IO) &&
	    (folio_test_dirty(folio) ||
	     (folio_test_anon(folio) && !folio_test_swapcache(folio))))
		return false;

	/* raced with release_pages() */
	if (!folio_try_get(folio))
		return false;

	/* raced with another isolation */
	if (!folio_test_clear_lru(folio)) {
		folio_put(folio);
		return false;
	}

	/* see the comment on LRU_REFS_FLAGS */
	if (!folio_test_referenced(folio))
		set_mask_bits(&folio->flags, LRU_REFS_MASK, 0);

	/* for shrink_folio_list() */
	folio_clear_reclaim(folio);

	success = lru_gen_del_folio(lruvec, folio, true);
	VM_WARN_ON_ONCE_FOLIO(!success, folio);

	return true;
}

static int scan_folios(struct lruvec *lruvec, struct scan_control *sc,
		       int type, int tier, struct list_head *list)
{
	int i;
	int gen;
	enum vm_event_item item;
	int sorted = 0;
	int scanned = 0;
	int isolated = 0;
	int skipped = 0;
	int remaining = MAX_LRU_BATCH;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);

	VM_WARN_ON_ONCE(!list_empty(list));

	if (get_nr_gens(lruvec, type) == MIN_NR_GENS)
		return 0;

	gen = lru_gen_from_seq(lrugen->min_seq[type]);

	for (i = MAX_NR_ZONES; i > 0; i--) {
		LIST_HEAD(moved);
		int skipped_zone = 0;
		int zone = (sc->reclaim_idx + i) % MAX_NR_ZONES;
		struct list_head *head = &lrugen->folios[gen][type][zone];

		while (!list_empty(head)) {
			struct folio *folio = lru_to_folio(head);
			int delta = folio_nr_pages(folio);

			VM_WARN_ON_ONCE_FOLIO(folio_test_unevictable(folio), folio);
			VM_WARN_ON_ONCE_FOLIO(folio_test_active(folio), folio);
			VM_WARN_ON_ONCE_FOLIO(folio_is_file_lru(folio) != type, folio);
			VM_WARN_ON_ONCE_FOLIO(folio_zonenum(folio) != zone, folio);

			scanned += delta;

			if (sort_folio(lruvec, folio, sc, tier))
				sorted += delta;
			else if (isolate_folio(lruvec, folio, sc)) {
				list_add(&folio->lru, list);
				isolated += delta;
			} else {
				list_move(&folio->lru, &moved);
				skipped_zone += delta;
			}

			if (!--remaining || max(isolated, skipped_zone) >= MIN_LRU_BATCH)
				break;
		}

		if (skipped_zone) {
			list_splice(&moved, head);
			__count_zid_vm_events(PGSCAN_SKIP, zone, skipped_zone);
			skipped += skipped_zone;
		}

		if (!remaining || isolated >= MIN_LRU_BATCH)
			break;
	}

	item = PGSCAN_KSWAPD + reclaimer_offset(sc);
	if (!cgroup_reclaim(sc)) {
		__count_vm_events(item, isolated);
		__count_vm_events(PGREFILL, sorted);
	}
	count_memcg_events(memcg, item, isolated);
	count_memcg_events(memcg, PGREFILL, sorted);
	__count_vm_events(PGSCAN_ANON + type, isolated);
	trace_mm_vmscan_lru_isolate(sc->reclaim_idx, sc->order, MAX_LRU_BATCH,
				scanned, skipped, isolated,
				type ? LRU_INACTIVE_FILE : LRU_INACTIVE_ANON);
	if (type == LRU_GEN_FILE)
		sc->nr.file_taken += isolated;
	/*
	 * There might not be eligible folios due to reclaim_idx. Check the
	 * remaining to prevent livelock if it's not making progress.
	 */
	return isolated || !remaining ? scanned : 0;
}

static int get_tier_idx(struct lruvec *lruvec, int type)
{
	int tier;
	struct ctrl_pos sp, pv;

	/*
	 * To leave a margin for fluctuations, use a larger gain factor (2:3).
	 * This value is chosen because any other tier would have at least twice
	 * as many refaults as the first tier.
	 */
	read_ctrl_pos(lruvec, type, 0, 2, &sp);
	for (tier = 1; tier < MAX_NR_TIERS; tier++) {
		read_ctrl_pos(lruvec, type, tier, 3, &pv);
		if (!positive_ctrl_err(&sp, &pv))
			break;
	}

	return tier - 1;
}

static int get_type_to_scan(struct lruvec *lruvec, int swappiness)
{
	struct ctrl_pos sp, pv;

	// 边界情况1：完全避免swap
	if (swappiness <= MIN_SWAPPINESS + 1)
		return LRU_GEN_FILE;

	// 边界情况2：积极使用swap
	if (swappiness >= MAX_SWAPPINESS)
		return LRU_GEN_ANON;
	/*
	 * Compare the sum of all tiers of anon with that of file to determine
	 * which type to scan.
	 */
	/*
     * 比较所有层级的匿名页和文件页的总和，
     * 以确定要扫描的类型
     */
	// 结构体包括 sp/pv->refaulted sp/pv->total
	// 读取匿名页控制位置（使用实际swappiness作为增益）
	read_ctrl_pos(lruvec, LRU_GEN_ANON, MAX_NR_TIERS, swappiness, &sp);
	// 读取文件页控制位置（使用互补值作为增益）
	read_ctrl_pos(lruvec, LRU_GEN_FILE, MAX_NR_TIERS, MAX_SWAPPINESS - swappiness, &pv);

	// 通过比较决定优先扫描类型
	return positive_ctrl_err(&sp, &pv);
}

static int isolate_folios(struct lruvec *lruvec, struct scan_control *sc, int swappiness,
			  int *type_scanned, struct list_head *list)
{
	int i;
	int type = get_type_to_scan(lruvec, swappiness);

	for_each_evictable_type(i, swappiness) {
		int scanned;
		int tier = get_tier_idx(lruvec, type);

		*type_scanned = type;

		scanned = scan_folios(lruvec, sc, type, tier, list);
		if (scanned)
			return scanned;

		type = !type;
	}

	return 0;
}

/*
	作用：从给定的 LRU 向量 (lruvec) 中隔离出一批页面，并尝试实际回收（evict）它们。它管理了从 LRU 列表隔离到最终释放的整个生命周期。
	参数：
		lruvec: 要执行回收的目标 LRU 向量。
		sc: 扫描控制结构，包含回收上下文。
		swappiness: 控制匿名页与文件页回收权重的值。
	返回值：返回成功扫描的页面数量（注意：不一定是回收的数量）。
*/
static int evict_folios(struct lruvec *lruvec, struct scan_control *sc, int swappiness)
{
	int type;							// 将记录本次回收的主要类型（匿名页或文件页）
	int scanned;
	int reclaimed;						// 用于记录扫描和回收的页面数
	LIST_HEAD(list);					// 两个链表头，用于临时存放从 LRU 列表隔离（isolate） 出来的页面。
	LIST_HEAD(clean);					// list 是主要的工作链表，clean 用于存放需要重试的页面
	struct folio *folio;
	struct folio *next;					// 用于遍历链表的指针
	enum vm_event_item item;
	struct reclaim_stat stat;			// 用于记录回收过程的详细统计信息
	struct lru_gen_mm_walk *walk;		// 指向 MM walker 结构，用于处理页表遍历
	bool skip_retry = false;			//  一个标志，控制是否跳过重试逻辑
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);	// 获取相关联的 LRUGen 结构、内存控制组和 NUMA 节点信息

	// 获取锁：获取保护 lruvec 链表的自旋锁，并禁用本地中断。这是必需的，因为接下来要修改链表结构
	spin_lock_irq(&lruvec->lru_lock);

	/*
		核心操作1 - 隔离：调用 isolate_folios。这是最关键的函数之一。它根据 LRUGen 的代际信息、swappiness 设置和扫描优先级，
		从“最老”的代中精心挑选出一批候选页面，将它们从 LRU 链表中移除，并加入到临时链表 list 中。scanned 记录了这次隔离了多少页面
	*/
	scanned = isolate_folios(lruvec, sc, swappiness, &type, &list);

	/*
		核心操作2 - 推进代序：调用 try_to_inc_min_seq。如果可能，它尝试增加 lrugen->min_seq（最小代序）。这意味着所有比这个
		新代序更老的页面都已经被回收或没有效用了。这是 LRUGen 算法管理代际的核心。
	*/
	scanned += try_to_inc_min_seq(lruvec, swappiness);

	/*
		有效性检查：检查可回收的最老代序是否与当前最大代序过于接近。如果是，说明代际轮转太快，可能没有足够的页面可供回收，
		此时将 scanned 重置为 0，暗示本次回收无效。
	*/
	if (evictable_min_seq(lrugen->min_seq, swappiness) + MIN_NR_GENS > lrugen->max_seq)
		scanned = 0;

	// 释放锁：释放 LRU 锁。这是一个重要的优化：实际耗时的页面回收操作（如I/O）将在无锁的情况下进行，避免长时间阻塞其他操作。
	spin_unlock_irq(&lruvec->lru_lock);

	// 空检查：如果隔离出来的链表是空的（没有找到可回收的页面），则直接返回扫描的页面数。
	if (list_empty(&list))
		return scanned;
retry:
	/*
		核心操作3 - 回收：调用 shrink_folio_list。这是另一个最关键的函数，它负责实际处理 list 中的每一个页面：
		匿名页：写入交换分区（swap out）。
		干净的文件页：直接丢弃。
		脏的文件页：安排回写（writeback）到磁盘。
		最终，将成功处理的页面从其映射中解除，并释放其内存。
		reclaimed 记录了成功回收的页面数。
	*/
	reclaimed = shrink_folio_list(&list, pgdat, sc, &stat, false, memcg);

	// 统计脏页：将本次回收中遇到的、无法立即加入回写队列的脏页数量累加到全局计数器。这是之前提到的触发 wakeup_flusher_threads 的关键数据。
	sc->nr.unqueued_dirty += stat.nr_unqueued_dirty;

	// 累计回收数：将本次回收的页面数累加到全局回收计数中。
	sc->nr_reclaimed += reclaimed;
	// 跟踪点：发出一个内核跟踪事件，用于调试和性能分析。工具如 perf 或 trace-cmd 可以捕获此事件。
	trace_mm_vmscan_lru_shrink_inactive(pgdat->node_id,
			scanned, reclaimed, &stat, sc->priority,
			type ? LRU_INACTIVE_FILE : LRU_INACTIVE_ANON);

	// 遍历剩余链表：反向遍历 list 链表。此时链表中包含的是未能被 shrink_folio_list 成功回收的页面。
	list_for_each_entry_safe_reverse(folio, next, &list, lru) {
		DEFINE_MIN_SEQ(lruvec);

		// 不可回收页处理：如果页面变得不可回收（例如，被 mlock 锁定），则将其从临时链表中删除，并放回其对应的 LRU 链表。
		if (!folio_evictable(folio)) {
			list_del(&folio->lru);
			folio_putback_lru(folio);
			continue;
		}

		// 重试候选页：如果页面非活跃、无映射、干净、不在回写中，说明它可能是一个很好的候选者，只是上次回收时可能错过了
		// 某些状态更新。将其移动到 clean 链表，准备进行重试。
		if (!skip_retry && !folio_test_active(folio) && !folio_mapped(folio) &&
		    !folio_test_dirty(folio) && !folio_test_writeback(folio)) {
			list_move(&folio->lru, &clean);
			continue;
		}

		// 拒绝页处理：对于那些属于最老代序 (min_seq) 却又回收失败的页面，通过强制设置 PG_active 标志
		// 来将其暂时排除在下一轮的回收范围之外，防止无限循环地尝试回收它们。
		if (lru_gen_folio_seq(lruvec, folio, false) == min_seq[type])
			set_mask_bits(&folio->flags, LRU_REFS_FLAGS, BIT(PG_active));
	}

	// 加锁并放回：重新获取 LRU 锁，将处理完的剩余页面（不包括已移到 clean 的）重新移回适当的 LRU 链表。
	spin_lock_irq(&lruvec->lru_lock);
	move_folios_to_lru(lruvec, &list);

	// 处理 MM Walker：如果当前回收上下文中存在批处理的页表遍历状态，则重置其批处理大小，可能与后续的页表访问位更新有关。
	// current->reclaim_state：当内存回收在执行直接回收（在进程上下文中）时，它会在进程的 task_struct 中存储一个
	// reclaim_state 结构，用于记录与本次回收相关的状态信息。
	walk = current->reclaim_state->mm_walk;	// 这行代码获取了与当前正在执行回收的进程相关联的页表遍历器
	// walk->batched 为 true：这是一个标志，表示这个遍历器正处于批处理模式
	// 批处理模式：为了提升效率，LRUGen 不会每处理一个页面就遍历一次页表，而是会“攒”一批页面，然后一次性遍历页表来收集
	// 所有这些页面的访问信息。walk->batched 为 true 就意味着这个遍历器正在执行这种批量操作。
	if (walk && walk->batched) {
		/*
			重置目标 LRU 向量：将页表遍历器的 lruvec 字段指向刚刚完成回收操作的 LRU 向量（即当前函数的参数 lruvec）。
			为什么需要这个？ 因为页表遍历器 (walk) 可能被多个 LRU 向量共享或重用。在完成对一个 lruvec 的操作后，需要
			更新遍历器的上下文，以确保后续的页表遍历（如果发生）收集到的信息会关联到正确的 LRU 向量上。
		*/
		walk->lruvec = lruvec;
		/*
			重置批处理大小：调用 reset_batch_size 函数。
			这个函数做什么？ 它的内部逻辑通常是：walk->max_batch = MAX_BATCH_SIZE; 或类似的代码。它将遍历器内部用于跟踪
			批处理进度的计数器重置为初始的最大值。
			为什么需要这个？ 批处理机制通常有一个预算（例如，最多一次收集 64 个页面的信息）。当一次批处理操作完成后
			（例如，为当前的 lruvec 完成了回收），需要“重置预算”，为下一次可能发生的批处理操作做好准备。这确保了每次批处理
			都有一个公平的、全额的初始预算，避免上一次的消耗影响到下一次。
		*/
		reset_batch_size(walk);
	}

	// 更新统计信息：更新 LRU 向量、内存控制组和全局 VM 的多种统计事件计数器（如 PGSTEAL_KSWAPD, PGSTEAL_ANON），
	// 这些信息可通过 /proc/vmstat 查看。
	__mod_lruvec_state(lruvec, PGDEMOTE_KSWAPD + reclaimer_offset(sc),
					stat.nr_demoted);

	item = PGSTEAL_KSWAPD + reclaimer_offset(sc);
	if (!cgroup_reclaim(sc))
		__count_vm_events(item, reclaimed);
	count_memcg_events(memcg, item, reclaimed);
	__count_vm_events(PGSTEAL_ANON + type, reclaimed);

	// 最终释放锁：释放 LRU 锁。
	spin_unlock_irq(&lruvec->lru_lock);

	// 重试：将之前分离到 clean 链表中的、被认为值得重试的页面，重新合并回主工作链表 list。如果这个链表不为空，
	// 则设置 skip_retry 标志（防止无限重试），并跳转回 retry 标签处，再次调用 shrink_folio_list 尝试回收它们。
	list_splice_init(&clean, &list);
	if (!list_empty(&list)) {
		skip_retry = true;
		goto retry;
	}

	// 返回：返回最初成功扫描/隔离的页面数量。
	return scanned;
}

static bool should_run_aging(struct lruvec *lruvec, unsigned long max_seq,
			     int swappiness, unsigned long *nr_to_scan)
{
	int gen, type, zone;
	unsigned long size = 0;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	DEFINE_MIN_SEQ(lruvec);

	*nr_to_scan = 0;
	/* have to run aging, since eviction is not possible anymore */
	if (evictable_min_seq(min_seq, swappiness) + MIN_NR_GENS > max_seq)
		return true;

	for_each_evictable_type(type, swappiness) {
		unsigned long seq;

		for (seq = min_seq[type]; seq <= max_seq; seq++) {
			gen = lru_gen_from_seq(seq);

			for (zone = 0; zone < MAX_NR_ZONES; zone++)
				size += max(READ_ONCE(lrugen->nr_pages[gen][type][zone]), 0L);
		}
	}

	*nr_to_scan = size;
	/* better to run aging even though eviction is still possible */
	return evictable_min_seq(min_seq, swappiness) + MIN_NR_GENS == max_seq;
}

/*
 * For future optimizations:
 * 1. Defer try_to_inc_max_seq() to workqueues to reduce latency for memcg
 *    reclaim.
 */
static long get_nr_to_scan(struct lruvec *lruvec, struct scan_control *sc, int swappiness)
{
	bool success;
	unsigned long nr_to_scan;
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	DEFINE_MAX_SEQ(lruvec);

	if (mem_cgroup_below_min(sc->target_mem_cgroup, memcg))
		return -1;

	success = should_run_aging(lruvec, max_seq, swappiness, &nr_to_scan);

	/* try to scrape all its memory if this memcg was deleted */
	if (nr_to_scan && !mem_cgroup_online(memcg))
		return nr_to_scan;

	/* try to get away with not aging at the default priority */
	if (!success || sc->priority == DEF_PRIORITY)
		return nr_to_scan >> sc->priority;

	/* stop scanning this lruvec as it's low on cold folios */
	return try_to_inc_max_seq(lruvec, max_seq, swappiness, false) ? -1 : 0;
}

static bool should_abort_scan(struct lruvec *lruvec, struct scan_control *sc)
{
	int i;
	enum zone_watermarks mark;

	/* don't abort memcg reclaim to ensure fairness */
	if (!root_reclaim(sc))
		return false;

	if (sc->nr_reclaimed >= max(sc->nr_to_reclaim, compact_gap(sc->order)))
		return true;

	/* check the order to exclude compaction-induced reclaim */
	if (!current_is_kswapd() || sc->order)
		return false;

	mark = sysctl_numa_balancing_mode & NUMA_BALANCING_MEMORY_TIERING ?
	       WMARK_PROMO : WMARK_HIGH;

	for (i = 0; i <= sc->reclaim_idx; i++) {
		struct zone *zone = lruvec_pgdat(lruvec)->node_zones + i;
		unsigned long size = wmark_pages(zone, mark) + MIN_LRU_BATCH;

		if (managed_zone(zone) && !zone_watermark_ok(zone, 0, size, sc->reclaim_idx, 0))
			return false;
	}

	/* kswapd should abort if all eligible zones are safe */
	return true;
}

/*
	作用：对一个给定的 LRU 向量 (lruvec) 进行内存页面回收的尝试。它会尝试回收该向量中一定数量的页面。
	参数：
		lruvec: 指向要回收的目标 LRU 向量的指针（代表一个 memcg 在某个 NUMA 节点上的内存）。
		sc: 指向扫描控制结构的指针，包含了回收的上下文信息（如优先级、分配阶数等）。
	返回值：返回一个布尔值，表示是否应该旋转（调整）该 LRU 向量在队列中的位置。true 表示应该调整，false 表示不需要。
*/
static bool try_to_shrink_lruvec(struct lruvec *lruvec, struct scan_control *sc)
{
	long nr_to_scan;								// 本次函数调用计划要扫描的页面总数。它是一个动态计算的值。
	unsigned long scanned = 0;						// 用于记录在当前循环中已经成功扫描的页面数量。
	int swappiness = get_swappiness(lruvec, sc);	// 通过 get_swappiness() 获取交换倾向性值。这个值决定了回收时在匿名页和文件页
													// 之间的偏好程度（0-200）。0 表示尽量避免交换匿名页，200 表示积极交换。
	while (true) {
		int delta;									// 用于记录单次 evict_folios 调用实际回收的页面数量。

		// 关键函数。它根据当前内存压力 (sc->priority)、LRUGen 的代际信息、以及 swappiness 设置，计算出本次循环期望回收的页面数量。
		// 这个值可能是正数，也可能是 0 或负数（后面会解释）。
		nr_to_scan = get_nr_to_scan(lruvec, sc, swappiness);
		/*
			退出条件 1：如果 get_nr_to_scan 返回的值小于等于 0，说明：
				要么没有更多页面需要扫描了（例如，该代的所有页面都已扫描过）。
				要么系统压力不大，不需要继续扫描。
				此时直接跳出循环。
		*/
		if (nr_to_scan <= 0)
			break;

		/*
			核心回收函数：evict_folios 是真正执行页面回收工作的函数。它：
			从 lruvec 的 LRU 列表中选出最合适的候选页面（通常是“最老”一代的页面）。
			根据页面类型和 swappiness 设置，决定是回收文件页还是匿名页。
			对于文件页：如果是脏页，会安排回写（writeback），然后将其从缓存中移除。
			对于匿名页：将其内容换出（swap out）到交换空间。
			最终解除页面与物理内存的映射，并将其释放回伙伴系统（Buddy System）。
			返回值：delta 表示本次调用实际成功回收的页面数量。
		*/
		delta = evict_folios(lruvec, sc, swappiness);
		/*
			退出条件 2：如果 delta 为 0，表示这次 evict_folios 调用没有成功回收任何页面。这可能是因为：
			所有找到的页面都被锁定了（mlock）或正在忙。
			所有文件页都是脏的，并且回写设备很慢，无法立即回收。
			没有可回收的页面了。
			既然这次调用一无所获，继续循环很可能也是徒劳，所以跳出循环。
		*/
		if (!delta)
			break;

		/*
			累计与退出条件 3：将本次回收的页面数 delta 累加到 scanned 中。
			如果累计回收的页面数已经达到或超过了本次循环计划扫描的数量 (nr_to_scan)，则任务完成，跳出循环。
		*/
		scanned += delta;
		if (scanned >= nr_to_scan)
			break;

		/*
			退出条件 4：检查是否应该中止扫描。should_abort_scan 可能返回 true 的原因包括：
			已经回收了足够的内存，满足了最初的请求。
			回收线程的运行时间片已用完。
			有更高优先级的任务需要运行。
			这是保证回收行为不会过度影响系统响应性的重要检查。
		*/
		if (should_abort_scan(lruvec, sc))
			break;

		/*
			主动调度：cond_resched() 是一个自愿让出 CPU 的提示。在长时间运行的循环中，它允许内核调度器有机会运行
			其他任务，防止回收线程独占CPU，从而避免系统卡顿和无响应。
		*/
		cond_resched();
	}

	/*
		处理脏页拥堵：这是一个非常重要的后处理步骤。
		sc->nr.file_taken: 在扫描过程中遇到的文件页的数量。
		sc->nr.unqueued_dirty: 其中，是脏的但还没有被加入到回写（writeback）队列的页面数量。
		条件判断：如果发现所有遇到的脏文件页都没有被成功加入回写队列（unqueued_dirty == file_taken），说明脏页的回写流程可能遇到了瓶颈或停滞。
		操作：此时，主动调用 wakeup_flusher_threads 来唤醒负责回写的内核线程（flusher threads），加速脏页的刷新，为后续的回收尝试创造条件。
	 */
	if (sc->nr.unqueued_dirty && sc->nr.unqueued_dirty == sc->nr.file_taken)
		wakeup_flusher_threads(WB_REASON_VMSCAN);

	/*
		最终返回值：函数的返回值是 (nr_to_scan < 0)。
		回想前面的 nr_to_scan = get_nr_to_scan(...)，这个函数在某些情况下会返回一个负值。这通常发生在系统内存压力非常小，
		扫描器处于“节能”模式，或者该 lruvec 需要被跳过时。
		因此，如果 nr_to_scan 是负数，函数返回 true，这是在向调用者 (shrink_one) 发送一个信号：“这个 lruvec 的回收工作
		已经完成或应该被跳过，可以考虑调整它在队列中的位置了（例如，把它移到更年轻的代）。”
		如果 nr_to_scan 是正数（说明是因为其他 break 条件退出，可能还有工作没做完），则返回 false，表示不需要调整。
	*/
	return nr_to_scan < 0;
}

/*
	对给定的 lruvec（代表一个 memcg 在某个 NUMA 节点上的内存）执行一次内存回收扫描。
	参数：
		lruvec: 指向要回收的目标 LRU 向量的指针。
		sc: 指向扫描控制结构的指针，包含了回收的上下文信息（如优先级、分配阶数等）。
	返回值：返回一个 enum 值（如 MEMCG_LRU_YOUNG, MEMCG_LRU_TAIL），用于指示调用方应如何调整该 memcg 在回收队列中的位置。
*/
static int shrink_one(struct lruvec *lruvec, struct scan_control *sc)
{
	bool success;					// 用于记录本次回收是否成功。
	unsigned long scanned = sc->nr_scanned;
	unsigned long reclaimed = sc->nr_reclaimed;			// 保存扫描开始前的初始值。用于计算本次函数调用实际扫描和回收的页面数（本次增量 = 结束时值 - 开始时值）。
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);	// 从 lruvec 中获取其所属的内存控制组。
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);	// 从 lruvec 中获取其所属的 NUMA 节点。

	/*
		最低保护检查：检查该 memcg 的内存使用是否低于其 memory.min 阈值。这是一个硬性保护线，表示该组的内存已达到生存所需的最低限度。
		操作：如果低于 min，则立即返回 MEMCG_LRU_YOUNG，不再进行任何回收。这相当于告诉上层：“这个组的内存已经少到不能少了，别再回收它了，把它移到年轻代保护起来。”
	*/
	if (mem_cgroup_below_min(NULL, memcg))
		return MEMCG_LRU_YOUNG;

	/*
		低水位保护检查：检查该 memcg 的内存使用是否低于其 memory.low 阈值。这是一个软性保护线，表示该组的内存使用已进入受保护范围，应尽量避免回收。
		操作：
		如果低于 low，并且它尚未被标记为 MEMCG_LRU_TAIL（即不在队列末尾），则返回 MEMCG_LRU_TAIL。意思是：“这个组受保护了，别急着回收它，先把它移到队列末尾，
		让别人先顶上去。”
		如果它已经在队列末尾了（seg == MEMCG_LRU_TAIL），则触发一个 MEMCG_LOW 事件（通知用户空间），然后继续执行后面的回收逻辑。因为如果所有组都在 low 以下，
		系统总得回收一些内存，不能完全停止。
	*/
	if (mem_cgroup_below_low(NULL, memcg)) {
		/* see the comment on MEMCG_NR_GENS */
		if (READ_ONCE(lruvec->lrugen.seg) != MEMCG_LRU_TAIL)
			return MEMCG_LRU_TAIL;

		memcg_memory_event(memcg, MEMCG_LOW);
	}

	/*
		核心回收操作：调用 try_to_shrink_lruvec 函数。这是真正执行页面回收的地方，它会扫描 lruvec 中的 LRU 列表，尝试回收（释放）一些页面。
		结果：将返回值存入 success，表示是否成功回收到页面。
	*/
	success = try_to_shrink_lruvec(lruvec, sc);

	// Slab 缓存回收：在回收了页面缓存之后，尝试回收该 memcg 相关的 Slab 缓存（如 dentry, inode 缓存等）。这是内存回收的另一重要组成部分。
	shrink_slab(sc->gfp_mask, pgdat->node_id, memcg, sc->priority);

	/*
		内存压力通知：如果本次回收是直接回收（!sc->proactive，即由应用程序的分配请求同步触发，而非后台线程 kswapd），则计算本次调用中实际扫描
		和回收的页面数（通过减掉之前保存的初始值得到增量），并通过 vmpressure 机制产生内存压力事件。这用于通知用户空间（如 Android LMKD）内存
		压力状况，使其可以采取相应措施（如杀死进程）。
	*/
	if (!sc->proactive)
		vmpressure(sc->gfp_mask, memcg, false, sc->nr_scanned - scanned,
			   sc->nr_reclaimed - reclaimed);

	// 刷新回收状态：将本次回收的统计信息（如 nr_reclaimed）更新到更全局的计数器中，确保其可见性。
	flush_reclaim_state(sc);

	/*
		成功回收且在线：如果回收成功并且该 memcg 仍然在线（未被删除），则返回 MEMCG_LRU_YOUNG。意思是：“这次回收很顺利，
		这个组里可能还有不少可回收的页面，但先让它休息一下，把它移到年轻代，下次再扫。”
	*/
	if (success && mem_cgroup_online(memcg))
		return MEMCG_LRU_YOUNG;

	/*
		回收失败但规模大：如果回收没有成功****并且该 lruvec 的规模仍然很大（lruvec_is_sizable），则返回 0 (MEMCG_LRU_NOP)。
		意思是：“这次没收回东西，但它明明还有很多页面，可能只是页面都比较活跃（热）。暂时不做任何调整，下次再试试看。”
	*/
	if (!success && lruvec_is_sizable(lruvec, sc))
		return 0;

	/*
		最终默认策略：这是一个条件操作符，是函数的最终默认返回值。
		如果该 lruvec 当前不是 MEMCG_LRU_TAIL 状态，则返回 MEMCG_LRU_TAIL。意思是：“这个组回收效果不理想，让它到队列末尾去排队，给别人让位。”
		如果该 lruvec 当前已经是 MEMCG_LRU_TAIL 状态，则返回 MEMCG_LRU_YOUNG。意思是：“它都已经在末尾了还是回收不好，那或许它的页面都很重要，
		先把它移到年轻代保护一下，减轻压力。”
	*/
	return READ_ONCE(lruvec->lrugen.seg) != MEMCG_LRU_TAIL ?
	       MEMCG_LRU_TAIL : MEMCG_LRU_YOUNG;
}

static void shrink_many(struct pglist_data *pgdat, struct scan_control *sc)
{
	int op;					// 操作结果，用于记录对单个 memcg 回收操作的结果
	int gen;				// 代(generation)编号，用于LRUGen算法
	int bin;				// 当前处理的bin(桶)索引
	int first_bin;			// 初始随机选择的bin索引
	struct lruvec *lruvec;	// 指向LRU向量的指针
	struct lru_gen_folio *lrugen;		// 指向LRUGen folio结构的指针
	struct mem_cgroup *memcg;			// 指向当前处理的内存控制组的指针
	struct hlist_nulls_node *pos;		// 用于遍历哈希链表的节点指针

	// 获取当前要处理的代(generation)编号。READ_ONCE 确保安全地读取可能被并发修改的值。
	gen = get_memcg_gen(READ_ONCE(pgdat->memcg_lru.seq));
	// bin 是一个用于对 memcg 进行散列分组的索引。它通过将 memcg 分散到多个短链表中，
	// 并结合随机起始点的扫描策略，极大地提升了内存回收的效率和公平性。
	bin = first_bin = get_random_u32_below(MEMCG_NR_BINS);
restart:
	op = 0;
	memcg = NULL;			// 初始化操作结果和当前memcg指针。

	rcu_read_lock();		// 进入RCU(Read-Copy-Update)读临界区，保护后续的链表遍历操作。

	// 开始遍历指定代(gen)和指定bin的memcg链表。这是一个RCU安全的遍历宏。
	// pgdat->memcg_lru.fifo[gen][bin] : 二维哈西表
	hlist_nulls_for_each_entry_rcu(lrugen, pos, &pgdat->memcg_lru.fifo[gen][bin], list) {
		// 如果前一个memcg的处理有操作结果(op不为0)，则执行相应的旋转操作，然后重置操作结果。
		if (op) {
			// 根据OP不同，执行不同的迁移动作：如果一个 memcg 很容易被回收（有很多冷内存），
			// 在成功回收后就被移到队列后面，相当于给它"放假"，避免因其"好欺负"而被过度回收
			// 如果一个 memcg 回收困难（内存都很活跃），就把它移到队列前面，持续关注它，
			// 确保它不会因为难以回收就永远躲在队列后面，从而逃避其应承担的内存回收责任
			lru_gen_rotate_memcg(lruvec, op);
			op = 0;
		}

		// 释放前一个memcg的引用计数，并清空指针。
		mem_cgroup_put(memcg);
		memcg = NULL;

		// 检查当前lrugen的代是否与我们要处理的代一致，如果不一致则跳过（可能已被并发修改）。
		if (gen != READ_ONCE(lrugen->gen))
			continue;

		// 通过lrugen指针获取包含它的lruvec结构。
		lruvec = container_of(lrugen, struct lruvec, lrugen);
		// 从lruvec获取对应的memcg。
		memcg = lruvec_memcg(lruvec);

		// 尝试获取memcg的引用计数，如果失败则释放相关资源并跳过这个memcg。
		if (!mem_cgroup_tryget(memcg)) {
			lru_gen_release_memcg(memcg);
			memcg = NULL;
			continue;
		}

		rcu_read_unlock();

		// 暂时退出RCU读临界区，因为接下来的操作可能阻塞。
		op = shrink_one(lruvec, sc);

		rcu_read_lock();	// 重新进入RCU读临界区，继续遍历。

		// 检查是否应该中止扫描（例如已回收足够内存），如果是则跳出循环。
		if (should_abort_scan(lruvec, sc))
			break;
	}

	// 退出RCU读临界区。
	rcu_read_unlock(); //  结束memcg链表的遍历循环。

	// 如果最后一个memcg有操作结果，执行相应的旋转操作。
	if (op)
		lru_gen_rotate_memcg(lruvec, op);

	// 释放最后一个memcg的引用计数。
	mem_cgroup_put(memcg);

	// 如果遍历没有到达链表末尾（即没有遍历完所有memcg），直接返回。
	// 没有遍历完有如下可能性：优先级提升：有更重要的进程需要CPU，当前回收线程需要让路。
	// 已回收足够页面：本次回收操作已经成功释放了足够多的内存，满足了请求，无需继续。
	// 时间片用尽：回收线程已经运行了足够长的时间，需要退出以避免占用过多CPU。
	// 其他信号或事件：例如，整个节点（NUMA node）的内存压力已经解除。
	if (!is_a_nulls(pos))
		return;

	// 检查是否与 lru_gen_rotate_memcg() 并发操作产生了竞争条件，如果是则重新开始。
	if (gen != get_nulls_value(pos))
		goto restart;

	// 尝试处理当前代的其他bin，如果还有未处理的bin，则重新开始。
	bin = get_memcg_bin(bin + 1);
	if (bin != first_bin)
		goto restart;
}

static void lru_gen_shrink_lruvec(struct lruvec *lruvec, struct scan_control *sc)
{
	struct blk_plug plug;

	VM_WARN_ON_ONCE(root_reclaim(sc));
	VM_WARN_ON_ONCE(!sc->may_writepage || !sc->may_unmap);

	lru_add_drain();

	blk_start_plug(&plug);

	set_mm_walk(NULL, sc->proactive);

	if (try_to_shrink_lruvec(lruvec, sc))
		lru_gen_rotate_memcg(lruvec, MEMCG_LRU_YOUNG);

	clear_mm_walk();

	blk_finish_plug(&plug);
}

static void lru_gen_shrink_node(struct pglist_data *pgdat, struct scan_control *sc)
{
	// 声明一个块设备插桩结构，用于优化I/O调度
	struct blk_plug plug;
	// 保存进入函数时已经回收的页面数量，用于后续比较
	unsigned long reclaimed = sc->nr_reclaimed;

	// 内核警告：确保本次回收是针对系统全局的（根memcg），而不是某个特定cgroup
	VM_WARN_ON_ONCE(!root_reclaim(sc));

	/*
     * 注释解释：未映射的干净folio已经被优先处理了。继续扫描它们可能徒劳无功，
     * 并且在存在大量memcg时可能导致很高的回收延迟。
     */
    // 如果本次回收不允许回写页面或取消映射，则跳过主要逻辑
	if (!sc->may_writepage || !sc->may_unmap)
		goto done; // 直接跳转到最后的done标签

	// 将per-CPU LRU缓存中的页面排空（drain）到相应的zone/LRU列表中，确保我们扫描的是最新状态
	lru_add_drain();

	// 将一段时间内产生的多个分散的、小的I/O请求合并（打包） 成更少、更大的I/O请求后再提交给磁盘驱动器，从而显著减少磁盘寻道次数，提升I/O吞吐量
	blk_start_plug(&plug);

	// 为当前执行内存回收任务的线程（通常是 kswapd 内核线程或执行直接回收的进程）准备一个 mm_walk 结构体
	set_mm_walk(pgdat, sc->proactive);

	// 根据当前内存压力、优先级等设置初始扫描优先级和控制参数
	set_initial_priority(pgdat, sc);

	// 如果当前进程是kswapd，则将回收计数重置为0。
    // 这是因为kswapd可能会多次调用此函数，我们想单独计算本次调用的回收量
	if (current_is_kswapd())
		sc->nr_reclaimed = 0;

	// 检查内存控制组(memcg)功能是否被禁用
	if (mem_cgroup_disabled())
		// 如果禁用，则只有一个全局的lruvec（在pgdat中），直接收缩它
		shrink_one(&pgdat->__lruvec, sc);
	else
		// 如果启用，则需要遍历所有memcg，并收缩每个memcg在该节点上的lruvec
		shrink_many(pgdat, sc);

	// 如果当前进程是kswapd，把本次函数调用回收的页面数加回到总计数中
	if (current_is_kswapd())
		sc->nr_reclaimed += reclaimed;

	// 清除之前设置的内存遍历(mm_walk)状态
	clear_mm_walk();

	// 结束块设备插桩，提交合并的I/O请求
	blk_finish_plug(&plug);
done:
	// 判断：如果在本函数执行过程中回收了页面（即最终计数大于初始计数）
	if (sc->nr_reclaimed > reclaimed)
		// 则重置该节点的kswapd失败次数计数器。表明回收有进展，情况在改善
		pgdat->kswapd_failures = 0;
}

/******************************************************************************
 *                          state change
 ******************************************************************************/

static bool __maybe_unused state_is_valid(struct lruvec *lruvec)
{
	struct lru_gen_folio *lrugen = &lruvec->lrugen;

	if (lrugen->enabled) {
		enum lru_list lru;

		for_each_evictable_lru(lru) {
			if (!list_empty(&lruvec->lists[lru]))
				return false;
		}
	} else {
		int gen, type, zone;

		for_each_gen_type_zone(gen, type, zone) {
			if (!list_empty(&lrugen->folios[gen][type][zone]))
				return false;
		}
	}

	return true;
}

static bool fill_evictable(struct lruvec *lruvec)
{
	enum lru_list lru;
	int remaining = MAX_LRU_BATCH;

	for_each_evictable_lru(lru) {
		int type = is_file_lru(lru);
		bool active = is_active_lru(lru);
		struct list_head *head = &lruvec->lists[lru];

		while (!list_empty(head)) {
			bool success;
			struct folio *folio = lru_to_folio(head);

			VM_WARN_ON_ONCE_FOLIO(folio_test_unevictable(folio), folio);
			VM_WARN_ON_ONCE_FOLIO(folio_test_active(folio) != active, folio);
			VM_WARN_ON_ONCE_FOLIO(folio_is_file_lru(folio) != type, folio);
			VM_WARN_ON_ONCE_FOLIO(folio_lru_gen(folio) != -1, folio);

			lruvec_del_folio(lruvec, folio);
			success = lru_gen_add_folio(lruvec, folio, false);
			VM_WARN_ON_ONCE(!success);

			if (!--remaining)
				return false;
		}
	}

	return true;
}

static bool drain_evictable(struct lruvec *lruvec)
{
	int gen, type, zone;
	int remaining = MAX_LRU_BATCH;

	for_each_gen_type_zone(gen, type, zone) {
		struct list_head *head = &lruvec->lrugen.folios[gen][type][zone];

		while (!list_empty(head)) {
			bool success;
			struct folio *folio = lru_to_folio(head);

			VM_WARN_ON_ONCE_FOLIO(folio_test_unevictable(folio), folio);
			VM_WARN_ON_ONCE_FOLIO(folio_test_active(folio), folio);
			VM_WARN_ON_ONCE_FOLIO(folio_is_file_lru(folio) != type, folio);
			VM_WARN_ON_ONCE_FOLIO(folio_zonenum(folio) != zone, folio);

			success = lru_gen_del_folio(lruvec, folio, false);
			VM_WARN_ON_ONCE(!success);
			lruvec_add_folio(lruvec, folio);

			if (!--remaining)
				return false;
		}
	}

	return true;
}

static void lru_gen_change_state(bool enabled)
{
	static DEFINE_MUTEX(state_mutex);

	struct mem_cgroup *memcg;

	cgroup_lock();
	cpus_read_lock();
	get_online_mems();
	mutex_lock(&state_mutex);

	if (enabled == lru_gen_enabled())
		goto unlock;

	if (enabled)
		static_branch_enable_cpuslocked(&lru_gen_caps[LRU_GEN_CORE]);
	else
		static_branch_disable_cpuslocked(&lru_gen_caps[LRU_GEN_CORE]);

	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		int nid;

		for_each_node(nid) {
			struct lruvec *lruvec = get_lruvec(memcg, nid);

			spin_lock_irq(&lruvec->lru_lock);

			VM_WARN_ON_ONCE(!seq_is_valid(lruvec));
			VM_WARN_ON_ONCE(!state_is_valid(lruvec));

			lruvec->lrugen.enabled = enabled;

			while (!(enabled ? fill_evictable(lruvec) : drain_evictable(lruvec))) {
				spin_unlock_irq(&lruvec->lru_lock);
				cond_resched();
				spin_lock_irq(&lruvec->lru_lock);
			}

			spin_unlock_irq(&lruvec->lru_lock);
		}

		cond_resched();
	} while ((memcg = mem_cgroup_iter(NULL, memcg, NULL)));
unlock:
	mutex_unlock(&state_mutex);
	put_online_mems();
	cpus_read_unlock();
	cgroup_unlock();
}

/******************************************************************************
 *                          sysfs interface
 ******************************************************************************/

static ssize_t min_ttl_ms_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", jiffies_to_msecs(READ_ONCE(lru_gen_min_ttl)));
}

/* see Documentation/admin-guide/mm/multigen_lru.rst for details */
static ssize_t min_ttl_ms_store(struct kobject *kobj, struct kobj_attribute *attr,
				const char *buf, size_t len)
{
	unsigned int msecs;

	if (kstrtouint(buf, 0, &msecs))
		return -EINVAL;

	WRITE_ONCE(lru_gen_min_ttl, msecs_to_jiffies(msecs));

	return len;
}

static struct kobj_attribute lru_gen_min_ttl_attr = __ATTR_RW(min_ttl_ms);

static ssize_t enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	unsigned int caps = 0;

	if (get_cap(LRU_GEN_CORE))
		caps |= BIT(LRU_GEN_CORE);

	if (should_walk_mmu())
		caps |= BIT(LRU_GEN_MM_WALK);

	if (should_clear_pmd_young())
		caps |= BIT(LRU_GEN_NONLEAF_YOUNG);

	return sysfs_emit(buf, "0x%04x\n", caps);
}

/* see Documentation/admin-guide/mm/multigen_lru.rst for details */
static ssize_t enabled_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t len)
{
	int i;
	unsigned int caps;

	if (tolower(*buf) == 'n')
		caps = 0;
	else if (tolower(*buf) == 'y')
		caps = -1;
	else if (kstrtouint(buf, 0, &caps))
		return -EINVAL;

	for (i = 0; i < NR_LRU_GEN_CAPS; i++) {
		bool enabled = caps & BIT(i);

		if (i == LRU_GEN_CORE)
			lru_gen_change_state(enabled);
		else if (enabled)
			static_branch_enable(&lru_gen_caps[i]);
		else
			static_branch_disable(&lru_gen_caps[i]);
	}

	return len;
}

static struct kobj_attribute lru_gen_enabled_attr = __ATTR_RW(enabled);

static struct attribute *lru_gen_attrs[] = {
	&lru_gen_min_ttl_attr.attr,
	&lru_gen_enabled_attr.attr,
	NULL
};

static const struct attribute_group lru_gen_attr_group = {
	.name = "lru_gen",
	.attrs = lru_gen_attrs,
};

/******************************************************************************
 *                          debugfs interface
 ******************************************************************************/

static void *lru_gen_seq_start(struct seq_file *m, loff_t *pos)
{
	struct mem_cgroup *memcg;
	loff_t nr_to_skip = *pos;

	m->private = kvmalloc(PATH_MAX, GFP_KERNEL);
	if (!m->private)
		return ERR_PTR(-ENOMEM);

	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		int nid;

		for_each_node_state(nid, N_MEMORY) {
			if (!nr_to_skip--)
				return get_lruvec(memcg, nid);
		}
	} while ((memcg = mem_cgroup_iter(NULL, memcg, NULL)));

	return NULL;
}

static void lru_gen_seq_stop(struct seq_file *m, void *v)
{
	if (!IS_ERR_OR_NULL(v))
		mem_cgroup_iter_break(NULL, lruvec_memcg(v));

	kvfree(m->private);
	m->private = NULL;
}

static void *lru_gen_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	int nid = lruvec_pgdat(v)->node_id;
	struct mem_cgroup *memcg = lruvec_memcg(v);

	++*pos;

	nid = next_memory_node(nid);
	if (nid == MAX_NUMNODES) {
		memcg = mem_cgroup_iter(NULL, memcg, NULL);
		if (!memcg)
			return NULL;

		nid = first_memory_node;
	}

	return get_lruvec(memcg, nid);
}

static void lru_gen_seq_show_full(struct seq_file *m, struct lruvec *lruvec,
				  unsigned long max_seq, unsigned long *min_seq,
				  unsigned long seq)
{
	int i;
	int type, tier;
	int hist = lru_hist_from_seq(seq);
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	struct lru_gen_mm_state *mm_state = get_mm_state(lruvec);

	for (tier = 0; tier < MAX_NR_TIERS; tier++) {
		seq_printf(m, "            %10d", tier);
		for (type = 0; type < ANON_AND_FILE; type++) {
			const char *s = "xxx";
			unsigned long n[3] = {};

			if (seq == max_seq) {
				s = "RTx";
				n[0] = READ_ONCE(lrugen->avg_refaulted[type][tier]);
				n[1] = READ_ONCE(lrugen->avg_total[type][tier]);
			} else if (seq == min_seq[type] || NR_HIST_GENS > 1) {
				s = "rep";
				n[0] = atomic_long_read(&lrugen->refaulted[hist][type][tier]);
				n[1] = atomic_long_read(&lrugen->evicted[hist][type][tier]);
				n[2] = READ_ONCE(lrugen->protected[hist][type][tier]);
			}

			for (i = 0; i < 3; i++)
				seq_printf(m, " %10lu%c", n[i], s[i]);
		}
		seq_putc(m, '\n');
	}

	if (!mm_state)
		return;

	seq_puts(m, "                      ");
	for (i = 0; i < NR_MM_STATS; i++) {
		const char *s = "xxxx";
		unsigned long n = 0;

		if (seq == max_seq && NR_HIST_GENS == 1) {
			s = "TYFA";
			n = READ_ONCE(mm_state->stats[hist][i]);
		} else if (seq != max_seq && NR_HIST_GENS > 1) {
			s = "tyfa";
			n = READ_ONCE(mm_state->stats[hist][i]);
		}

		seq_printf(m, " %10lu%c", n, s[i]);
	}
	seq_putc(m, '\n');
}

/* see Documentation/admin-guide/mm/multigen_lru.rst for details */
static int lru_gen_seq_show(struct seq_file *m, void *v)
{
	unsigned long seq;
	bool full = !debugfs_real_fops(m->file)->write;
	struct lruvec *lruvec = v;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	int nid = lruvec_pgdat(lruvec)->node_id;
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	DEFINE_MAX_SEQ(lruvec);
	DEFINE_MIN_SEQ(lruvec);

	if (nid == first_memory_node) {
		const char *path = memcg ? m->private : "";

#ifdef CONFIG_MEMCG
		if (memcg)
			cgroup_path(memcg->css.cgroup, m->private, PATH_MAX);
#endif
		seq_printf(m, "memcg %5hu %s\n", mem_cgroup_id(memcg), path);
	}

	seq_printf(m, " node %5d\n", nid);

	if (!full)
		seq = evictable_min_seq(min_seq, MAX_SWAPPINESS / 2);
	else if (max_seq >= MAX_NR_GENS)
		seq = max_seq - MAX_NR_GENS + 1;
	else
		seq = 0;

	for (; seq <= max_seq; seq++) {
		int type, zone;
		int gen = lru_gen_from_seq(seq);
		unsigned long birth = READ_ONCE(lruvec->lrugen.timestamps[gen]);

		seq_printf(m, " %10lu %10u", seq, jiffies_to_msecs(jiffies - birth));

		for (type = 0; type < ANON_AND_FILE; type++) {
			unsigned long size = 0;
			char mark = full && seq < min_seq[type] ? 'x' : ' ';

			for (zone = 0; zone < MAX_NR_ZONES; zone++)
				size += max(READ_ONCE(lrugen->nr_pages[gen][type][zone]), 0L);

			seq_printf(m, " %10lu%c", size, mark);
		}

		seq_putc(m, '\n');

		if (full)
			lru_gen_seq_show_full(m, lruvec, max_seq, min_seq, seq);
	}

	return 0;
}

static const struct seq_operations lru_gen_seq_ops = {
	.start = lru_gen_seq_start,
	.stop = lru_gen_seq_stop,
	.next = lru_gen_seq_next,
	.show = lru_gen_seq_show,
};

static int run_aging(struct lruvec *lruvec, unsigned long seq,
		     int swappiness, bool force_scan)
{
	DEFINE_MAX_SEQ(lruvec);

	if (seq > max_seq)
		return -EINVAL;

	return try_to_inc_max_seq(lruvec, max_seq, swappiness, force_scan) ? 0 : -EEXIST;
}

static int run_eviction(struct lruvec *lruvec, unsigned long seq, struct scan_control *sc,
			int swappiness, unsigned long nr_to_reclaim)
{
	DEFINE_MAX_SEQ(lruvec);

	if (seq + MIN_NR_GENS > max_seq)
		return -EINVAL;

	sc->nr_reclaimed = 0;

	while (!signal_pending(current)) {
		DEFINE_MIN_SEQ(lruvec);

		if (seq < evictable_min_seq(min_seq, swappiness))
			return 0;

		if (sc->nr_reclaimed >= nr_to_reclaim)
			return 0;

		if (!evict_folios(lruvec, sc, swappiness))
			return 0;

		cond_resched();
	}

	return -EINTR;
}

static int run_cmd(char cmd, int memcg_id, int nid, unsigned long seq,
		   struct scan_control *sc, int swappiness, unsigned long opt)
{
	struct lruvec *lruvec;
	int err = -EINVAL;
	struct mem_cgroup *memcg = NULL;

	if (nid < 0 || nid >= MAX_NUMNODES || !node_state(nid, N_MEMORY))
		return -EINVAL;

	if (!mem_cgroup_disabled()) {
		rcu_read_lock();

		memcg = mem_cgroup_from_id(memcg_id);
		if (!mem_cgroup_tryget(memcg))
			memcg = NULL;

		rcu_read_unlock();

		if (!memcg)
			return -EINVAL;
	}

	if (memcg_id != mem_cgroup_id(memcg))
		goto done;

	lruvec = get_lruvec(memcg, nid);

	if (swappiness < MIN_SWAPPINESS)
		swappiness = get_swappiness(lruvec, sc);
	else if (swappiness > SWAPPINESS_ANON_ONLY)
		goto done;

	switch (cmd) {
	case '+':
		err = run_aging(lruvec, seq, swappiness, opt);
		break;
	case '-':
		err = run_eviction(lruvec, seq, sc, swappiness, opt);
		break;
	}
done:
	mem_cgroup_put(memcg);

	return err;
}

/* see Documentation/admin-guide/mm/multigen_lru.rst for details */
static ssize_t lru_gen_seq_write(struct file *file, const char __user *src,
				 size_t len, loff_t *pos)
{
	void *buf;
	char *cur, *next;
	unsigned int flags;
	struct blk_plug plug;
	int err = -EINVAL;
	struct scan_control sc = {
		.may_writepage = true,
		.may_unmap = true,
		.may_swap = true,
		.reclaim_idx = MAX_NR_ZONES - 1,
		.gfp_mask = GFP_KERNEL,
	};

	buf = kvmalloc(len + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, src, len)) {
		kvfree(buf);
		return -EFAULT;
	}

	set_task_reclaim_state(current, &sc.reclaim_state);
	flags = memalloc_noreclaim_save();
	blk_start_plug(&plug);
	if (!set_mm_walk(NULL, true)) {
		err = -ENOMEM;
		goto done;
	}

	next = buf;
	next[len] = '\0';

	while ((cur = strsep(&next, ",;\n"))) {
		int n;
		int end;
		char cmd, swap_string[5];
		unsigned int memcg_id;
		unsigned int nid;
		unsigned long seq;
		unsigned int swappiness;
		unsigned long opt = -1;

		cur = skip_spaces(cur);
		if (!*cur)
			continue;

		n = sscanf(cur, "%c %u %u %lu %n %4s %n %lu %n", &cmd, &memcg_id, &nid,
			   &seq, &end, swap_string, &end, &opt, &end);
		if (n < 4 || cur[end]) {
			err = -EINVAL;
			break;
		}

		if (n == 4) {
			swappiness = -1;
		} else if (!strcmp("max", swap_string)) {
			/* set by userspace for anonymous memory only */
			swappiness = SWAPPINESS_ANON_ONLY;
		} else {
			err = kstrtouint(swap_string, 0, &swappiness);
			if (err)
				break;
		}

		err = run_cmd(cmd, memcg_id, nid, seq, &sc, swappiness, opt);
		if (err)
			break;
	}
done:
	clear_mm_walk();
	blk_finish_plug(&plug);
	memalloc_noreclaim_restore(flags);
	set_task_reclaim_state(current, NULL);

	kvfree(buf);

	return err ? : len;
}

static int lru_gen_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &lru_gen_seq_ops);
}

static const struct file_operations lru_gen_rw_fops = {
	.open = lru_gen_seq_open,
	.read = seq_read,
	.write = lru_gen_seq_write,
	.llseek = seq_lseek,
	.release = seq_release,
};

static const struct file_operations lru_gen_ro_fops = {
	.open = lru_gen_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

/******************************************************************************
 *                          initialization
 ******************************************************************************/

void lru_gen_init_pgdat(struct pglist_data *pgdat)
{
	int i, j;

	spin_lock_init(&pgdat->memcg_lru.lock);

	for (i = 0; i < MEMCG_NR_GENS; i++) {
		for (j = 0; j < MEMCG_NR_BINS; j++)
			INIT_HLIST_NULLS_HEAD(&pgdat->memcg_lru.fifo[i][j], i);
	}
}

void lru_gen_init_lruvec(struct lruvec *lruvec)
{
	int i;
	int gen, type, zone;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	struct lru_gen_mm_state *mm_state = get_mm_state(lruvec);

	lrugen->max_seq = MIN_NR_GENS + 1;
	lrugen->enabled = lru_gen_enabled();

	for (i = 0; i <= MIN_NR_GENS + 1; i++)
		lrugen->timestamps[i] = jiffies;

	for_each_gen_type_zone(gen, type, zone)
		INIT_LIST_HEAD(&lrugen->folios[gen][type][zone]);

	if (mm_state)
		mm_state->seq = MIN_NR_GENS;
}

#ifdef CONFIG_MEMCG

void lru_gen_init_memcg(struct mem_cgroup *memcg)
{
	struct lru_gen_mm_list *mm_list = get_mm_list(memcg);

	if (!mm_list)
		return;

	INIT_LIST_HEAD(&mm_list->fifo);
	spin_lock_init(&mm_list->lock);
}

void lru_gen_exit_memcg(struct mem_cgroup *memcg)
{
	int i;
	int nid;
	struct lru_gen_mm_list *mm_list = get_mm_list(memcg);

	VM_WARN_ON_ONCE(mm_list && !list_empty(&mm_list->fifo));

	for_each_node(nid) {
		struct lruvec *lruvec = get_lruvec(memcg, nid);
		struct lru_gen_mm_state *mm_state = get_mm_state(lruvec);

		VM_WARN_ON_ONCE(memchr_inv(lruvec->lrugen.nr_pages, 0,
					   sizeof(lruvec->lrugen.nr_pages)));

		lruvec->lrugen.list.next = LIST_POISON1;

		if (!mm_state)
			continue;

		for (i = 0; i < NR_BLOOM_FILTERS; i++) {
			bitmap_free(mm_state->filters[i]);
			mm_state->filters[i] = NULL;
		}
	}
}

#endif /* CONFIG_MEMCG */

static int __init init_lru_gen(void)
{
	BUILD_BUG_ON(MIN_NR_GENS + 1 >= MAX_NR_GENS);
	BUILD_BUG_ON(BIT(LRU_GEN_WIDTH) <= MAX_NR_GENS);

	if (sysfs_create_group(mm_kobj, &lru_gen_attr_group))
		pr_err("lru_gen: failed to create sysfs group\n");

	debugfs_create_file("lru_gen", 0644, NULL, NULL, &lru_gen_rw_fops);
	debugfs_create_file("lru_gen_full", 0444, NULL, NULL, &lru_gen_ro_fops);

	return 0;
};
late_initcall(init_lru_gen);

#else /* !CONFIG_LRU_GEN */

static void lru_gen_age_node(struct pglist_data *pgdat, struct scan_control *sc)
{
	BUILD_BUG();
}

static void lru_gen_shrink_lruvec(struct lruvec *lruvec, struct scan_control *sc)
{
	BUILD_BUG();
}

static void lru_gen_shrink_node(struct pglist_data *pgdat, struct scan_control *sc)
{
	BUILD_BUG();
}

#endif /* CONFIG_LRU_GEN */

static void shrink_lruvec(struct lruvec *lruvec, struct scan_control *sc)
{
	unsigned long nr[NR_LRU_LISTS];       // 各LRU类型需扫描页数
	unsigned long targets[NR_LRU_LISTS];   // 原始扫描目标
	unsigned long nr_to_scan;              // 当前扫描批次数量
	enum lru_list lru;                     // LRU类型枚举
	unsigned long nr_reclaimed = 0;        // 已回收页数
	unsigned long nr_to_reclaim = sc->nr_to_reclaim; // 总体需回收页数
	bool proportional_reclaim;             // 是否启用比例回收
	struct blk_plug plug;                  // I/O合并优化

	// 新一代LRU检测
	// 条件：启用多代LRU且非全局回收时
	// 行为：转用新一代回收算法并退出
	if (lru_gen_enabled() && !root_reclaim(sc)) {
		lru_gen_shrink_lruvec(lruvec, sc);
		return;
	}

	// 扫描目标计算
	// get_scan_count()：综合考虑四因子计算扫描权重：
	// 系统内存压力
	// swap使用率
	// cgroup限制
	// 回收优先级 (sc->priority)
	get_scan_count(lruvec, sc, nr);  // 计算各LRU的扫描权重
	memcpy(targets, nr, sizeof(nr)); // 保存原始目标值

	// 比例回收标志
	// 置位条件：
	// 1. 非 Cgroup 回收
	// 2. 当前进程非 kswapd (直接回收)
	// 3. 优先级为默认优先级 (DEF_PRIORITY)
	// 含义：允许直接回收在轻压力时完成整个批次扫描。
	proportional_reclaim = (!cgroup_reclaim(sc) && !current_is_kswapd() &&
				sc->priority == DEF_PRIORITY);

	// I/O 优化
	// 启动 Block I/O Plunging：合并后续产生的 I/O 请求，减少磁盘寻址开销。
	blk_start_plug(&plug);
	// 主回收循环
	// 循环条件：匿名非活跃、文件活跃/非活跃 LRU 中仍有待扫描页。
	while (nr[LRU_INACTIVE_ANON] || nr[LRU_ACTIVE_FILE] ||
					nr[LRU_INACTIVE_FILE]) {
		unsigned long nr_anon, nr_file, percentage;
		unsigned long nr_scanned;

		for_each_evictable_lru(lru) {
			// 每次扫描最多 SWAP_CLUSTER_MAX (常为 32) 页
			if (nr[lru]) {
				nr_to_scan = min(nr[lru], SWAP_CLUSTER_MAX);
				nr[lru] -= nr_to_scan;

				// shrink_list()：执行实际的页回收（可能触发页面换出或释放）。
				nr_reclaimed += shrink_list(lru, nr_to_scan,
							    lruvec, sc);
			}
		}

		// cond_resched()：主动让出 CPU 避免长时间占用。
		cond_resched();

		// 若未达总目标或启用比例回收，则继续下一轮循环。
		if (nr_reclaimed < nr_to_reclaim || proportional_reclaim)
			// 直到按比例计算出的nr全部扫描完毕
			continue;

		// 比例回收调整（达到目标后）
		// 核心逻辑：当达成回收目标后，强制两种 LRU 按原始比例完成扫描：
		// 1. 将占比更大的 LRU 类型扫描量置零（停止扫描）。
		// 2. 根据已扫描比例，重新计算另一类型的剩余扫描量。
		nr_file = nr[LRU_INACTIVE_FILE] + nr[LRU_ACTIVE_FILE];
		nr_anon = nr[LRU_INACTIVE_ANON] + nr[LRU_ACTIVE_ANON];

		if (!nr_file || !nr_anon)  // 任一LRU降至0则退出
			break;

		// 计算占比更大的LRU类型
		if (nr_file > nr_anon) {
			unsigned long scan_target = targets[LRU_INACTIVE_ANON] +
						targets[LRU_ACTIVE_ANON] + 1;  // 避免除0
			lru = LRU_BASE;         // 目标:匿名页
			percentage = nr_anon * 100 / scan_target;
		} else {
			unsigned long scan_target = targets[LRU_INACTIVE_FILE] +
						targets[LRU_ACTIVE_FILE] + 1;
			lru = LRU_FILE;         // 目标:文件页
			percentage = nr_file * 100 / scan_target;
		}

		// 停止扫描占比较大的LRU类型
		nr[lru] = 0;                // 非活跃部分
		nr[lru + LRU_ACTIVE] = 0;   // 活跃部分

		// 按比例重新计算另一LRU的扫描量
		lru = (lru == LRU_FILE) ? LRU_BASE : LRU_FILE;
		nr_scanned = targets[lru] - nr[lru];       // 已扫描量
		nr[lru] = targets[lru] * (100 - percentage) / 100;
		nr[lru] -= min(nr[lru], nr_scanned);        // 减去已完成部分

		// 活跃部分同理调整
		lru += LRU_ACTIVE;
		nr_scanned = targets[lru] - nr[lru];
		nr[lru] = targets[lru] * (100 - percentage) / 100;
		nr[lru] -= min(nr[lru], nr_scanned);
	}
	blk_finish_plug(&plug);

	// 收尾操作
	// 1. 更新全局回收计数。
	// 2. 匿名页活跃/非活跃平衡：
	//        条件：允许匿名页老化 + 非活跃匿名页过少。
	//        操作：从活跃匿名链表 (LRU_ACTIVE_ANON) 回收页面到非活跃链表。
	sc->nr_reclaimed += nr_reclaimed; // 更新总回收页数

	if (can_age_anon_pages(lruvec, sc) &&
	    inactive_is_low(lruvec, LRU_INACTIVE_ANON))
		shrink_active_list(SWAP_CLUSTER_MAX, lruvec,
				   sc, LRU_ACTIVE_ANON);
}

/* Use reclaim/compaction for costly allocs or under memory pressure */
static bool in_reclaim_compaction(struct scan_control *sc)
{
	if (gfp_compaction_allowed(sc->gfp_mask) && sc->order &&
			(sc->order > PAGE_ALLOC_COSTLY_ORDER ||
			 sc->priority < DEF_PRIORITY - 2))
		return true;

	return false;
}

/*
 * Reclaim/compaction is used for high-order allocation requests. It reclaims
 * order-0 pages before compacting the zone. should_continue_reclaim() returns
 * true if more pages should be reclaimed such that when the page allocator
 * calls try_to_compact_pages() that it will have enough free pages to succeed.
 * It will give up earlier than that if there is difficulty reclaiming pages.
 */
static inline bool should_continue_reclaim(struct pglist_data *pgdat,
					unsigned long nr_reclaimed,
					struct scan_control *sc)
{
	unsigned long pages_for_compaction;
	unsigned long inactive_lru_pages;
	int z;
	struct zone *zone;

	/* If not in reclaim/compaction mode, stop */
	if (!in_reclaim_compaction(sc))
		return false;

	/*
	 * Stop if we failed to reclaim any pages from the last SWAP_CLUSTER_MAX
	 * number of pages that were scanned. This will return to the caller
	 * with the risk reclaim/compaction and the resulting allocation attempt
	 * fails. In the past we have tried harder for __GFP_RETRY_MAYFAIL
	 * allocations through requiring that the full LRU list has been scanned
	 * first, by assuming that zero delta of sc->nr_scanned means full LRU
	 * scan, but that approximation was wrong, and there were corner cases
	 * where always a non-zero amount of pages were scanned.
	 */
	if (!nr_reclaimed)
		return false;

	/* If compaction would go ahead or the allocation would succeed, stop */
	for_each_managed_zone_pgdat(zone, pgdat, z, sc->reclaim_idx) {
		unsigned long watermark = min_wmark_pages(zone);

		/* Allocation can already succeed, nothing to do */
		if (zone_watermark_ok(zone, sc->order, watermark,
				      sc->reclaim_idx, 0))
			return false;

		if (compaction_suitable(zone, sc->order, watermark,
					sc->reclaim_idx))
			return false;
	}

	/*
	 * If we have not reclaimed enough pages for compaction and the
	 * inactive lists are large enough, continue reclaiming
	 */
	pages_for_compaction = compact_gap(sc->order);
	inactive_lru_pages = node_page_state(pgdat, NR_INACTIVE_FILE);
	if (can_reclaim_anon_pages(NULL, pgdat->node_id, sc))
		inactive_lru_pages += node_page_state(pgdat, NR_INACTIVE_ANON);

	return inactive_lru_pages > pages_for_compaction;
}

// 核心功能：在内存节点级别遍历并回收所有符合条件的memcgroup的内存资源
static void shrink_node_memcgs(pg_data_t *pgdat, struct scan_control *sc)
{
	struct mem_cgroup *target_memcg = sc->target_mem_cgroup;
	// reclaim cookie：记录节点信息的迭代状态跟踪器
	struct mem_cgroup_reclaim_cookie reclaim = {
		.pgdat = pgdat,
	};
	// partial：决定是否执行部分回收迭代
	struct mem_cgroup_reclaim_cookie *partial = &reclaim;
	struct mem_cgroup *memcg;

	// 遍历策略决策
	// 1. kswapd(后台回收)	全量遍历	确保稳定回收进度
	// 2. 直接回收	增量遍历	降低延迟，提高响应速度
	// 3. 主动回收	强制全量遍历	深度清洁(memcg_full_walk)
	if (current_is_kswapd() || sc->memcg_full_walk)
		partial = NULL;

	// 开始memcg迭代
	// 迭代初始化：
	// 1. 获取第一个符合条件的memcg
	// 2. 创建memcg+node关联的LRU向量
	// 3. 准备记录本轮扫描统计的临时变量
	memcg = mem_cgroup_iter(target_memcg, NULL, partial);
	do {
		struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
		unsigned long reclaimed;
		unsigned long scanned;

		// 防CPU死锁保护
		// 重要机制：防止长时间运行导致CPU软死锁，特别针对：
		// 1. 受保护memcg(无回收页)
		// 2. 内存被显式保护的memcg    通过主动让出CPU避免系统冻结
		cond_resched();

		mem_cgroup_calculate_protection(target_memcg, memcg);

		// 硬保护检查
		if (mem_cgroup_below_min(target_memcg, memcg)) {
			continue;
		// 软保护检查
		} else if (mem_cgroup_below_low(target_memcg, memcg)) {
			if (!sc->memcg_low_reclaim) {
				sc->memcg_low_skipped = 1;
				continue;
			}
			memcg_memory_event(memcg, MEMCG_LOW);
		}

		// 核心回收操作
		// 双层级回收：
		// 1. 页面缓存回收：扫描LRU链表回收文件页/匿名页
		// 2. Slab缓存回收：清理dentry/inode等内核对象缓存
		reclaimed = sc->nr_reclaimed;
		scanned = sc->nr_scanned;

		// 回收页面缓存
		shrink_lruvec(lruvec, sc);

		// 回收Slab缓存
		shrink_slab(sc->gfp_mask, pgdat->node_id, memcg,
			    sc->priority);

		// cgroup级压力反馈
		if (!sc->proactive)
			// 压力计算：
			// 压力值 = (回收页数 / 扫描页数) * 100%
			// 通知用户空间守护进程(如Android的lmkd)
			vmpressure(sc->gfp_mask, memcg, false,
				   sc->nr_scanned - scanned,
				   sc->nr_reclaimed - reclaimed);

		// 增量回收优化
		// 增量回收特性：
		// 1. 仅适用于直接回收进程(!kswapd)
		// 2. 当达到回收目标(nr_to_reclaim)立即终止
		// 3. 保存断点(mem_cgroup_iter_break)供下次增量使用
		if (partial && sc->nr_reclaimed >= sc->nr_to_reclaim) {
			mem_cgroup_iter_break(target_memcg, memcg);
			break;
		}
	// 迭代继续条件
	// 迭代器行为：
	// 1. 全量模式(partial=NULL)：深度优先遍历整颗memcg树
	// 2. 增量模式(partial!=NULL)：基于上次断点继续
	// 3. 终止条件：返回NULL表示无更多需回收的memcg
	} while ((memcg = mem_cgroup_iter(target_memcg, memcg, partial)));
}

// 核心功能：在内存节点级别执行实际内存回收操作，协调脏页处理、写回限制和进程节流机制
static void shrink_node(pg_data_t *pgdat, struct scan_control *sc)
{
	unsigned long nr_reclaimed, nr_scanned, nr_node_reclaimed;
	struct lruvec *target_lruvec;
	bool reclaimable = false;

	// 新一代LRU处理 (可选)
	// 条件：当启用多代LRU且为全局回收时
	// 优势：更高效的页面老化策略，减少扫描开销
	if (lru_gen_enabled() && root_reclaim(sc)) {
		memset(&sc->nr, 0, sizeof(sc->nr));
		lru_gen_shrink_node(pgdat, sc); // 使用新一代LRU算法
		return;
	}

	// target_lruvec：指向内存cgroup或节点的LRU向量
	target_lruvec = mem_cgroup_lruvec(sc->target_mem_cgroup, pgdat);

again:
	// sc->nr：记录各类页面状态的计数器结构体
	memset(&sc->nr, 0, sizeof(sc->nr));

	nr_reclaimed = sc->nr_reclaimed;
	nr_scanned = sc->nr_scanned;

	// 多代内存管理，直接返回
	prepare_scan_control(pgdat, sc);

	// 分层扫描内存cgroup
	// 平衡不同cgroup间的回收压力
	// 聚合各CPU的回收统计
	shrink_node_memcgs(pgdat, sc); // 遍历memcg执行回收
	flush_reclaim_state(sc);        // 刷新CPU本地状态到全局
	nr_node_reclaimed = sc->nr_reclaimed - nr_reclaimed; // 本周期回收量

	// 压力反馈机制
	if (!sc->proactive)
	 	// vmpressure系统：向用户空间发送内存压力事件
		// 计算：压力程度 = 回收量/扫描量
		// 通知Android/OOMD等内存监控进程
		vmpressure(sc->gfp_mask, sc->target_mem_cgroup, true,
			   sc->nr_scanned - nr_scanned, nr_node_reclaimed);

	if (nr_node_reclaimed)
		reclaimable = true;

	if (current_is_kswapd()) {
		// 情况1：完全写回状态：所有回收页都需写回
		if (sc->nr.writeback && sc->nr.writeback == sc->nr.taken)
			set_bit(PGDAT_WRITEBACK, &pgdat->flags);

		// 情况2：脏页堆积状态：文件脏页未被加入写回队列
		if (sc->nr.unqueued_dirty &&
			sc->nr.unqueued_dirty == sc->nr.file_taken)
			set_bit(PGDAT_DIRTY, &pgdat->flags);

		// 情况3：紧急回收状态：需立即回收的写回页
		if (sc->nr.immediate)
			reclaim_throttle(pgdat, VMSCAN_THROTTLE_WRITEBACK);
	}

	// 拥塞控制机制
	// 拥塞条件：当 所有脏页 同时满足：
	// 1. 需要写回(脏页)
	// 2. 需要立即回收(拥塞状态)
	if (sc->nr.dirty && sc->nr.dirty == sc->nr.congested) {
		// memcgroup拥塞标记
		if (cgroup_reclaim(sc) && writeback_throttling_sane(sc))
			set_bit(LRUVEC_CGROUP_CONGESTED, &target_lruvec->flags);

		// 节点级拥塞标记
		if (current_is_kswapd())
			set_bit(LRUVEC_NODE_CONGESTED, &target_lruvec->flags);
	}

	// 节流控制策略
	// 节流触发条件：
	// 1. 直接回收进程(非kswapd)
	// 2. 当前允许节流
	// 3. cgroup或节点标记为拥塞   效果：阻塞进程直到拥塞缓解
	if (!current_is_kswapd() && current_may_throttle() &&
	    !sc->hibernation_mode &&
	    (test_bit(LRUVEC_CGROUP_CONGESTED, &target_lruvec->flags) ||
	     test_bit(LRUVEC_NODE_CONGESTED, &target_lruvec->flags)))
		reclaim_throttle(pgdat, VMSCAN_THROTTLE_CONGESTED);

	// 回收延续决策
	// should_continue_reclaim 检查：
	// 1. 扫描比例是否达标
	// 2. 回收效率是否过低
	// 3. 是否仍低于水位线    循环本质：内存回收达不到目标时重试
	if (should_continue_reclaim(pgdat, nr_node_reclaimed, sc))
		goto again;

	// 结果反馈：
	// 1. 回收成功：清除失败计数
	// 2. 完全失败：标记特殊状态供后续处理
	if (reclaimable)
		pgdat->kswapd_failures = 0;  // 重置失败计数
	else if (sc->cache_trim_mode)
		sc->cache_trim_mode_failed = 1; // 记录缓存修剪失败
}

/*
 * Returns true if compaction should go ahead for a costly-order request, or
 * the allocation would already succeed without compaction. Return false if we
 * should reclaim first.
 */
static inline bool compaction_ready(struct zone *zone, struct scan_control *sc)
{
	unsigned long watermark;

	if (!gfp_compaction_allowed(sc->gfp_mask))
		return false;

	/* Allocation can already succeed, nothing to do */
	if (zone_watermark_ok(zone, sc->order, min_wmark_pages(zone),
			      sc->reclaim_idx, 0))
		return true;

	/*
	 * Direct reclaim usually targets the min watermark, but compaction
	 * takes time to run and there are potentially other callers using the
	 * pages just freed. So target a higher buffer to give compaction a
	 * reasonable chance of completing and allocating the pages.
	 *
	 * Note that we won't actually reclaim the whole buffer in one attempt
	 * as the target watermark in should_continue_reclaim() is lower. But if
	 * we are already above the high+gap watermark, don't reclaim at all.
	 */
	watermark = high_wmark_pages(zone);
	if (compaction_suitable(zone, sc->order, watermark, sc->reclaim_idx))
		return true;

	return false;
}

static void consider_reclaim_throttle(pg_data_t *pgdat, struct scan_control *sc)
{
	/*
	 * If reclaim is making progress greater than 12% efficiency then
	 * wake all the NOPROGRESS throttled tasks.
	 */
	if (sc->nr_reclaimed > (sc->nr_scanned >> 3)) {
		wait_queue_head_t *wqh;

		wqh = &pgdat->reclaim_wait[VMSCAN_THROTTLE_NOPROGRESS];
		if (waitqueue_active(wqh))
			wake_up(wqh);

		return;
	}

	/*
	 * Do not throttle kswapd or cgroup reclaim on NOPROGRESS as it will
	 * throttle on VMSCAN_THROTTLE_WRITEBACK if there are too many pages
	 * under writeback and marked for immediate reclaim at the tail of the
	 * LRU.
	 */
	if (current_is_kswapd() || cgroup_reclaim(sc))
		return;

	/* Throttle if making no progress at high prioities. */
	if (sc->priority == 1 && !sc->nr_reclaimed)
		reclaim_throttle(pgdat, VMSCAN_THROTTLE_NOPROGRESS);
}

/*
 * This is the direct reclaim path, for page-allocating processes.  We only
 * try to reclaim pages from zones which will satisfy the caller's allocation
 * request.
 *
 * If a zone is deemed to be full of pinned pages then just give it a light
 * scan then give up on it.
 */
static void shrink_zones(struct zonelist *zonelist, struct scan_control *sc)
{
	struct zoneref *z;
	struct zone *zone;
	unsigned long nr_soft_reclaimed;
	unsigned long nr_soft_scanned;
	gfp_t orig_mask;
	pg_data_t *last_pgdat = NULL;
	pg_data_t *first_pgdat = NULL;

	/*
	 * If the number of buffer_heads in the machine exceeds the maximum
	 * allowed level, force direct reclaim to scan the highmem zone as
	 * highmem pages could be pinning lowmem pages storing buffer_heads
	 */
	orig_mask = sc->gfp_mask;
	if (buffer_heads_over_limit) {
		sc->gfp_mask |= __GFP_HIGHMEM;
		sc->reclaim_idx = gfp_zone(sc->gfp_mask);
	}

	for_each_zone_zonelist_nodemask(zone, z, zonelist,
					sc->reclaim_idx, sc->nodemask) {
		/*
		 * Take care memory controller reclaiming has small influence
		 * to global LRU.
		 */
		if (!cgroup_reclaim(sc)) {
			if (!cpuset_zone_allowed(zone,
						 GFP_KERNEL | __GFP_HARDWALL))
				continue;

			/*
			 * If we already have plenty of memory free for
			 * compaction in this zone, don't free any more.
			 * Even though compaction is invoked for any
			 * non-zero order, only frequent costly order
			 * reclamation is disruptive enough to become a
			 * noticeable problem, like transparent huge
			 * page allocations.
			 */
			if (IS_ENABLED(CONFIG_COMPACTION) &&
			    sc->order > PAGE_ALLOC_COSTLY_ORDER &&
			    compaction_ready(zone, sc)) {
				sc->compaction_ready = true;
				continue;
			}

			/*
			 * Shrink each node in the zonelist once. If the
			 * zonelist is ordered by zone (not the default) then a
			 * node may be shrunk multiple times but in that case
			 * the user prefers lower zones being preserved.
			 */
			if (zone->zone_pgdat == last_pgdat)
				continue;

			/*
			 * This steals pages from memory cgroups over softlimit
			 * and returns the number of reclaimed pages and
			 * scanned pages. This works for global memory pressure
			 * and balancing, not for a memcg's limit.
			 */
			nr_soft_scanned = 0;
			nr_soft_reclaimed = memcg1_soft_limit_reclaim(zone->zone_pgdat,
								      sc->order, sc->gfp_mask,
								      &nr_soft_scanned);
			sc->nr_reclaimed += nr_soft_reclaimed;
			sc->nr_scanned += nr_soft_scanned;
			/* need some check for avoid more shrink_zone() */
		}

		if (!first_pgdat)
			first_pgdat = zone->zone_pgdat;

		/* See comment about same check for global reclaim above */
		if (zone->zone_pgdat == last_pgdat)
			continue;
		last_pgdat = zone->zone_pgdat;
		shrink_node(zone->zone_pgdat, sc);
	}

	if (first_pgdat)
		consider_reclaim_throttle(first_pgdat, sc);

	/*
	 * Restore to original mask to avoid the impact on the caller if we
	 * promoted it to __GFP_HIGHMEM.
	 */
	sc->gfp_mask = orig_mask;
}

static void snapshot_refaults(struct mem_cgroup *target_memcg, pg_data_t *pgdat)
{
	struct lruvec *target_lruvec;
	unsigned long refaults;

	if (lru_gen_enabled())
		return;

	target_lruvec = mem_cgroup_lruvec(target_memcg, pgdat);
	refaults = lruvec_page_state(target_lruvec, WORKINGSET_ACTIVATE_ANON);
	target_lruvec->refaults[WORKINGSET_ANON] = refaults;
	refaults = lruvec_page_state(target_lruvec, WORKINGSET_ACTIVATE_FILE);
	target_lruvec->refaults[WORKINGSET_FILE] = refaults;
}

/*
 * This is the main entry point to direct page reclaim.
 *
 * If a full scan of the inactive list fails to free enough memory then we
 * are "out of memory" and something needs to be killed.
 *
 * If the caller is !__GFP_FS then the probability of a failure is reasonably
 * high - the zone may be full of dirty or under-writeback pages, which this
 * caller can't do much about.  We kick the writeback threads and take explicit
 * naps in the hope that some of these pages can be written.  But if the
 * allocating task holds filesystem locks which prevent writeout this might not
 * work, and the allocation attempt will fail.
 *
 * returns:	0, if no pages reclaimed
 * 		else, the number of pages reclaimed
 */
static unsigned long do_try_to_free_pages(struct zonelist *zonelist,
					  struct scan_control *sc)
{
	int initial_priority = sc->priority;
	pg_data_t *last_pgdat;
	struct zoneref *z;
	struct zone *zone;
retry:
	delayacct_freepages_start();

	if (!cgroup_reclaim(sc))
		__count_zid_vm_events(ALLOCSTALL, sc->reclaim_idx, 1);

	do {
		if (!sc->proactive)
			vmpressure_prio(sc->gfp_mask, sc->target_mem_cgroup,
					sc->priority);
		sc->nr_scanned = 0;
		shrink_zones(zonelist, sc);

		if (sc->nr_reclaimed >= sc->nr_to_reclaim)
			break;

		if (sc->compaction_ready)
			break;

		/*
		 * If we're getting trouble reclaiming, start doing
		 * writepage even in laptop mode.
		 */
		if (sc->priority < DEF_PRIORITY - 2)
			sc->may_writepage = 1;
	} while (--sc->priority >= 0);

	last_pgdat = NULL;
	for_each_zone_zonelist_nodemask(zone, z, zonelist, sc->reclaim_idx,
					sc->nodemask) {
		if (zone->zone_pgdat == last_pgdat)
			continue;
		last_pgdat = zone->zone_pgdat;

		snapshot_refaults(sc->target_mem_cgroup, zone->zone_pgdat);

		if (cgroup_reclaim(sc)) {
			struct lruvec *lruvec;

			lruvec = mem_cgroup_lruvec(sc->target_mem_cgroup,
						   zone->zone_pgdat);
			clear_bit(LRUVEC_CGROUP_CONGESTED, &lruvec->flags);
		}
	}

	delayacct_freepages_end();

	if (sc->nr_reclaimed)
		return sc->nr_reclaimed;

	/* Aborted reclaim to try compaction? don't OOM, then */
	if (sc->compaction_ready)
		return 1;

	/*
	 * In most cases, direct reclaimers can do partial walks
	 * through the cgroup tree to meet the reclaim goal while
	 * keeping latency low. Since the iterator state is shared
	 * among all direct reclaim invocations (to retain fairness
	 * among cgroups), though, high concurrency can result in
	 * individual threads not seeing enough cgroups to make
	 * meaningful forward progress. Avoid false OOMs in this case.
	 */
	if (!sc->memcg_full_walk) {
		sc->priority = initial_priority;
		sc->memcg_full_walk = 1;
		goto retry;
	}

	/*
	 * We make inactive:active ratio decisions based on the node's
	 * composition of memory, but a restrictive reclaim_idx or a
	 * memory.low cgroup setting can exempt large amounts of
	 * memory from reclaim. Neither of which are very common, so
	 * instead of doing costly eligibility calculations of the
	 * entire cgroup subtree up front, we assume the estimates are
	 * good, and retry with forcible deactivation if that fails.
	 */
	if (sc->skipped_deactivate) {
		sc->priority = initial_priority;
		sc->force_deactivate = 1;
		sc->skipped_deactivate = 0;
		goto retry;
	}

	/* Untapped cgroup reserves?  Don't OOM, retry. */
	if (sc->memcg_low_skipped) {
		sc->priority = initial_priority;
		sc->force_deactivate = 0;
		sc->memcg_low_reclaim = 1;
		sc->memcg_low_skipped = 0;
		goto retry;
	}

	return 0;
}

static bool allow_direct_reclaim(pg_data_t *pgdat)
{
	struct zone *zone;
	unsigned long pfmemalloc_reserve = 0;
	unsigned long free_pages = 0;
	int i;
	bool wmark_ok;

	if (pgdat->kswapd_failures >= MAX_RECLAIM_RETRIES)
		return true;

	for_each_managed_zone_pgdat(zone, pgdat, i, ZONE_NORMAL) {
		if (!zone_reclaimable_pages(zone))
			continue;

		pfmemalloc_reserve += min_wmark_pages(zone);
		free_pages += zone_page_state_snapshot(zone, NR_FREE_PAGES);
	}

	/* If there are no reserves (unexpected config) then do not throttle */
	if (!pfmemalloc_reserve)
		return true;

	wmark_ok = free_pages > pfmemalloc_reserve / 2;

	/* kswapd must be awake if processes are being throttled */
	if (!wmark_ok && waitqueue_active(&pgdat->kswapd_wait)) {
		if (READ_ONCE(pgdat->kswapd_highest_zoneidx) > ZONE_NORMAL)
			WRITE_ONCE(pgdat->kswapd_highest_zoneidx, ZONE_NORMAL);

		wake_up_interruptible(&pgdat->kswapd_wait);
	}

	return wmark_ok;
}

/*
 * Throttle direct reclaimers if backing storage is backed by the network
 * and the PFMEMALLOC reserve for the preferred node is getting dangerously
 * depleted. kswapd will continue to make progress and wake the processes
 * when the low watermark is reached.
 *
 * Returns true if a fatal signal was delivered during throttling. If this
 * happens, the page allocator should not consider triggering the OOM killer.
 */
static bool throttle_direct_reclaim(gfp_t gfp_mask, struct zonelist *zonelist,
					nodemask_t *nodemask)
{
	struct zoneref *z;
	struct zone *zone;
	pg_data_t *pgdat = NULL;

	/*
	 * Kernel threads should not be throttled as they may be indirectly
	 * responsible for cleaning pages necessary for reclaim to make forward
	 * progress. kjournald for example may enter direct reclaim while
	 * committing a transaction where throttling it could forcing other
	 * processes to block on log_wait_commit().
	 */
	if (current->flags & PF_KTHREAD)
		goto out;

	/*
	 * If a fatal signal is pending, this process should not throttle.
	 * It should return quickly so it can exit and free its memory
	 */
	if (fatal_signal_pending(current))
		goto out;

	/*
	 * Check if the pfmemalloc reserves are ok by finding the first node
	 * with a usable ZONE_NORMAL or lower zone. The expectation is that
	 * GFP_KERNEL will be required for allocating network buffers when
	 * swapping over the network so ZONE_HIGHMEM is unusable.
	 *
	 * Throttling is based on the first usable node and throttled processes
	 * wait on a queue until kswapd makes progress and wakes them. There
	 * is an affinity then between processes waking up and where reclaim
	 * progress has been made assuming the process wakes on the same node.
	 * More importantly, processes running on remote nodes will not compete
	 * for remote pfmemalloc reserves and processes on different nodes
	 * should make reasonable progress.
	 */
	for_each_zone_zonelist_nodemask(zone, z, zonelist,
					gfp_zone(gfp_mask), nodemask) {
		if (zone_idx(zone) > ZONE_NORMAL)
			continue;

		/* Throttle based on the first usable node */
		pgdat = zone->zone_pgdat;
		if (allow_direct_reclaim(pgdat))
			goto out;
		break;
	}

	/* If no zone was usable by the allocation flags then do not throttle */
	if (!pgdat)
		goto out;

	/* Account for the throttling */
	count_vm_event(PGSCAN_DIRECT_THROTTLE);

	/*
	 * If the caller cannot enter the filesystem, it's possible that it
	 * is due to the caller holding an FS lock or performing a journal
	 * transaction in the case of a filesystem like ext[3|4]. In this case,
	 * it is not safe to block on pfmemalloc_wait as kswapd could be
	 * blocked waiting on the same lock. Instead, throttle for up to a
	 * second before continuing.
	 */
	if (!(gfp_mask & __GFP_FS))
		wait_event_interruptible_timeout(pgdat->pfmemalloc_wait,
			allow_direct_reclaim(pgdat), HZ);
	else
		/* Throttle until kswapd wakes the process */
		wait_event_killable(zone->zone_pgdat->pfmemalloc_wait,
			allow_direct_reclaim(pgdat));

	if (fatal_signal_pending(current))
		return true;

out:
	return false;
}

unsigned long try_to_free_pages(struct zonelist *zonelist, int order,
				gfp_t gfp_mask, nodemask_t *nodemask)
{
	unsigned long nr_reclaimed;
	struct scan_control sc = {
		.nr_to_reclaim = SWAP_CLUSTER_MAX,
		.gfp_mask = current_gfp_context(gfp_mask),
		.reclaim_idx = gfp_zone(gfp_mask),
		.order = order,
		.nodemask = nodemask,
		.priority = DEF_PRIORITY,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = 1,
	};

	/*
	 * scan_control uses s8 fields for order, priority, and reclaim_idx.
	 * Confirm they are large enough for max values.
	 */
	BUILD_BUG_ON(MAX_PAGE_ORDER >= S8_MAX);
	BUILD_BUG_ON(DEF_PRIORITY > S8_MAX);
	BUILD_BUG_ON(MAX_NR_ZONES > S8_MAX);

	/*
	 * Do not enter reclaim if fatal signal was delivered while throttled.
	 * 1 is returned so that the page allocator does not OOM kill at this
	 * point.
	 */
	if (throttle_direct_reclaim(sc.gfp_mask, zonelist, nodemask))
		return 1;

	set_task_reclaim_state(current, &sc.reclaim_state);
	trace_mm_vmscan_direct_reclaim_begin(order, sc.gfp_mask);

	nr_reclaimed = do_try_to_free_pages(zonelist, &sc);

	trace_mm_vmscan_direct_reclaim_end(nr_reclaimed);
	set_task_reclaim_state(current, NULL);

	return nr_reclaimed;
}

#ifdef CONFIG_MEMCG

/* Only used by soft limit reclaim. Do not reuse for anything else. */
unsigned long mem_cgroup_shrink_node(struct mem_cgroup *memcg,
						gfp_t gfp_mask, bool noswap,
						pg_data_t *pgdat,
						unsigned long *nr_scanned)
{
	struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
	struct scan_control sc = {
		.nr_to_reclaim = SWAP_CLUSTER_MAX,
		.target_mem_cgroup = memcg,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.reclaim_idx = MAX_NR_ZONES - 1,
		.may_swap = !noswap,
	};

	WARN_ON_ONCE(!current->reclaim_state);

	sc.gfp_mask = (gfp_mask & GFP_RECLAIM_MASK) |
			(GFP_HIGHUSER_MOVABLE & ~GFP_RECLAIM_MASK);

	trace_mm_vmscan_memcg_softlimit_reclaim_begin(sc.order,
						      sc.gfp_mask);

	/*
	 * NOTE: Although we can get the priority field, using it
	 * here is not a good idea, since it limits the pages we can scan.
	 * if we don't reclaim here, the shrink_node from balance_pgdat
	 * will pick up pages from other mem cgroup's as well. We hack
	 * the priority and make it zero.
	 */
	shrink_lruvec(lruvec, &sc);

	trace_mm_vmscan_memcg_softlimit_reclaim_end(sc.nr_reclaimed);

	*nr_scanned = sc.nr_scanned;

	return sc.nr_reclaimed;
}

unsigned long try_to_free_mem_cgroup_pages(struct mem_cgroup *memcg,
					   unsigned long nr_pages,
					   gfp_t gfp_mask,
					   unsigned int reclaim_options,
					   int *swappiness)
{
	unsigned long nr_reclaimed;
	unsigned int noreclaim_flag;
	struct scan_control sc = {
		.nr_to_reclaim = max(nr_pages, SWAP_CLUSTER_MAX),
		.proactive_swappiness = swappiness,
		.gfp_mask = (current_gfp_context(gfp_mask) & GFP_RECLAIM_MASK) |
				(GFP_HIGHUSER_MOVABLE & ~GFP_RECLAIM_MASK),
		.reclaim_idx = MAX_NR_ZONES - 1,
		.target_mem_cgroup = memcg,
		.priority = DEF_PRIORITY,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = !!(reclaim_options & MEMCG_RECLAIM_MAY_SWAP),
		.proactive = !!(reclaim_options & MEMCG_RECLAIM_PROACTIVE),
	};
	/*
	 * Traverse the ZONELIST_FALLBACK zonelist of the current node to put
	 * equal pressure on all the nodes. This is based on the assumption that
	 * the reclaim does not bail out early.
	 */
	struct zonelist *zonelist = node_zonelist(numa_node_id(), sc.gfp_mask);

	set_task_reclaim_state(current, &sc.reclaim_state);
	trace_mm_vmscan_memcg_reclaim_begin(0, sc.gfp_mask);
	noreclaim_flag = memalloc_noreclaim_save();

	nr_reclaimed = do_try_to_free_pages(zonelist, &sc);

	memalloc_noreclaim_restore(noreclaim_flag);
	trace_mm_vmscan_memcg_reclaim_end(nr_reclaimed);
	set_task_reclaim_state(current, NULL);

	return nr_reclaimed;
}
#endif

static void kswapd_age_node(struct pglist_data *pgdat, struct scan_control *sc)
{
	struct mem_cgroup *memcg;
	struct lruvec *lruvec;

	if (lru_gen_enabled()) {
		lru_gen_age_node(pgdat, sc);
		return;
	}

	lruvec = mem_cgroup_lruvec(NULL, pgdat);
	if (!can_age_anon_pages(lruvec, sc))
		return;

	if (!inactive_is_low(lruvec, LRU_INACTIVE_ANON))
		return;

	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		lruvec = mem_cgroup_lruvec(memcg, pgdat);
		shrink_active_list(SWAP_CLUSTER_MAX, lruvec,
				   sc, LRU_ACTIVE_ANON);
		memcg = mem_cgroup_iter(NULL, memcg, NULL);
	} while (memcg);
}

static bool pgdat_watermark_boosted(pg_data_t *pgdat, int highest_zoneidx)
{
	int i;
	struct zone *zone;

	/*
	 * Check for watermark boosts top-down as the higher zones
	 * are more likely to be boosted. Both watermarks and boosts
	 * should not be checked at the same time as reclaim would
	 * start prematurely when there is no boosting and a lower
	 * zone is balanced.
	 */
	for (i = highest_zoneidx; i >= 0; i--) {
		zone = pgdat->node_zones + i;
		if (!managed_zone(zone))
			continue;

		if (zone->watermark_boost)
			return true;
	}

	return false;
}

// 检查给定的NUMA节点 pgdat 是否在指定 order (分配阶数) 和 highest_zoneidx (允许分配的最高内存区域索引) 的限制下，
// 拥有至少一个“合格”且“平衡”的内存区域（zone）。
// pgdat： 指向要检查的NUMA节点数据的指针。
// order： 伙伴分配器中的分配阶数。例如，order=0 申请一页(4KB)，order=3 申请8页(32KB)。它代表了连续物理页的需求。
// highest_zoneidx： 调用方允许从哪个区域索引及以下的区域进行分配。例如，如果调用只能从 ZONE_NORMAL 及以下分配，这个值就是 ZONE_NORMAL 的索引。
// 返回值： true 如果至少找到一个符合条件的zone，否则 false。
static bool pgdat_balanced(pg_data_t *pgdat, int order, int highest_zoneidx)
{
	int i;
	unsigned long mark = -1; // 初始化标记为-1，这是一个特殊值
	struct zone *zone;

	// 开始一个宏循环：遍历NUMA节点 pgdat 中，索引从0到 highest_zoneidx 的所有被有效管理的内存区域（zone）。
	// 例如，如果 highest_zoneidx 是 ZONE_NORMAL，它就不会遍历 ZONE_HIGHMEM。
	for_each_managed_zone_pgdat(zone, pgdat, i, highest_zoneidx) {
		enum zone_stat_item item;
		unsigned long free_pages;

		if (sysctl_numa_balancing_mode & NUMA_BALANCING_MEMORY_TIERING)
			// 如果系统配置了基于内存分层（Memory Tiering） 的NUMA平衡策略，则使用 promo_wmark_pages(zone) 作为标记。
			// 这个水位线通常比普通的高水位线更低，目的是为了促进（promote）页面在NUMA节点间迁移，即使空闲内存不多，也尝试平衡。
			mark = promo_wmark_pages(zone);
		else
			// 否则，使用标准的高水位线（high watermark） high_wmark_pages(zone)。这是zone的空闲页数需要超过的一个标准阈值，
			// 以达到“平衡”状态。如果一个zone的空闲页高于高水位线，说明它很充裕。
			mark = high_wmark_pages(zone);

		if (defrag_mode && order)
			// 如果调用方开启了碎片整理模式（defrag_mode）并且申请的是高阶内存（order > 0），则使用 NR_FREE_PAGES_BLOCKS。
			// 这个统计项计算的是足够大、能够满足当前 order 需求的连续空闲页块的数量。这避免了碎片化严重时，总空闲页多但都是零散小页，无法满足大块分配请求的情况。
			item = NR_FREE_PAGES_BLOCKS;
		else
			// 否则，使用最常规的 NR_FREE_PAGES，即zone中所有空闲页的总和。
			item = NR_FREE_PAGES;

		// 从zone的统计信息中，获取上一步选择的统计项（item）的当前值，存入 free_pages。
		free_pages = zone_page_state(zone, item);
		/*
			处理CPU计数器的漂移（Drift）：这是一个优化和容错处理。
			每个CPU都有本地的内存统计计数器，定期同步到zone的总计中。zone_page_state 读取的是总计，可能略有滞后。
			percpu_drift_mark 是一个阈值，如果计算出的 free_pages 低于这个值，说明空闲页已经非常紧张。
			在这种情况下，为了避免因为计数器不同步而误判，函数会使用 zone_page_state_snapshot。这个函数代价更高，
			它会精确地汇总所有CPU的本地计数器，得到一个最新、最准确的空闲页数量。
		*/
		if (zone->percpu_drift_mark && free_pages < zone->percpu_drift_mark)
			free_pages = zone_page_state_snapshot(zone, item);

		/*
			核心检查：调用 __zone_watermark_ok 函数，使用前面计算出的参数，检查当前zone是否满足水位要求。
			zone: 要检查的zone。
			order: 需求的分配阶。
			mark: 要超过的水位线（high_wmark 或 promo_wmark）。
			highest_zoneidx: 允许的最高区域。
			0: 这是一个保留的访问标志，通常为0。
			free_pages: 用于比较的空闲页数（可能是总计也可能是快照）。
			如果这个zone通过了检查（即空闲页足够），函数立即返回 true，表示找到了一个平衡的zone。
		*/
		if (__zone_watermark_ok(zone, order, mark, highest_zoneidx,
					0, free_pages))
			return true;
	}

	/*
		处理循环未执行的情况：如果 mark 还是初始值 -1，说明上面的 for 循环一次都没有执行。
		循环未执行的原因通常是：highest_zoneidx 参数可能是一个无效的索引（比如小于0），或者该NUMA节点在请求的索引范围内没有任何被管理的zone。
		在这种情况下，函数认为没有zone需要检查，因此默认返回 true（“平衡”），这是一种安全退出的策略。
	*/
	if (mark == -1)
		return true;

	// 如果循环执行了（mark 不是 -1）但没有找到任何一个合格的zone，则返回 false，表示这个NUMA节点在要求的条件下不平衡，内存回收器或分配器需要采取行动。
	return false;
}

/* Clear pgdat state for congested, dirty or under writeback. */
static void clear_pgdat_congested(pg_data_t *pgdat)
{
	struct lruvec *lruvec = mem_cgroup_lruvec(NULL, pgdat);

	clear_bit(LRUVEC_NODE_CONGESTED, &lruvec->flags);
	clear_bit(LRUVEC_CGROUP_CONGESTED, &lruvec->flags);
	clear_bit(PGDAT_DIRTY, &pgdat->flags);
	clear_bit(PGDAT_WRITEBACK, &pgdat->flags);
}

/*
 * Prepare kswapd for sleeping. This verifies that there are no processes
 * waiting in throttle_direct_reclaim() and that watermarks have been met.
 *
 * Returns true if kswapd is ready to sleep
 */
static bool prepare_kswapd_sleep(pg_data_t *pgdat, int order,
				int highest_zoneidx)
{
	/*
	 * The throttled processes are normally woken up in balance_pgdat() as
	 * soon as allow_direct_reclaim() is true. But there is a potential
	 * race between when kswapd checks the watermarks and a process gets
	 * throttled. There is also a potential race if processes get
	 * throttled, kswapd wakes, a large process exits thereby balancing the
	 * zones, which causes kswapd to exit balance_pgdat() before reaching
	 * the wake up checks. If kswapd is going to sleep, no process should
	 * be sleeping on pfmemalloc_wait, so wake them now if necessary. If
	 * the wake up is premature, processes will wake kswapd and get
	 * throttled again. The difference from wake ups in balance_pgdat() is
	 * that here we are under prepare_to_wait().
	 */
	if (waitqueue_active(&pgdat->pfmemalloc_wait))
		wake_up_all(&pgdat->pfmemalloc_wait);

	/* Hopeless node, leave it to direct reclaim */
	if (pgdat->kswapd_failures >= MAX_RECLAIM_RETRIES)
		return true;

	if (pgdat_balanced(pgdat, order, highest_zoneidx)) {
		clear_pgdat_congested(pgdat);
		return true;
	}

	return false;
}

/*
	kswapd 会收缩当前不平衡的页面节点，这些页面节点位于最高可用区域或以下。

	如果 kswapd 扫描的页面数量至少达到请求的回收数量，或者由于页面处于回写状态而导致
	进度缓慢，则返回 true。这用于确定是否需要提高扫描优先级。
*/
static bool kswapd_shrink_node(pg_data_t *pgdat,
			       struct scan_control *sc)
{
	struct zone *zone;
	int z;
	unsigned long nr_reclaimed = sc->nr_reclaimed;  // 记录初始已回收页数

	sc->nr_to_reclaim = 0;
	// 遍历需回收的zone（受限于sc->reclaim_idx）
	for_each_managed_zone_pgdat(zone, pgdat, z, sc->reclaim_idx) {
		// high_wmark_pages(zone)：该zone的高水位页数
		// SWAP_CLUSTER_MAX：32（典型值），最小回收单元
		// 取二者最大值：确保每轮回收足够页面，防止小规模无效回收
		sc->nr_to_reclaim += max(high_wmark_pages(zone), SWAP_CLUSTER_MAX);
	}

	// 核心回收执行
	shrink_node(pgdat, sc);

	// 当进行高阶内存分配（order>0）的回收时，如果实际回收页数已经达到该order对应的压缩间隙阈值，就主动降级回收目标（将order设为0）。
	// 高阶分配需要大量连续内存，回收压力大。如果已经回收了“足够多”的页（通过compact_gap计算），可能已经满足了原始需求或触发了其他
	// 机制（如压缩），这时继续坚持高阶回收可能效率低下，不如降级为普通单页回收更高效。
	if (sc->order && sc->nr_reclaimed >= compact_gap(sc->order))
		sc->order = 0;

	/* account for progress from mm_account_reclaimed_pages() */
	// 回收成效验证
	// 计算实际回收增量：sc->nr_reclaimed - nr_reclaimed
	// 与扫描页数(sc->nr_scanned)比较
	return max(sc->nr_scanned, sc->nr_reclaimed - nr_reclaimed) >= sc->nr_to_reclaim;
}

/* Page allocator PCP high watermark is lowered if reclaim is active. */
static inline void
update_reclaim_active(pg_data_t *pgdat, int highest_zoneidx, bool active)
{
	int i;
	struct zone *zone;

	for_each_managed_zone_pgdat(zone, pgdat, i, highest_zoneidx) {
		if (active)
			set_bit(ZONE_RECLAIM_ACTIVE, &zone->flags);
		else
			clear_bit(ZONE_RECLAIM_ACTIVE, &zone->flags);
	}
}

static inline void
set_reclaim_active(pg_data_t *pgdat, int highest_zoneidx)
{
	update_reclaim_active(pgdat, highest_zoneidx, true);
}

static inline void
clear_reclaim_active(pg_data_t *pgdat, int highest_zoneidx)
{
	update_reclaim_active(pgdat, highest_zoneidx, false);
}

/*
 * For kswapd, balance_pgdat() will reclaim pages across a node from zones
 * that are eligible for use by the caller until at least one zone is
 * balanced.
 *
 * Returns the order kswapd finished reclaiming at.
 *
 * kswapd scans the zones in the highmem->normal->dma direction.  It skips
 * zones which have free_pages > high_wmark_pages(zone), but once a zone is
 * found to have free_pages <= high_wmark_pages(zone), any page in that zone
 * or lower is eligible for reclaim until at least one usable zone is
 * balanced.
 */
/*
	对于 kswapd，balance_pgdat() 将从调用者可用的区域中回收节点内的页面，直到至少一个可用区域达到平衡。

	返回 kswapd 完成回收的顺序。

	kswapd 会按 highmem->normal->dma 方向扫描区域。它会跳过 free_pages > high_wmark_pages(zone) 的
	区域，但一旦发现某个区域的 free_pages <= high_wmark_pages(zone)，则该区域或更低区域内的任何页面
	都有资格回收，直到至少一个可用区域达到平衡。
*/
// pgdat：指向要平衡的内存节点的指针。
// order：要求回收的页面数量（2的order次方个页面）。
// highest_zoneidx：回收可以触及的最高内存区域索引（zone索引，从0开始，数值越小表示内存越稀缺）。
static int balance_pgdat(pg_data_t *pgdat, int order, int highest_zoneidx)
{
	int i;
	unsigned long nr_soft_reclaimed;    	// 软限制回收的页面数
	unsigned long nr_soft_scanned;       	// 软限制扫描的页面数
	unsigned long pflags;                	// 用于psi（压力停滞信息）的标志
	unsigned long nr_boost_reclaim;      	// 需要回收的boost总量
	unsigned long zone_boosts[MAX_NR_ZONES] = { 0, }; 	// 每个zone的boost值
	bool boosted;                        	// 是否发生了boost
	struct zone *zone;                   	// 遍历时指向当前zone的指针
	struct scan_control sc = {           	// 扫描控制结构，配置回收行为
		.gfp_mask = GFP_KERNEL,       		// 使用GFP_KERNEL标志，允许等待
		.order = order,               		// 传入的order
		.may_unmap = 1,               		// 允许取消页面映射（即回收匿名页或页面缓存时解除映射）
	};

	set_task_reclaim_state(current, &sc.reclaim_state); 	// 设置当前任务的回收状态
	/*
		典型调用位置
		1. 直接内存回收路径（最核心场景）:内核在直接内存回收（Direct Reclaim） 期间调用，当进程因内存不足被迫等待回收完成时
		2. 内存压缩路径:在内存碎片整理（Compaction） 中，当进程因碎片问题需要迁移页面时
		3. 页面错误处理路径:进程触发页面错误（Page Fault） 且需要等待内存分配时
		4. 内存分配慢路径:当进程通过 __alloc_pages_slowpath() 分配内存时陷入等待
		5. cgroup 内存限制:当 cgroup 达到内存限制阈值时，触发进程阻塞
	*/
	psi_memstall_enter(&pflags);                        	// 进入内存停滞状态，用于PSI统计
	__fs_reclaim_acquire(_THIS_IP_);                     	// 禁止文件系统回收（防止递归死锁）

	count_vm_event(PAGEOUTRUN);                          	// 增加VM事件计数：一次页面回收运行

	nr_boost_reclaim = 0;
	// watermark_boost：每个zone有一个boost值，当分配失败时可能会提高水位线（watermark）以触发
	// kswapd更积极地回收。这里记录下当前的boost值，以便在回收完成后降低boost。
	for_each_managed_zone_pgdat(zone, pgdat, i, highest_zoneidx) {
		/*
			zone->watermark_boost 是 Linux 内核在每个内存区（zone）里维护的一个“动态加成值”（单位：页），用来临时抬高该 zone 的水位线（min/low/high）。
			它的目的，是在系统经历过高阶（order>0）页分配压力时，预留出更多空闲页，让 kswapd 更积极地回收，提前为将来的高阶分配准备连续空闲内存，
			降低分配卡顿和失败概率。
		*/
		nr_boost_reclaim += zone->watermark_boost;   	// 累加所有zone的watermark_boost
		zone_boosts[i] = zone->watermark_boost;       	// 记录每个zone的boost值
	}
	boosted = nr_boost_reclaim;   // 如果 nr_boost_reclaim 大于0，则 boosted 为 true

restart:
	set_reclaim_active(pgdat, highest_zoneidx); 		// 设置节点为回收活跃状态
	sc.priority = DEF_PRIORITY;                 		// 初始化扫描优先级为默认值（12）
	do {
		unsigned long nr_reclaimed = sc.nr_reclaimed; 	// 记录本轮循环开始时已回收的页面数
		bool raise_priority = true;                  	// 默认下一轮需要提高优先级（即降低优先级数值）
		bool balanced;
		bool ret;
		bool was_frozen;

		sc.reclaim_idx = highest_zoneidx;           	// 设置扫描控制中的回收索引为最高zone索引

		// 当系统因管理海量磁盘缓存映射（buffer_head）而面临性能瓶颈时，此代码会强制内存回收器改变策略，
		// 优先甚至专门从高端内存区域（ZONE_HIGHMEM）开始回收内存，因为那里是问题的根源所在。
		// 问题根源：buffer_heads_over_limit 为真，意味着内核花费了太多资源在管理 buffer_head 结构体上，而不是文件数据本身。这是一个性能瓶颈信号。
		// ZONE_HIGHMEM（高端内存区） 传统上专门用于存放用户进程的数据和文件的页缓存（Page Cache）。而文件的页缓存，正是绝大多数 buffer_head 所映射和管理的对象。
		if (buffer_heads_over_limit) {
			// 如果超过，则进入紧急处理模式。
			// 初始化一个循环，从最高索引的内存区域向最低索引遍历。
			// MAX_NR_ZONES - 1 通常是 ZONE_HIGHMEM 或 ZONE_MOVABLE 的索引。
			for (i = MAX_NR_ZONES - 1; i >= 0; i--) {
				// 获取当前遍历到的内存区域（zone）的指针。
        		// 例如：i=2 对应 ZONE_HIGHMEM, i=1 对应 ZONE_NORMAL, i=0 对应 ZONE_DMA。
				zone = pgdat->node_zones + i;
				// 检查该区域是否被内核有效管理（例如，是否存在且有页面）。
        		// 如果不是，则跳过此区域，继续检查下一个（更低）的区域。
				if (!managed_zone(zone))
					continue;

				// 如果找到一个被有效管理的内存区域，立即将内存回收器（sc）的
        		// 回收索引（reclaim_idx）设置为当前区域的索引（i）。
				sc.reclaim_idx = i;
				// 然后立刻跳出循环。因为我们只需要找到第一个（即最高地址的）有效区域。
				break;
			}
		}

		// 如果节点不平衡（即有zone的水位线不满足要求）并且之前有boost，那么放弃boost（因为boost可能打破了平衡），然后重新开始。
		balanced = pgdat_balanced(pgdat, sc.order, highest_zoneidx); // 检查节点是否已平衡（即所有可达zone的水位线满足要求）
		if (!balanced && nr_boost_reclaim) {
			nr_boost_reclaim = 0;  // 重置boost_reclaim计数
			goto restart;           // 重新开始，因为boost可能导致不平衡，现在取消boost并重试
		}

		if (!nr_boost_reclaim && balanced)
			goto out;   // 不需要回收，退出

		if (nr_boost_reclaim && sc.priority == DEF_PRIORITY - 2)
			raise_priority = false;   // 如果已经提高到较高优先级（数值为10），则不再提高（避免写回过多）

		// boost回收的目标是快速释放少量内存（通常为了满足高阶分配），因此禁止写回和交换（因为它们慢且可能不是必要的）。
		sc.may_writepage = !laptop_mode && !nr_boost_reclaim; // 允许写页面，除非是笔记本模式或处于boost回收
		sc.may_swap = !nr_boost_reclaim; // 允许交换，除非处于boost回收

		// 通过扫描活动列表，将一段时间未被访问的页面标记为不活跃，以便后续回收。
		kswapd_age_node(pgdat, &sc);  // 对节点的页面进行老化（将不活跃页面移动到不活跃列表的尾部）

		// 在低优先级时强制允许写回
		if (sc.priority < DEF_PRIORITY - 2) // 如果优先级提高到比较高的程度（数值小于10）
			sc.may_writepage = 1;      // 强制允许写回，因为回收困难

		// 软限制回收
		sc.nr_scanned = 0;   // 重置扫描计数
		nr_soft_scanned = 0;
		// 如果启用了MGlru，则始终返回0，多代lru不支持软限制回收
		nr_soft_reclaimed = memcg1_soft_limit_reclaim(pgdat, sc.order,
							      sc.gfp_mask, &nr_soft_scanned);
		sc.nr_reclaimed += nr_soft_reclaimed;  // 累加软限制回收的页面数

		// 收缩节点
		// kswapd_shrink_node 是核心回收函数，它遍历节点的zone并回收页面。
		// 如果它返回true，表示已经回收到足够多的页面，因此不需要在下一轮
		// 提高优先级（即保持当前优先级继续回收）。
		if (kswapd_shrink_node(pgdat, &sc)) // 执行实际的回收工作
			raise_priority = false;    // 如果回收足够有效，则不需要提高优先级

		// 1. 检查：是否有至关重要的内核线程因为等不到保留内存而在等待队列里睡着了？
		if (waitqueue_active(&pgdat->pfmemalloc_wait) &&
				// 2. 检查：当前内存节点的状态是否允许进行直接回收？ (例如，检查水位线，确保唤醒它们后，回收操作有成功的机会)
				allow_direct_reclaim(pgdat))
			// 3. 如果两个条件都满足，就唤醒所有在这个队列上睡眠的线程
			wake_up_all(&pgdat->pfmemalloc_wait); // 如果允许直接回收，唤醒等待的进程

		// 检查是否应该停止（冻结或终止）
		__fs_reclaim_release(_THIS_IP_);  // 临时释放FS回收锁，允许进行冻结操作
		// 检查当前内核线程是否应该停止运行，或者是否曾被冻结过。kswapd 需要定期检查两个信号：
		// kthread_should_stop()：是否有人（例如，内核模块卸载或系统关闭）要求此线程退出。
		// freezing(current)：系统是否正在进行休眠（hibernation/suspend）并要求冻结（freeze）所有内核线程。
		ret = kthread_freezable_should_stop(&was_frozen);
		__fs_reclaim_acquire(_THIS_IP_);   // 重新获取FS回收锁
		if (was_frozen || ret)           // 如果被冻结或需要停止，则跳出循环
			break;

		// 调整优先级和boost计数
		nr_reclaimed = sc.nr_reclaimed - nr_reclaimed; // 计算本轮循环回收的页面数
		nr_boost_reclaim -= min(nr_boost_reclaim, nr_reclaimed); // 减少待回收的boost页面数

		// 如果本次回收没有回收到页面且nr_boost_reclaim>0，则跳出循环（避免死循环）
		if (nr_boost_reclaim && !nr_reclaimed)
			break;
		
		// 如果需要提高优先级或者本轮没有回收页面，则提高优先级（降低优先级数值）
		if (raise_priority || !nr_reclaimed)
			sc.priority--;
	} while (sc.priority >= 1);  // 当优先级大于等于1（即优先级数值从12降到1）时继续循环

	// 如果整个优先级循环都执行完了（优先级降到1以下）但没有回收到页面，
	// 并且是因为cache_trim_mode失败，则重试一次（关闭cache_trim_mode）
	if (!sc.nr_reclaimed && sc.priority < 1 &&
	    !sc.no_cache_trim_mode && sc.cache_trim_mode_failed) {
		sc.no_cache_trim_mode = 1;  // 本次回收的目标非常明确和紧急，请专注于回收最核心的内存（页面缓存和匿名页），不要分心去尝试释放那些VFS缓存，即使它们也占用了内存。
		goto restart;
	}

	// 如果整个回收过程中没有回收任何页面，增加失败计数
	if (!sc.nr_reclaimed)
		pgdat->kswapd_failures++;

out:
	clear_reclaim_active(pgdat, highest_zoneidx); // 清除节点的回收活跃状态

	// 处理boost回收后的清理
	if (boosted) {
		unsigned long flags;

		// 遍历所有zone，减去本次回收中使用的boost值
		for (i = 0; i <= highest_zoneidx; i++) {
			if (!zone_boosts[i])
				continue;

			/* Increments are under the zone lock */
			zone = pgdat->node_zones + i;
			spin_lock_irqsave(&zone->lock, flags);
			zone->watermark_boost -= min(zone->watermark_boost, zone_boosts[i]); // 减去本次使用的boost值
			spin_unlock_irqrestore(&zone->lock, flags);
		}

		// 因为通过回收释放了空间，唤醒kcompactd进行内存碎片整理
		wakeup_kcompactd(pgdat, pageblock_order, highest_zoneidx);
	}

	snapshot_refaults(NULL, pgdat);   // 记录refault（重新进入）的页面数，用于工作集检测
	__fs_reclaim_release(_THIS_IP_);  // 释放FS回收锁
	psi_memstall_leave(&pflags);      // 离开内存停滞状态
	set_task_reclaim_state(current, NULL); // 清除当前任务的回收状态

	// 注意：这个返回值会在kswapd()函数中用于判断是否重新进入休眠。如果实际回收
	// 的阶数（reclaim_order）小于请求的阶数（alloc_order），则重新进入休眠检查
	// 流程（可能因为又有新的请求到来，所以会再次尝试）。
	return sc.order;  // 返回kswapd停止回收时的order，以便上层判断是否满足高阶分配
}

/*
 * The pgdat->kswapd_highest_zoneidx is used to pass the highest zone index to
 * be reclaimed by kswapd from the waker. If the value is MAX_NR_ZONES which is
 * not a valid index then either kswapd runs for first time or kswapd couldn't
 * sleep after previous reclaim attempt (node is still unbalanced). In that
 * case return the zone index of the previous kswapd reclaim cycle.
 */
static enum zone_type kswapd_highest_zoneidx(pg_data_t *pgdat,
					   enum zone_type prev_highest_zoneidx)
{
	enum zone_type curr_idx = READ_ONCE(pgdat->kswapd_highest_zoneidx);

	return curr_idx == MAX_NR_ZONES ? prev_highest_zoneidx : curr_idx;
}

//  kswapd（内核内存回收线程）尝试进入睡眠状态的核心逻辑，旨在平衡内存回收效率与 CPU 资源占用
static void kswapd_try_to_sleep(pg_data_t *pgdat, int alloc_order, int reclaim_order,
				unsigned int highest_zoneidx)
{
	long remaining = 0;
	DEFINE_WAIT(wait);

	// 若线程需冻结（如系统挂起）或显式停止（如 rmmod），直接退出。
	if (freezing(current) || kthread_should_stop())
		return;

	// 将线程加入 pgdat->kswapd_wait 等待队列，状态设为可中断睡眠
	prepare_to_wait(&pgdat->kswapd_wait, &wait, TASK_INTERRUPTIBLE);

	// 检查是否可睡眠（如内存压力已缓解）。
	if (prepare_kswapd_sleep(pgdat, reclaim_order, highest_zoneidx)) {
		// 唤醒时清除压缩失败历史记录（reset_isolation_suitable），为后续压缩操作提供新机会。
		reset_isolation_suitable(pgdat);

		// 触发 kcompactd 压缩内存以腾出连续空间（wakeup_kcompactd）。
		wakeup_kcompactd(pgdat, alloc_order, highest_zoneidx);

		// 通过 schedule_timeout(HZ/10) 休眠 100ms。
		remaining = schedule_timeout(HZ/10);

		if (remaining) { // 若提前唤醒
			WRITE_ONCE(pgdat->kswapd_highest_zoneidx,	// 更新节点最高回收区索引（kswapd_highest_zoneidx）。
					kswapd_highest_zoneidx(pgdat,
							highest_zoneidx));

			// 若当前回收需求大于历史记录（kswapd_order < reclaim_order），更新为更大值。
			if (READ_ONCE(pgdat->kswapd_order) < reclaim_order)
				WRITE_ONCE(pgdat->kswapd_order, reclaim_order);
		}

		finish_wait(&pgdat->kswapd_wait, &wait);
		prepare_to_wait(&pgdat->kswapd_wait, &wait, TASK_INTERRUPTIBLE);
	}

	// 深度睡眠条件：短时睡眠未被中断（!remaining）且当前仍满足睡眠条件。
	if (!remaining &&
	    prepare_kswapd_sleep(pgdat, reclaim_order, highest_zoneidx)) {
		trace_mm_vmscan_kswapd_sleep(pgdat->node_id);

		// 睡眠前切换至 宽松阈值（calculate_normal_threshold），减少误唤醒。
		set_pgdat_percpu_threshold(pgdat, calculate_normal_threshold);

		if (!kthread_should_stop())
			// 调用 schedule() 释放 CPU，直至被唤醒（如内存不足事件）。
			schedule();

		// 唤醒后恢复 压力阈值（calculate_pressure_threshold），提高内存压力敏感度。
		set_pgdat_percpu_threshold(pgdat, calculate_pressure_threshold);
	} else {
		if (remaining)
			// 快速命中（短时睡眠中唤醒）：KSWAPD_LOW_WMARK_HIT_QUICKLY。
			count_vm_event(KSWAPD_LOW_WMARK_HIT_QUICKLY);
		else
			// 内存压力已缓解（直接跳过睡眠）：KSWAPD_HIGH_WMARK_HIT_QUICKLY。
			count_vm_event(KSWAPD_HIGH_WMARK_HIT_QUICKLY);
	}
	finish_wait(&pgdat->kswapd_wait, &wait);
}

/*
 * The background pageout daemon, started as a kernel thread
 * from the init process.
 *
 * This basically trickles out pages so that we have _some_
 * free memory available even if there is no other activity
 * that frees anything up. This is needed for things like routing
 * etc, where we otherwise might have all activity going on in
 * asynchronous contexts that cannot page things out.
 *
 * If there are applications that are active memory-allocators
 * (most normal use), this basically shouldn't matter.
 */
/*
	后台页面调出守护进程，作为内核线程从 init 进程启动。

	这基本上会逐步调出页面，以便即使没有其他活动释放内存，我们仍然有一些可用的空闲内存。这对于路由等任务来说是必需的，
	否则所有活动都可能在异步上下文中进行，无法进行页面调出。

	如果某些应用程序正在使用内存分配器（这是最常见的用途），这基本上不会造成影响。 
*/
static int kswapd(void *p)
{
	unsigned int alloc_order, reclaim_order;
	unsigned int highest_zoneidx = MAX_NR_ZONES - 1;
	pg_data_t *pgdat = (pg_data_t *)p;
	struct task_struct *tsk = current;

	// PF_MEMALLOC ： 赋予 特权内存分配权限，允许在内存紧张时直接分配页面（突破水位线限制），避免递归回收死锁。
	// PF_KSWAPD   ： 标记为 kswapd 线程，便于调试和统计。
	tsk->flags |= PF_MEMALLOC | PF_KSWAPD;
	// 允许内核冻结机制在系统挂起时暂停该线程，并在状态设置完成后，自动尝试一次freeze。
	set_freezable();

	// 此处刚开始初始化kswapd，因此认为之前设置的分配阶数均无效，该阶数表达其他线程请求的需要连续分配的页面的阶数。
	WRITE_ONCE(pgdat->kswapd_order, 0);
	// 取消内存区域优先级限制，该参数用于指导kswapd线程在哪些内存区域范围内执行回收，如下列区域，重要特性：区域类型值越小，表示在内存架构中位置越低。
	/*
	enum zone_type {
    ZONE_DMA,       // 0: 直接内存访问区 (0-16MB)
    ZONE_DMA32,     // 1: 32位DMA区 (<4GB)
    ZONE_NORMAL,    // 2: 普通映射区 (直接映射)
    ZONE_HIGHMEM,   // 3: 高端内存 (32位系统)
    ZONE_MOVABLE,   // 4: 可移动区域
    __MAX_NR_ZONES  // 5: 区域总数
	};
	*/
	// 只回收 <= kswapd_highest_zoneidx 的区域，节点恢复平衡后，重置为 MAX_NR_ZONES（表示不限制区域类型）。
	WRITE_ONCE(pgdat->kswapd_highest_zoneidx, MAX_NR_ZONES);
	// 重置 I/O 节流计数器，准备准确跟踪脏页写回状态。
	/*
	节流登记划分：
		正常 0-10% 最大脏页数		无节流
		轻度 10-30% 最大脏页数		延迟提价
		中度 30-60% 最大脏页数		减少并发
		严重 60-100% 最大脏页数		停止提交

	节流效果矩阵：
		节流等级	回写提交延迟	  最大并发IO	 内存回收强度
		正常		无延迟			 无限制			低
		轻度		100ms			 减少25%		中
		中度		500ms			 减少50%		高
		严重		1s+				 停止提交		紧急回收
	*/
	atomic_set(&pgdat->nr_writeback_throttled, 0);
	for ( ; ; ) {
		bool was_frozen;

		// 读取其他线程设置的 kswapd_order（由内存分配失败触发）。
		alloc_order = reclaim_order = READ_ONCE(pgdat->kswapd_order);
		highest_zoneidx = kswapd_highest_zoneidx(pgdat,
							highest_zoneidx);

kswapd_try_sleep:
		// 通过 kswapd_try_to_sleep() 进入可控休眠
		kswapd_try_to_sleep(pgdat, alloc_order, reclaim_order,
					highest_zoneidx);

		// 读取后立即清零状态，表示请求已被接管。
		alloc_order = READ_ONCE(pgdat->kswapd_order);
		highest_zoneidx = kswapd_highest_zoneidx(pgdat,
							highest_zoneidx);
		// 读取后立即清零状态，表示请求已被接管。
		WRITE_ONCE(pgdat->kswapd_order, 0);
		WRITE_ONCE(pgdat->kswapd_highest_zoneidx, MAX_NR_ZONES);

		// 若线程被解冻，跳过本轮回收（防止解冻后立即触发冗余回收）。
		if (kthread_freezable_should_stop(&was_frozen))
			break; // 跳过解冻后首次回收

		if (was_frozen)
			continue;

		trace_mm_vmscan_kswapd_wake(pgdat->node_id, highest_zoneidx, // 记录唤醒事件
						alloc_order);
		// 执行核心回收逻辑：
		// 1. 按 alloc_order 启动高阶内存回收。
		// 2. 若失败则降级为低阶（最终降至 order-0）回收。
		reclaim_order = balance_pgdat(pgdat, alloc_order,
						highest_zoneidx);
		// 回收结果验证：
		// 1. 成功（reclaim_order >= alloc_order）：正常进入下一轮休眠。
		// 2. 失败（reclaim_order < alloc_order）：跳回休眠检查点（kswapd_try_sleep），重新评估需求。
		if (reclaim_order < alloc_order)
			goto kswapd_try_sleep; // 跳回休眠检查
	}

	tsk->flags &= ~(PF_MEMALLOC | PF_KSWAPD);

	return 0;
}

/*
 * A zone is low on free memory or too fragmented for high-order memory.  If
 * kswapd should reclaim (direct reclaim is deferred), wake it up for the zone's
 * pgdat.  It will wake up kcompactd after reclaiming memory.  If kswapd reclaim
 * has failed or is not needed, still wake up kcompactd if only compaction is
 * needed.
 */
void wakeup_kswapd(struct zone *zone, gfp_t gfp_flags, int order,
		   enum zone_type highest_zoneidx)
{
	pg_data_t *pgdat;
	enum zone_type curr_idx;

	if (!managed_zone(zone))
		return;

	if (!cpuset_zone_allowed(zone, gfp_flags))
		return;

	pgdat = zone->zone_pgdat;
	curr_idx = READ_ONCE(pgdat->kswapd_highest_zoneidx);

	if (curr_idx == MAX_NR_ZONES || curr_idx < highest_zoneidx)
		WRITE_ONCE(pgdat->kswapd_highest_zoneidx, highest_zoneidx);

	if (READ_ONCE(pgdat->kswapd_order) < order)
		WRITE_ONCE(pgdat->kswapd_order, order);

	if (!waitqueue_active(&pgdat->kswapd_wait))
		return;

	/* Hopeless node, leave it to direct reclaim if possible */
	if (pgdat->kswapd_failures >= MAX_RECLAIM_RETRIES ||
	    (pgdat_balanced(pgdat, order, highest_zoneidx) &&
	     !pgdat_watermark_boosted(pgdat, highest_zoneidx))) {
		/*
		 * There may be plenty of free memory available, but it's too
		 * fragmented for high-order allocations.  Wake up kcompactd
		 * and rely on compaction_suitable() to determine if it's
		 * needed.  If it fails, it will defer subsequent attempts to
		 * ratelimit its work.
		 */
		if (!(gfp_flags & __GFP_DIRECT_RECLAIM))
			wakeup_kcompactd(pgdat, order, highest_zoneidx);
		return;
	}

	trace_mm_vmscan_wakeup_kswapd(pgdat->node_id, highest_zoneidx, order,
				      gfp_flags);
	wake_up_interruptible(&pgdat->kswapd_wait);
}

#ifdef CONFIG_HIBERNATION
/*
 * Try to free `nr_to_reclaim' of memory, system-wide, and return the number of
 * freed pages.
 *
 * Rather than trying to age LRUs the aim is to preserve the overall
 * LRU order by reclaiming preferentially
 * inactive > active > active referenced > active mapped
 */
unsigned long shrink_all_memory(unsigned long nr_to_reclaim)
{
	struct scan_control sc = {
		.nr_to_reclaim = nr_to_reclaim,
		.gfp_mask = GFP_HIGHUSER_MOVABLE,
		.reclaim_idx = MAX_NR_ZONES - 1,
		.priority = DEF_PRIORITY,
		.may_writepage = 1,
		.may_unmap = 1,
		.may_swap = 1,
		.hibernation_mode = 1,
	};
	struct zonelist *zonelist = node_zonelist(numa_node_id(), sc.gfp_mask);
	unsigned long nr_reclaimed;
	unsigned int noreclaim_flag;

	fs_reclaim_acquire(sc.gfp_mask);
	noreclaim_flag = memalloc_noreclaim_save();
	set_task_reclaim_state(current, &sc.reclaim_state);

	nr_reclaimed = do_try_to_free_pages(zonelist, &sc);

	set_task_reclaim_state(current, NULL);
	memalloc_noreclaim_restore(noreclaim_flag);
	fs_reclaim_release(sc.gfp_mask);

	return nr_reclaimed;
}
#endif /* CONFIG_HIBERNATION */

/*
 * This kswapd start function will be called by init and node-hot-add.
 */
void __meminit kswapd_run(int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);

	pgdat_kswapd_lock(pgdat);
	if (!pgdat->kswapd) {
		// kswapd 回调函数
		// pgdat 入参
		// nid node id
		pgdat->kswapd = kthread_create_on_node(kswapd, pgdat, nid, "kswapd%d", nid);
		if (IS_ERR(pgdat->kswapd)) {
			/* failure at boot is fatal */
			pr_err("Failed to start kswapd on node %d，ret=%ld\n",
				   nid, PTR_ERR(pgdat->kswapd));
			BUG_ON(system_state < SYSTEM_RUNNING);
			pgdat->kswapd = NULL;
		} else {
			wake_up_process(pgdat->kswapd);
		}
	}
	pgdat_kswapd_unlock(pgdat);
}

/*
 * Called by memory hotplug when all memory in a node is offlined.  Caller must
 * be holding mem_hotplug_begin/done().
 */
void __meminit kswapd_stop(int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	struct task_struct *kswapd;

	pgdat_kswapd_lock(pgdat);
	kswapd = pgdat->kswapd;
	if (kswapd) {
		kthread_stop(kswapd);
		pgdat->kswapd = NULL;
	}
	pgdat_kswapd_unlock(pgdat);
}

static const struct ctl_table vmscan_sysctl_table[] = {
	{
		.procname	= "swappiness",
		.data		= &vm_swappiness,
		.maxlen		= sizeof(vm_swappiness),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_TWO_HUNDRED,
	},
#ifdef CONFIG_NUMA
	{
		.procname	= "zone_reclaim_mode",
		.data		= &node_reclaim_mode,
		.maxlen		= sizeof(node_reclaim_mode),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	}
#endif
};

static int __init kswapd_init(void)
{
	int nid;

	swap_setup();
	for_each_node_state(nid, N_MEMORY)
 		kswapd_run(nid);
	register_sysctl_init("vm", vmscan_sysctl_table);
	return 0;
}

module_init(kswapd_init)

#ifdef CONFIG_NUMA
/*
 * Node reclaim mode
 *
 * If non-zero call node_reclaim when the number of free pages falls below
 * the watermarks.
 */
int node_reclaim_mode __read_mostly;

/*
 * Priority for NODE_RECLAIM. This determines the fraction of pages
 * of a node considered for each zone_reclaim. 4 scans 1/16th of
 * a zone.
 */
#define NODE_RECLAIM_PRIORITY 4

/*
 * Percentage of pages in a zone that must be unmapped for node_reclaim to
 * occur.
 */
int sysctl_min_unmapped_ratio = 1;

/*
 * If the number of slab pages in a zone grows beyond this percentage then
 * slab reclaim needs to occur.
 */
int sysctl_min_slab_ratio = 5;

static inline unsigned long node_unmapped_file_pages(struct pglist_data *pgdat)
{
	unsigned long file_mapped = node_page_state(pgdat, NR_FILE_MAPPED);
	unsigned long file_lru = node_page_state(pgdat, NR_INACTIVE_FILE) +
		node_page_state(pgdat, NR_ACTIVE_FILE);

	/*
	 * It's possible for there to be more file mapped pages than
	 * accounted for by the pages on the file LRU lists because
	 * tmpfs pages accounted for as ANON can also be FILE_MAPPED
	 */
	return (file_lru > file_mapped) ? (file_lru - file_mapped) : 0;
}

/* Work out how many page cache pages we can reclaim in this reclaim_mode */
static unsigned long node_pagecache_reclaimable(struct pglist_data *pgdat)
{
	unsigned long nr_pagecache_reclaimable;
	unsigned long delta = 0;

	/*
	 * If RECLAIM_UNMAP is set, then all file pages are considered
	 * potentially reclaimable. Otherwise, we have to worry about
	 * pages like swapcache and node_unmapped_file_pages() provides
	 * a better estimate
	 */
	if (node_reclaim_mode & RECLAIM_UNMAP)
		nr_pagecache_reclaimable = node_page_state(pgdat, NR_FILE_PAGES);
	else
		nr_pagecache_reclaimable = node_unmapped_file_pages(pgdat);

	/* If we can't clean pages, remove dirty pages from consideration */
	if (!(node_reclaim_mode & RECLAIM_WRITE))
		delta += node_page_state(pgdat, NR_FILE_DIRTY);

	/* Watch for any possible underflows due to delta */
	if (unlikely(delta > nr_pagecache_reclaimable))
		delta = nr_pagecache_reclaimable;

	return nr_pagecache_reclaimable - delta;
}

/*
 * Try to free up some pages from this node through reclaim.
 */
static int __node_reclaim(struct pglist_data *pgdat, gfp_t gfp_mask, unsigned int order)
{
	/* Minimum pages needed in order to stay on node */
	const unsigned long nr_pages = 1 << order;
	struct task_struct *p = current;
	unsigned int noreclaim_flag;
	struct scan_control sc = {
		.nr_to_reclaim = max(nr_pages, SWAP_CLUSTER_MAX),
		.gfp_mask = current_gfp_context(gfp_mask),
		.order = order,
		.priority = NODE_RECLAIM_PRIORITY,
		.may_writepage = !!(node_reclaim_mode & RECLAIM_WRITE),
		.may_unmap = !!(node_reclaim_mode & RECLAIM_UNMAP),
		.may_swap = 1,
		.reclaim_idx = gfp_zone(gfp_mask),
	};
	unsigned long pflags;

	trace_mm_vmscan_node_reclaim_begin(pgdat->node_id, order,
					   sc.gfp_mask);

	cond_resched();
	psi_memstall_enter(&pflags);
	delayacct_freepages_start();
	fs_reclaim_acquire(sc.gfp_mask);
	/*
	 * We need to be able to allocate from the reserves for RECLAIM_UNMAP
	 */
	noreclaim_flag = memalloc_noreclaim_save();
	set_task_reclaim_state(p, &sc.reclaim_state);

	if (node_pagecache_reclaimable(pgdat) > pgdat->min_unmapped_pages ||
	    node_page_state_pages(pgdat, NR_SLAB_RECLAIMABLE_B) > pgdat->min_slab_pages) {
		/*
		 * Free memory by calling shrink node with increasing
		 * priorities until we have enough memory freed.
		 */
		do {
			shrink_node(pgdat, &sc);
		} while (sc.nr_reclaimed < nr_pages && --sc.priority >= 0);
	}

	set_task_reclaim_state(p, NULL);
	memalloc_noreclaim_restore(noreclaim_flag);
	fs_reclaim_release(sc.gfp_mask);
	psi_memstall_leave(&pflags);
	delayacct_freepages_end();

	trace_mm_vmscan_node_reclaim_end(sc.nr_reclaimed);

	return sc.nr_reclaimed >= nr_pages;
}

int node_reclaim(struct pglist_data *pgdat, gfp_t gfp_mask, unsigned int order)
{
	int ret;

	/*
	 * Node reclaim reclaims unmapped file backed pages and
	 * slab pages if we are over the defined limits.
	 *
	 * A small portion of unmapped file backed pages is needed for
	 * file I/O otherwise pages read by file I/O will be immediately
	 * thrown out if the node is overallocated. So we do not reclaim
	 * if less than a specified percentage of the node is used by
	 * unmapped file backed pages.
	 */
	if (node_pagecache_reclaimable(pgdat) <= pgdat->min_unmapped_pages &&
	    node_page_state_pages(pgdat, NR_SLAB_RECLAIMABLE_B) <=
	    pgdat->min_slab_pages)
		return NODE_RECLAIM_FULL;

	/*
	 * Do not scan if the allocation should not be delayed.
	 */
	if (!gfpflags_allow_blocking(gfp_mask) || (current->flags & PF_MEMALLOC))
		return NODE_RECLAIM_NOSCAN;

	/*
	 * Only run node reclaim on the local node or on nodes that do not
	 * have associated processors. This will favor the local processor
	 * over remote processors and spread off node memory allocations
	 * as wide as possible.
	 */
	if (node_state(pgdat->node_id, N_CPU) && pgdat->node_id != numa_node_id())
		return NODE_RECLAIM_NOSCAN;

	if (test_and_set_bit_lock(PGDAT_RECLAIM_LOCKED, &pgdat->flags))
		return NODE_RECLAIM_NOSCAN;

	ret = __node_reclaim(pgdat, gfp_mask, order);
	clear_bit_unlock(PGDAT_RECLAIM_LOCKED, &pgdat->flags);

	if (ret)
		count_vm_event(PGSCAN_ZONE_RECLAIM_SUCCESS);
	else
		count_vm_event(PGSCAN_ZONE_RECLAIM_FAILED);

	return ret;
}
#endif

/**
 * check_move_unevictable_folios - Move evictable folios to appropriate zone
 * lru list
 * @fbatch: Batch of lru folios to check.
 *
 * Checks folios for evictability, if an evictable folio is in the unevictable
 * lru list, moves it to the appropriate evictable lru list. This function
 * should be only used for lru folios.
 */
void check_move_unevictable_folios(struct folio_batch *fbatch)
{
	struct lruvec *lruvec = NULL;
	int pgscanned = 0;
	int pgrescued = 0;
	int i;

	for (i = 0; i < fbatch->nr; i++) {
		struct folio *folio = fbatch->folios[i];
		int nr_pages = folio_nr_pages(folio);

		pgscanned += nr_pages;

		/* block memcg migration while the folio moves between lrus */
		if (!folio_test_clear_lru(folio))
			continue;

		lruvec = folio_lruvec_relock_irq(folio, lruvec);
		if (folio_evictable(folio) && folio_test_unevictable(folio)) {
			lruvec_del_folio(lruvec, folio);
			folio_clear_unevictable(folio);
			lruvec_add_folio(lruvec, folio);
			pgrescued += nr_pages;
		}
		folio_set_lru(folio);
	}

	if (lruvec) {
		__count_vm_events(UNEVICTABLE_PGRESCUED, pgrescued);
		__count_vm_events(UNEVICTABLE_PGSCANNED, pgscanned);
		unlock_page_lruvec_irq(lruvec);
	} else if (pgscanned) {
		count_vm_events(UNEVICTABLE_PGSCANNED, pgscanned);
	}
}
EXPORT_SYMBOL_GPL(check_move_unevictable_folios);
