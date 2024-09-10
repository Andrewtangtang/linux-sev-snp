/* SPDX-License-Identifier: GPL-2.0
 *
 *	Network memory
 *
 *	Author:	Mina Almasry <almasrymina@google.com>
 */

#ifndef _NET_NETMEM_H
#define _NET_NETMEM_H

/**
 * typedef netmem_ref - a nonexistent type marking a reference to generic
 * network memory.
 *
 * A netmem_ref currently is always a reference to a struct page. This
 * abstraction is introduced so support for new memory types can be added.
 *
 * Use the supplied helpers to obtain the underlying memory pointer and fields.
 */
typedef unsigned long __bitwise netmem_ref;

static inline bool netmem_is_net_iov(const netmem_ref netmem)
{
	return (__force unsigned long)netmem & NET_IOV;
}

/* This conversion fails (returns NULL) if the netmem_ref is not struct page
 * backed.
 */
static inline struct page *netmem_to_page(netmem_ref netmem)
{
	if (WARN_ON_ONCE(netmem_is_net_iov(netmem)))
		return NULL;

	return (__force struct page *)netmem;
}

static inline struct net_iov *netmem_to_net_iov(netmem_ref netmem)
{
	if (netmem_is_net_iov(netmem))
		return (struct net_iov *)((__force unsigned long)netmem &
					  ~NET_IOV);

	DEBUG_NET_WARN_ON_ONCE(true);
	return NULL;
}

static inline netmem_ref net_iov_to_netmem(struct net_iov *niov)
{
	return (__force netmem_ref)((unsigned long)niov | NET_IOV);
}

static inline netmem_ref page_to_netmem(struct page *page)
{
	return (__force netmem_ref)page;
}

static inline int netmem_ref_count(netmem_ref netmem)
{
	/* The non-pp refcount of net_iov is always 1. On net_iov, we only
	 * support pp refcounting which uses the pp_ref_count field.
	 */
	if (netmem_is_net_iov(netmem))
		return 1;

	return page_ref_count(netmem_to_page(netmem));
}

static inline unsigned long netmem_pfn_trace(netmem_ref netmem)
{
	if (netmem_is_net_iov(netmem))
		return 0;

	return page_to_pfn(netmem_to_page(netmem));
}

static inline struct net_iov *__netmem_clear_lsb(netmem_ref netmem)
{
	return (struct net_iov *)((__force unsigned long)netmem & ~NET_IOV);
}

static inline struct page_pool *netmem_get_pp(netmem_ref netmem)
{
	return __netmem_clear_lsb(netmem)->pp;
}

static inline atomic_long_t *netmem_get_pp_ref_count_ref(netmem_ref netmem)
{
	return &__netmem_clear_lsb(netmem)->pp_ref_count;
}

static inline bool netmem_is_pref_nid(netmem_ref netmem, int pref_nid)
{
	/* NUMA node preference only makes sense if we're allocating
	 * system memory. Memory providers (which give us net_iovs)
	 * choose for us.
	 */
	if (netmem_is_net_iov(netmem))
		return true;

	return page_to_nid(netmem_to_page(netmem)) == pref_nid;
}

static inline netmem_ref netmem_compound_head(netmem_ref netmem)
{
	/* niov are never compounded */
	if (netmem_is_net_iov(netmem))
		return netmem;

	return page_to_netmem(compound_head(netmem_to_page(netmem)));
}

static inline void *netmem_address(netmem_ref netmem)
{
	if (netmem_is_net_iov(netmem))
		return NULL;

	return page_address(netmem_to_page(netmem));
}

static inline unsigned long netmem_get_dma_addr(netmem_ref netmem)
{
	return __netmem_clear_lsb(netmem)->dma_addr;
}

#endif /* _NET_NETMEM_H */
