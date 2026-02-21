// SPDX-License-Identifier: GPL-2.0-only
/*
 * vhost transport for vsock
 *
 * Copyright (C) 2013-2015 Red Hat, Inc.
 * Author: Asias He <asias@redhat.com>
 *         Stefan Hajnoczi <stefanha@redhat.com>
 */
#include <linux/miscdevice.h>
#include <linux/atomic.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <linux/sched/clock.h>
#include <net/sock.h>
#include <linux/virtio_vsock.h>
#include <linux/vhost.h>
#include <linux/hashtable.h>

#include <net/af_vsock.h>
#include "vhost.h"

#define VHOST_VSOCK_DEFAULT_HOST_CID	2
/* Max number of bytes transferred before requeueing the job.
 * Using this limit prevents one virtqueue from starving others. */
#define VHOST_VSOCK_WEIGHT 0x80000
/* Max number of packets transferred before requeueing the job.
 * Using this limit prevents one virtqueue from starving others with
 * small pkts.
 */
#define VHOST_VSOCK_PKT_WEIGHT 256
#define VHOST_VSOCK_PKT_WINDOW_SIZE 16

enum {
	VHOST_VSOCK_FEATURES = VHOST_FEATURES |
			       (1ULL << VIRTIO_F_ACCESS_PLATFORM) |
			       (1ULL << VIRTIO_VSOCK_F_SEQPACKET)
};

enum {
	VHOST_VSOCK_BACKEND_FEATURES = (1ULL << VHOST_BACKEND_F_IOTLB_MSG_V2)
};

static unsigned int busyloop_timeout_us;
module_param(busyloop_timeout_us, uint, 0644);
MODULE_PARM_DESC(busyloop_timeout_us,
	"Default busy poll timeout in microseconds for all vqs (0 = disabled)");

/* Used to track all the vhost_vsock instances on the system. */
static DEFINE_MUTEX(vhost_vsock_pool_mutex);
static DEFINE_READ_MOSTLY_HASHTABLE(vhost_vsock_pool_hash, 8);

struct vhost_vsock {
	struct vhost_dev dev;
	struct vhost_virtqueue vqs[2];

	struct vhost_work send_pkt_work;
	struct sk_buff_head send_pkt_queue; /* host->guest pending packets */

	atomic_t queued_replies;
	u32 guest_cid;
	bool seqpacket_allow;

	struct vhost_vsock_pool *vsock_pool;
	u16 idx;
};

#define VHOST_VSOCK_MAX_NUM 256
/* This new data structure is required since in `vhost_transport_send_pkt`,
 * we need to acquire the corresponding `struct vhost_vsock` based on
 * `skb->queue_mapping`. Therefore, we need a data structure holding an array of
 * `struct vhost_vsock`.
 */
struct vhost_vsock_pool {
	/* The lock protectes vsock_pool, vsock_pool_num, is_closed. */
	spinlock_t pool_lock;
	/* A temporary workaround. A more reasonable approach is to use a
	 * dyanmic-size array.
	 */
	struct vhost_vsock __rcu *vsock_pool[VHOST_VSOCK_MAX_NUM];
	u16 vsock_pool_num;
	/* For simplicity, while removing elements from vsock_pool, disallow
	 * all underlying transmission. When closing a vhost_vsocks, users
	 * should close all vhost_vsock having same guest_cid at once.
	 *
	 * Otherwise, we need to handle cases that only part of vsock_pool is
	 * removed while other are not.
	 */
	bool is_closed;

	/* Link to global vhost_vsock_pool_hash, writes use vhost_vsock_mutex */
	struct hlist_node hash;
	u32 guest_cid;
};

static u32 vhost_transport_get_local_cid(void)
{
	return VHOST_VSOCK_DEFAULT_HOST_CID;
}

/* Callers that dereference the return value must hold vhost_vsock_mutex or the
 * RCU read lock.
 */
static struct vhost_vsock_pool *vhost_vsock_pool_get(u32 guest_cid)
{
	struct vhost_vsock_pool *vsock_pool;

	hash_for_each_possible_rcu(vhost_vsock_pool_hash, vsock_pool, hash, guest_cid) {
		u32 other_cid = vsock_pool->guest_cid;

		/* Skip instances that have no CID yet */
		if (other_cid == 0)
			continue;

		if (other_cid == guest_cid)
			return vsock_pool;

	}

	return NULL;
}

static inline unsigned long busy_clock(void)
{
	return local_clock() >> 10;
}

static bool vhost_can_busy_poll(unsigned long endtime)
{
	return likely(!need_resched() &&
		      !time_after(busy_clock(), endtime) &&
		      !signal_pending(current));
}

/*
 * Busy-poll both virtqueues for a bounded period.
 *
 * We must hold the paired vq's mutex while calling vhost_vq_avail_empty()
 * on it, because vhost_get_avail_idx() writes to vq->avail_idx.
 * This matches vhost-net's approach (net.c:556).
 */
static void vhost_vsock_busy_poll(struct vhost_vsock *vsock,
				  struct vhost_virtqueue *vq,
				  bool *busyloop_intr)
{
	struct vhost_virtqueue *tx_vq = &vsock->vqs[VSOCK_VQ_TX];
	struct vhost_virtqueue *rx_vq = &vsock->vqs[VSOCK_VQ_RX];
	struct vhost_virtqueue *paired_vq;
	unsigned long endtime;
	u32 timeout;

	timeout = vq->busyloop_timeout;
	if (!timeout)
		return;

	paired_vq = (vq == rx_vq) ? tx_vq : rx_vq;

	if (!mutex_trylock(&paired_vq->mutex))
		return;
	vhost_disable_notify(&vsock->dev, paired_vq);

	preempt_disable();
	endtime = busy_clock() + timeout;

	while (vhost_can_busy_poll(endtime)) {
		if (vhost_vq_has_work(vq)) {
			*busyloop_intr = true;
			break;
		}

		if (!vhost_vq_avail_empty(&vsock->dev, tx_vq))
			break;

		if (!skb_queue_empty(&vsock->send_pkt_queue) &&
		    !vhost_vq_avail_empty(&vsock->dev, rx_vq))
			break;

		cpu_relax();
	}

	preempt_enable();

	if (!vhost_vq_avail_empty(&vsock->dev, paired_vq)) {
		vhost_poll_queue(&paired_vq->poll);
	} else if (unlikely(vhost_enable_notify(&vsock->dev, paired_vq))) {
		vhost_disable_notify(&vsock->dev, paired_vq);
		vhost_poll_queue(&paired_vq->poll);
	}

	mutex_unlock(&paired_vq->mutex);
}

static int fill_payload_to_iov_iter(struct vhost_vsock *vsock,
				    struct vhost_virtqueue *vq,
				    struct sk_buff *skb,
				    struct iov_iter *iov_iter,
				    size_t iov_len,
				    size_t *total_flow_len,
				    bool *restart_tx)
{
	struct vhost_virtqueue *tx_vq = &vsock->vqs[VSOCK_VQ_TX];
	struct virtio_vsock_hdr *hdr;
	u32 flags_to_restore = 0;
	size_t payload_len;
	u32 offset;
	int ret;

	offset = VIRTIO_VSOCK_SKB_CB(skb)->offset;
	payload_len = skb->len - offset;
	hdr = virtio_vsock_hdr(skb);

	/* If the packet is greater than the space available in the
	 * buffer, we split it using multiple buffers.
	 */
	if (payload_len > iov_len - *total_flow_len - sizeof(*hdr)) {
		payload_len = iov_len - *total_flow_len - sizeof(*hdr);

		/* As we are copying pieces of large packet's buffer to
		 * small rx buffers, headers of packets in rx queue are
		 * created dynamically and are initialized with header
		 * of current packet(except length). But in case of
		 * SOCK_SEQPACKET, we also must clear message delimeter
		 * bit (VIRTIO_VSOCK_SEQ_EOM) and MSG_EOR bit
		 * (VIRTIO_VSOCK_SEQ_EOR) if set. Otherwise,
		 * there will be sequence of packets with these
		 * bits set. After initialized header will be copied to
		 * rx buffer, these required bits will be restored.
		 */
		if (le32_to_cpu(hdr->flags) & VIRTIO_VSOCK_SEQ_EOM) {
			hdr->flags &= ~cpu_to_le32(VIRTIO_VSOCK_SEQ_EOM);
			flags_to_restore |= VIRTIO_VSOCK_SEQ_EOM;

			if (le32_to_cpu(hdr->flags) & VIRTIO_VSOCK_SEQ_EOR) {
				hdr->flags &= ~cpu_to_le32(VIRTIO_VSOCK_SEQ_EOR);
				flags_to_restore |= VIRTIO_VSOCK_SEQ_EOR;
			}
		}
	}

	if ((ret = skb_copy_datagram_iter(skb,
					  offset,
					  iov_iter,
					  payload_len))) {
		kfree_skb(skb);
		vq_err(vq, "Faulted on copying pkt buf\n");
		return -1;
	}

	/* Deliver to monitoring devices all packets that we
	 * will transmit.
	 */
	virtio_transport_deliver_tap_pkt(skb);

	VIRTIO_VSOCK_SKB_CB(skb)->offset += payload_len;
	*total_flow_len += payload_len;

	/* If we didn't send all the payload we can requeue the packet
	 * to send it with the next available buffer.
	 */
	if (VIRTIO_VSOCK_SKB_CB(skb)->offset < skb->len) {
		hdr->flags |= cpu_to_le32(flags_to_restore);

		/* We are queueing the same skb to handle
		 * the remaining bytes, and we want to deliver it
		 * to monitoring devices in the next iteration.
		 */
		virtio_vsock_skb_clear_tap_delivered(skb);
		virtio_vsock_skb_queue_head(&vsock->send_pkt_queue, skb);
	} else {
		if (virtio_vsock_skb_reply(skb)) {
			int val;

			val = atomic_dec_return(&vsock->queued_replies);

			/* Do we have resources to resume tx
			 * processing?
			 */
			if (val + 1 == tx_vq->num)
				*restart_tx = true;
		}

		virtio_transport_consume_skb_sent(skb, true);
	}
	return 0;
}

static void
vhost_transport_do_send_pkt(struct vhost_vsock *vsock,
			    struct vhost_virtqueue *vq)
{
	struct vhost_virtqueue *tx_vq = &vsock->vqs[VSOCK_VQ_TX];
	int pkts = 0, total_len = 0;
	bool restart_tx = false;
	bool queue_is_empty = false;
	bool busyloop_intr = false;
	bool added = false;

	mutex_lock(&vq->mutex);

	if (!vhost_vq_get_backend(vq))
		goto out;

	if (!vq_meta_prefetch(vq))
		goto out;

	/* Avoid further vmexits, we're already processing the virtqueue */
	vhost_disable_notify(&vsock->dev, vq);

	do {
		struct virtio_vsock_hdr *hdr, flow_hdr;
		size_t iov_len, total_flow_len = 0;
		struct iov_iter iov_iter;
		unsigned out, in, cnt = 0;
		bool is_first = true;
		struct sk_buff *skb;
		size_t nbytes;
		int fill_err;
		int head;
		queue_is_empty = false;

		if (skb_queue_empty(&vsock->send_pkt_queue)) {
			if (vq->busyloop_timeout) {
				vhost_vsock_busy_poll(vsock, vq,
						      &busyloop_intr);
				if (!skb_queue_empty(&vsock->send_pkt_queue))
					goto have_pkt;
			}
			queue_is_empty = true;
			break;
		}
have_pkt:
		head = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov),
					 &out, &in, NULL, NULL);
		if (head < 0)
			break;

		if (head == vq->num) {
			if (vq->busyloop_timeout) {
				vhost_vsock_busy_poll(vsock, vq,
						      &busyloop_intr);
				head = vhost_get_vq_desc(vq, vq->iov,
					ARRAY_SIZE(vq->iov),
					&out, &in, NULL, NULL);
				if (head >= 0 && head != vq->num)
					goto got_desc;
			}
			/* We cannot finish yet if more buffers snuck in while
			 * re-enabling notify.
			 */
			if (unlikely(vhost_enable_notify(&vsock->dev, vq))) {
				vhost_disable_notify(&vsock->dev, vq);
				continue;
			}
			break;
		}
got_desc:

		if (out) {
			vq_err(vq, "Expected 0 output buffers, got %u\n", out);
			break;
		}

		iov_len = iov_length(&vq->iov[out], in);
		if (iov_len < sizeof(*hdr)) {
			vq_err(vq, "Buffer len [%zu] too small\n", iov_len);
			break;
		}

		while (cnt++ < VHOST_VSOCK_PKT_WINDOW_SIZE &&
		       total_flow_len + sizeof(*hdr) < iov_len) {
			skb = virtio_vsock_skb_dequeue(&vsock->send_pkt_queue);
			if (!skb) {
				queue_is_empty = true;
				break;
			}
			hdr = virtio_vsock_hdr(skb);

			if (is_first || virtio_vsock_is_same_payload(&flow_hdr, hdr)) {
				if (is_first) {
					/* Preserve the space for hdr in iov_iter. Write the correct
					 * length later.
					 */
					iov_iter_init(&iov_iter, ITER_DEST, &vq->iov[out], in, iov_len);
					nbytes = copy_to_iter(hdr, sizeof(*hdr), &iov_iter);
					if (nbytes != sizeof(*hdr)) {
						kfree_skb(skb);
						vq_err(vq, "Faulted on copying pkt hdr\n");
						break;
					}
					memcpy(&flow_hdr, hdr, sizeof(*hdr));
					is_first = false;
				}
				fill_err = fill_payload_to_iov_iter(vsock, vq,
					skb, &iov_iter, iov_len, &total_flow_len,
					&restart_tx);
			} else {
				virtio_vsock_skb_queue_head(&vsock->send_pkt_queue, skb);
				break;
			}

			if (fill_err)
				goto out;
		}

		/* Set the correct length in the header */
		flow_hdr.len = cpu_to_le32(total_flow_len);
		iov_iter_init(&iov_iter, ITER_DEST, &vq->iov[out], in, iov_len);
		nbytes = copy_to_iter(&flow_hdr, sizeof(flow_hdr), &iov_iter);
		if (nbytes != sizeof(flow_hdr)) {
			vq_err(vq, "Faulted on copying pkt hdr\n");
			break;
		}

		vhost_add_used(vq, head, sizeof(flow_hdr) + total_flow_len);
		added = true;

		total_len += total_flow_len;
	} while(likely(!vhost_exceeds_weight(vq, ++pkts, total_len)) && !queue_is_empty);
out:
	if (queue_is_empty)
		vhost_enable_notify(&vsock->dev, vq);
	if (added)
		vhost_signal(&vsock->dev, vq);
	mutex_unlock(&vq->mutex);

	if (restart_tx)
		vhost_poll_queue(&tx_vq->poll);

	if (unlikely(busyloop_intr))
		vhost_vq_work_queue(vq, &vsock->send_pkt_work);
}

static void vhost_transport_send_pkt_work(struct vhost_work *work)
{
	struct vhost_virtqueue *vq;
	struct vhost_vsock *vsock;

	vsock = container_of(work, struct vhost_vsock, send_pkt_work);
	vq = &vsock->vqs[VSOCK_VQ_RX];

	vhost_transport_do_send_pkt(vsock, vq);
}

static int
vhost_transport_send_pkt(struct sk_buff *skb)
{
	struct virtio_vsock_hdr *hdr = virtio_vsock_hdr(skb);
	struct vhost_vsock_pool *vsock_pool;
	struct vhost_vsock *vsock;
	int len = skb->len;
	u16 queue_idx;

	rcu_read_lock();

	/* Find the vhost_vsock according to guest context id  */
	vsock_pool = vhost_vsock_pool_get(le64_to_cpu(hdr->dst_cid));
	if (!vsock_pool) {
		rcu_read_unlock();
		kfree_skb(skb);
		return -ENODEV;
	}

	spin_lock(&vsock_pool->pool_lock);
	queue_idx = skb->hash % vsock_pool->vsock_pool_num;
	vsock = rcu_dereference(vsock_pool->vsock_pool[queue_idx]);
	spin_unlock(&vsock_pool->pool_lock);

	if (!vsock)
		return -ENODEV;

	if (virtio_vsock_skb_reply(skb))
		atomic_inc(&vsock->queued_replies);

	virtio_vsock_skb_queue_tail(&vsock->send_pkt_queue, skb);
	vhost_vq_work_queue(&vsock->vqs[VSOCK_VQ_RX], &vsock->send_pkt_work);

	rcu_read_unlock();
	return len;
}

static int
vhost_transport_cancel_pkt(struct vsock_sock *vsk)
{
	struct vhost_vsock_pool *vsock_pool;
	struct vhost_vsock *vsock;
	int cnt = 0;
	int ret = -ENODEV;

	rcu_read_lock();

	/* Find the vhost_vsock according to guest context id  */
	vsock_pool = vhost_vsock_pool_get(vsk->remote_addr.svm_cid);
	if (!vsock_pool)
		goto out;

	vsock = vsock_pool->vsock_pool[0];
	cnt = virtio_transport_purge_skbs(vsk, &vsock->send_pkt_queue);

	if (cnt) {
		struct vhost_virtqueue *tx_vq = &vsock->vqs[VSOCK_VQ_TX];
		int new_cnt;

		new_cnt = atomic_sub_return(cnt, &vsock->queued_replies);
		if (new_cnt + cnt >= tx_vq->num && new_cnt < tx_vq->num)
			vhost_poll_queue(&tx_vq->poll);
	}

	ret = 0;
out:
	rcu_read_unlock();
	return ret;
}

static struct sk_buff *
vhost_vsock_alloc_skb(struct vhost_virtqueue *vq,
		      unsigned int out, unsigned int in)
{
	struct virtio_vsock_hdr *hdr;
	struct iov_iter iov_iter;
	struct sk_buff *skb;
	struct page *page;
	size_t payload_len;
	size_t nbytes;
	size_t len;
	int frags_flag = (GFP_ATOMIC & ~__GFP_DIRECT_RECLAIM) |
			  __GFP_COMP | __GFP_NOWARN |
			  __GFP_NORETRY;

	if (in != 0) {
		vq_err(vq, "Expected 0 input buffers, got %u\n", in);
		return NULL;
	}

	/* len contains both payload and hdr */
	len = iov_length(vq->iov, out);

	if (len > PAGE_SIZE)
		skb = virtio_vsock_alloc_skb(VIRTIO_VSOCK_SKB_HEADROOM, GFP_KERNEL);
	else
		skb = virtio_vsock_alloc_skb(len, GFP_KERNEL);

	if (!skb)
		return NULL;

	iov_iter_init(&iov_iter, ITER_SOURCE, vq->iov, out, len);

	hdr = virtio_vsock_hdr(skb);
	nbytes = copy_from_iter(hdr, sizeof(*hdr), &iov_iter);
	if (nbytes != sizeof(*hdr)) {
		vq_err(vq, "Expected %zu bytes for pkt->hdr, got %zu bytes\n",
		       sizeof(*hdr), nbytes);
		kfree_skb(skb);
		return NULL;
	}

	payload_len = le32_to_cpu(hdr->len);

	/* No payload */
	if (!payload_len)
		return skb;

	/* The pkt is too big or the length in the header is invalid */
	if (payload_len > VIRTIO_VSOCK_MAX_PKT_BUF_SIZE ||
	    payload_len + sizeof(*hdr) > len) {
		kfree_skb(skb);
		return NULL;
	}

	if (len > PAGE_SIZE) {
		page = alloc_pages(frags_flag, ilog2(roundup_pow_of_two(payload_len)) - PAGE_SHIFT);
		if (!page) {
			kfree_skb(skb);
			return NULL;
		}

		nbytes = copy_from_iter(page_to_virt(page), payload_len, &iov_iter);
		skb_add_rx_frag(skb, 0, page, 0, payload_len, roundup_pow_of_two(payload_len));
	} else {
		virtio_vsock_skb_rx_put(skb);
		nbytes = copy_from_iter(skb->data, payload_len, &iov_iter);
	}

	if (nbytes != payload_len) {
		vq_err(vq, "Expected %zu byte payload, got %zu bytes\n",
		       payload_len, nbytes);
		kfree_skb(skb);
		return NULL;
	}

	return skb;
}

/* Is there space left for replies to rx packets? */
static bool vhost_vsock_more_replies(struct vhost_vsock *vsock)
{
	struct vhost_virtqueue *vq = &vsock->vqs[VSOCK_VQ_TX];
	int val;

	smp_rmb(); /* paired with atomic_inc() and atomic_dec_return() */
	val = atomic_read(&vsock->queued_replies);

	return val < vq->num;
}

static bool vhost_transport_msgzerocopy_allow(void)
{
	return true;
}

static bool vhost_transport_seqpacket_allow(u32 remote_cid);

static struct virtio_transport vhost_transport = {
	.transport = {
		.module                   = THIS_MODULE,

		.get_local_cid            = vhost_transport_get_local_cid,

		.init                     = virtio_transport_do_socket_init,
		.destruct                 = virtio_transport_destruct,
		.release                  = virtio_transport_release,
		.connect                  = virtio_transport_connect,
		.shutdown                 = virtio_transport_shutdown,
		.cancel_pkt               = vhost_transport_cancel_pkt,

		.dgram_enqueue            = virtio_transport_dgram_enqueue,
		.dgram_dequeue            = virtio_transport_dgram_dequeue,
		.dgram_bind               = virtio_transport_dgram_bind,
		.dgram_allow              = virtio_transport_dgram_allow,

		.stream_enqueue           = virtio_transport_stream_enqueue,
		.stream_dequeue           = virtio_transport_stream_dequeue,
		.stream_has_data          = virtio_transport_stream_has_data,
		.stream_has_space         = virtio_transport_stream_has_space,
		.stream_rcvhiwat          = virtio_transport_stream_rcvhiwat,
		.stream_is_active         = virtio_transport_stream_is_active,
		.stream_allow             = virtio_transport_stream_allow,

		.seqpacket_dequeue        = virtio_transport_seqpacket_dequeue,
		.seqpacket_enqueue        = virtio_transport_seqpacket_enqueue,
		.seqpacket_allow          = vhost_transport_seqpacket_allow,
		.seqpacket_has_data       = virtio_transport_seqpacket_has_data,

		.msgzerocopy_allow        = vhost_transport_msgzerocopy_allow,

		.notify_poll_in           = virtio_transport_notify_poll_in,
		.notify_poll_out          = virtio_transport_notify_poll_out,
		.notify_recv_init         = virtio_transport_notify_recv_init,
		.notify_recv_pre_block    = virtio_transport_notify_recv_pre_block,
		.notify_recv_pre_dequeue  = virtio_transport_notify_recv_pre_dequeue,
		.notify_recv_post_dequeue = virtio_transport_notify_recv_post_dequeue,
		.notify_send_init         = virtio_transport_notify_send_init,
		.notify_send_pre_block    = virtio_transport_notify_send_pre_block,
		.notify_send_pre_enqueue  = virtio_transport_notify_send_pre_enqueue,
		.notify_send_post_enqueue = virtio_transport_notify_send_post_enqueue,
		.notify_buffer_size       = virtio_transport_notify_buffer_size,
		.notify_set_rcvlowat      = virtio_transport_notify_set_rcvlowat,

		.unsent_bytes             = virtio_transport_unsent_bytes,

		.read_skb = virtio_transport_read_skb,
	},

	.send_pkt = vhost_transport_send_pkt,
};

static bool vhost_transport_seqpacket_allow(u32 remote_cid)
{
	struct vhost_vsock_pool *vsock_pool;
	bool seqpacket_allow = false;

	rcu_read_lock();
	vsock_pool = vhost_vsock_pool_get(remote_cid);

	if (vsock_pool)
		seqpacket_allow = vsock_pool->vsock_pool[0]->seqpacket_allow;

	rcu_read_unlock();

	return seqpacket_allow;
}

static void vhost_vsock_handle_tx_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						  poll.work);
	struct vhost_vsock *vsock = container_of(vq->dev, struct vhost_vsock,
						 dev);
	int head, pkts = 0, total_len = 0;
	unsigned int out, in;
	struct sk_buff *skb;
	bool busyloop_intr = false;
	bool added = false;

	mutex_lock(&vq->mutex);

	if (!vhost_vq_get_backend(vq))
		goto out;

	if (!vq_meta_prefetch(vq))
		goto out;

	vhost_disable_notify(&vsock->dev, vq);
	do {
		struct virtio_vsock_hdr *hdr;

		if (!vhost_vsock_more_replies(vsock)) {
			/* Stop tx until the device processes already
			 * pending replies.  Leave tx virtqueue
			 * callbacks disabled.
			 */
			goto no_more_replies;
		}

		head = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov),
					 &out, &in, NULL, NULL);
		if (head < 0)
			break;

		if (head == vq->num) {
			if (vq->busyloop_timeout) {
				vhost_vsock_busy_poll(vsock, vq,
						      &busyloop_intr);
				head = vhost_get_vq_desc(vq, vq->iov,
					ARRAY_SIZE(vq->iov),
					&out, &in, NULL, NULL);
				if (head >= 0 && head != vq->num)
					goto process;
			}
			if (unlikely(vhost_enable_notify(&vsock->dev, vq))) {
				vhost_disable_notify(&vsock->dev, vq);
				continue;
			}
			break;
		}
process:
		skb = vhost_vsock_alloc_skb(vq, out, in);
		if (!skb) {
			vq_err(vq, "Faulted on pkt\n");
			continue;
		}

		total_len += sizeof(*hdr) + skb->len;

		/* Deliver to monitoring devices all received packets */
		virtio_transport_deliver_tap_pkt(skb);

		hdr = virtio_vsock_hdr(skb);

		/* Only accept correctly addressed packets */
		if (le64_to_cpu(hdr->src_cid) == vsock->guest_cid &&
		    le64_to_cpu(hdr->dst_cid) ==
		    vhost_transport_get_local_cid())
			virtio_transport_recv_pkt(&vhost_transport, skb);
		else
			kfree_skb(skb);

		vhost_add_used(vq, head, 0);
		added = true;
	} while(likely(!vhost_exceeds_weight(vq, ++pkts, total_len)));

no_more_replies:
	if (added)
		vhost_signal(&vsock->dev, vq);

	if (unlikely(busyloop_intr))
		vhost_poll_queue(&vq->poll);

out:
	mutex_unlock(&vq->mutex);
}

static void vhost_vsock_handle_rx_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						poll.work);
	struct vhost_vsock *vsock = container_of(vq->dev, struct vhost_vsock,
						 dev);

	vhost_transport_do_send_pkt(vsock, vq);
}

static int vhost_vsock_start(struct vhost_vsock *vsock)
{
	struct vhost_virtqueue *vq;
	size_t i;
	int ret;

	mutex_lock(&vsock->dev.mutex);

	ret = vhost_dev_check_owner(&vsock->dev);
	if (ret)
		goto err;

	for (i = 0; i < ARRAY_SIZE(vsock->vqs); i++) {
		vq = &vsock->vqs[i];

		mutex_lock(&vq->mutex);

		if (!vhost_vq_access_ok(vq)) {
			ret = -EFAULT;
			goto err_vq;
		}

		if (!vhost_vq_get_backend(vq)) {
			vhost_vq_set_backend(vq, vsock);
			ret = vhost_vq_init_access(vq);
			if (ret)
				goto err_vq;
		}

		vq->busyloop_timeout = busyloop_timeout_us;

		mutex_unlock(&vq->mutex);
	}

	/* Some packets may have been queued before the device was started,
	 * let's kick the send worker to send them.
	 */
	vhost_vq_work_queue(&vsock->vqs[VSOCK_VQ_RX], &vsock->send_pkt_work);

	mutex_unlock(&vsock->dev.mutex);
	return 0;

err_vq:
	vhost_vq_set_backend(vq, NULL);
	mutex_unlock(&vq->mutex);

	for (i = 0; i < ARRAY_SIZE(vsock->vqs); i++) {
		vq = &vsock->vqs[i];

		mutex_lock(&vq->mutex);
		vhost_vq_set_backend(vq, NULL);
		mutex_unlock(&vq->mutex);
	}
err:
	mutex_unlock(&vsock->dev.mutex);
	return ret;
}

static int vhost_vsock_stop(struct vhost_vsock *vsock, bool check_owner)
{
	size_t i;
	int ret = 0;

	mutex_lock(&vsock->dev.mutex);

	if (check_owner) {
		ret = vhost_dev_check_owner(&vsock->dev);
		if (ret)
			goto err;
	}

	for (i = 0; i < ARRAY_SIZE(vsock->vqs); i++) {
		struct vhost_virtqueue *vq = &vsock->vqs[i];

		mutex_lock(&vq->mutex);
		vhost_vq_set_backend(vq, NULL);
		mutex_unlock(&vq->mutex);
	}

err:
	mutex_unlock(&vsock->dev.mutex);
	return ret;
}

static void vhost_vsock_free(struct vhost_vsock *vsock)
{
	kvfree(vsock);
}

static int vhost_vsock_dev_open(struct inode *inode, struct file *file)
{
	struct vhost_virtqueue **vqs;
	struct vhost_vsock *vsock;
	int ret;

	/* This struct is large and allocation could fail, fall back to vmalloc
	 * if there is no other way.
	 */
	vsock = kvmalloc(sizeof(*vsock), GFP_KERNEL | __GFP_RETRY_MAYFAIL);
	if (!vsock)
		return -ENOMEM;

	vqs = kmalloc_array(ARRAY_SIZE(vsock->vqs), sizeof(*vqs), GFP_KERNEL);
	if (!vqs) {
		ret = -ENOMEM;
		goto out;
	}

	vsock->guest_cid = 0; /* no CID assigned yet */
	vsock->seqpacket_allow = false;

	atomic_set(&vsock->queued_replies, 0);

	vqs[VSOCK_VQ_TX] = &vsock->vqs[VSOCK_VQ_TX];
	vqs[VSOCK_VQ_RX] = &vsock->vqs[VSOCK_VQ_RX];
	vsock->vqs[VSOCK_VQ_TX].handle_kick = vhost_vsock_handle_tx_kick;
	vsock->vqs[VSOCK_VQ_RX].handle_kick = vhost_vsock_handle_rx_kick;

	vhost_dev_init(&vsock->dev, vqs, ARRAY_SIZE(vsock->vqs),
		       UIO_MAXIOV, VHOST_VSOCK_PKT_WEIGHT,
		       VHOST_VSOCK_WEIGHT, true, NULL);

	file->private_data = vsock;
	skb_queue_head_init(&vsock->send_pkt_queue);
	vhost_work_init(&vsock->send_pkt_work, vhost_transport_send_pkt_work);
	return 0;

out:
	vhost_vsock_free(vsock);
	return ret;
}

static void vhost_vsock_flush(struct vhost_vsock *vsock)
{
	vhost_dev_flush(&vsock->dev);
}

static void vhost_vsock_reset_orphans(struct sock *sk)
{
	struct vsock_sock *vsk = vsock_sk(sk);

	/* vmci_transport.c doesn't take sk_lock here either.  At least we're
	 * under vsock_table_lock so the sock cannot disappear while we're
	 * executing.
	 */

	/* If the peer is still valid, no need to reset connection */
	if (vhost_vsock_pool_get(vsk->remote_addr.svm_cid))
		return;

	/* If the close timeout is pending, let it expire.  This avoids races
	 * with the timeout callback.
	 */
	if (vsk->close_work_scheduled)
		return;

	sock_set_flag(sk, SOCK_DONE);
	vsk->peer_shutdown = SHUTDOWN_MASK;
	sk->sk_state = SS_UNCONNECTED;
	sk->sk_err = ECONNRESET;
	sk_error_report(sk);
}

static int vhost_vsock_dev_release(struct inode *inode, struct file *file)
{
	struct vhost_vsock *vsock = file->private_data;
	struct vhost_vsock_pool *vsock_pool = vsock->vsock_pool;

	mutex_lock(&vhost_vsock_pool_mutex);
	if (vsock->guest_cid) {
		spin_lock(&vsock_pool->pool_lock);
		rcu_assign_pointer(vsock_pool->vsock_pool[vsock->idx], NULL);
		vsock_pool->vsock_pool_num--;
		vsock_pool->is_closed = true;
		if (!vsock_pool->vsock_pool_num)
			hash_del_rcu(&vsock_pool->hash);
		spin_unlock(&vsock_pool->pool_lock);
	}
	mutex_unlock(&vhost_vsock_pool_mutex);

	/* Wait for other CPUs to finish using vsock */
	synchronize_rcu();

	/* Iterating over all connections for all CIDs to find orphans is
	 * inefficient.  Room for improvement here. */
	vsock_for_each_connected_socket(&vhost_transport.transport,
					vhost_vsock_reset_orphans);

	/* Don't check the owner, because we are in the release path, so we
	 * need to stop the vsock device in any case.
	 * vhost_vsock_stop() can not fail in this case, so we don't need to
	 * check the return code.
	 */
	vhost_vsock_stop(vsock, false);
	vhost_vsock_flush(vsock);
	vhost_dev_stop(&vsock->dev);

	virtio_vsock_skb_queue_purge(&vsock->send_pkt_queue);

	vhost_dev_cleanup(&vsock->dev);
	kfree(vsock->dev.vqs);
	vhost_vsock_free(vsock);

	spin_lock(&vsock_pool->pool_lock);
	if (!vsock_pool->vsock_pool_num)
		kfree(vsock_pool);
	spin_unlock(&vsock_pool->pool_lock);
	return 0;
}

/* Should be called as the last step. */
static int vhost_vsock_set_cid(struct vhost_vsock *vsock, u64 guest_cid)
{
	int ret = 0;
	struct vhost_vsock_pool *other;

	/* Refuse reserved CIDs */
	if (guest_cid <= VMADDR_CID_HOST ||
	    guest_cid == U32_MAX)
		return -EINVAL;

	/* 64-bit CIDs are not yet supported */
	if (guest_cid > U32_MAX)
		return -EINVAL;

	/* Refuse if CID is assigned to the guest->host transport (i.e. nested
	 * VM), to make the loopback work.
	 */
	if (vsock_find_cid(guest_cid))
		return -EADDRINUSE;

	/* If CID is already in use, push it into the vsock_pool */
	mutex_lock(&vhost_vsock_pool_mutex);
	other = vhost_vsock_pool_get(guest_cid);

	if (!other) {
		other = kvmalloc(sizeof(*vsock), GFP_KERNEL | __GFP_RETRY_MAYFAIL);
		if (!other) {
			ret = -ENOMEM;
			goto out_mutex;
		}
		memset(other, 0, sizeof(*other));
		spin_lock_init(&other->pool_lock);
		other->guest_cid = guest_cid;
		hash_add_rcu(vhost_vsock_pool_hash, &other->hash, other->guest_cid);
	}

	vsock->guest_cid = guest_cid;

	spin_lock(&other->pool_lock);
	if (other->is_closed) {
		pr_err("Some vsock in the pool with guest_cid:%llu is closing. \
			Disable vhost_vsock creation to prevent complicated \
			situation", guest_cid);
		ret = -EINVAL;
		goto out_nested;
	}
	vsock->idx = other->vsock_pool_num;
	vsock->vsock_pool = other;
	rcu_assign_pointer(other->vsock_pool[other->vsock_pool_num++], vsock);
out_nested:
	spin_unlock(&other->pool_lock);
out_mutex:
	mutex_unlock(&vhost_vsock_pool_mutex);

	return ret;
}

static int vhost_vsock_set_features(struct vhost_vsock *vsock, u64 features)
{
	struct vhost_virtqueue *vq;
	int i;

	if (features & ~VHOST_VSOCK_FEATURES)
		return -EOPNOTSUPP;

	mutex_lock(&vsock->dev.mutex);
	if ((features & (1 << VHOST_F_LOG_ALL)) &&
	    !vhost_log_access_ok(&vsock->dev)) {
		goto err;
	}

	if ((features & (1ULL << VIRTIO_F_ACCESS_PLATFORM))) {
		if (vhost_init_device_iotlb(&vsock->dev))
			goto err;
	}

	vsock->seqpacket_allow = features & (1ULL << VIRTIO_VSOCK_F_SEQPACKET);

	for (i = 0; i < ARRAY_SIZE(vsock->vqs); i++) {
		vq = &vsock->vqs[i];
		mutex_lock(&vq->mutex);
		vq->acked_features = features;
		mutex_unlock(&vq->mutex);
	}
	mutex_unlock(&vsock->dev.mutex);
	return 0;

err:
	mutex_unlock(&vsock->dev.mutex);
	return -EFAULT;
}

static long vhost_vsock_dev_ioctl(struct file *f, unsigned int ioctl,
				  unsigned long arg)
{
	struct vhost_vsock *vsock = f->private_data;
	void __user *argp = (void __user *)arg;
	u64 guest_cid;
	u64 features;
	int start;
	int r;

	switch (ioctl) {
	case VHOST_VSOCK_SET_GUEST_CID:
		if (copy_from_user(&guest_cid, argp, sizeof(guest_cid)))
			return -EFAULT;
		return vhost_vsock_set_cid(vsock, guest_cid);
	case VHOST_VSOCK_SET_RUNNING:
		if (copy_from_user(&start, argp, sizeof(start)))
			return -EFAULT;
		if (start)
			return vhost_vsock_start(vsock);
		else
			return vhost_vsock_stop(vsock, true);
	case VHOST_GET_FEATURES:
		features = VHOST_VSOCK_FEATURES;
		if (copy_to_user(argp, &features, sizeof(features)))
			return -EFAULT;
		return 0;
	case VHOST_SET_FEATURES:
		if (copy_from_user(&features, argp, sizeof(features)))
			return -EFAULT;
		return vhost_vsock_set_features(vsock, features);
	case VHOST_GET_BACKEND_FEATURES:
		features = VHOST_VSOCK_BACKEND_FEATURES;
		if (copy_to_user(argp, &features, sizeof(features)))
			return -EFAULT;
		return 0;
	case VHOST_SET_BACKEND_FEATURES:
		if (copy_from_user(&features, argp, sizeof(features)))
			return -EFAULT;
		if (features & ~VHOST_VSOCK_BACKEND_FEATURES)
			return -EOPNOTSUPP;
		vhost_set_backend_features(&vsock->dev, features);
		return 0;
	default:
		mutex_lock(&vsock->dev.mutex);
		r = vhost_dev_ioctl(&vsock->dev, ioctl, argp);
		if (r == -ENOIOCTLCMD)
			r = vhost_vring_ioctl(&vsock->dev, ioctl, argp);
		else
			vhost_vsock_flush(vsock);
		mutex_unlock(&vsock->dev.mutex);
		return r;
	}
}

static ssize_t vhost_vsock_chr_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct vhost_vsock *vsock = file->private_data;
	struct vhost_dev *dev = &vsock->dev;
	int noblock = file->f_flags & O_NONBLOCK;

	return vhost_chr_read_iter(dev, to, noblock);
}

static ssize_t vhost_vsock_chr_write_iter(struct kiocb *iocb,
					struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct vhost_vsock *vsock = file->private_data;
	struct vhost_dev *dev = &vsock->dev;

	return vhost_chr_write_iter(dev, from);
}

static __poll_t vhost_vsock_chr_poll(struct file *file, poll_table *wait)
{
	struct vhost_vsock *vsock = file->private_data;
	struct vhost_dev *dev = &vsock->dev;

	return vhost_chr_poll(file, dev, wait);
}

static const struct file_operations vhost_vsock_fops = {
	.owner          = THIS_MODULE,
	.open           = vhost_vsock_dev_open,
	.release        = vhost_vsock_dev_release,
	.llseek		= noop_llseek,
	.unlocked_ioctl = vhost_vsock_dev_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
	.read_iter      = vhost_vsock_chr_read_iter,
	.write_iter     = vhost_vsock_chr_write_iter,
	.poll           = vhost_vsock_chr_poll,
};

static struct miscdevice vhost_vsock_misc = {
	.minor = VHOST_VSOCK_MINOR,
	.name = "vhost-vsock",
	.fops = &vhost_vsock_fops,
};

static int __init vhost_vsock_init(void)
{
	int ret;

	ret = vsock_core_register(&vhost_transport.transport,
				  VSOCK_TRANSPORT_F_H2G);
	if (ret < 0)
		return ret;

	ret = misc_register(&vhost_vsock_misc);
	if (ret) {
		vsock_core_unregister(&vhost_transport.transport);
		return ret;
	}

	return 0;
};

static void __exit vhost_vsock_exit(void)
{
	misc_deregister(&vhost_vsock_misc);
	vsock_core_unregister(&vhost_transport.transport);
};

module_init(vhost_vsock_init);
module_exit(vhost_vsock_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Asias He");
MODULE_DESCRIPTION("vhost transport for vsock ");
MODULE_ALIAS_MISCDEV(VHOST_VSOCK_MINOR);
MODULE_ALIAS("devname:vhost-vsock");
