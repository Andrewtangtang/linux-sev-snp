// SPDX-License-Identifier: GPL-2.0-only
/*
 * virtio transport for vsock
 *
 * Copyright (C) 2013-2015 Red Hat, Inc.
 * Author: Asias He <asias@redhat.com>
 *         Stefan Hajnoczi <stefanha@redhat.com>
 *
 * Some of the code is take from Gerd Hoffmann <kraxel@redhat.com>'s
 * early virtio-vsock proof-of-concept bits.
 */
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_vsock.h>
#include <net/sock.h>
#include <linux/mutex.h>
#include <net/af_vsock.h>

static unsigned virtio_vsock_rx_buf_size;
module_param(virtio_vsock_rx_buf_size, uint, 0664);
MODULE_PARM_DESC(virtio_vsock_rx_buf_size, "Adjust rx buf size");

static struct workqueue_struct *virtio_vsock_workqueue;
static struct virtio_vsock __rcu *the_virtio_vsock;
static DEFINE_MUTEX(the_virtio_vsock_mutex); /* protects the_virtio_vsock */
static struct virtio_transport virtio_transport; /* forward declaration */

struct tx_queue {
	char name[16];
	struct virtqueue *vq;
	/* Virtqueue processing is deferred to a workqueue */
	struct work_struct tx_work;
	/* The following fields are protected by tx_lock.  vqs[VSOCK_VQ_TX]
	 * must be accessed with tx_lock held.
	 */
	struct mutex tx_lock;
	spinlock_t   tx_spinlock;
	bool tx_run;

	struct work_struct send_pkt_work;
	struct sk_buff_head send_pkt_queue;

	atomic_t queued_replies;

	/* These fields are used only in tx path in function
	 * 'virtio_transport_send_pkt_work()', so to save
	 * stack space in it, place both of them here. Each
	 * pointer from 'out_sgs' points to the corresponding
	 * element in 'out_bufs' - this is initialized in
	 * 'virtio_vsock_probe()'. Both fields are protected
	 * by 'tx_lock'. +1 is needed for packet header.
	 */
	struct scatterlist *out_sgs[MAX_SKB_FRAGS + 1];
	struct scatterlist out_bufs[MAX_SKB_FRAGS + 1];
};

struct rx_queue {
	char name[16];
	struct virtqueue *vq;
	/* Virtqueue processing is deferred to a workqueue */
	struct work_struct rx_work;
	/* The following fields are protected by rx_lock.  vqs[VSOCK_VQ_RX]
	 * must be accessed with rx_lock held.
	 */
	struct mutex rx_lock;
	spinlock_t   rx_spinlock;
	bool rx_run;
	int rx_buf_nr;
	int rx_buf_max_nr;
};

struct virtio_vsock {
	struct virtio_device *vdev;
	u16 max_queue_pairs;

	/* Use the first rx_queue & tx_queue for connection-related operation */
	struct rx_queue __rcu *rx_queues;
	struct tx_queue __rcu *tx_queues;

	struct virtqueue *event_queue;
	/* Virtqueue processing is deferred to a workqueue */
	struct work_struct event_work;
	/* The following fields are protected by event_lock.
	 * vqs[VSOCK_VQ_EVENT] must be accessed with event_lock held.
	 */
	struct mutex event_lock;
	spinlock_t   event_spinlock;
	bool event_run;
	struct virtio_vsock_event event_list[8];

	u32 guest_cid;
	bool seqpacket_allow;
};

static u32 virtio_transport_get_local_cid(void)
{
	struct virtio_vsock *vsock;
	u32 ret;

	rcu_read_lock();
	vsock = rcu_dereference(the_virtio_vsock);
	if (!vsock) {
		ret = VMADDR_CID_ANY;
		goto out_rcu;
	}

	ret = vsock->guest_cid;
out_rcu:
	rcu_read_unlock();
	return ret;
}

/* Caller need to hold vsock->tx_lock on vq */
static int virtio_transport_send_skb(struct sk_buff *skb, struct virtqueue *vq,
				     struct virtio_vsock *vsock, gfp_t gfp)
{
	int ret, in_sg = 0, out_sg = 0;
	struct scatterlist **sgs;
	struct tx_queue *tq = &vsock->tx_queues[skb_get_queue_mapping(skb)];

	sgs = tq->out_sgs;
	sg_init_one(sgs[out_sg], virtio_vsock_hdr(skb),
		    sizeof(*virtio_vsock_hdr(skb)));
	out_sg++;

	if (!skb_is_nonlinear(skb)) {
		if (skb->len > 0) {
			sg_init_one(sgs[out_sg], skb->data, skb->len);
			out_sg++;
		}
	} else {
		struct skb_shared_info *si;
		int i;

		/* If skb is nonlinear, then its buffer must contain
		 * only header and nothing more. Data is stored in
		 * the fragged part.
		 */
		WARN_ON_ONCE(skb_headroom(skb) != sizeof(*virtio_vsock_hdr(skb)));

		si = skb_shinfo(skb);

		for (i = 0; i < si->nr_frags; i++) {
			skb_frag_t *skb_frag = &si->frags[i];
			void *va;

			/* We will use 'page_to_virt()' for the userspace page
			 * here, because virtio or dma-mapping layers will call
			 * 'virt_to_phys()' later to fill the buffer descriptor.
			 * We don't touch memory at "virtual" address of this page.
			 */
			va = page_to_virt(skb_frag_page(skb_frag));
			sg_init_one(sgs[out_sg],
				    va + skb_frag_off(skb_frag),
				    skb_frag_size(skb_frag));
			out_sg++;
		}
	}

	ret = virtqueue_add_sgs(vq, sgs, out_sg, in_sg, skb, gfp);
	/* Usually this means that there is no more space available in
	 * the vq
	 */
	if (ret < 0)
		return ret;

	virtio_transport_deliver_tap_pkt(skb);
	return 0;
}

static void
virtio_transport_send_pkt_work(struct work_struct *work)
{
	struct tx_queue *tq =
		container_of(work, struct tx_queue, send_pkt_work);
	struct virtio_vsock *vsock;
	struct rx_queue *rq;
	struct virtqueue *vq;
	bool added = false;
	bool restart_rx = false;

	rcu_read_lock();
	vsock = rcu_dereference(the_virtio_vsock);
	if (!vsock)
		goto out_rcu;
	rq = &vsock->rx_queues[0];

	spin_lock_bh(&tq->tx_spinlock);

	if (!tq->tx_run)
		goto out;

	vq = tq->vq;

	for (;;) {
		struct sk_buff *skb;
		bool reply;
		int ret;

		skb = virtio_vsock_skb_dequeue(&tq->send_pkt_queue);
		if (!skb)
			break;

		reply = virtio_vsock_skb_reply(skb);

		ret = virtio_transport_send_skb(skb, vq, vsock, GFP_ATOMIC);
		if (ret < 0) {
			virtio_vsock_skb_queue_head(&tq->send_pkt_queue, skb);
			break;
		}

		if (reply) {
			int val;

			val = atomic_dec_return(&tq->queued_replies);

			/* Do we now have resources to resume rx processing? */
			if (val + 1 == virtqueue_get_vring_size(rq->vq))
				restart_rx = true;
		}

		added = true;
	}

	if (added)
		virtqueue_kick(vq);

out:
	spin_unlock_bh(&tq->tx_spinlock);
out_rcu:
	rcu_read_unlock();

	if (restart_rx)
		queue_work(virtio_vsock_workqueue, &rq->rx_work);
}

/* Caller need to hold RCU for vsock.
 * Returns 0 if the packet is successfully put on the vq.
 */
static int virtio_transport_send_skb_fast_path(struct virtio_vsock *vsock, struct sk_buff *skb)
{
	struct tx_queue *tq = &vsock->tx_queues[skb_get_queue_mapping(skb)];
	struct virtqueue *vq = tq->vq;
	int ret;

	/* Inside RCU, can't sleep! */
	spin_lock_bh(&tq->tx_spinlock);

	ret = virtio_transport_send_skb(skb, vq, vsock, GFP_ATOMIC);
	if (ret == 0)
		virtqueue_kick(vq);

	spin_unlock_bh(&tq->tx_spinlock);

	return ret;
}

static int
virtio_transport_send_pkt(struct sk_buff *skb)
{
	struct virtio_vsock_hdr *hdr;
	struct virtio_vsock *vsock;
	struct tx_queue *tq;
	int len = skb->len;

	hdr = virtio_vsock_hdr(skb);

	rcu_read_lock();
	vsock = rcu_dereference(the_virtio_vsock);
	if (!vsock) {
		kfree_skb(skb);
		len = -ENODEV;
		goto out_rcu;
	}

	if (le64_to_cpu(hdr->dst_cid) == vsock->guest_cid) {
		kfree_skb(skb);
		len = -ENODEV;
		goto out_rcu;
	}
	skb->queue_mapping = skb->hash % vsock->max_queue_pairs;
	tq = &vsock->tx_queues[skb_get_queue_mapping(skb)];

	/* If send_pkt_queue is empty, we can safely bypass this queue
	 * because packet order is maintained and (try) to put the packet
	 * on the virtqueue using virtio_transport_send_skb_fast_path.
	 * If this fails we simply put the packet on the intermediate
	 * queue and schedule the worker.
	 */
	if (!skb_queue_empty_lockless(&tq->send_pkt_queue) ||
	    virtio_transport_send_skb_fast_path(vsock, skb)) {
		if (virtio_vsock_skb_reply(skb))
			atomic_inc(&tq->queued_replies);

		virtio_vsock_skb_queue_tail(&tq->send_pkt_queue, skb);
		queue_work(virtio_vsock_workqueue, &tq->send_pkt_work);
	}

out_rcu:
	rcu_read_unlock();
	return len;
}

static int
virtio_transport_cancel_pkt(struct vsock_sock *vsk)
{
	struct virtio_vsock *vsock;
	int cnt = 0, ret;
	struct rx_queue *connect_rq;
	struct tx_queue *connect_tq;

	rcu_read_lock();
	vsock = rcu_dereference(the_virtio_vsock);
	if (!vsock) {
		ret = -ENODEV;
		goto out_rcu;
	}

	connect_rq = &vsock->rx_queues[0];
	connect_tq = &vsock->tx_queues[0];

	cnt = virtio_transport_purge_skbs(vsk, &connect_tq->send_pkt_queue);

	if (cnt) {
		int new_cnt;

		new_cnt = atomic_sub_return(cnt, &connect_tq->queued_replies);
		if (new_cnt + cnt >= virtqueue_get_vring_size(connect_rq->vq) &&
		    new_cnt < virtqueue_get_vring_size(connect_rq->vq))
			queue_work(virtio_vsock_workqueue, &connect_rq->rx_work);
	}

	ret = 0;

out_rcu:
	rcu_read_unlock();
	return ret;
}

static void virtio_vsock_rx_fill(struct rx_queue *rq)
{
	unsigned skb_len = virtio_vsock_rx_buf_size < PAGE_SIZE ?
		virtio_vsock_rx_buf_size : 0;
	struct scatterlist hdr, data, *sgs[2];
	struct virtqueue *vq;
	struct sk_buff *skb;
	struct page *page;
	int ret;
	int frags_flag = (GFP_ATOMIC & ~__GFP_DIRECT_RECLAIM) |
			  __GFP_COMP | __GFP_NOWARN |
			  __GFP_NORETRY;

	vq = rq->vq;

	do {
		unsigned int in = 0;
		unsigned int data_len = skb_len + VIRTIO_VSOCK_SKB_HEADROOM;

		skb = virtio_vsock_alloc_skb(data_len, GFP_ATOMIC);
		if (!skb)
			break;

		memset(skb->head, 0, VIRTIO_VSOCK_SKB_HEADROOM);
		sg_init_one(&hdr, virtio_vsock_hdr(skb), data_len);
		sgs[in++] = &hdr;
		if (!skb_len) {
			phys_addr_t phys;
			// page = alloc_pages(frags_flag,
			// 		   ilog2(virtio_vsock_rx_buf_size) - PAGE_SHIFT);
			// if (!page) {
			// 	kfree_skb(skb);
			// 	break;
			// }
			phys = swiotlb_map(NULL, INVALID_PHYS_ADDR,
				           virtio_vsock_rx_buf_size, DMA_NONE, 0);
			if (phys == DMA_MAPPING_ERROR) {
				kfree_skb(skb);
				break;
			}
			page = phys_to_page(phys);

			sg_init_one(&data, page_address(page), virtio_vsock_rx_buf_size);
			sgs[in++] = &data;

			VIRTIO_VSOCK_SKB_CB(skb)->p = page;
		}

		ret = virtqueue_add_sgs(vq, sgs, 0, in, skb, GFP_ATOMIC);
		if (ret < 0) {
			kfree_skb(skb);
			break;
		}

		rq->rx_buf_nr++;
	} while (vq->num_free);
	if (rq->rx_buf_nr > rq->rx_buf_max_nr)
		rq->rx_buf_max_nr = rq->rx_buf_nr;
	virtqueue_kick(vq);
}

static void virtio_transport_tx_work(struct work_struct *work)
{
	struct tx_queue *tq = container_of(work, struct tx_queue, tx_work);
	struct virtqueue *vq;
	bool added = false;

	vq = tq->vq;
	spin_lock_bh(&tq->tx_spinlock);

	if (!tq->tx_run)
		goto out;

	do {
		struct sk_buff *skb;
		unsigned int len;

		virtqueue_disable_cb(vq);
		while ((skb = virtqueue_get_buf(vq, &len)) != NULL) {
			virtio_transport_consume_skb_sent(skb, true);
			added = true;
		}
	} while (!virtqueue_enable_cb(vq));

out:
	spin_unlock_bh(&tq->tx_spinlock);

	if (added)
		queue_work(virtio_vsock_workqueue, &tq->send_pkt_work);
}

/* Is there space left for replies to rx packets? */
static bool virtio_transport_more_replies(struct virtio_vsock *vsock)
{
	struct rx_queue *connect_rq = &vsock->rx_queues[0];
	struct tx_queue *connect_tq = &vsock->tx_queues[0];
	int val;

	smp_rmb(); /* paired with atomic_inc() and atomic_dec_return() */
	val = atomic_read(&connect_tq->queued_replies);

	return val < virtqueue_get_vring_size(connect_rq->vq);
}

/* event_lock must be held */
static int virtio_vsock_event_fill_one(struct virtio_vsock *vsock,
				       struct virtio_vsock_event *event)
{
	struct scatterlist sg;
	struct virtqueue *vq;

	vq = vsock->event_queue;

	sg_init_one(&sg, event, sizeof(*event));

	return virtqueue_add_inbuf(vq, &sg, 1, event, GFP_ATOMIC);
}

/* event_lock must be held */
static void virtio_vsock_event_fill(struct virtio_vsock *vsock)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(vsock->event_list); i++) {
		struct virtio_vsock_event *event = &vsock->event_list[i];

		virtio_vsock_event_fill_one(vsock, event);
	}

	virtqueue_kick(vsock->event_queue);
}

static void virtio_vsock_reset_sock(struct sock *sk)
{
	/* vmci_transport.c doesn't take sk_lock here either.  At least we're
	 * under vsock_table_lock so the sock cannot disappear while we're
	 * executing.
	 */

	sk->sk_state = TCP_CLOSE;
	sk->sk_err = ECONNRESET;
	sk_error_report(sk);
}

static void virtio_vsock_update_guest_cid(struct virtio_vsock *vsock)
{
	struct virtio_device *vdev = vsock->vdev;
	__le64 guest_cid;

	vdev->config->get(vdev, offsetof(struct virtio_vsock_config, guest_cid),
			  &guest_cid, sizeof(guest_cid));
	vsock->guest_cid = le64_to_cpu(guest_cid);
}

static void virtio_vsock_update_max_queue_pairs(struct virtio_vsock *vsock)
{
	struct virtio_device *vdev = vsock->vdev;
	__le64 max_queue_pairs;

	vdev->config->get(vdev, offsetof(struct virtio_vsock_config, max_virtqueue_pairs),
			  &max_queue_pairs, sizeof(max_queue_pairs));
	if (max_queue_pairs < VIRTIO_VSOCK_VQ_PAIRS_MIN ||
	    max_queue_pairs > VIRTIO_VSOCK_VQ_PAIRS_MAX)
		max_queue_pairs = 1;

	vsock->max_queue_pairs = le64_to_cpu(max_queue_pairs);
}

/* event_lock must be held */
static void virtio_vsock_event_handle(struct virtio_vsock *vsock,
				      struct virtio_vsock_event *event)
{
	switch (le32_to_cpu(event->id)) {
	case VIRTIO_VSOCK_EVENT_TRANSPORT_RESET:
		virtio_vsock_update_guest_cid(vsock);
		vsock_for_each_connected_socket(&virtio_transport.transport,
						virtio_vsock_reset_sock);
		break;
	}
}

static void virtio_transport_event_work(struct work_struct *work)
{
	struct virtio_vsock *vsock =
		container_of(work, struct virtio_vsock, event_work);
	struct virtqueue *vq;

	vq = vsock->event_queue;

	spin_lock_bh(&vsock->event_spinlock);

	if (!vsock->event_run)
		goto out;

	do {
		struct virtio_vsock_event *event;
		unsigned int len;

		virtqueue_disable_cb(vq);
		while ((event = virtqueue_get_buf(vq, &len)) != NULL) {
			if (len == sizeof(*event))
				virtio_vsock_event_handle(vsock, event);

			virtio_vsock_event_fill_one(vsock, event);
		}
	} while (!virtqueue_enable_cb(vq));

	virtqueue_kick(vsock->event_queue);
out:
	spin_unlock_bh(&vsock->event_spinlock);
}

static void virtio_vsock_event_done(struct virtqueue *vq)
{
	struct virtio_vsock *vsock = vq->vdev->priv;

	if (!vsock)
		return;
	queue_work(virtio_vsock_workqueue, &vsock->event_work);
}

static void virtio_vsock_tx_done(struct virtqueue *vq)
{
	struct virtio_vsock *vsock = vq->vdev->priv;
	struct tx_queue *tq = &vsock->tx_queues[vq2txq(vq)];

	if (!vsock)
		return;
	queue_work(virtio_vsock_workqueue, &tq->tx_work);
}

static void virtio_vsock_rx_done(struct virtqueue *vq)
{
	struct virtio_vsock *vsock = vq->vdev->priv;
	struct rx_queue *rq = &vsock->rx_queues[vq2rxq(vq)];

	if (!vsock)
		return;
	queue_work(virtio_vsock_workqueue, &rq->rx_work);
}

static bool virtio_transport_can_msgzerocopy(int bufs_num)
{
	struct virtio_vsock *vsock;
	bool res = false;

	rcu_read_lock();

	vsock = rcu_dereference(the_virtio_vsock);
	if (vsock) {
		struct virtqueue *vq = vsock->tx_queues[0].vq;

		/* Check that tx queue is large enough to keep whole
		 * data to send. This is needed, because when there is
		 * not enough free space in the queue, current skb to
		 * send will be reinserted to the head of tx list of
		 * the socket to retry transmission later, so if skb
		 * is bigger than whole queue, it will be reinserted
		 * again and again, thus blocking other skbs to be sent.
		 * Each page of the user provided buffer will be added
		 * as a single buffer to the tx virtqueue, so compare
		 * number of pages against maximum capacity of the queue.
		 * Since every tq has the same size, check the first tq
		 * is sufficient.
		 */
		if (bufs_num <= vq->num_max)
			res = true;
	}

	rcu_read_unlock();

	return res;
}

static bool virtio_transport_msgzerocopy_allow(void)
{
	return true;
}

static bool virtio_transport_seqpacket_allow(u32 remote_cid);

static struct virtio_transport virtio_transport = {
	.transport = {
		.module                   = THIS_MODULE,

		.get_local_cid            = virtio_transport_get_local_cid,

		.init                     = virtio_transport_do_socket_init,
		.destruct                 = virtio_transport_destruct,
		.release                  = virtio_transport_release,
		.connect                  = virtio_transport_connect,
		.shutdown                 = virtio_transport_shutdown,
		.cancel_pkt               = virtio_transport_cancel_pkt,

		.dgram_bind               = virtio_transport_dgram_bind,
		.dgram_dequeue            = virtio_transport_dgram_dequeue,
		.dgram_enqueue            = virtio_transport_dgram_enqueue,
		.dgram_allow              = virtio_transport_dgram_allow,

		.stream_dequeue           = virtio_transport_stream_dequeue,
		.stream_enqueue           = virtio_transport_stream_enqueue,
		.stream_has_data          = virtio_transport_stream_has_data,
		.stream_has_space         = virtio_transport_stream_has_space,
		.stream_rcvhiwat          = virtio_transport_stream_rcvhiwat,
		.stream_is_active         = virtio_transport_stream_is_active,
		.stream_allow             = virtio_transport_stream_allow,

		.seqpacket_dequeue        = virtio_transport_seqpacket_dequeue,
		.seqpacket_enqueue        = virtio_transport_seqpacket_enqueue,
		.seqpacket_allow          = virtio_transport_seqpacket_allow,
		.seqpacket_has_data       = virtio_transport_seqpacket_has_data,

		.msgzerocopy_allow        = virtio_transport_msgzerocopy_allow,

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

	.send_pkt = virtio_transport_send_pkt,
	.can_msgzerocopy = virtio_transport_can_msgzerocopy,
};

static bool virtio_transport_seqpacket_allow(u32 remote_cid)
{
	struct virtio_vsock *vsock;
	bool seqpacket_allow;

	seqpacket_allow = false;
	rcu_read_lock();
	vsock = rcu_dereference(the_virtio_vsock);
	if (vsock)
		seqpacket_allow = vsock->seqpacket_allow;
	rcu_read_unlock();

	return seqpacket_allow;
}

static void virtio_transport_rx_work(struct work_struct *work)
{
	struct rx_queue *rq = container_of(work, struct rx_queue, rx_work);
	struct virtio_vsock *vsock;
	struct virtqueue *vq;

	vq = rq->vq;

	rcu_read_lock();
	vsock = rcu_dereference(the_virtio_vsock);
	if (!vsock)
		goto out_rcu;
	spin_lock_bh(&rq->rx_spinlock);

	if (!rq->rx_run)
		goto out;

	do {
		virtqueue_disable_cb(vq);
		for (;;) {
			struct sk_buff *skb;
			struct page *p;
			unsigned int len, payload_len;

			if (!virtio_transport_more_replies(vsock)) {
				/* Stop rx until the device processes already
				 * pending replies.  Leave rx virtqueue
				 * callbacks disabled.
				 */
				goto out;
			}

			skb = virtqueue_get_buf(vq, &len);
			if (!skb)
				break;

			p = VIRTIO_VSOCK_SKB_CB(skb)->p;
			rq->rx_buf_nr--;

			/* Drop short/long packets */
			if (unlikely(len < sizeof(struct virtio_vsock_hdr) ||
				     len > VIRTIO_VSOCK_SKB_HEADROOM + VIRTIO_VSOCK_DEFAULT_RX_BUF_SIZE)) {
				kfree_skb(skb);
				continue;
			}

			payload_len = le32_to_cpu(virtio_vsock_hdr(skb)->len);
			if (p)
				skb_add_rx_frag(skb, 0, p, 0, payload_len, virtio_vsock_rx_buf_size);
			else
				virtio_vsock_skb_rx_put(skb);
			virtio_transport_deliver_tap_pkt(skb);
			virtio_transport_recv_pkt(&virtio_transport, skb);
		}
	} while (!virtqueue_enable_cb(vq));

out:
	if (rq->rx_buf_nr < rq->rx_buf_max_nr / 2)
		virtio_vsock_rx_fill(rq);
	spin_unlock_bh(&rq->rx_spinlock);
out_rcu:
	rcu_read_unlock();
}

static int virtio_vsock_alloc_queues(struct virtio_vsock *vsock)
{
	int i;

	vsock->tx_queues = kcalloc(vsock->max_queue_pairs,
				   sizeof(*vsock->tx_queues), GFP_KERNEL);
	if (!vsock->tx_queues)
		goto err_tx;
	vsock->rx_queues = kcalloc(vsock->max_queue_pairs,
				   sizeof(*vsock->rx_queues), GFP_KERNEL);
	if (!vsock->rx_queues)
		goto err_rx;

	for (i = 0; i < vsock->max_queue_pairs; i++) {
		int j;
		struct rx_queue *rq = &vsock->rx_queues[i];
		struct tx_queue *tq = &vsock->tx_queues[i];

		mutex_init(&rq->rx_lock);
		spin_lock_init(&rq->rx_spinlock);
		INIT_WORK(&rq->rx_work, virtio_transport_rx_work);
		rq->rx_buf_nr = 0;
		rq->rx_buf_max_nr = 0;

		mutex_init(&tq->tx_lock);
		atomic_set(&tq->queued_replies, 0);
		spin_lock_init(&tq->tx_spinlock);
		INIT_WORK(&tq->tx_work, virtio_transport_tx_work);
		INIT_WORK(&tq->send_pkt_work, virtio_transport_send_pkt_work);
		for (j = 0; j < ARRAY_SIZE(tq->out_sgs); j++)
			tq->out_sgs[j] = &tq->out_bufs[j];
		skb_queue_head_init(&tq->send_pkt_queue);
	}
	mutex_init(&vsock->event_lock);
	spin_lock_init(&vsock->event_spinlock);
	INIT_WORK(&vsock->event_work, virtio_transport_event_work);

	return 0;
err_rx:
	kfree(vsock->tx_queues);
err_tx:
	return -ENOMEM;
}

static int virtio_vsock_vqs_init(struct virtio_vsock *vsock)
{
	struct virtqueue **vqs;
	struct virtqueue_info *vqs_info;
	struct virtio_device *vdev = vsock->vdev;
	u16 total_vqs;
	int ret = -ENOMEM;
	int i;

	virtio_vsock_update_max_queue_pairs(vsock);
	virtio_vsock_alloc_queues(vsock);

	total_vqs = vsock->max_queue_pairs*2 + 1;
	vqs = kcalloc(total_vqs, sizeof(*vqs), GFP_KERNEL);
	if (!vqs)
		goto err_vq;
	vqs_info = kcalloc(total_vqs, sizeof(*vqs_info), GFP_KERNEL);
	if (!vqs_info)
		goto err_vqs_info;

	for (i = 0; i < vsock->max_queue_pairs; i++) {
		vqs_info[rxq2vq(i)].callback = virtio_vsock_rx_done;
		vqs_info[txq2vq(i)].callback = virtio_vsock_tx_done;

		sprintf(vsock->rx_queues[i].name, "rx.%u", i);
		sprintf(vsock->tx_queues[i].name, "tx.%u", i);

		vqs_info[rxq2vq(i)].name = vsock->rx_queues[i].name;
		vqs_info[txq2vq(i)].name = vsock->tx_queues[i].name;
	}
	vqs_info[total_vqs-1].callback = virtio_vsock_event_done;
	vqs_info[total_vqs-1].name = "event";

	ret = virtio_find_vqs(vdev, total_vqs, vqs, vqs_info, NULL);
	if (ret < 0)
		return ret;

	virtio_vsock_update_guest_cid(vsock);

	for (i = 0; i < vsock->max_queue_pairs; i++) {
		struct rx_queue *rq = &vsock->rx_queues[i];
		struct tx_queue *tq = &vsock->tx_queues[i];

		rq->vq = vqs[rxq2vq(i)];
		tq->vq = vqs[txq2vq(i)];
	}
	vsock->event_queue = vqs[total_vqs-1];

	virtio_device_ready(vdev);

	kfree(vqs_info);
err_vqs_info:
	kfree(vqs);
err_vq:
	return ret;
}

static void virtio_vsock_vqs_start(struct virtio_vsock *vsock)
{
	int i;

	for (i = 0; i < vsock->max_queue_pairs; i++) {
		struct rx_queue *rq = &vsock->rx_queues[i];
		struct tx_queue *tq = &vsock->tx_queues[i];

		mutex_lock(&rq->rx_lock);
		spin_lock(&rq->rx_spinlock);
		virtio_vsock_rx_fill(rq);
		spin_unlock(&rq->rx_spinlock);
		rq->rx_run = true;
		mutex_unlock(&rq->rx_lock);

		mutex_lock(&tq->tx_lock);
		tq->tx_run = true;
		mutex_unlock(&tq->tx_lock);
		/* virtio_transport_send_pkt() can queue packets once
		 * the_virtio_vsock is set, but they won't be processed until
		 * vsock->tx_run is set to true. We queue vsock->send_pkt_work
		 * when initialization finishes to send those packets queued
		 * earlier.
		 * We don't need to queue the other workers (rx, event) because
		 * as long as we don't fill the queues with empty buffers, the
		 * host can't send us any notification.
		 */
		queue_work(virtio_vsock_workqueue, &tq->send_pkt_work);
	}

	mutex_lock(&vsock->event_lock);
	spin_lock(&vsock->event_spinlock);
	virtio_vsock_event_fill(vsock);
	spin_unlock(&vsock->event_spinlock);
	vsock->event_run = true;
	mutex_unlock(&vsock->event_lock);
}

static void virtio_vsock_vqs_del(struct virtio_vsock *vsock)
{
	int i;
	struct virtio_device *vdev = vsock->vdev;
	struct sk_buff *skb;

	/* Reset all connected sockets when the VQs disappear */
	vsock_for_each_connected_socket(&virtio_transport.transport,
					virtio_vsock_reset_sock);

	/* Stop all work handlers to make sure no one is accessing the device,
	 * so we can safely call virtio_reset_device().
	 */
	for (i = 0; i < vsock->max_queue_pairs; i++) {
		struct tx_queue *tq = &vsock->tx_queues[i];
		struct rx_queue *rq = &vsock->rx_queues[i];

		spin_lock(&rq->rx_spinlock);
		rq->rx_run = false;
		spin_unlock(&rq->rx_spinlock);

		spin_lock(&tq->tx_spinlock);
		tq->tx_run = false;
		spin_unlock(&tq->tx_spinlock);
	}

	mutex_lock(&vsock->event_lock);
	vsock->event_run = false;
	mutex_unlock(&vsock->event_lock);

	/* Flush all device writes and interrupts, device will not use any
	 * more buffers.
	 */
	virtio_reset_device(vdev);

	for (i = 0; i < vsock->max_queue_pairs; i++) {
		struct rx_queue *rq = &vsock->rx_queues[i];
		struct tx_queue *tq = &vsock->tx_queues[i];

		spin_lock_bh(&rq->rx_spinlock);
		while ((skb = virtqueue_detach_unused_buf(rq->vq)))
			kfree_skb(skb);
		spin_unlock_bh(&rq->rx_spinlock);

		spin_lock_bh(&tq->tx_spinlock);
		while ((skb = virtqueue_detach_unused_buf(tq->vq)))
			kfree_skb(skb);
		virtio_vsock_skb_queue_purge(&tq->send_pkt_queue);
		spin_unlock_bh(&tq->tx_spinlock);
	}

	/* Delete virtqueues and flush outstanding callbacks if any */
	vdev->config->del_vqs(vdev);
}

static int virtio_vsock_probe(struct virtio_device *vdev)
{
	struct virtio_vsock *vsock = NULL;
	int ret;

	ret = mutex_lock_interruptible(&the_virtio_vsock_mutex);
	if (ret)
		return ret;

	/* Only one virtio-vsock device per guest is supported */
	if (rcu_dereference_protected(the_virtio_vsock,
				lockdep_is_held(&the_virtio_vsock_mutex))) {
		ret = -EBUSY;
		goto out;
	}

	vsock = kzalloc(sizeof(*vsock), GFP_KERNEL);
	if (!vsock) {
		ret = -ENOMEM;
		goto out;
	}

	vsock->vdev = vdev;

	ret = virtio_vsock_vqs_init(vsock);
	if (ret < 0)
		goto out;

	if (virtio_has_feature(vdev, VIRTIO_VSOCK_F_SEQPACKET))
		vsock->seqpacket_allow = true;

	vdev->priv = vsock;

	rcu_assign_pointer(the_virtio_vsock, vsock);
	virtio_vsock_vqs_start(vsock);

	mutex_unlock(&the_virtio_vsock_mutex);

	return 0;

out:
	kfree(vsock);
	mutex_unlock(&the_virtio_vsock_mutex);
	return ret;
}

static void virtio_vsock_remove(struct virtio_device *vdev)
{
	int i;
	struct virtio_vsock *vsock = vdev->priv;

	mutex_lock(&the_virtio_vsock_mutex);

	vdev->priv = NULL;
	rcu_assign_pointer(the_virtio_vsock, NULL);
	synchronize_rcu();

	virtio_vsock_vqs_del(vsock);

	/* Other works can be queued before 'config->del_vqs()', so we flush
	 * all works before to free the vsock object to avoid use after free.
	 */
	for (i = 0; i < vsock->max_queue_pairs; i++) {
		struct rx_queue *rq = &vsock->rx_queues[i];
		struct tx_queue *tq = &vsock->tx_queues[i];

		flush_work(&rq->rx_work);
		flush_work(&tq->tx_work);
		flush_work(&tq->send_pkt_work);
	}
	flush_work(&vsock->event_work);
	kfree(vsock->rx_queues);
	kfree(vsock->tx_queues);

	mutex_unlock(&the_virtio_vsock_mutex);

	kfree(vsock);
}

#ifdef CONFIG_PM_SLEEP
static int virtio_vsock_freeze(struct virtio_device *vdev)
{
	int i;
	struct virtio_vsock *vsock = vdev->priv;

	mutex_lock(&the_virtio_vsock_mutex);

	rcu_assign_pointer(the_virtio_vsock, NULL);
	synchronize_rcu();

	for (i = 0; i < vsock->max_queue_pairs; i++) {
		rcu_assign_pointer(vsock->tx_queues, NULL);
		rcu_assign_pointer(vsock->rx_queues, NULL);
	}
	synchronize_rcu();

	virtio_vsock_vqs_del(vsock);
	kfree(vsock->rx_queues);
	kfree(vsock->tx_queues);

	mutex_unlock(&the_virtio_vsock_mutex);

	return 0;
}

static int virtio_vsock_restore(struct virtio_device *vdev)
{
	struct virtio_vsock *vsock = vdev->priv;
	int ret;

	mutex_lock(&the_virtio_vsock_mutex);

	/* Only one virtio-vsock device per guest is supported */
	if (rcu_dereference_protected(the_virtio_vsock,
				lockdep_is_held(&the_virtio_vsock_mutex))) {
		ret = -EBUSY;
		goto out;
	}

	ret = virtio_vsock_vqs_init(vsock);
	if (ret < 0)
		goto out;

	rcu_assign_pointer(the_virtio_vsock, vsock);
	virtio_vsock_vqs_start(vsock);

out:
	mutex_unlock(&the_virtio_vsock_mutex);
	return ret;
}
#endif /* CONFIG_PM_SLEEP */

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_VSOCK, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	VIRTIO_VSOCK_F_SEQPACKET
};

static struct virtio_driver virtio_vsock_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name = KBUILD_MODNAME,
	.id_table = id_table,
	.probe = virtio_vsock_probe,
	.remove = virtio_vsock_remove,
#ifdef CONFIG_PM_SLEEP
	.freeze = virtio_vsock_freeze,
	.restore = virtio_vsock_restore,
#endif
};

static int __init virtio_vsock_init(void)
{
	int ret;

	virtio_vsock_rx_buf_size = VIRTIO_VSOCK_DEFAULT_RX_BUF_SIZE;
	virtio_vsock_workqueue = alloc_workqueue("virtio_vsock", WQ_HIGHPRI | WQ_BH, 0);
	if (!virtio_vsock_workqueue)
		return -ENOMEM;

	ret = vsock_core_register(&virtio_transport.transport,
				  VSOCK_TRANSPORT_F_G2H);
	if (ret)
		goto out_wq;

	ret = register_virtio_driver(&virtio_vsock_driver);
	if (ret)
		goto out_vci;

	return 0;

out_vci:
	vsock_core_unregister(&virtio_transport.transport);
out_wq:
	destroy_workqueue(virtio_vsock_workqueue);
	return ret;
}

static void __exit virtio_vsock_exit(void)
{
	unregister_virtio_driver(&virtio_vsock_driver);
	vsock_core_unregister(&virtio_transport.transport);
	destroy_workqueue(virtio_vsock_workqueue);
}

module_init(virtio_vsock_init);
module_exit(virtio_vsock_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Asias He");
MODULE_DESCRIPTION("virtio transport for vsock");
MODULE_DEVICE_TABLE(virtio, id_table);
