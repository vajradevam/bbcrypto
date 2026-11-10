// SPDX-License-Identifier: GPL-2.0
/*
 * bbcrypto - USB crypto accelerator driver (host side).
 *
 * Binds to a vendor-specific interface exported by a BeagleBone Black running
 * bbcryptod and registers SHA-1, SHA-256, HMAC-SHA256 (shash and async ahash),
 * ECB/CBC/CTR-AES (async skcipher) and GCM-AES (async AEAD) with the kernel crypto API.
 * Overview and file map: ../docs/ARCHITECTURE.md. Every operation is shipped over a USB bulk pipe
 * to the board and executed there (on the AM335x SHA/AES engines when the board kernel exposes
 * them). User space reaches the algorithms through AF_ALG by driver name, e.g.
 * "sha256-bbcrypto" or "cbc-aes-bbcrypto".
 *
 * Structure
 * ---------
 * A small asynchronous command engine sits between the crypto API and the USB core:
 *
 *   crypto request ──► bbc_cmd (tagged) ──► queue ──► OUT urb ──► board
 *                                                                   │
 *   crypto completion ◄── done list ◄── tag lookup ◄── IN urb ◄─────┘
 *
 *  - up to `window` commands are on the wire at once; the board executes them in order,
 *    so the USB transfer of command N+1 overlaps the crypto work of command N;
 *  - one IN urb is always posted; replies are matched to commands by tag, so the engine
 *    does not care about reply timing;
 *  - a timer resends commands whose reply is overdue (same tag; the board answers a
 *    repeated tag from its reply cache instead of executing it twice);
 *  - all state changes other than urb completions run on one ordered workqueue.
 *
 * Ciphers are asynchronous (CRYPTO_ALG_ASYNC): encrypt()/decrypt() return -EINPROGRESS and a
 * large request is cut into chunks that are pipelined where the maths allows it
 * (ECB, CTR and CBC-decrypt chunks are independent; CBC-encrypt chunks are serial).
 * Hashes keep the synchronous shash interface but run on the same engine, so several
 * concurrent callers are pipelined as well.
 *
 * Wire format: see ../proto.h.
 */
#include <linux/module.h>
#include <linux/usb.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/kref.h>
#include <linux/ktime.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/unaligned.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>
#include <crypto/internal/aead.h>
#include <crypto/gcm.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include <crypto/aes.h>
#include "proto.h"

#define DRV "bbcrypto"
#define BBC_BUFSZ (ALIGN(BBC_MAX_MSG, 512) + 512)
#define BBC_RX_TIMEOUT_MS 1000 /* reply overdue: resend the command */
#define BBC_RETRIES 4	       /* transmissions before giving up */
#define BBC_TICK msecs_to_jiffies(100)

static unsigned int prio = 50;
module_param(prio, uint, 0444);
MODULE_PARM_DESC(prio, "crypto API priority of the registered algorithms (default 50: only used "
		       "when asked for by driver name; >300 to prefer them everywhere)");

static unsigned int window = 4;
module_param(window, uint, 0644);
MODULE_PARM_DESC(window, "commands in flight per board, 1..8 (default 4)");

static unsigned int chunk = 16384;
module_param(chunk, uint, 0644);
MODULE_PARM_DESC(chunk, "bytes per cipher command, multiple of 16, up to 32768 (default 16384)");

static unsigned int win(void)
{
	return clamp(READ_ONCE(window), 1U, 8U);
}

static unsigned int chunk_sz(void)
{
	return clamp(round_down(READ_ONCE(chunk), 16U), 16U, (unsigned int)BBC_MAX_DATA);
}

static struct workqueue_struct *bbc_wq;

/* ------------------------------------------------------------------ */
/* device                                                              */
/* ------------------------------------------------------------------ */

struct bbc_cmd;

struct bbc_dev {
	struct kref ref;
	struct list_head node; /* in bbc_devs */
	u32 devid;
	struct usb_device *udev;
	struct usb_interface *intf;
	unsigned int pipe_out, pipe_in;

	spinlock_t lock; /* protects everything below up to 'anchor' */
	bool dead;
	u32 tag;
	struct list_head queue;	   /* submitted, waiting for a window slot */
	struct list_head inflight; /* on the wire or awaiting a reply */
	struct list_head donelist; /* finished, waiting for ->done() */
	struct list_head active;   /* cipher requests that still have chunks to emit */
	unsigned int n_queued, n_inflight, max_inflight;

	struct work_struct pump_work, done_work, fail_work;
	struct delayed_work to_work;

	struct usb_anchor anchor;
	struct urb *rx_urb;
	u8 *rx_buf;
	unsigned int rx_errs;

	atomic64_t n_req, n_bytes, n_err, n_retry, n_lat_us;
	char info[256];
	char bench[160]; /* result of the last 'ping' run */
};

static DEFINE_SPINLOCK(bbc_reg_lock);
static LIST_HEAD(bbc_devs);
static unsigned int bbc_ndevs;
static u32 bbc_next_devid;
static struct bbc_dev *bbc_rr;
static DEFINE_MUTEX(bbc_algs_lock);
static bool bbc_algs_up;

static void bbc_release(struct kref *k)
{
	struct bbc_dev *d = container_of(k, struct bbc_dev, ref);

	usb_free_urb(d->rx_urb);
	kfree(d->rx_buf);
	usb_put_dev(d->udev);
	kfree(d);
}

static void bbc_put(struct bbc_dev *d)
{
	kref_put(&d->ref, bbc_release);
}

/* pick a live board, round-robin */
static struct bbc_dev *bbc_get(void)
{
	struct bbc_dev *d = NULL;
	unsigned long fl;

	spin_lock_irqsave(&bbc_reg_lock, fl);
	if (!list_empty(&bbc_devs)) {
		struct list_head *n = bbc_rr ? bbc_rr->node.next : bbc_devs.next;

		if (n == &bbc_devs)
			n = bbc_devs.next;
		d = list_entry(n, struct bbc_dev, node);
		bbc_rr = d;
		kref_get(&d->ref);
	}
	spin_unlock_irqrestore(&bbc_reg_lock, fl);
	return d;
}

/* hash sessions live on one particular board */
static struct bbc_dev *bbc_get_id(u32 devid)
{
	struct bbc_dev *d, *found = NULL;
	unsigned long fl;

	spin_lock_irqsave(&bbc_reg_lock, fl);
	list_for_each_entry(d, &bbc_devs, node) if (d->devid == devid)
	{
		kref_get(&d->ref);
		found = d;
		break;
	}
	spin_unlock_irqrestore(&bbc_reg_lock, fl);
	return found;
}

/* queue work holding a device reference that the work function drops */
static void bbc_kick(struct bbc_dev *d, struct work_struct *w)
{
	kref_get(&d->ref);
	if (!queue_work(bbc_wq, w))
		bbc_put(d);
}

/* ------------------------------------------------------------------ */
/* commands                                                            */
/* ------------------------------------------------------------------ */

enum { CMD_NEW, CMD_QUEUED, CMD_INFLIGHT, CMD_DONE };

struct bbc_cmd {
	struct list_head node, rnode;
	struct kref ref; /* engine + every urb submission (+ a sync waiter) */
	struct bbc_dev *d;
	struct urb *urb;
	u8 *obuf;
	u32 olen;
	u8 *rbuf;
	u32 rcap, rlen;
	u32 tag, bytes;
	int state;
	int status; /* transport status; board status is in the reply */
	unsigned int attempts;
	unsigned long sent;
	bool waiting; /* out urb finished, reply awaited */
	ktime_t t0;
	void (*done)(struct bbc_cmd *);
	void *priv;
	struct completion comp;
	u32 off, len; /* cipher chunk position within the request */
};

static void bbc_cmd_free(struct kref *k)
{
	struct bbc_cmd *c = container_of(k, struct bbc_cmd, ref);

	usb_free_urb(c->urb);
	kfree(c->obuf);
	kfree(c->rbuf);
	bbc_put(c->d);
	kfree(c);
}

static void bbc_cmd_put(struct bbc_cmd *c)
{
	kref_put(&c->ref, bbc_cmd_free);
}

/*
 * Allocate a command. *datap points at the room reserved for the payload, which the
 * caller fills in before submitting.
 */
static struct bbc_cmd *bbc_cmd_new(struct bbc_dev *d, u16 op, u16 flags, u32 id, u32 alg,
				   const void *key, u32 keylen, const void *iv, u32 ivlen,
				   u32 datalen, u32 rcap, u8 **datap)
{
	struct bbc_cmd *c;
	struct bbc_req *rq;
	u8 *p;

	c = kzalloc(sizeof(*c), GFP_NOIO);
	if (!c)
		return NULL;
	c->olen = sizeof(*rq) + keylen + ivlen + datalen;
	c->obuf = kmalloc(c->olen + 1, GFP_NOIO);
	c->rcap = rcap;
	c->rbuf = kmalloc(rcap, GFP_NOIO);
	c->urb = usb_alloc_urb(0, GFP_NOIO);
	if (!c->obuf || !c->rbuf || !c->urb) {
		usb_free_urb(c->urb);
		kfree(c->obuf);
		kfree(c->rbuf);
		kfree(c);
		return NULL;
	}
	kref_init(&c->ref);
	kref_get(&d->ref);
	c->d = d;
	c->bytes = datalen;
	INIT_LIST_HEAD(&c->node);
	INIT_LIST_HEAD(&c->rnode);

	rq = (struct bbc_req *)c->obuf;
	rq->magic = cpu_to_le32(BBC_MAGIC);
	rq->op = cpu_to_le16(op);
	rq->flags = cpu_to_le16(flags);
	rq->id = cpu_to_le32(id);
	rq->alg = cpu_to_le32(alg);
	rq->keylen = cpu_to_le32(keylen);
	rq->ivlen = cpu_to_le32(ivlen);
	rq->datalen = cpu_to_le32(datalen);
	p = c->obuf + sizeof(*rq);
	if (keylen) {
		memcpy(p, key, keylen);
		p += keylen;
	}
	if (ivlen) {
		memcpy(p, iv, ivlen);
		p += ivlen;
	}
	*datap = p;
	if (c->olen % 512 == 0)
		c->obuf[c->olen++] = 0; /* force a short final packet */
	return c;
}

/* move a command from inflight to done. Caller holds d->lock. */
static bool bbc_finish_locked(struct bbc_dev *d, struct bbc_cmd *c, int status)
{
	if (c->state != CMD_INFLIGHT)
		return false;
	c->state = CMD_DONE;
	c->status = status;
	list_move_tail(&c->node, &d->donelist);
	d->n_inflight--;
	return true;
}

static void bbc_cmd_submit(struct bbc_cmd *c, void (*done)(struct bbc_cmd *), void *priv)
{
	struct bbc_dev *d = c->d;
	unsigned long fl;

	c->done = done;
	c->priv = priv;
	c->t0 = ktime_get();
	spin_lock_irqsave(&d->lock, fl);
	if (d->dead) {
		c->state = CMD_DONE;
		c->status = -ENODEV;
		list_add_tail(&c->node, &d->donelist);
		spin_unlock_irqrestore(&d->lock, fl);
		bbc_kick(d, &d->done_work);
		return;
	}
	c->tag = ++d->tag;
	((struct bbc_req *)c->obuf)->tag = cpu_to_le32(c->tag);
	c->state = CMD_QUEUED;
	list_add_tail(&c->node, &d->queue);
	d->n_queued++;
	spin_unlock_irqrestore(&d->lock, fl);
	bbc_kick(d, &d->pump_work);
}

static void bbc_out_complete(struct urb *u)
{
	struct bbc_cmd *c = u->context;
	struct bbc_dev *d = c->d;
	unsigned long fl;
	bool fin = false;

	spin_lock_irqsave(&d->lock, fl);
	if (u->status)
		fin = bbc_finish_locked(d, c, d->dead ? -ENODEV : u->status);
	else if (c->state == CMD_INFLIGHT)
		c->waiting = true;
	spin_unlock_irqrestore(&d->lock, fl);
	if (fin)
		bbc_kick(d, &d->done_work);
	bbc_cmd_put(c); /* the urb's reference */
}

/* (re)transmit a command; consumes one reference on success or failure */
static int bbc_send(struct bbc_dev *d, struct bbc_cmd *c)
{
	int ret;

	usb_fill_bulk_urb(c->urb, d->udev, d->pipe_out, c->obuf, c->olen, bbc_out_complete, c);
	usb_anchor_urb(c->urb, &d->anchor);
	ret = usb_submit_urb(c->urb, GFP_NOIO);
	if (ret) {
		unsigned long fl;
		bool fin;

		usb_unanchor_urb(c->urb);
		spin_lock_irqsave(&d->lock, fl);
		fin = bbc_finish_locked(d, c, ret);
		spin_unlock_irqrestore(&d->lock, fl);
		if (fin)
			bbc_kick(d, &d->done_work);
		bbc_cmd_put(c);
	}
	return ret;
}

static void bbc_send_queued(struct bbc_dev *d)
{
	for (;;) {
		struct bbc_cmd *c;
		unsigned long fl;

		spin_lock_irqsave(&d->lock, fl);
		if (d->dead || d->n_inflight >= win() || list_empty(&d->queue)) {
			spin_unlock_irqrestore(&d->lock, fl);
			return;
		}
		c = list_first_entry(&d->queue, struct bbc_cmd, node);
		list_move_tail(&c->node, &d->inflight);
		c->state = CMD_INFLIGHT;
		c->waiting = false;
		c->attempts = 1;
		c->sent = jiffies;
		d->n_queued--;
		if (++d->n_inflight > d->max_inflight)
			d->max_inflight = d->n_inflight;
		kref_get(&c->ref); /* for the urb */
		/* arm the retransmission timer; checked under the lock so a disconnect wins */
		kref_get(&d->ref);
		if (!queue_delayed_work(bbc_wq, &d->to_work, BBC_TICK))
			bbc_put(d);
		spin_unlock_irqrestore(&d->lock, fl);
		bbc_send(d, c);
	}
}

/* ------------------------------------------------------------------ */
/* reply path                                                          */
/* ------------------------------------------------------------------ */

static void bbc_rx_complete(struct urb *u)
{
	struct bbc_dev *d = u->context;
	struct bbc_resp *rs = (struct bbc_resp *)d->rx_buf;
	unsigned long fl;
	bool fin = false;
	int ret;

	switch (u->status) {
	case 0:
		d->rx_errs = 0;
		break;
	case -ENOENT:
	case -ECONNRESET:
	case -ESHUTDOWN:
		return; /* urb killed */
	default:
		if (++d->rx_errs > 20) {
			dev_err(&d->intf->dev, "reply pipe failing (%d), giving up\n", u->status);
			return;
		}
		goto resubmit;
	}

	if (u->actual_length >= sizeof(*rs) && le32_to_cpu(rs->magic) == BBC_MAGIC) {
		u32 tag = le32_to_cpu(rs->tag);
		struct bbc_cmd *c;

		spin_lock_irqsave(&d->lock, fl);
		list_for_each_entry(c, &d->inflight, node)
		{
			u64 need;
			int st = 0;

			if (c->tag != tag)
				continue;
			need = (u64)sizeof(*rs) + le32_to_cpu(rs->ivlen) + le32_to_cpu(rs->datalen);
			if (need > u->actual_length)
				st = -EPROTO;
			else if (u->actual_length > c->rcap)
				st = -EMSGSIZE;
			else {
				memcpy(c->rbuf, rs, u->actual_length);
				c->rlen = u->actual_length;
			}
			fin = bbc_finish_locked(d, c, st);
			break;
		}
		spin_unlock_irqrestore(&d->lock, fl);
		if (fin)
			bbc_kick(d, &d->done_work);
		/* no match: a duplicate (the board replayed a reply we already had) - ignore */
	}
resubmit:
	if (READ_ONCE(d->dead))
		return;
	usb_anchor_urb(u, &d->anchor);
	ret = usb_submit_urb(u, GFP_ATOMIC);
	if (ret) {
		usb_unanchor_urb(u);
		dev_err(&d->intf->dev, "cannot repost reply urb: %d\n", ret);
	}
}

/* ------------------------------------------------------------------ */
/* cipher requests (declared early: the workers drive them)            */
/* ------------------------------------------------------------------ */

struct bbc_creq {
	struct list_head node; /* in d->active */
	struct skcipher_request *req;
	struct bbc_dev *d;
	u32 total, off, inflight;
	int err;
	bool dec, serial;
	u32 alg;
	unsigned int ivsize;
	u8 iv[AES_BLOCK_SIZE]; /* IV for the next chunk to emit; the final IV at the end */
};

static void bbc_creq_emit(struct bbc_creq *cr);
static void bbc_creq_progress(struct bbc_creq *cr);

static void bbc_emit_chunks(struct bbc_dev *d)
{
	for (;;) {
		struct bbc_creq *cr = NULL, *it;
		unsigned long fl;

		spin_lock_irqsave(&d->lock, fl);
		if (d->dead || d->n_inflight + d->n_queued >= win()) {
			spin_unlock_irqrestore(&d->lock, fl);
			return;
		}
		list_for_each_entry(it, &d->active, node)
		{
			if (it->err || it->off >= it->total)
				continue;
			if (it->inflight >= (it->serial ? 1 : win()))
				continue;
			cr = it;
			break;
		}
		if (cr)
			list_move_tail(&cr->node, &d->active); /* round-robin between requests */
		spin_unlock_irqrestore(&d->lock, fl);
		if (!cr)
			return;
		bbc_creq_emit(cr);
	}
}

static void bbc_pump_work(struct work_struct *w)
{
	struct bbc_dev *d = container_of(w, struct bbc_dev, pump_work);

	bbc_emit_chunks(d);
	bbc_send_queued(d);
	bbc_put(d);
}

static void bbc_done_work(struct work_struct *w)
{
	struct bbc_dev *d = container_of(w, struct bbc_dev, done_work);
	struct bbc_cmd *c, *tmp;
	LIST_HEAD(l);
	unsigned long fl;

	for (;;) {
		spin_lock_irqsave(&d->lock, fl);
		list_splice_init(&d->donelist, &l);
		spin_unlock_irqrestore(&d->lock, fl);
		if (list_empty(&l))
			break;
		list_for_each_entry_safe(c, tmp, &l, node)
		{
			list_del_init(&c->node);
			if (c->status) {
				atomic64_inc(&d->n_err);
			} else {
				atomic64_inc(&d->n_req);
				atomic64_add(c->bytes, &d->n_bytes);
			}
			atomic64_add(ktime_us_delta(ktime_get(), c->t0), &d->n_lat_us);
			c->done(c);
			bbc_cmd_put(c); /* the engine's reference */
		}
	}
	bbc_emit_chunks(d); /* window slots just freed */
	bbc_send_queued(d);
	bbc_put(d);
}

/* retransmit commands whose reply is overdue */
static void bbc_to_work(struct work_struct *w)
{
	struct bbc_dev *d = container_of(to_delayed_work(w), struct bbc_dev, to_work);
	struct bbc_cmd *c, *tmp;
	LIST_HEAD(resend);
	unsigned long fl;
	bool fin = false;

	spin_lock_irqsave(&d->lock, fl);
	list_for_each_entry_safe(c, tmp, &d->inflight, node)
	{
		if (!c->waiting ||
		    !time_after(jiffies, c->sent + msecs_to_jiffies(BBC_RX_TIMEOUT_MS)))
			continue;
		if (c->attempts >= BBC_RETRIES) {
			dev_err(&d->intf->dev, "tag %u: no reply after %u attempts\n", c->tag,
				c->attempts);
			fin |= bbc_finish_locked(d, c, -ETIMEDOUT);
			continue;
		}
		c->attempts++;
		c->waiting = false;
		c->sent = jiffies;
		atomic64_inc(&d->n_retry);
		kref_get(&c->ref);
		list_add_tail(&c->rnode, &resend);
	}
	if (!d->dead && !list_empty(&d->inflight)) {
		kref_get(&d->ref);
		if (!queue_delayed_work(bbc_wq, &d->to_work, BBC_TICK))
			bbc_put(d);
	}
	spin_unlock_irqrestore(&d->lock, fl);

	list_for_each_entry_safe(c, tmp, &resend, rnode)
	{
		list_del_init(&c->rnode);
		dev_dbg(&d->intf->dev, "resending tag %u (attempt %u)\n", c->tag, c->attempts);
		bbc_send(d, c);
	}
	if (fin)
		bbc_kick(d, &d->done_work);
	bbc_put(d);
}

/* disconnect: fail everything that is still pending (runs on the ordered workqueue) */
static void bbc_fail_work(struct work_struct *w)
{
	struct bbc_dev *d = container_of(w, struct bbc_dev, fail_work);
	struct bbc_creq *cr, *tmp;
	struct bbc_cmd *c, *ctmp;
	LIST_HEAD(act);
	unsigned long fl;

	spin_lock_irqsave(&d->lock, fl);
	list_for_each_entry_safe(c, ctmp, &d->queue, node)
	{
		c->state = CMD_DONE;
		c->status = -ENODEV;
		list_move_tail(&c->node, &d->donelist);
	}
	d->n_queued = 0;
	list_for_each_entry_safe(c, ctmp, &d->inflight, node)
	{
		c->state = CMD_DONE;
		c->status = -ENODEV;
		list_move_tail(&c->node, &d->donelist);
	}
	d->n_inflight = 0;
	spin_unlock_irqrestore(&d->lock, fl);

	kref_get(&d->ref);	      /* bbc_done_work() consumes one reference */
	bbc_done_work(&d->done_work); /* completes the failed chunks */

	spin_lock_irqsave(&d->lock, fl);
	list_splice_init(&d->active, &act);
	spin_unlock_irqrestore(&d->lock, fl);
	list_for_each_entry_safe(cr, tmp, &act, node)
	{
		cr->err = -ENODEV;
		bbc_creq_progress(cr);
	}
	bbc_put(d);
}

/* ------------------------------------------------------------------ */
/* synchronous round trip (used by the hashes and by probe)            */
/* ------------------------------------------------------------------ */

struct bbc_out {
	u32 id;
	u8 *iv;
	u32 ivcap, ivlen;
	u8 *data;
	u32 datacap, datalen;
};

static void bbc_sync_done(struct bbc_cmd *c)
{
	complete(&c->comp);
}

static int bbc_xfer(struct bbc_dev *d, u16 op, u16 flags, u32 id, u32 alg, const void *key,
		    u32 keylen, const void *iv, u32 ivlen, const void *data, u32 datalen,
		    struct bbc_out *out)
{
	struct bbc_cmd *c;
	struct bbc_resp *rs;
	u32 rcap, ilen, dlen;
	u8 *dp, *p;
	int ret;

	if (keylen > BBC_MAX_KEY || ivlen > BBC_MAX_IV || datalen > BBC_MAX_DATA)
		return -EINVAL;
	rcap = sizeof(*rs) + BBC_MAX_IV + max_t(u32, out ? out->datacap : 0, 64);
	c = bbc_cmd_new(d, op, flags, id, alg, key, keylen, iv, ivlen, datalen, rcap, &dp);
	if (!c)
		return -ENOMEM;
	if (datalen)
		memcpy(dp, data, datalen);
	init_completion(&c->comp);
	kref_get(&c->ref); /* ours; the engine's is dropped after ->done() */
	bbc_cmd_submit(c, bbc_sync_done, NULL);
	wait_for_completion(&c->comp);

	ret = c->status;
	if (ret)
		goto out;
	rs = (struct bbc_resp *)c->rbuf;
	ilen = le32_to_cpu(rs->ivlen);
	dlen = le32_to_cpu(rs->datalen);
	ret = (s32)le32_to_cpu(rs->status);
	if (ret)
		goto out;
	p = c->rbuf + sizeof(*rs);
	if (out) {
		out->id = le32_to_cpu(rs->id);
		if (out->iv) {
			out->ivlen = min(ilen, out->ivcap);
			memcpy(out->iv, p, out->ivlen);
		}
		if (out->data) {
			if (dlen > out->datacap) {
				ret = -EMSGSIZE;
				goto out;
			}
			out->datalen = dlen;
			memcpy(out->data, p + ilen, dlen);
		}
	}
out:
	bbc_cmd_put(c);
	return ret;
}

/* ------------------------------------------------------------------ */
/* hashes                                                              */
/* ------------------------------------------------------------------ */

struct bbc_hash_ctx { /* per tfm */
	u8 key[BBC_MAX_KEY];
	u32 keylen;
};

struct bbc_hash_desc { /* per request; id 0 = no board session yet */
	u32 id;
	u32 devid; /* the board that holds the session */
};

struct bbc_shash {
	struct shash_alg alg;
	u32 id; /* enum bbc_alg */
	bool registered;
};

static struct bbc_shash *to_bshash(struct crypto_shash *tfm)
{
	return container_of(crypto_shash_alg(tfm), struct bbc_shash, alg);
}

static int bbc_hash_setkey(struct crypto_shash *tfm, const u8 *key, unsigned int len)
{
	struct bbc_hash_ctx *c = crypto_shash_ctx(tfm);

	if (len > BBC_MAX_KEY)
		return -EINVAL;
	memcpy(c->key, key, len);
	c->keylen = len;
	return 0;
}

static int bbc_hash_init(struct shash_desc *desc)
{
	struct bbc_hash_desc *dd = shash_desc_ctx(desc);

	dd->id = 0; /* session is created lazily */
	dd->devid = 0;
	return 0;
}

/* the board for this request: the one holding its session, else any */
static struct bbc_dev *bbc_hash_dev(struct bbc_hash_desc *dd)
{
	return dd->id ? bbc_get_id(dd->devid) : bbc_get();
}

static int bbc_hash_new(struct bbc_dev *d, struct shash_desc *desc)
{
	struct bbc_hash_desc *dd = shash_desc_ctx(desc);
	struct bbc_hash_ctx *c = crypto_shash_ctx(desc->tfm);
	struct bbc_out out = {};
	int ret;

	ret = bbc_xfer(d, BBC_OP_HASH_NEW, 0, 0, to_bshash(desc->tfm)->id, c->key, c->keylen, NULL,
		       0, NULL, 0, &out);
	if (!ret) {
		dd->id = out.id;
		dd->devid = d->devid;
	}
	return ret;
}

static int bbc_hash_update_dev(struct bbc_dev *d, struct shash_desc *desc, const u8 *data,
			       unsigned int len)
{
	struct bbc_hash_desc *dd = shash_desc_ctx(desc);
	int ret;

	if (!dd->id) {
		ret = bbc_hash_new(d, desc);
		if (ret)
			return ret;
	}
	while (len) {
		unsigned int n = min_t(unsigned int, len, BBC_MAX_DATA);

		ret = bbc_xfer(d, BBC_OP_HASH_UPDATE, 0, dd->id, 0, NULL, 0, NULL, 0, data, n,
			       NULL);
		if (ret)
			return ret;
		data += n;
		len -= n;
	}
	return 0;
}

static int bbc_hash_update(struct shash_desc *desc, const u8 *data, unsigned int len)
{
	struct bbc_dev *d = bbc_hash_dev(shash_desc_ctx(desc));
	int ret;

	if (!d)
		return -ENODEV;
	ret = bbc_hash_update_dev(d, desc, data, len);
	bbc_put(d);
	return ret;
}

static int bbc_hash_final_dev(struct bbc_dev *d, struct shash_desc *desc, const u8 *data,
			      unsigned int len, u8 *out)
{
	struct bbc_hash_desc *dd = shash_desc_ctx(desc);
	struct bbc_hash_ctx *c = crypto_shash_ctx(desc->tfm);
	struct bbc_out o = {.data = out, .datacap = crypto_shash_digestsize(desc->tfm)};
	int ret;

	if (!dd->id && len <= BBC_MAX_DATA) /* whole message in one round trip */
		return bbc_xfer(d, BBC_OP_HASH_NEW, BBC_F_ONESHOT, 0, to_bshash(desc->tfm)->id,
				c->key, c->keylen, NULL, 0, data, len, &o);
	ret = bbc_hash_update_dev(d, desc, data, len);
	if (ret)
		return ret;
	ret = bbc_xfer(d, BBC_OP_HASH_FINAL, 0, dd->id, 0, NULL, 0, NULL, 0, NULL, 0, &o);
	dd->id = 0; /* board frees the session on FINAL */
	return ret;
}

static int bbc_hash_finup(struct shash_desc *desc, const u8 *data, unsigned int len, u8 *out)
{
	struct bbc_dev *d = bbc_hash_dev(shash_desc_ctx(desc));
	int ret;

	if (!d)
		return -ENODEV;
	ret = bbc_hash_final_dev(d, desc, data, len, out);
	bbc_put(d);
	return ret;
}

static int bbc_hash_final(struct shash_desc *desc, u8 *out)
{
	return bbc_hash_finup(desc, NULL, 0, out);
}

static int bbc_hash_digest(struct shash_desc *desc, const u8 *data, unsigned int len, u8 *out)
{
	bbc_hash_init(desc);
	return bbc_hash_finup(desc, data, len, out);
}

/* export/import: the state lives on the board; export clones the session */
static int bbc_hash_export(struct shash_desc *desc, void *out)
{
	struct bbc_hash_desc *dd = shash_desc_ctx(desc);
	struct bbc_dev *d;
	struct bbc_out o = {};
	u32 id = 0, devid = 0;
	int ret = 0;

	if (dd->id) {
		d = bbc_get_id(dd->devid);
		if (!d)
			return -ENODEV;
		ret = bbc_xfer(d, BBC_OP_HASH_CLONE, 0, dd->id, 0, NULL, 0, NULL, 0, NULL, 0, &o);
		devid = d->devid;
		bbc_put(d);
		if (ret)
			return ret;
		id = o.id;
	}
	put_unaligned_le32(id, out);
	put_unaligned_le32(devid, out + 4);
	return 0;
}

static int bbc_hash_import(struct shash_desc *desc, const void *in)
{
	struct bbc_hash_desc *dd = shash_desc_ctx(desc);

	dd->id = get_unaligned_le32(in);
	dd->devid = get_unaligned_le32(in + 4);
	return 0;
}

#define BBC_HASH(_alg, _name, _drv, _dsz, _bsz, _hmac)                                             \
	{                                                                                          \
		.id = _alg,                                                                        \
		.alg = {.init = bbc_hash_init,                                                     \
			.update = bbc_hash_update,                                                 \
			.final = bbc_hash_final,                                                   \
			.finup = bbc_hash_finup,                                                   \
			.digest = bbc_hash_digest,                                                 \
			.export = bbc_hash_export,                                                 \
			.import = bbc_hash_import,                                                 \
			.setkey = (_hmac) ? bbc_hash_setkey : NULL,                                \
			.descsize = sizeof(struct bbc_hash_desc),                                  \
			.digestsize = _dsz,                                                        \
			.statesize = 2 * sizeof(u32),                                              \
			.base = {.cra_name = _name,                                                \
				 .cra_driver_name = _drv,                                          \
				 .cra_blocksize = _bsz,                                            \
				 .cra_ctxsize = sizeof(struct bbc_hash_ctx),                       \
				 .cra_module = THIS_MODULE} }                                      \
	}

static struct bbc_shash bbc_hashes[] = {
	BBC_HASH(BBC_ALG_SHA1, "sha1", "sha1-bbcrypto", SHA1_DIGEST_SIZE, SHA1_BLOCK_SIZE, false),
	BBC_HASH(BBC_ALG_SHA256, "sha256", "sha256-bbcrypto", SHA256_DIGEST_SIZE, SHA256_BLOCK_SIZE,
		 false),
	BBC_HASH(BBC_ALG_HMAC_SHA256, "hmac(sha256)", "hmac-sha256-bbcrypto", SHA256_DIGEST_SIZE,
		 SHA256_BLOCK_SIZE, true),
};

/* ------------------------------------------------------------------ */
/* AES modes (asynchronous)                                            */
/* ------------------------------------------------------------------ */

struct bbc_skcipher {
	struct skcipher_alg alg;
	u32 id;
	bool registered;
};

struct bbc_cipher_ctx {
	u8 key[AES_MAX_KEY_SIZE];
	u32 keylen;
};

static struct bbc_skcipher *to_bsk(struct crypto_skcipher *tfm)
{
	return container_of(crypto_skcipher_alg(tfm), struct bbc_skcipher, alg);
}

static int bbc_cipher_init(struct crypto_skcipher *tfm)
{
	crypto_skcipher_set_reqsize(tfm, sizeof(struct bbc_creq));
	return 0;
}

static int bbc_cipher_setkey(struct crypto_skcipher *tfm, const u8 *key, unsigned int len)
{
	struct bbc_cipher_ctx *c = crypto_skcipher_ctx(tfm);

	if (len != AES_KEYSIZE_128 && len != AES_KEYSIZE_192 && len != AES_KEYSIZE_256)
		return -EINVAL;
	memcpy(c->key, key, len);
	c->keylen = len;
	return 0;
}

/* advance a 128-bit big-endian counter by 'blocks' */
static void bbc_ctr_add(u8 *iv, u64 blocks)
{
	int i;
	unsigned int carry;

	for (i = 15; i >= 0 && blocks; i--) {
		carry = iv[i] + (blocks & 0xff);
		iv[i] = carry & 0xff;
		blocks = (blocks >> 8) + (carry >> 8);
	}
	for (; i >= 0 && blocks; i--)
		if (++iv[i])
			break;
}

/* all runs on the ordered workqueue */
static void bbc_creq_progress(struct bbc_creq *cr)
{
	struct skcipher_request *req = cr->req;
	struct bbc_dev *d = cr->d;
	unsigned long fl;
	int err;

	if (cr->inflight || (!cr->err && cr->off < cr->total))
		return;
	spin_lock_irqsave(&d->lock, fl);
	if (!list_empty(&cr->node))
		list_del_init(&cr->node);
	spin_unlock_irqrestore(&d->lock, fl);

	err = cr->err;
	if (!err && cr->ivsize)
		memcpy(req->iv, cr->iv, cr->ivsize);
	bbc_put(d);
	skcipher_request_complete(req, err); /* req (and cr) may be gone after this */
}

static void bbc_chunk_done(struct bbc_cmd *c)
{
	struct bbc_creq *cr = c->priv;
	struct skcipher_request *req = cr->req;
	int ret = c->status;

	if (!ret) {
		struct bbc_resp *rs = (struct bbc_resp *)c->rbuf;
		u32 ilen = le32_to_cpu(rs->ivlen), dlen = le32_to_cpu(rs->datalen);
		u8 *p = c->rbuf + sizeof(*rs);

		ret = (s32)le32_to_cpu(rs->status);
		if (!ret && dlen != c->len)
			ret = -EPROTO;
		if (!ret) {
			if (cr->serial && ilen == AES_BLOCK_SIZE)
				memcpy(cr->iv, p, AES_BLOCK_SIZE); /* CBC chain */
			sg_pcopy_from_buffer(req->dst, sg_nents(req->dst), p + ilen, c->len,
					     c->off);
		}
	}
	if (ret && !cr->err)
		cr->err = ret;
	cr->inflight--;
	bbc_creq_progress(cr);
}

static void bbc_creq_emit(struct bbc_creq *cr)
{
	struct skcipher_request *req = cr->req;
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct bbc_cipher_ctx *kc = crypto_skcipher_ctx(tfm);
	u32 n = min_t(u32, cr->total - cr->off, chunk_sz());
	struct bbc_cmd *c;
	u8 *dp;

	c = bbc_cmd_new(cr->d, BBC_OP_CIPHER, cr->dec ? BBC_F_DECRYPT : 0, 0, cr->alg, kc->key,
			kc->keylen, cr->ivsize ? cr->iv : NULL, cr->ivsize, n,
			sizeof(struct bbc_resp) + BBC_MAX_IV + n, &dp);
	if (!c) {
		cr->err = -ENOMEM;
		bbc_creq_progress(cr);
		return;
	}
	sg_pcopy_to_buffer(req->src, sg_nents(req->src), dp, n, cr->off);
	c->off = cr->off;
	c->len = n;

	/* IV of the following chunk, where it can be known in advance */
	if (cr->alg == BBC_ALG_CBC_AES && cr->dec)
		memcpy(cr->iv, dp + n - AES_BLOCK_SIZE, AES_BLOCK_SIZE); /* last ciphertext block */
	else if (cr->alg == BBC_ALG_CTR_AES)
		bbc_ctr_add(cr->iv, DIV_ROUND_UP(n, AES_BLOCK_SIZE));
	/* CBC encrypt: the board hands the chained IV back with each reply */

	cr->off += n;
	cr->inflight++;
	bbc_cmd_submit(c, bbc_chunk_done, cr);
}

static int bbc_cipher_crypt(struct skcipher_request *req, bool dec)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct bbc_creq *cr = skcipher_request_ctx(req);
	unsigned int bs = crypto_skcipher_blocksize(tfm);
	struct bbc_dev *d;
	unsigned long fl;

	if (!req->cryptlen)
		return 0;
	if (bs > 1 && req->cryptlen % bs)
		return -EINVAL;
	d = bbc_get();
	if (!d)
		return -ENODEV;

	memset(cr, 0, sizeof(*cr));
	INIT_LIST_HEAD(&cr->node);
	cr->req = req;
	cr->d = d;
	cr->total = req->cryptlen;
	cr->dec = dec;
	cr->alg = to_bsk(tfm)->id;
	cr->serial = cr->alg == BBC_ALG_CBC_AES && !dec;
	cr->ivsize = crypto_skcipher_ivsize(tfm);
	if (cr->ivsize)
		memcpy(cr->iv, req->iv, cr->ivsize);

	spin_lock_irqsave(&d->lock, fl);
	if (d->dead) {
		spin_unlock_irqrestore(&d->lock, fl);
		bbc_put(d);
		return -ENODEV;
	}
	list_add_tail(&cr->node, &d->active);
	spin_unlock_irqrestore(&d->lock, fl);
	bbc_kick(d, &d->pump_work);
	return -EINPROGRESS;
}

static int bbc_cipher_encrypt(struct skcipher_request *req)
{
	return bbc_cipher_crypt(req, false);
}
static int bbc_cipher_decrypt(struct skcipher_request *req)
{
	return bbc_cipher_crypt(req, true);
}

#define BBC_CIPHER(_alg, _name, _drv, _bs, _iv)                                                    \
	{                                                                                          \
		.id = _alg,                                                                        \
		.alg = {.init = bbc_cipher_init,                                                   \
			.setkey = bbc_cipher_setkey,                                               \
			.encrypt = bbc_cipher_encrypt,                                             \
			.decrypt = bbc_cipher_decrypt,                                             \
			.min_keysize = AES_MIN_KEY_SIZE,                                           \
			.max_keysize = AES_MAX_KEY_SIZE,                                           \
			.ivsize = _iv,                                                             \
			.chunksize = 16,                                                           \
			.base = {.cra_name = _name,                                                \
				 .cra_driver_name = _drv,                                          \
				 .cra_blocksize = _bs,                                             \
				 .cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_ALLOCATES_MEMORY,      \
				 .cra_ctxsize = sizeof(struct bbc_cipher_ctx),                     \
				 .cra_module = THIS_MODULE} }                                      \
	}

static struct bbc_skcipher bbc_ciphers[] = {
	BBC_CIPHER(BBC_ALG_ECB_AES, "ecb(aes)", "ecb-aes-bbcrypto", AES_BLOCK_SIZE, 0),
	BBC_CIPHER(BBC_ALG_CBC_AES, "cbc(aes)", "cbc-aes-bbcrypto", AES_BLOCK_SIZE, AES_BLOCK_SIZE),
	BBC_CIPHER(BBC_ALG_CTR_AES, "ctr(aes)", "ctr-aes-bbcrypto", 1, AES_BLOCK_SIZE),
};

/* ------------------------------------------------------------------ */
/* ahash: the same hashes with a fully asynchronous interface          */
/* ------------------------------------------------------------------ */

/*
 * An ahash request is a small state machine driven by command completions:
 *   [NEW] -> UPDATE* -> [FINAL]      or      ONESHOT (whole message fits one command)
 * The board-side session (id/devid) is the persistent hash state and lives in the request
 * context between calls; the rest of the context is per call.
 */
enum { AH_NEW, AH_UPD, AH_FIN, AH_ONE };

struct bbc_ahreq {
	u32 id, devid; /* persistent: board session */
	struct ahash_request *req;
	u32 total, off, n;
	bool fin;
	int stage;
};

struct bbc_ahash {
	struct ahash_alg alg;
	u32 id;
	bool registered;
};

static struct bbc_ahash *to_bah(struct crypto_ahash *tfm)
{
	return container_of(crypto_ahash_alg(tfm), struct bbc_ahash, alg);
}

static int bbc_ah_init_tfm(struct crypto_ahash *tfm)
{
	crypto_ahash_set_reqsize(tfm, sizeof(struct bbc_ahreq));
	return 0;
}

static int bbc_ah_setkey(struct crypto_ahash *tfm, const u8 *key, unsigned int len)
{
	struct bbc_hash_ctx *c = crypto_ahash_ctx(tfm);

	if (len > BBC_MAX_KEY)
		return -EINVAL;
	memcpy(c->key, key, len);
	c->keylen = len;
	return 0;
}

static void bbc_ah_step(struct bbc_ahreq *ar);

static void bbc_ah_done(struct bbc_cmd *c)
{
	struct bbc_ahreq *ar = c->priv;
	struct ahash_request *req = ar->req;
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	int ret = c->status;

	if (!ret) {
		struct bbc_resp *rs = (struct bbc_resp *)c->rbuf;
		u32 ilen = le32_to_cpu(rs->ivlen), dlen = le32_to_cpu(rs->datalen);

		ret = (s32)le32_to_cpu(rs->status);
		if (!ret) {
			switch (ar->stage) {
			case AH_NEW:
				ar->id = le32_to_cpu(rs->id);
				ar->devid = c->d->devid;
				bbc_ah_step(ar);
				return;
			case AH_UPD:
				ar->off += ar->n;
				bbc_ah_step(ar);
				return;
			default: /* FINAL / ONESHOT: the digest */
				if (dlen > crypto_ahash_digestsize(tfm))
					ret = -EMSGSIZE;
				else
					memcpy(req->result, c->rbuf + sizeof(*rs) + ilen, dlen);
			}
		}
	}
	ar->id = 0; /* finished, or the session is unusable */
	ahash_request_complete(req, ret);
}

static void bbc_ah_step(struct bbc_ahreq *ar)
{
	struct ahash_request *req = ar->req;
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct bbc_hash_ctx *kc = crypto_ahash_ctx(tfm);
	u32 alg = to_bah(tfm)->id, left = ar->total - ar->off;
	u16 op = BBC_OP_HASH_NEW, flags = 0, id = 0;
	u32 n = 0, rcap = sizeof(struct bbc_resp) + 64;
	const void *key = NULL;
	u32 keylen = 0;
	struct bbc_cmd *c;
	struct bbc_dev *d;
	u8 *dp;

	if (!ar->id) {
		if (!ar->fin && !left)
			goto finished;
		if (ar->fin && left <= BBC_MAX_DATA) {
			ar->stage = AH_ONE;
			flags = BBC_F_ONESHOT;
			n = left;
		} else {
			ar->stage = AH_NEW;
		}
		key = kc->key;
		keylen = kc->keylen;
	} else if (left) {
		ar->stage = AH_UPD;
		op = BBC_OP_HASH_UPDATE;
		id = ar->id;
		n = ar->n = min_t(u32, left, BBC_MAX_DATA);
	} else if (ar->fin) {
		ar->stage = AH_FIN;
		op = BBC_OP_HASH_FINAL;
		id = ar->id;
	} else {
		goto finished;
	}

	d = ar->id ? bbc_get_id(ar->devid) : bbc_get();
	if (!d) {
		ar->id = 0;
		ahash_request_complete(req, -ENODEV);
		return;
	}
	c = bbc_cmd_new(d, op, flags, id, alg, key, keylen, NULL, 0, n, rcap, &dp);
	bbc_put(d); /* the command holds its own reference */
	if (!c) {
		ar->id = 0;
		ahash_request_complete(req, -ENOMEM);
		return;
	}
	if (n)
		sg_pcopy_to_buffer(req->src, sg_nents(req->src), dp, n, ar->off);
	bbc_cmd_submit(c, bbc_ah_done, ar);
	return;
finished:
	ahash_request_complete(req, 0);
}

static int bbc_ah_run(struct ahash_request *req, u32 total, bool fin)
{
	struct bbc_ahreq *ar = ahash_request_ctx(req);

	ar->req = req;
	ar->total = total;
	ar->off = 0;
	ar->fin = fin;
	bbc_ah_step(ar);
	return -EINPROGRESS;
}

static int bbc_ah_init(struct ahash_request *req)
{
	struct bbc_ahreq *ar = ahash_request_ctx(req);

	ar->id = ar->devid = 0;
	return 0;
}
