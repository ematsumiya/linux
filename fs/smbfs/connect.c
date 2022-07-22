// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) International Business Machines Corp., 2002,2011
 * Author(s): Steve French <sfrench@us.ibm.com>
*/
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/string.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/ctype.h>
#include <linux/utsname.h>
#include <linux/mempool.h>
#include <linux/delay.h>
#include <linux/completion.h>
#include <linux/kthread.h>
#include <linux/pagevec.h>
#include <linux/freezer.h>
#include <linux/namei.h>
#include <linux/uuid.h>
#include <linux/uaccess.h>
#include <asm/processor.h>
#include <linux/inet.h>
#include <linux/module.h>
#include <keys/user-type.h>
#include <net/ipv6.h>
#include <linux/parser.h>
#include <linux/bvec.h>

#include "cifspdu.h"
#include "server_info.h"
#include "ses.h"
#include "defs.h"
#include "cifs_unicode.h"
#include "debug.h"
#include "proc.h"
#include "cifs_fs_sb.h"
#include "ntlmssp.h"
#include "nterr.h"
#include "rfc1002pdu.h"
#include "fscache.h"
#include "smb2proto.h"
#include "smbdirect.h"
#include "dns_resolve.h"
#ifdef CONFIG_SMBFS_DFS_UPCALL
#include "dfs_cache.h"
#endif
#include "fs_context.h"
#include "cifs_swn.h"
#include "defs.h"

extern mempool_t *cifs_req_poolp;
extern bool disable_legacy_dialects;
extern bool unix_extensions;

/* FIXME: should these be tunable? */
#define TLINK_ERROR_EXPIRE	(1 * HZ)
#define TLINK_IDLE_EXPIRE	(600 * HZ)

/* Drop the connection to not overload the server */
#define NUM_STATUS_IO_TIMEOUT   5

struct mount_ctx {
	struct cifs_sb_info *cifs_sb;
	struct smb3_fs_context *fs_ctx;
	unsigned int xid;
	struct smbfs_server_info *server;
	struct smbfs_ses *ses;
	struct smbfs_tcon *tcon;
#ifdef CONFIG_SMBFS_DFS_UPCALL
	struct smbfs_ses *root_ses;
	uuid_t mount_id;
	char *origin_fullpath, *leaf_fullpath;
#endif
};

static int ip_connect(struct smbfs_server_info *server);
static int generic_ip_connect(struct smbfs_server_info *server);
static void tlink_rb_insert(struct rb_root *root, struct smbfs_tcon_link *new_tlink);
static void smbfs_prune_tlinks(struct work_struct *work);

/*
 * Resolve hostname and set ip addr in tcp ses. Useful for hostnames that may
 * get their ip addresses changed at some point.
 *
 * This should be called with server->srv_mutex held.
 */
static int reconn_set_ipaddr_from_hostname(struct smbfs_server_info *server)
{
	int rc;
	int len;
	char *unc, *ipaddr = NULL;
	time64_t expiry, now;
	unsigned long ttl = SMB_DNS_RESOLVE_INTERVAL_DEFAULT;

	if (!server->hostname)
		return -EINVAL;

	/* if server hostname isn't populated, there's nothing to do here */
	if (server->hostname[0] == '\0')
		return 0;

	len = strlen(server->hostname) + 3;

	unc = kmalloc(len, GFP_KERNEL);
	if (!unc) {
		smbfs_dbg("failed to create UNC path\n");
		return -ENOMEM;
	}
	scnprintf(unc, len, "\\\\%s", server->hostname);

	rc = dns_resolve_server_name_to_ip(unc, &ipaddr, &expiry);
	kfree(unc);

	if (rc < 0) {
		smbfs_dbg("failed to resolve server part of '%s' to IP: %d\n",
			  server->hostname, rc);
		goto requeue_resolve;
	}

	spin_lock(&g_servers_lock);
	rc = cifs_convert_address((struct sockaddr *)&server->dstaddr, ipaddr,
				  strlen(ipaddr));
	spin_unlock(&g_servers_lock);
	kfree(ipaddr);

	/* rc == 1 means success here */
	if (rc) {
		now = ktime_get_real_seconds();
		if (expiry && expiry > now)
			/*
			 * To make sure we don't use the cached entry, retry 1s
			 * after expiry.
			 */
			ttl = max_t(unsigned long, expiry - now, SMB_DNS_RESOLVE_INTERVAL_MIN) + 1;
	}
	rc = !rc ? -1 : 0;

requeue_resolve:
	smbfs_dbg("next dns resolution scheduled for %lu seconds in the future\n", ttl);
	mod_delayed_work(cifsiod_wq, &server->resolve, (ttl * HZ));

	return rc;
}

void smb2_query_server_interfaces(struct work_struct *work)
{
	int rc;
	struct smbfs_tcon *tcon = container_of(work,
					struct smbfs_tcon,
					query_interfaces.work);

	/*
	 * query server network interfaces, in case they change
	 */
	rc = SMB3_request_interfaces(0, tcon);
	if (rc)
		smbfs_dbg("failed to query server interfaces: %d\n", rc);

	queue_delayed_work(cifsiod_wq, &tcon->query_interfaces,
			   (SMBFS_INTERFACE_POLL_INTERVAL * HZ));
}

static void cifs_resolve_server(struct work_struct *work)
{
	int rc;
	struct smbfs_server_info *server = container_of(work,
					struct smbfs_server_info, resolve.work);

	server_lock(server);

	/*
	 * Resolve the hostname again to make sure that IP address is up-to-date.
	 */
	rc = reconn_set_ipaddr_from_hostname(server);
	if (rc)
		smbfs_dbg("failed to resolve hostname, rc=%d\n", rc);

	server_unlock(server);
}

/*
 * Update the tcpStatus for the server.
 * This is used to signal the cifsd thread to call cifs_reconnect
 * ONLY cifsd thread should call cifs_reconnect. For any other
 * thread, use this function
 *
 * @server: the tcp ses for which reconnect is needed
 * @all_channels: if this needs to be done for all channels
 */
void
cifs_signal_cifsd_for_reconnect(struct smbfs_server_info *server,
				bool all_channels)
{
	struct smbfs_server_info *pserver;
	struct smbfs_ses *ses;
	int i;

	/* If server is a channel, select the primary channel */
	pserver = IS_CHANNEL(server) ? server->primary : server;

	spin_lock(&g_servers_lock);
	if (!all_channels) {
		pserver->status = SMBFS_STATUS_NEED_RECONNECT;
		spin_unlock(&g_servers_lock);
		return;
	}

	list_for_each_entry(ses, &pserver->sessions, head) {
		spin_lock(&ses->channel_lock);
		for (i = 0; i < ses->channel_count; i++)
			ses->channels[i].server->status = SMBFS_STATUS_NEED_RECONNECT;
		spin_unlock(&ses->channel_lock);
	}
	spin_unlock(&g_servers_lock);
}

/*
 * Mark all sessions and tcons for reconnect.
 * IMPORTANT: make sure that this gets called only from
 * cifsd thread. For any other thread, use
 * cifs_signal_cifsd_for_reconnect
 *
 * @server: the tcp ses for which reconnect is needed
 * @server needs to be previously set to SMBFS_STATUS_NEED_RECONNECT.
 * @mark_smb_session: whether even sessions need to be marked
 */
void
cifs_mark_server_conns_for_reconnect(struct smbfs_server_info *server,
				      bool mark_smb_session)
{
	struct smbfs_server_info *pserver;
	struct smbfs_ses *ses, *nses;
	struct smbfs_tcon *tcon;

	/*
	 * before reconnecting the tcp session, mark the smb session (uid) and the tid bad so they
	 * are not used until reconnected.
	 */
	smbfs_dbg("marking necessary sessions and tcons for reconnect\n");

	/* If server is a channel, select the primary channel */
	pserver = IS_CHANNEL(server) ? server->primary : server;


	spin_lock(&g_servers_lock);
	list_for_each_entry_safe(ses, nses, &pserver->sessions, head) {
		/* check if iface is still active */
		if (!smbfs_channel_is_iface_active(ses, server)) {
			/*
			 * HACK: drop the lock before calling
			 * smbfs_channel_update_iface to avoid deadlock
			 */
			ses->count++;
			spin_unlock(&g_servers_lock);
			smbfs_channel_update_iface(ses, server);
			spin_lock(&g_servers_lock);
			ses->count--;
		}

		spin_lock(&ses->channel_lock);
		if (!mark_smb_session && smbfs_channel_needs_reconnect(ses, server))
			goto next_session;

		if (mark_smb_session)
			SET_ALL_CHANS_NEED_RECONNECT(ses);
		else
			smbfs_channel_set_need_reconnect(ses, server);

		/* If all channels need reconnect, then tcon needs reconnect */
		if (!mark_smb_session && !ALL_CHANNELS_NEED_RECONNECT(ses))
			goto next_session;

		ses->status = SMBFS_SES_STATUS_NEED_RECONNECT;

		list_for_each_entry(tcon, &ses->tcons, head) {
			set_tcon_flag(tcon, NEED_RECONNECT);
			tcon->status = SMBFS_TCON_STATUS_NEED_RECONNECT;
		}
		if (ses->tcon_ipc)
			ses->tcon_ipc->need_reconnect = true;

next_session:
		spin_unlock(&ses->channel_lock);
	}
	spin_unlock(&g_servers_lock);
}

static void
cifs_abort_connection(struct smbfs_server_info *server)
{
	struct smbfs_mid_entry *mid, *nmid;
	struct list_head retry_list;

	server->maxBuf = 0;
	server->max_read = 0;

	/* do not want to be sending data on a socket we are freeing */
	smbfs_dbg("tearing down socket\n");
	server_lock(server);
	if (server->ssocket) {
		smbfs_dbg("state: 0x%x, flags: 0x%lx\n", server->ssocket->state,
			 server->ssocket->flags);
		kernel_sock_shutdown(server->ssocket, SHUT_WR);
		smbfs_dbg("post shutdown state: 0x%x, flags: 0x%lx\n", server->ssocket->state,
			 server->ssocket->flags);
		sock_release(server->ssocket);
		server->ssocket = NULL;
	}
	server->seqn = 0;
	server->session_estab = false;
	kfree(server->sec.session_key.response);
	server->sec.session_key.response = NULL;
	server->sec.session_key.len = 0;
	server->lstrp = jiffies;

	/* mark submitted MIDs for retry and issue callback */
	INIT_LIST_HEAD(&retry_list);
	
	smbfs_dbg("moving mids to private list\n");
	spin_lock(&g_mid_lock);
	list_for_each_entry_safe(mid, nmid, &server->pending_mids, head) {
		kref_get(&mid->refcount);
		if (mid->state == MID_REQUEST_SUBMITTED)
			mid->state = MID_RETRY_NEEDED;
		list_move(&mid->head, &retry_list);
		mid->flags |= MID_DELETED;
	}
	spin_unlock(&g_mid_lock);
	server_unlock(server);

	smbfs_dbg("issuing mid callbacks\n");
	list_for_each_entry_safe(mid, nmid, &retry_list, qhead) {
		list_del_init(&mid->head);
		mid->callback(mid);
		cifs_mid_q_entry_release(mid);
	}

	if (cifs_rdma_enabled(server)) {
		server_lock(server);
		smbd_destroy(server);
		server_unlock(server);
	}
}

static bool cifs_server_needs_reconnect(struct smbfs_server_info *server, int num_targets)
{
	spin_lock(&g_servers_lock);
	server->nr_targets = num_targets;
	if (server->status == SMBFS_STATUS_EXITING) {
		/* the demux thread will exit normally next time through the loop */
		spin_unlock(&g_servers_lock);
		wake_up(&server->response_q);
		return false;
	}

	smbfs_dbg("Mark tcp session as need reconnect\n");
	trace_smb3_reconnect(server->current_mid, server->conn_id,
			     server->hostname);
	server->status = SMBFS_STATUS_NEED_RECONNECT;

	spin_unlock(&g_servers_lock);
	return true;
}

/*
 * cifs tcp session reconnection
 *
 * mark tcp session as reconnecting so temporarily locked
 * mark all smb sessions as reconnecting for tcp session
 * reconnect tcp session
 * wake up waiters on reconnection? - (not needed currently)
 *
 * if mark_smb_session is passed as true, unconditionally mark
 * the smb session (and tcon) for reconnect as well. This value
 * doesn't really matter for non-multichannel scenario.
*/
static int __cifs_reconnect(struct smbfs_server_info *server,
			    bool mark_smb_session)
{
	int rc = 0;

	if (!cifs_server_needs_reconnect(server, 1))
		return 0;

	cifs_mark_server_conns_for_reconnect(server, mark_smb_session);

	cifs_abort_connection(server);

	do {
		try_to_freeze();
		server_lock(server);

		if (!cifs_swn_set_server_dstaddr(server)) {
			/* resolve the hostname again to make sure that IP address is up-to-date */
			rc = reconn_set_ipaddr_from_hostname(server);
			smbfs_dbg("reconn_set_ipaddr_from_hostname: rc=%d\n", rc);
		}

		if (cifs_rdma_enabled(server))
			rc = smbd_reconnect(server);
		else
			rc = generic_ip_connect(server);
		if (rc) {
			server_unlock(server);
			smbfs_dbg("reconnect error %d\n", rc);
			msleep(3000);
		} else {
			atomic_inc(&g_server_reconnect_count);
			set_credits(server, 1);
			spin_lock(&g_servers_lock);
			if (server->status != SMBFS_STATUS_EXITING)
				server->status = SMBFS_STATUS_NEED_NEGOTIATE;
			spin_unlock(&g_servers_lock);
			cifs_swn_reset_server_dstaddr(server);
			server_unlock(server);
			mod_delayed_work(cifsiod_wq, &server->reconnect, 0);
		}
	} while (server->status == SMBFS_STATUS_NEED_RECONNECT);

	spin_lock(&g_servers_lock);
	if (server->status == SMBFS_STATUS_NEED_NEGOTIATE)
		mod_delayed_work(cifsiod_wq, &server->echo, 0);
	spin_unlock(&g_servers_lock);

	wake_up(&server->response_q);
	return rc;
}

#ifdef CONFIG_SMBFS_DFS_UPCALL
static int __reconnect_target_unlocked(struct smbfs_server_info *server, const char *target)
{
	int rc;
	char *hostname;

	if (!cifs_swn_set_server_dstaddr(server)) {
		if (server->hostname != target) {
			hostname = extract_hostname(target);
			if (!IS_ERR(hostname)) {
				kfree(server->hostname);
				server->hostname = hostname;
			} else {
				smbfs_dbg("couldn't extract hostname or address from dfs target: %ld\n",
					  PTR_ERR(hostname));
				smbfs_dbg("default to last target server: %s\n",
					  server->hostname);
			}
		}
		/* resolve the hostname again to make sure that IP address is up-to-date. */
		rc = reconn_set_ipaddr_from_hostname(server);
		smbfs_dbg("reconn_set_ipaddr_from_hostname: rc=%d\n", rc);
	}
	/* Reconnect the socket */
	if (cifs_rdma_enabled(server))
		rc = smbd_reconnect(server);
	else
		rc = generic_ip_connect(server);

	return rc;
}

static int reconnect_target_unlocked(struct smbfs_server_info *server, struct dfs_cache_tgt_list *tl,
				     struct dfs_cache_tgt_iterator **target_hint)
{
	int rc;
	struct dfs_cache_tgt_iterator *tit;

	*target_hint = NULL;

	/* If dfs target list is empty, then reconnect to last server */
	tit = dfs_cache_get_tgt_iterator(tl);
	if (!tit)
		return __reconnect_target_unlocked(server, server->hostname);

	/* Otherwise, try every dfs target in @tl */
	for (; tit; tit = dfs_cache_get_next_tgt(tl, tit)) {
		rc = __reconnect_target_unlocked(server, dfs_cache_get_tgt_name(tit));
		if (!rc) {
			*target_hint = tit;
			break;
		}
	}
	return rc;
}

static int reconnect_dfs_server(struct smbfs_server_info *server)
{
	int rc = 0;
	const char *refpath = server->current_fullpath + 1;
	struct dfs_cache_tgt_list tl = DFS_CACHE_TGT_LIST_INIT(tl);
	struct dfs_cache_tgt_iterator *target_hint = NULL;
	int num_targets = 0;

	/*
	 * Determine the number of dfs targets the referral path in @cifs_sb resolves to.
	 *
	 * smb2_reconnect() needs to know how long it should wait based upon the number of dfs
	 * targets (server->nr_targets).  It's also possible that the cached referral was cleared
	 * through /proc/fs/smbfs/dfscache or the target list is empty due to server settings after
	 * refreshing the referral, so, in this case, default it to 1.
	 */
	if (!dfs_cache_noreq_find(refpath, NULL, &tl))
		num_targets = dfs_cache_get_nr_tgts(&tl);
	if (!num_targets)
		num_targets = 1;

	if (!cifs_server_needs_reconnect(server, num_targets))
		return 0;

	/*
	 * Unconditionally mark all sessions & tcons for reconnect as we might be connecting to a
	 * different server or share during failover.  It could be improved by adding some logic to
	 * only do that in case it connects to a different server or share, though.
	 */
	cifs_mark_server_conns_for_reconnect(server, true);

	cifs_abort_connection(server);

	do {
		try_to_freeze();
		server_lock(server);

		rc = reconnect_target_unlocked(server, &tl, &target_hint);
		if (rc) {
			/* Failed to reconnect socket */
			server_unlock(server);
			smbfs_dbg("reconnect error %d\n", rc);
			msleep(3000);
			continue;
		}
		/*
		 * Socket was created.  Update tcp session status to SMBFS_STATUS_NEED_NEGOTIATE so that a
		 * process waiting for reconnect will know it needs to re-establish session and tcon
		 * through the reconnected target server.
		 */
		atomic_inc(&g_server_reconnect_count);
		set_credits(server, 1);
		spin_lock(&g_servers_lock);
		if (server->status != SMBFS_STATUS_EXITING)
			server->status = SMBFS_STATUS_NEED_NEGOTIATE;
		spin_unlock(&g_servers_lock);
		cifs_swn_reset_server_dstaddr(server);
		server_unlock(server);
		mod_delayed_work(cifsiod_wq, &server->reconnect, 0);
	} while (server->status == SMBFS_STATUS_NEED_RECONNECT);

	if (target_hint)
		dfs_cache_noreq_update_tgthint(refpath, target_hint);

	dfs_cache_free_tgts(&tl);

	/* Need to set up echo worker again once connection has been established */
	spin_lock(&g_servers_lock);
	if (server->status == SMBFS_STATUS_NEED_NEGOTIATE)
		mod_delayed_work(cifsiod_wq, &server->echo, 0);

	spin_unlock(&g_servers_lock);

	wake_up(&server->response_q);
	return rc;
}

int cifs_reconnect(struct smbfs_server_info *server, bool mark_smb_session)
{
	/* If tcp session is not an dfs connection, then reconnect to last target server */
	spin_lock(&g_servers_lock);
	if (!server->is_dfs_conn) {
		spin_unlock(&g_servers_lock);
		return __cifs_reconnect(server, mark_smb_session);
	}
	spin_unlock(&g_servers_lock);

	mutex_lock(&server->refpath_lock);
	if (!server->origin_fullpath || !server->leaf_fullpath) {
		mutex_unlock(&server->refpath_lock);
		return __cifs_reconnect(server, mark_smb_session);
	}
	mutex_unlock(&server->refpath_lock);

	return reconnect_dfs_server(server);
}
#else
int cifs_reconnect(struct smbfs_server_info *server, bool mark_smb_session)
{
	return __cifs_reconnect(server, mark_smb_session);
}
#endif

static void
cifs_echo_request(struct work_struct *work)
{
	int rc;
	struct smbfs_server_info *server = container_of(work,
					struct smbfs_server_info, echo.work);

	/*
	 * We cannot send an echo if it is disabled.
	 * Also, no need to ping if we got a response recently.
	 */

	if (server->status == SMBFS_STATUS_NEED_RECONNECT ||
	    server->status == SMBFS_STATUS_EXITING ||
	    server->status == SMBFS_STATUS_NEW ||
	    (server->ops->can_echo && !server->ops->can_echo(server)) ||
	    time_before(jiffies, server->lstrp + server->echo_interval - HZ))
		goto requeue_echo;

	rc = server->ops->echo ? server->ops->echo(server) : -ENOSYS;
	if (rc)
		smbfs_dbg("Unable to send echo request to server '%s'\n",
			 server->hostname);

	/* Check witness registrations */
	cifs_swn_check();

requeue_echo:
	queue_delayed_work(cifsiod_wq, &server->echo, server->echo_interval);
}

static bool
allocate_buffers(struct smbfs_server_info *server)
{
	if (!server->bigbuf) {
		server->bigbuf = (char *)cifs_buf_get();
		if (!server->bigbuf) {
			smbfs_server_log(server, "No memory for large SMB response\n");
			msleep(3000);
			/* retry will check if exiting */
			return false;
		}
	} else if (server->large_buf) {
		/* we are reusing a dirty large buf, clear its start */
		memset(server->bigbuf, 0, HEADER_SIZE(server));
	}

	if (!server->smallbuf) {
		server->smallbuf = (char *)cifs_small_buf_get();
		if (!server->smallbuf) {
			smbfs_server_log(server, "No memory for SMB response\n");
			msleep(1000);
			/* retry will check if exiting */
			return false;
		}
		/* beginning of smb buffer is cleared in our buf_get */
	} else {
		/* if existing small buf clear beginning */
		memset(server->smallbuf, 0, HEADER_SIZE(server));
	}

	return true;
}

static bool
server_unresponsive(struct smbfs_server_info *server)
{
	/*
	 * We need to wait 3 echo intervals to make sure we handle such
	 * situations right:
	 * 1s client sends a normal SMB request
	 * 2s client gets a response
	 * 30s echo workqueue job pops, and decides we got a response recently
	 *     and don't need to send another
	 * ...
	 * 65s kernel_recvmsg times out, and we see that we haven't gotten
	 *     a response in >60s.
	 */
	spin_lock(&g_servers_lock);
	if ((server->status == SMBFS_STATUS_GOOD ||
	    server->status == SMBFS_STATUS_NEED_NEGOTIATE) &&
	    (!server->ops->can_echo || server->ops->can_echo(server)) &&
	    time_after(jiffies, server->lstrp + 3 * server->echo_interval)) {
		spin_unlock(&g_servers_lock);
		smbfs_server_log(server, "has not responded in %lu seconds. Reconnecting...\n",
			 (3 * server->echo_interval) / HZ);
		cifs_reconnect(server, false);
		return true;
	}
	spin_unlock(&g_servers_lock);

	return false;
}

static inline bool
zero_credits(struct smbfs_server_info *server)
{
	int val;

	spin_lock(&server->req_lock);
	val = server->credits + server->echo_credits + server->oplock_credits;
	if (server->in_flight == 0 && val == 0) {
		spin_unlock(&server->req_lock);
		return true;
	}
	spin_unlock(&server->req_lock);
	return false;
}

static int
cifs_readv_from_socket(struct smbfs_server_info *server, struct msghdr *smb_msg)
{
	int length = 0;
	int total_read;

	smb_msg->msg_control = NULL;
	smb_msg->msg_controllen = 0;

	for (total_read = 0; msg_data_left(smb_msg); total_read += length) {
		try_to_freeze();

		/* reconnect if no credits and no requests in flight */
		if (zero_credits(server)) {
			cifs_reconnect(server, false);
			return -ECONNABORTED;
		}

		if (server_unresponsive(server))
			return -ECONNABORTED;
		if (cifs_rdma_enabled(server) && server->smbd_conn)
			length = smbd_recv(server->smbd_conn, smb_msg);
		else
			length = sock_recvmsg(server->ssocket, smb_msg, 0);

		spin_lock(&g_servers_lock);
		if (server->status == SMBFS_STATUS_EXITING) {
			spin_unlock(&g_servers_lock);
			return -ESHUTDOWN;
		}

		if (server->status == SMBFS_STATUS_NEED_RECONNECT) {
			spin_unlock(&g_servers_lock);
			cifs_reconnect(server, false);
			return -ECONNABORTED;
		}
		spin_unlock(&g_servers_lock);

		if (length == -ERESTARTSYS ||
		    length == -EAGAIN ||
		    length == -EINTR) {
			/*
			 * Minimum sleep to prevent looping, allowing socket
			 * to clear and app threads to set tcpStatus
			 * SMBFS_STATUS_NEED_RECONNECT if server hung.
			 */
			usleep_range(1000, 2000);
			length = 0;
			continue;
		}

		if (length <= 0) {
			smbfs_dbg("Received no data or error: %d\n", length);
			cifs_reconnect(server, false);
			return -ECONNABORTED;
		}
	}
	return total_read;
}

int
cifs_read_from_socket(struct smbfs_server_info *server, char *buf,
		      unsigned int to_read)
{
	struct msghdr smb_msg;
	struct kvec iov = {.iov_base = buf, .iov_len = to_read};
	iov_iter_kvec(&smb_msg.msg_iter, READ, &iov, 1, to_read);

	return cifs_readv_from_socket(server, &smb_msg);
}

ssize_t
cifs_discard_from_socket(struct smbfs_server_info *server, size_t to_read)
{
	struct msghdr smb_msg;

	/*
	 *  iov_iter_discard already sets smb_msg.type and count and iov_offset
	 *  and cifs_readv_from_socket sets msg_control and msg_controllen
	 *  so little to initialize in struct msghdr
	 */
	smb_msg.msg_name = NULL;
	smb_msg.msg_namelen = 0;
	iov_iter_discard(&smb_msg.msg_iter, READ, to_read);

	return cifs_readv_from_socket(server, &smb_msg);
}

int
cifs_read_page_from_socket(struct smbfs_server_info *server, struct page *page,
	unsigned int page_offset, unsigned int to_read)
{
	struct msghdr smb_msg;
	struct bio_vec bv = {
		.bv_page = page, .bv_len = to_read, .bv_offset = page_offset};
	iov_iter_bvec(&smb_msg.msg_iter, READ, &bv, 1, to_read);
	return cifs_readv_from_socket(server, &smb_msg);
}

static bool
is_smb_response(struct smbfs_server_info *server, unsigned char type)
{
	/*
	 * The first byte big endian of the length field,
	 * is actually not part of the length but the type
	 * with the most common, zero, as regular data.
	 */
	switch (type) {
	case RFC1002_SESSION_MESSAGE:
		/* Regular SMB response */
		return true;
	case RFC1002_SESSION_KEEP_ALIVE:
		smbfs_dbg("RFC 1002 session keep alive\n");
		break;
	case RFC1002_POSITIVE_SESSION_RESPONSE:
		smbfs_dbg("RFC 1002 positive session response\n");
		break;
	case RFC1002_NEGATIVE_SESSION_RESPONSE:
		/*
		 * We get this from Windows 98 instead of an error on
		 * SMB negprot response.
		 */
		smbfs_dbg("RFC 1002 negative session response\n");
		/* give server a second to clean up */
		msleep(1000);
		/*
		 * Always try 445 first on reconnect since we get NACK
		 * on some if we ever connected to port 139 (the NACK
		 * is since we do not begin with RFC1001 session
		 * initialize frame).
		 */
		cifs_set_port((struct sockaddr *)&server->dstaddr, SMB_PORT);
		cifs_reconnect(server, true);
		break;
	default:
		smbfs_server_log(server, "RFC 1002 unknown response type 0x%x\n", type);
		cifs_reconnect(server, true);
	}

	return false;
}

void
dequeue_mid(struct smbfs_mid_entry *mid)
{
#ifdef CONFIG_SMBFS_STATS_EXTRA
	mid->when_received = jiffies;
#endif
	if (mid->flags & MID_DELETED) {
		pr_warn_once("trying to dequeue a deleted mid\n");
		return;
	}

	spin_lock(&g_mid_lock);
	list_del_init(&mid->head);
	mid->flags |= MID_DELETED;
	spin_unlock(&g_mid_lock);
}

static unsigned int
smb2_get_credits_from_hdr(char *buffer, struct smbfs_server_info *server)
{
	struct smb2_hdr *shdr = (struct smb2_hdr *)buffer;

	/*
	 * SMB1 does not use credits.
	 */
	if (server->settings->header_preamble_size)
		return 0;

	return le16_to_cpu(shdr->CreditRequest);
}

static void
handle_mid(struct smbfs_mid_entry *mid, struct smbfs_server_info *server, char *buf)
{
	if (server->ops->check_trans2 &&
	    server->ops->check_trans2(mid, server, buf))
		return;

	mid->credits_received = smb2_get_credits_from_hdr(buf, server);
	mid->resp_buf = buf;
	mid->has_large_buf = server->large_buf;

	/* Was previous buf put in mpx struct for multi-rsp? */
	if (!mid->has_multi_rsp) {
		/* smb buffer will be freed by user thread */
		if (server->large_buf)
			server->bigbuf = NULL;
		else
			server->smallbuf = NULL;
	}

	dequeue_mid(mid);
}

static void clean_demultiplex_info(struct smbfs_server_info *server)
{
	int length;

	/* take it off the list, if it's not already */
	spin_lock(&g_servers_lock);
	list_del_init(&server->head);
	spin_unlock(&g_servers_lock);

	cancel_delayed_work_sync(&server->echo);
	cancel_delayed_work_sync(&server->resolve);

	spin_lock(&g_servers_lock);
	server->status = SMBFS_STATUS_EXITING;
	spin_unlock(&g_servers_lock);
	wake_up_all(&server->response_q);

	/* check if we have blocked requests that need to free */
	spin_lock(&server->req_lock);
	if (server->credits <= 0)
		server->credits = 1;
	spin_unlock(&server->req_lock);
	/*
	 * Although there should not be any requests blocked on this queue it
	 * can not hurt to be paranoid and try to wake up requests that may
	 * haven been blocked when more than 50 at time were on the wire to the
	 * same server - they now will see the session is in exit state and get
	 * out of SendReceive.
	 */
	wake_up_all(&server->request_q);
	/* give those requests time to exit */
	msleep(125);
	if (cifs_rdma_enabled(server))
		smbd_destroy(server);
	if (server->ssocket) {
		sock_release(server->ssocket);
		server->ssocket = NULL;
	}

	if (!list_empty(&server->pending_mids)) {
		struct list_head dispose_list;
		struct smbfs_mid_entry *mid_entry;
		struct list_head *tmp, *tmp2;

		INIT_LIST_HEAD(&dispose_list);
		spin_lock(&g_mid_lock);
		list_for_each_safe(tmp, tmp2, &server->pending_mids) {
			mid_entry = list_entry(tmp, struct smbfs_mid_entry, qhead);
			smbfs_dbg("Clearing mid %llu\n", mid_entry->mid);
			kref_get(&mid_entry->refcount);
			mid_entry->state = MID_SHUTDOWN;
			list_move(&mid_entry->head, &dispose_list);
			mid_entry->flags |= MID_DELETED;
		}
		spin_unlock(&g_mid_lock);

		/* now walk dispose list and issue callbacks */
		list_for_each_safe(tmp, tmp2, &dispose_list) {
			mid_entry = list_entry(tmp, struct smbfs_mid_entry, qhead);
			smbfs_dbg("Callback mid %llu\n", mid_entry->mid);
			list_del_init(&mid_entry->head);
			mid_entry->callback(mid_entry);
			cifs_mid_q_entry_release(mid_entry);
		}
		/* 1/8th of sec is more than enough time for them to exit */
		msleep(125);
	}

	if (!list_empty(&server->pending_mids)) {
		/*
		 * mpx threads have not exited yet give them at least the smb
		 * send timeout time for long ops.
		 *
		 * Due to delays on oplock break requests, we need to wait at
		 * least 45 seconds before giving up on a request getting a
		 * response and going ahead and killing cifsd.
		 */
		smbfs_dbg("Wait for exit from demultiplex thread\n");
		msleep(46000);
		/*
		 * If threads still have not exited they are probably never
		 * coming home not much else we can do but free the memory.
		 */
	}

#ifdef CONFIG_SMBFS_DFS_UPCALL
	kfree(server->origin_fullpath);
	kfree(server->leaf_fullpath);
#endif
	kfree(server);

	length = atomic_dec_return(&g_server_alloc_count);
	if (length > 0)
		mempool_resize(cifs_req_poolp, length + cifs_min_rcv);
}

static int
standard_receive3(struct smbfs_server_info *server, struct smbfs_mid_entry *mid)
{
	int length;
	char *buf = server->smallbuf;
	unsigned int pdu_length = server->pdu_size;

	/* make sure this will fit in a large buffer */
	if (pdu_length > max_buf_size + MAX_HEADER_SIZE(server) -
		server->settings->header_preamble_size) {
		smbfs_server_log(server, "SMB response too long (%u bytes)\n", pdu_length);
		cifs_reconnect(server, true);
		return -ECONNABORTED;
	}

	/* switch to large buffer if too big for a small one */
	if (pdu_length > MAX_SMBFS_SMALL_BUFFER_SIZE - 4) {
		server->large_buf = true;
		memcpy(server->bigbuf, buf, server->total_read);
		buf = server->bigbuf;
	}

	/* now read the rest */
	length = cifs_read_from_socket(server, buf + HEADER_SIZE(server) - 1,
				       pdu_length - HEADER_SIZE(server) + 1
				       + server->settings->header_preamble_size);

	if (length < 0)
		return length;
	server->total_read += length;

	smbfs_dump_smb(buf, server->total_read);

	return cifs_handle_standard(server, mid);
}

int
cifs_handle_standard(struct smbfs_server_info *server, struct smbfs_mid_entry *mid)
{
	char *buf = server->large_buf ? server->bigbuf : server->smallbuf;
	int rc;

	/*
	 * We know that we received enough to get to the MID as we
	 * checked the pdu_length earlier. Now check to see
	 * if the rest of the header is OK.
	 *
	 * 48 bytes is enough to display the header and a little bit
	 * into the payload for debugging purposes.
	 */
	rc = server->ops->check_message(buf, server->total_read, server);

	if (server->ops->is_session_expired &&
	    server->ops->is_session_expired(buf)) {
		cifs_reconnect(server, true);
		return -1;
	}

	if (server->ops->is_status_pending &&
	    server->ops->is_status_pending(buf, server))
		return -1;

	if (!mid)
		return rc;

	if (unlikely(rc)) {
		smbfs_dump_mem("Bad SMB: ", buf,
			      min_t(unsigned int, server->total_read, 48));
		/* mid is malformed */
		mid->state = MID_RESPONSE_MALFORMED;
	} else {
		mid->state = MID_RESPONSE_RECEIVED;
	}

	handle_mid(mid, server, buf);
	return 0;
}

static void
smb2_add_credits_from_hdr(char *buffer, struct smbfs_server_info *server)
{
	struct smb2_hdr *shdr = (struct smb2_hdr *)buffer;
	int scredits, in_flight;

	/*
	 * SMB1 does not use credits.
	 */
	if (server->settings->header_preamble_size)
		return;

	if (shdr->CreditRequest) {
		spin_lock(&server->req_lock);
		server->credits += le16_to_cpu(shdr->CreditRequest);
		scredits = server->credits;
		in_flight = server->in_flight;
		spin_unlock(&server->req_lock);
		wake_up(&server->request_q);

		trace_smb3_hdr_credits(server->current_mid,
				server->conn_id, server->hostname, scredits,
				le16_to_cpu(shdr->CreditRequest), in_flight);
		smbfs_server_dbg(server, "added %u credits total=%d\n",
				 le16_to_cpu(shdr->CreditRequest), scredits);
	}
}


static int
cifs_demultiplex_thread(void *p)
{
	int i, num_mids, length;
	struct smbfs_server_info *server = p;
	unsigned int pdu_length;
	unsigned int next_offset;
	char *buf = NULL;
	struct task_struct *task_to_wake = NULL;
	struct smbfs_mid_entry *mids[SMBFS_MAX_COMPOUND];
	char *bufs[SMBFS_MAX_COMPOUND];
	unsigned int noreclaim_flag, num_io_timeout = 0;

	noreclaim_flag = memalloc_noreclaim_save();
	smbfs_dbg("Demultiplex PID: %d\n", task_pid_nr(current));

	length = atomic_inc_return(&g_server_alloc_count);
	if (length > 1)
		mempool_resize(cifs_req_poolp, length + cifs_min_rcv);

	set_freezable();
	allow_kernel_signal(SIGKILL);
	while (server->status != SMBFS_STATUS_EXITING) {
		if (try_to_freeze())
			continue;

		if (!allocate_buffers(server))
			continue;

		server->large_buf = false;
		buf = server->smallbuf;
		pdu_length = 4; /* enough to get RFC1001 header */

		length = cifs_read_from_socket(server, buf, pdu_length);
		if (length < 0)
			continue;

		if (server->settings->header_preamble_size == 0)
			server->total_read = 0;
		else
			server->total_read = length;

		/*
		 * The right amount was read from socket - 4 bytes,
		 * so we can now interpret the length field.
		 */
		pdu_length = get_rfc1002_len(buf);

		smbfs_dbg("RFC1002 header 0x%x\n", pdu_length);
		if (!is_smb_response(server, buf[0]))
			continue;
next_pdu:
		server->pdu_size = pdu_length;

		/* make sure we have enough to get to the MID */
		if (server->pdu_size < HEADER_SIZE(server) - 1 -
		    server->settings->header_preamble_size) {
			smbfs_server_log(server, "SMB response too short (%u bytes)\n",
				 server->pdu_size);
			cifs_reconnect(server, true);
			continue;
		}

		/* read down to the MID */
		length = cifs_read_from_socket(server,
			     buf + server->settings->header_preamble_size,
			     HEADER_SIZE(server) - 1
			     - server->settings->header_preamble_size);
		if (length < 0)
			continue;
		server->total_read += length;

		if (server->ops->next_header) {
			next_offset = server->ops->next_header(buf);
			if (next_offset)
				server->pdu_size = next_offset;
		}

		memset(mids, 0, sizeof(mids));
		memset(bufs, 0, sizeof(bufs));
		num_mids = 0;

		if (server->ops->is_transform_hdr &&
		    server->ops->receive_transform &&
		    server->ops->is_transform_hdr(buf)) {
			length = server->ops->receive_transform(server,
								mids,
								bufs,
								&num_mids);
		} else {
			mids[0] = server->ops->find_mid(server, buf);
			bufs[0] = buf;
			num_mids = 1;

			if (!mids[0] || !mids[0]->receive)
				length = standard_receive3(server, mids[0]);
			else
				length = mids[0]->receive(server, mids[0]);
		}

		if (length < 0) {
			for (i = 0; i < num_mids; i++)
				if (mids[i])
					cifs_mid_q_entry_release(mids[i]);
			continue;
		}

		if (server->ops->is_status_io_timeout &&
		    server->ops->is_status_io_timeout(buf)) {
			num_io_timeout++;
			if (num_io_timeout > NUM_STATUS_IO_TIMEOUT) {
				cifs_reconnect(server, false);
				num_io_timeout = 0;
				continue;
			}
		}

		server->lstrp = jiffies;

		for (i = 0; i < num_mids; i++) {
			if (mids[i] != NULL) {
				mids[i]->resp_buf_size = server->pdu_size;

				if (bufs[i] && server->ops->is_network_name_deleted)
					server->ops->is_network_name_deleted(bufs[i],
									server);

				if (!mids[i]->has_multi_rsp || mids[i]->has_multi_end)
					mids[i]->callback(mids[i]);

				cifs_mid_q_entry_release(mids[i]);
			} else if (server->ops->is_oplock_break &&
				   server->ops->is_oplock_break(bufs[i],
								server)) {
				smb2_add_credits_from_hdr(bufs[i], server);
				smbfs_dbg("Received oplock break\n");
			} else {
				smbfs_server_log(server, "No task to wake, unknown frame received! NumMids %d\n",
						atomic_read(&g_mid_count));
				smbfs_dump_mem("Received Data is: ", bufs[i],
					      HEADER_SIZE(server));
				smb2_add_credits_from_hdr(bufs[i], server);
#ifdef CONFIG_SMBFS_DEBUG_EXTRA
				smbfs_dump_detail(bufs[i], server);
				smbfs_dump_mids(server);
#endif /* SMBFS_DEBUG_EXTRA */
			}
		}

		if (pdu_length > server->pdu_size) {
			if (!allocate_buffers(server))
				continue;
			pdu_length -= server->pdu_size;
			server->total_read = 0;
			server->large_buf = false;
			buf = server->smallbuf;
			goto next_pdu;
		}
	} /* end while !EXITING */

	/* buffer usually freed in free_mid - need to free it here on exit */
	cifs_buf_release(server->bigbuf);
	if (server->smallbuf) /* no sense logging a debug message if NULL */
		cifs_small_buf_release(server->smallbuf);

	task_to_wake = xchg(&server->task, NULL);
	clean_demultiplex_info(server);

	/* if server->task was NULL then wait for a signal before exiting */
	if (!task_to_wake) {
		set_current_state(TASK_INTERRUPTIBLE);
		while (!signal_pending(current)) {
			schedule();
			set_current_state(TASK_INTERRUPTIBLE);
		}
		set_current_state(TASK_RUNNING);
	}

	memalloc_noreclaim_restore(noreclaim_flag);
	module_put_and_kthread_exit(0);
}

/*
 * Returns true if srcaddr isn't specified and rhs isn't specified, or
 * if srcaddr is specified and matches the IP address of the rhs argument
 */
bool
cifs_match_ipaddr(struct sockaddr *srcaddr, struct sockaddr *rhs)
{
	switch (srcaddr->sa_family) {
	case AF_UNSPEC:
		return (rhs->sa_family == AF_UNSPEC);
	case AF_INET: {
		struct sockaddr_in *saddr4 = (struct sockaddr_in *)srcaddr;
		struct sockaddr_in *vaddr4 = (struct sockaddr_in *)rhs;
		return (saddr4->sin_addr.s_addr == vaddr4->sin_addr.s_addr);
	}
	case AF_INET6: {
		struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *)srcaddr;
		struct sockaddr_in6 *vaddr6 = (struct sockaddr_in6 *)rhs;
		return ipv6_addr_equal(&saddr6->sin6_addr, &vaddr6->sin6_addr);
	}
	default:
		WARN_ON(1);
		return false; /* don't expect to be here */
	}
}

/*
 * If no port is specified in addr structure, we try to match with 445 port
 * and if it fails - with 139 ports. It should be called only if address
 * families of server and addr are equal.
 */
static bool
match_port(struct smbfs_server_info *server, struct sockaddr *addr)
{
	__be16 port, *sport;

	/* SMBDirect manages its own ports, don't match it here */
	if (server->rdma)
		return true;

	switch (addr->sa_family) {
	case AF_INET:
		sport = &((struct sockaddr_in *) &server->dstaddr)->sin_port;
		port = ((struct sockaddr_in *) addr)->sin_port;
		break;
	case AF_INET6:
		sport = &((struct sockaddr_in6 *) &server->dstaddr)->sin6_port;
		port = ((struct sockaddr_in6 *) addr)->sin6_port;
		break;
	default:
		WARN_ON(1);
		return false;
	}

	if (!port) {
		port = htons(SMB_PORT);
		if (port == *sport)
			return true;

		port = htons(RFC1001_PORT);
	}

	return port == *sport;
}

static bool
match_address(struct smbfs_server_info *server, struct sockaddr *addr,
	      struct sockaddr *srcaddr)
{
	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
		struct sockaddr_in *srv_addr4 =
					(struct sockaddr_in *)&server->dstaddr;

		if (addr4->sin_addr.s_addr != srv_addr4->sin_addr.s_addr)
			return false;
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
		struct sockaddr_in6 *srv_addr6 =
					(struct sockaddr_in6 *)&server->dstaddr;

		if (!ipv6_addr_equal(&addr6->sin6_addr,
				     &srv_addr6->sin6_addr))
			return false;
		if (addr6->sin6_scope_id != srv_addr6->sin6_scope_id)
			return false;
		break;
	}
	default:
		WARN_ON(1);
		return false; /* don't expect to be here */
	}

	if (!cifs_match_ipaddr(srcaddr, (struct sockaddr *)&server->srcaddr))
		return false;

	return true;
}

static bool
match_security(struct smbfs_server_info *server, struct smb3_fs_context *ctx)
{
	/*
	 * The select_sectype function should either return the ctx->sectype
	 * that was specified, or "Unspecified" if that sectype was not
	 * compatible with the given NEGOTIATE request.
	 */
	if (server->ops->select_sectype(server, ctx->sectype)
	     == SMBFS_SECURITY_UNSPECIFIED)
		return false;

	/*
	 * Now check if signing mode is acceptable. No need to check
	 * security_flags at this point since if MUST_SIGN is set then
	 * the server->sec.signing_enabled had better be too.
	 */
	if (ctx->sign && !server->sec.signing_enabled)
		return false;

	return true;
}

static int match_server(struct smbfs_server_info *server, struct smb3_fs_context *ctx)
{
	struct sockaddr *addr = (struct sockaddr *)&ctx->dstaddr;

	if (ctx->nosharesock)
		return 0;

	/* this server does not share socket */
	if (server->nosharesock)
		return 0;

	/* If multidialect negotiation see if existing sessions match one */
	if (strcmp(ctx->vals->version_string, SMB3ANY_VERSION_STRING) == 0) {
		if (server->settings->protocol_id < SMB30_PROT_ID)
			return 0;
	} else if (strcmp(ctx->vals->version_string,
		   SMBDEFAULT_VERSION_STRING) == 0) {
		if (server->settings->protocol_id < SMB21_PROT_ID)
			return 0;
	} else if ((server->settings != ctx->vals) || (server->ops != ctx->ops))
		return 0;

	if (!net_eq(smbfs_net_ns(server), current->nsproxy->net_ns))
		return 0;

	if (strcasecmp(server->hostname, ctx->server_hostname))
		return 0;

	if (!match_address(server, addr,
			   (struct sockaddr *)&ctx->srcaddr))
		return 0;

	if (!match_port(server, addr))
		return 0;

	if (!match_security(server, ctx))
		return 0;

	if (server->echo_interval != ctx->echo_interval * HZ)
		return 0;

	if (server->rdma != ctx->rdma)
		return 0;

	if (server->sec.ignore_signature != ctx->ignore_signature)
		return 0;

	if (server->min_offload != ctx->min_offload)
		return 0;

	return 1;
}

struct smbfs_server_info *
smbfs_find_server(struct smb3_fs_context *ctx)
{
	struct smbfs_server_info *server;

	spin_lock(&g_servers_lock);
	list_for_each_entry(server, &g_servers_list, head) {
#ifdef CONFIG_SMBFS_DFS_UPCALL
		/*
		 * DFS failover implementation in cifs_reconnect() requires unique tcp sessions for
		 * DFS connections to do failover properly, so avoid sharing them with regular
		 * shares or even links that may connect to same server but having completely
		 * different failover targets.
		 */
		if (server->is_dfs_conn)
			continue;
#endif
		/*
		 * Skip ses channels since they're only handled in lower layers
		 * (e.g. cifs_send_recv).
		 */
		if (IS_CHANNEL(server) || !match_server(server, ctx))
			continue;

		++server->count;
		spin_unlock(&g_servers_lock);
		smbfs_dbg("Existing tcp session with server found\n");
		return server;
	}
	spin_unlock(&g_servers_lock);
	return NULL;
}

void
smbfs_put_server(struct smbfs_server_info *server, int from_reconnect)
{
	struct task_struct *task;

	spin_lock(&g_servers_lock);
	if (--server->count > 0) {
		spin_unlock(&g_servers_lock);
		return;
	}

	/* srv_count can never go negative */
	WARN_ON(server->count < 0);

	put_net(smbfs_net_ns(server));

	list_del_init(&server->head);
	spin_unlock(&g_servers_lock);

	/* For secondary channels, we pick up ref-count on the primary server */
	if (IS_CHANNEL(server))
		smbfs_put_server(server->primary, from_reconnect);

	cancel_delayed_work_sync(&server->echo);
	cancel_delayed_work_sync(&server->resolve);

	if (from_reconnect)
		/*
		 * Avoid deadlock here: reconnect work calls
		 * smbfs_put_server() at its end. Need to be sure
		 * that reconnect work does nothing with server pointer after
		 * that step.
		 */
		cancel_delayed_work(&server->reconnect);
	else
		cancel_delayed_work_sync(&server->reconnect);

	spin_lock(&g_servers_lock);
	server->status = SMBFS_STATUS_EXITING;
	spin_unlock(&g_servers_lock);

	cifs_crypto_secmech_release(server);

	kfree(server->sec.session_key.response);
	server->sec.session_key.response = NULL;
	server->sec.session_key.len = 0;
	kfree(server->hostname);

	task = xchg(&server->task, NULL);
	if (task)
		send_sig(SIGKILL, task, 1);
}

struct smbfs_server_info *
smbfs_get_server(struct smb3_fs_context *ctx,
		     struct smbfs_server_info *primary_server)
{
	struct smbfs_server_info *server = NULL;
	int rc;

	smbfs_dbg("UNC: %s\n", ctx->UNC);

	/* see if we already have a matching server */
	server = smbfs_find_server(ctx);
	if (server)
		return server;

	server = kzalloc(sizeof(struct smbfs_server_info), GFP_KERNEL);
	if (!server) {
		rc = -ENOMEM;
		goto out_err;
	}

	server->hostname = kstrdup(ctx->server_hostname, GFP_KERNEL);
	if (!server->hostname) {
		rc = -ENOMEM;
		goto out_err;
	}

	if (ctx->nosharesock)
		server->nosharesock = true;

	server->ops = ctx->ops;
	server->vals = ctx->vals;
	cifs_set_net_ns(server, get_net(current->nsproxy->net_ns));

	server->conn_id = atomic_inc_return(&g_server_next_id);
	server->noblockcnt = ctx->rootfs;
	server->noblocksnd = ctx->noblocksnd || ctx->rootfs;
	server->noautotune = ctx->noautotune;
	server->tcp_nodelay = ctx->sockopt_tcp_nodelay;
	server->rdma = ctx->rdma;
	server->in_flight = 0;
	server->max_in_flight = 0;
	server->credits = 1;
	if (primary_server) {
		spin_lock(&g_servers_lock);
		++primary_server->count;
		server->primary = primary_server;
		spin_unlock(&g_servers_lock);
	}
	init_waitqueue_head(&server->response_q);
	init_waitqueue_head(&server->request_q);
	INIT_LIST_HEAD(&server->pending_mids);
	mutex_init(&server->lock);
	memcpy(server->rfc1001_client_name,
		ctx->source_rfc1001_name, RFC1001_NAME_LEN_NUL);
	memcpy(server->rfc1001_name,
		ctx->target_rfc1001_name, RFC1001_NAME_LEN_NUL);
	server->session_estab = false;
	server->seqn = 0;
	server->reconnect_instance = 1;
	server->lstrp = jiffies;
	server->sec.compress_algo = cpu_to_le16(ctx->compression);
	spin_lock_init(&server->req_lock);
	INIT_LIST_HEAD(&server->head);
	INIT_LIST_HEAD(&server->head);
	INIT_DELAYED_WORK(&server->echo, cifs_echo_request);
	INIT_DELAYED_WORK(&server->resolve, cifs_resolve_server);
	INIT_DELAYED_WORK(&server->reconnect, smb2_reconnect_server);
	mutex_init(&server->reconnect_lock);
#ifdef CONFIG_SMBFS_DFS_UPCALL
	mutex_init(&server->refpath_lock);
#endif
	memcpy(&server->srcaddr, &ctx->srcaddr,
	       sizeof(server->srcaddr));
	memcpy(&server->dstaddr, &ctx->dstaddr,
		sizeof(server->dstaddr));
	if (ctx->use_client_guid)
		memcpy(server->client_guid, ctx->client_guid,
		       SMB2_CLIENT_GUID_SIZE);
	else
		generate_random_uuid(server->client_guid);
	/*
	 * at this point we are the only ones with the pointer
	 * to the struct since the kernel thread not created yet
	 * no need to spinlock this init of tcpStatus or srv_count
	 */
	server->status = SMBFS_STATUS_NEW;
	++server->srv_count;

	if (ctx->echo_interval >= SMBFS_ECHO_INTERVAL_MIN &&
		ctx->echo_interval <= SMBFS_ECHO_INTERVAL_MAX)
		server->echo_interval = ctx->echo_interval * HZ;
	else
		server->echo_interval = SMBFS_ECHO_INTERVAL_DEF * HZ;
	if (server->rdma) {
#ifndef CONFIG_SMBFS_SMB_DIRECT
		smbfs_log("CONFIG_SMBFS_SMB_DIRECT is not enabled\n");
		rc = -ENOENT;
		goto out_err_crypto_release;
#endif
		server->smbd_conn = smbd_get_connection(
			server, (struct sockaddr *)&ctx->dstaddr);
		if (server->smbd_conn) {
			smbfs_log("RDMA transport established\n");
			rc = 0;
			goto smbd_connected;
		} else {
			rc = -ENOENT;
			goto out_err_crypto_release;
		}
	}
	rc = ip_connect(server);
	if (rc < 0) {
		smbfs_log("Error connecting to socket. Aborting operation.\n");
		goto out_err_crypto_release;
	}
smbd_connected:
	/*
	 * since we're in a cifs function already, we know that
	 * this will succeed. No need for try_module_get().
	 */
	__module_get(THIS_MODULE);
	server->task = kthread_run(cifs_demultiplex_thread,
				  server, "cifsd");
	if (IS_ERR(server->task)) {
		rc = PTR_ERR(server->task);
		smbfs_log("error %d create cifsd thread\n", rc);
		module_put(THIS_MODULE);
		goto out_err_crypto_release;
	}
	server->min_offload = ctx->min_offload;
	/*
	 * at this point we are the only ones with the pointer
	 * to the struct since the kernel thread not created yet
	 * no need to spinlock this update of tcpStatus
	 */
	spin_lock(&g_servers_lock);
	server->status = SMBFS_STATUS_NEED_NEGOTIATE;
	spin_unlock(&g_servers_lock);

	if ((ctx->max_credits < 20) || (ctx->max_credits > 60000))
		server->max_credits = SMBFS_MAX_CREDITS_AVAILABLE;
	else
		server->max_credits = ctx->max_credits;

	server->nr_targets = 1;
	server->ignore_signature = ctx->ignore_signature;
	/* thread spawned, put it on the list */
	spin_lock(&g_servers_lock);
	list_add(&server->head, &g_servers_list);
	spin_unlock(&g_servers_lock);

	/* queue echo request delayed work */
	queue_delayed_work(cifsiod_wq, &server->echo, server->echo_interval);

	/* queue dns resolution delayed work */
	smbfs_dbg("next dns resolution scheduled for %d seconds in the future\n",
		  SMBFS_DNS_RESOLVE_INTERVAL_DEF);

	queue_delayed_work(cifsiod_wq, &server->resolve,
			   (SMBFS_DNS_RESOLVE_INTERVAL_DEF * HZ));

	return server;

out_err_crypto_release:
	cifs_crypto_secmech_release(server);

	put_net(smbfs_net_ns(server));

out_err:
	if (server) {
		if (IS_CHANNEL(server))
			smbfs_put_server(server->primary, false);
		kfree(server->hostname);
		if (server->ssocket)
			sock_release(server->ssocket);
		kfree(server);
	}
	return ERR_PTR(rc);
}

static int match_session(struct smbfs_ses *ses, struct smb3_fs_context *ctx)
{
	if (ctx->sectype != SMBFS_SECURITY_UNSPECIFIED &&
	    ctx->sectype != ses->sectype)
		return 0;

	/*
	 * If an existing session is limited to less channels than
	 * requested, it should not be reused
	 */
	spin_lock(&ses->channel_lock);
	if (ses->max_channels < ctx->max_channels) {
		spin_unlock(&ses->channel_lock);
		return 0;
	}
	spin_unlock(&ses->channel_lock);

	switch (ses->sectype) {
	case SMBFS_SECURITY_KERBEROS:
		if (!uid_eq(ctx->cred_uid, ses->cred_uid))
			return 0;
		break;
	default:
		/* NULL username means anonymous session */
		if (ses->user_name == NULL) {
			if (!ctx->nullauth)
				return 0;
			break;
		}

		/* anything else takes username/password */
		if (strncmp(ses->user_name,
			    ctx->username ? ctx->username : "",
			    CIFS_MAX_USERNAME_LEN))
			return 0;
		if ((ctx->username && strlen(ctx->username) != 0) &&
		    ses->password != NULL &&
		    strncmp(ses->password,
			    ctx->password ? ctx->password : "",
			    CIFS_MAX_PASSWORD_LEN))
			return 0;
	}
	return 1;
}

/**
 * cifs_setup_ipc - helper to setup the IPC tcon for the session
 * @ses: smb session to issue the request on
 * @ctx: the superblock configuration context to use for building the
 *       new tree connection for the IPC (interprocess communication RPC)
 *
 * A new IPC connection is made and stored in the session
 * tcon_ipc. The IPC tcon has the same lifetime as the session.
 */
static int
cifs_setup_ipc(struct smbfs_ses *ses, struct smb3_fs_context *ctx)
{
	int rc = 0, xid;
	struct smbfs_tcon *tcon;
	char unc[SMBFS_SERVER_NAME_LEN + sizeof("//x/IPC$")] = { 0 };
	bool seal = false;
	struct smbfs_server_info *server = ses->server;

	/*
	 * If the mount request that resulted in the creation of the
	 * session requires encryption, force IPC to be encrypted too.
	 */
	if (ctx->seal) {
		if (server->capabilities & SMB2_GLOBAL_CAP_ENCRYPTION)
			seal = true;
		else {
			smbfs_server_log(server, "IPC: server doesn't support encryption\n");
			return -EOPNOTSUPP;
		}
	}

	tcon = smbfs_tcon_alloc();
	if (tcon == NULL)
		return -ENOMEM;

	scnprintf(unc, sizeof(unc), "\\\\%s\\IPC$", server->hostname);

	xid = get_xid();
	tcon->ses = ses;
	set_tcon_flag(tcon, IS_IPC);
	set_tcon_flag(tcon, USE_SEAL);
	rc = server->ops->tree_connect(xid, ses, unc, tcon, ctx->local_nls);
	free_xid(xid);

	if (rc) {
		smbfs_server_log(server, "failed to connect to IPC (rc=%d)\n", rc);
		smbfs_tcon_free(tcon);
		goto out;
	}

	smbfs_dbg("IPC tcon rc=%d ipc tid=0x%x\n", rc, tcon->tid);

	ses->tcon_ipc = tcon;
out:
	return rc;
}

/**
 * cifs_free_ipc - helper to release the session IPC tcon
 * @ses: smb session to unmount the IPC from
 *
 * Needs to be called everytime a session is destroyed.
 *
 * On session close, the IPC is closed and the server must release all tcons of the session.
 * No need to send a tree disconnect here.
 *
 * Besides, it will make the server to not close durable and resilient files on session close, as
 * specified in MS-SMB2 3.3.5.6 Receiving an SMB2 LOGOFF Request.
 */
static int
cifs_free_ipc(struct smbfs_ses *ses)
{
	struct smbfs_tcon *tcon = ses->tcon_ipc;

	if (tcon == NULL)
		return 0;

	smbfs_tcon_free(tcon);
	ses->tcon_ipc = NULL;
	return 0;
}

static struct smbfs_ses *
cifs_find_smb_ses(struct smbfs_server_info *server, struct smb3_fs_context *ctx)
{
	struct smbfs_ses *ses;

	spin_lock(&g_servers_lock);
	list_for_each_entry(ses, &server->sessions, head) {
		if (ses->status == SMBFS_SES_STATUS_EXITING)
			continue;
		if (!match_session(ses, ctx))
			continue;
		++ses->count;
		spin_unlock(&g_servers_lock);
		return ses;
	}
	spin_unlock(&g_servers_lock);
	return NULL;
}

void cifs_put_smb_ses(struct smbfs_ses *ses)
{
	unsigned int rc, xid;
	unsigned int channel_count;
	struct smbfs_server_info *server = ses->server;

	spin_lock(&g_servers_lock);
	if (ses->status == SMBFS_SES_STATUS_EXITING) {
		spin_unlock(&g_servers_lock);
		return;
	}

	smbfs_dbg("count=%d\n", ses->count);
	smbfs_dbg("ses ipc: %s\n", ses->tcon_ipc ? ses->tcon_ipc->tree_name : "none");

	if (--ses->count > 0) {
		spin_unlock(&g_servers_lock);
		return;
	}

	/* count can never go negative */
	WARN_ON(ses->count < 0);

	if (ses->status == SMBFS_SES_STATUS_GOOD)
		ses->status = SMBFS_SES_STATUS_EXITING;
	spin_unlock(&g_servers_lock);

	cifs_free_ipc(ses);

	if (ses->status == SMBFS_SES_STATUS_EXITING && server->ops->logoff) {
		xid = get_xid();
		rc = server->ops->logoff(xid, ses);
		if (rc)
			smbfs_server_log(server, "Session Logoff failed, rc=%d\n", rc);
		_free_xid(xid);
	}

	spin_lock(&g_servers_lock);
	list_del_init(&ses->head);
	spin_unlock(&g_servers_lock);

	channel_count = ses->channel_count;

	/* close any extra channels */
	if (channel_count > 1) {
		int i;

		for (i = 1; i < channel_count; i++) {
			if (ses->channels[i].iface) {
				kref_put(&ses->channels[i].iface->refcount, release_iface);
				ses->channels[i].iface = NULL;
			}
			smbfs_put_server(ses->channels[i].server, 0);
			ses->channels[i].server = NULL;
		}
	}

	sesInfoFree(ses);
	smbfs_put_server(server, 0);
}

#ifdef CONFIG_KEYS

/* strlen("cifs:a:") + CIFS_MAX_DOMAINNAME_LEN + 1 */
#define CIFSCREDS_DESC_SIZE (7 + CIFS_MAX_DOMAINNAME_LEN + 1)

/* Populate username and pw fields from keyring if possible */
static int
cifs_set_cifscreds(struct smb3_fs_context *ctx, struct smbfs_ses *ses)
{
	int rc = 0;
	int is_domain = 0;
	const char *delim, *payload;
	char *desc;
	ssize_t len;
	struct key *key;
	struct smbfs_server_info *server = ses->server;
	struct sockaddr_in *sa;
	struct sockaddr_in6 *sa6;
	const struct user_key_payload *upayload;

	desc = kmalloc(CIFSCREDS_DESC_SIZE, GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	/* try to find an address key first */
	switch (server->dstaddr.ss_family) {
	case AF_INET:
		sa = (struct sockaddr_in *)&server->dstaddr;
		sprintf(desc, "cifs:a:%pI4", &sa->sin_addr.s_addr);
		break;
	case AF_INET6:
		sa6 = (struct sockaddr_in6 *)&server->dstaddr;
		sprintf(desc, "cifs:a:%pI6c", &sa6->sin6_addr.s6_addr);
		break;
	default:
		smbfs_dbg("Bad ss_family (%hu)\n",
			 server->dstaddr.ss_family);
		rc = -EINVAL;
		goto out_err;
	}

	smbfs_dbg("desc=%s\n", desc);
	key = request_key(&key_type_logon, desc, "");
	if (IS_ERR(key)) {
		if (!ses->domain_name) {
			smbfs_dbg("domain_name is NULL\n");
			rc = PTR_ERR(key);
			goto out_err;
		}

		/* didn't work, try to find a domain key */
		sprintf(desc, "cifs:d:%s", ses->domain_name);
		smbfs_dbg("desc=%s\n", desc);
		key = request_key(&key_type_logon, desc, "");
		if (IS_ERR(key)) {
			rc = PTR_ERR(key);
			goto out_err;
		}
		is_domain = 1;
	}

	down_read(&key->sem);
	upayload = user_key_payload_locked(key);
	if (IS_ERR_OR_NULL(upayload)) {
		rc = upayload ? PTR_ERR(upayload) : -EINVAL;
		goto out_key_put;
	}

	/* find first : in payload */
	payload = upayload->data;
	delim = strnchr(payload, upayload->datalen, ':');
	smbfs_dbg("payload=%s\n", payload);
	if (!delim) {
		smbfs_dbg("Unable to find ':' in payload (datalen=%d)\n",
			 upayload->datalen);
		rc = -EINVAL;
		goto out_key_put;
	}

	len = delim - payload;
	if (len > CIFS_MAX_USERNAME_LEN || len <= 0) {
		smbfs_dbg("Bad value from username search (len=%zd)\n",
			 len);
		rc = -EINVAL;
		goto out_key_put;
	}

	ctx->username = kstrndup(payload, len, GFP_KERNEL);
	if (!ctx->username) {
		smbfs_dbg("Unable to allocate %zd bytes for username\n",
			 len);
		rc = -ENOMEM;
		goto out_key_put;
	}
	smbfs_dbg("username=%s\n", ctx->username);

	len = key->datalen - (len + 1);
	if (len > CIFS_MAX_PASSWORD_LEN || len <= 0) {
		smbfs_dbg("Bad len for password search (len=%zd)\n", len);
		rc = -EINVAL;
		kfree(ctx->username);
		ctx->username = NULL;
		goto out_key_put;
	}

	++delim;
	ctx->password = kstrndup(delim, len, GFP_KERNEL);
	if (!ctx->password) {
		smbfs_dbg("Unable to allocate %zd bytes for password\n",
			 len);
		rc = -ENOMEM;
		kfree(ctx->username);
		ctx->username = NULL;
		goto out_key_put;
	}

	/*
	 * If we have a domain key then we must set the domain_name in the
	 * for the request.
	 */
	if (is_domain && ses->domain_name) {
		ctx->domainname = kstrdup(ses->domain_name, GFP_KERNEL);
		if (!ctx->domainname) {
			smbfs_dbg("Unable to allocate %zd bytes for domain\n",
				 len);
			rc = -ENOMEM;
			kfree(ctx->username);
			ctx->username = NULL;
			kfree_sensitive(ctx->password);
			ctx->password = NULL;
			goto out_key_put;
		}
	}

	strscpy(ctx->client_name, ses->client_name, sizeof(ctx->client_name));

out_key_put:
	up_read(&key->sem);
	key_put(key);
out_err:
	kfree(desc);
	smbfs_dbg("returning %d\n", rc);
	return rc;
}
#else /* ! CONFIG_KEYS */
static inline int
cifs_set_cifscreds(struct smb3_fs_context *ctx __attribute__((unused)),
		   struct smbfs_ses *ses __attribute__((unused)))
{
	return -ENOSYS;
}
#endif /* CONFIG_KEYS */

/**
 * cifs_get_smb_ses - get a session matching @ctx data from @server
 * @server: server to setup the session to
 * @ctx: superblock configuration context to use to setup the session
 *
 * This function assumes it is being called from cifs_mount() where we
 * already got a server reference (server refcount +1). See
 * smbfs_get_tcon() for refcount explanations.
 */
struct smbfs_ses *
cifs_get_smb_ses(struct smbfs_server_info *server, struct smb3_fs_context *ctx)
{
	int rc = -ENOMEM;
	unsigned int xid;
	struct smbfs_ses *ses;
	struct sockaddr_in *addr = (struct sockaddr_in *)&server->dstaddr;
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&server->dstaddr;

	xid = get_xid();

	ses = cifs_find_smb_ses(server, ctx);
	if (ses) {
		smbfs_dbg("Existing smb sess found (status=%d)\n",
			 ses->status);

		spin_lock(&ses->channel_lock);
		if (smbfs_channel_needs_reconnect(ses, server)) {
			spin_unlock(&ses->channel_lock);
			smbfs_dbg("Session needs reconnect\n");

			mutex_lock(&ses->lock);
			rc = cifs_negotiate_protocol(xid, ses, server);
			if (rc) {
				mutex_unlock(&ses->lock);
				/* problem -- put our ses reference */
				cifs_put_smb_ses(ses);
				free_xid(xid);
				return ERR_PTR(rc);
			}

			rc = cifs_setup_session(xid, ses, server,
						ctx->local_nls);
			if (rc) {
				mutex_unlock(&ses->lock);
				/* problem -- put our reference */
				cifs_put_smb_ses(ses);
				free_xid(xid);
				return ERR_PTR(rc);
			}
			mutex_unlock(&ses->lock);

			spin_lock(&ses->channel_lock);
		}
		spin_unlock(&ses->channel_lock);

		/* existing SMB ses has a server reference already */
		smbfs_put_server(server, 0);
		free_xid(xid);
		return ses;
	}

	smbfs_dbg("Existing smb sess not found\n");
	ses = sesInfoAlloc();
	if (ses == NULL)
		goto get_ses_fail;

	/* new SMB session uses our server ref */
	ses->server = server;
	if (server->dstaddr.ss_family == AF_INET6)
		sprintf(ses->ip_addr, "%pI6", &addr6->sin6_addr);
	else
		sprintf(ses->ip_addr, "%pI4", &addr->sin_addr);

	if (ctx->username) {
		ses->user_name = kstrdup(ctx->username, GFP_KERNEL);
		if (!ses->user_name)
			goto get_ses_fail;
	}

	/* ctx->password freed at unmount */
	if (ctx->password) {
		ses->password = kstrdup(ctx->password, GFP_KERNEL);
		if (!ses->password)
			goto get_ses_fail;
	}
	if (ctx->domainname) {
		ses->domain_name = kstrdup(ctx->domainname, GFP_KERNEL);
		if (!ses->domain_name)
			goto get_ses_fail;
	}

	strscpy(ses->client_name, ctx->client_name, sizeof(ses->client_name));

	if (ctx->domainauto)
		ses->domain_auto = ctx->domainauto;
	ses->cred_uid = ctx->cred_uid;
	ses->linux_uid = ctx->linux_uid;

	ses->sectype = ctx->sectype;
	ses->signing_required = ctx->sign;

	/* add server as first channel */
	spin_lock(&ses->channel_lock);
	ses->channels[0].server = server;
	ses->channel_count = 1;
	ses->max_channels = ctx->multichannel ? ctx->max_channels:1;
	ses->channels_need_reconnect = 1;
	spin_unlock(&ses->channel_lock);

	mutex_lock(&ses->lock);
	rc = cifs_negotiate_protocol(xid, ses, server);
	if (!rc)
		rc = cifs_setup_session(xid, ses, server, ctx->local_nls);
	mutex_unlock(&ses->lock);

	/* each channel uses a different signing key */
	spin_lock(&ses->channel_lock);
	memcpy(ses->channels[0].signkey, ses->smb3signingkey,
	       sizeof(ses->smb3signingkey));
	spin_unlock(&ses->channel_lock);

	if (rc)
		goto get_ses_fail;

	/*
	 * success, put it on the list and add it as first channel
	 * note: the session becomes active soon after this. So you'll
	 * need to lock before changing something in the session.
	 */
	spin_lock(&g_servers_lock);
	list_add(&ses->head, &server->sessions);
	spin_unlock(&g_servers_lock);

	free_xid(xid);

	cifs_setup_ipc(ses, ctx);

	return ses;

get_ses_fail:
	sesInfoFree(ses);
	free_xid(xid);
	return ERR_PTR(rc);
}

static int
compare_mount_options(struct super_block *sb, struct smbfs_mnt_data *mnt_data)
{
	struct cifs_sb_info *old = CIFS_SB(sb);
	struct cifs_sb_info *new = mnt_data->sb;
	unsigned int oldflags = old->mnt_cifs_flags & CIFS_MOUNT_MASK;
	unsigned int newflags = new->mnt_cifs_flags & CIFS_MOUNT_MASK;

	if ((sb->s_flags & SMBFS_MS_MASK) != (mnt_data->flags & SMBFS_MS_MASK))
		return 0;

	if (old->mnt_cifs_serverino_autodisabled)
		newflags &= ~CIFS_MOUNT_SERVER_INUM;

	if (oldflags != newflags)
		return 0;

	/*
	 * We want to share sb only if we don't specify an r/wsize or
	 * specified r/wsize is greater than or equal to existing one.
	 */
	if (new->ctx->wsize && new->ctx->wsize < old->ctx->wsize)
		return 0;

	if (new->ctx->rsize && new->ctx->rsize < old->ctx->rsize)
		return 0;

	if (!uid_eq(old->ctx->linux_uid, new->ctx->linux_uid) ||
	    !gid_eq(old->ctx->linux_gid, new->ctx->linux_gid))
		return 0;

	if (old->ctx->file_mode != new->ctx->file_mode ||
	    old->ctx->dir_mode != new->ctx->dir_mode)
		return 0;

	if (strcmp(old->local_nls->charset, new->local_nls->charset))
		return 0;

	if (old->ctx->acregmax != new->ctx->acregmax)
		return 0;
	if (old->ctx->acdirmax != new->ctx->acdirmax)
		return 0;

	return 1;
}

static int
match_prepath(struct super_block *sb, struct smbfs_mnt_data *mnt_data)
{
	struct cifs_sb_info *old = CIFS_SB(sb);
	struct cifs_sb_info *new = mnt_data->sb;
	bool old_set = (old->mnt_cifs_flags & CIFS_MOUNT_USE_PREFIX_PATH) &&
		old->prepath;
	bool new_set = (new->mnt_cifs_flags & CIFS_MOUNT_USE_PREFIX_PATH) &&
		new->prepath;

	if (old_set && new_set && !strcmp(new->prepath, old->prepath))
		return 1;
	else if (!old_set && !new_set)
		return 1;

	return 0;
}

int
cifs_match_super(struct super_block *sb, void *data)
{
	struct smbfs_mnt_data *mnt_data = (struct smbfs_mnt_data *)data;
	struct smb3_fs_context *ctx;
	struct cifs_sb_info *cifs_sb;
	struct smbfs_server_info *tcp_srv;
	struct smbfs_ses *ses;
	struct smbfs_tcon *tcon;
	struct smbfs_tcon_link *tlink;
	int rc = 0;

	spin_lock(&g_servers_lock);
	cifs_sb = CIFS_SB(sb);
	tlink = smbfs_get_tlink(smbfs_sb_master_tlink(cifs_sb));
	if (tlink == NULL) {
		/* can not match superblock if tlink were ever null */
		spin_unlock(&g_servers_lock);
		return 0;
	}
	tcon = tlink_tcon(tlink);
	ses = tcon->ses;
	tcp_srv = ses->server;

	ctx = mnt_data->ctx;

	if (!match_server(tcp_srv, ctx) ||
	    !match_session(ses, ctx) ||
	    !match_tcon(tcon, ctx) ||
	    !match_prepath(sb, mnt_data)) {
		rc = 0;
		goto out;
	}

	rc = compare_mount_options(sb, mnt_data);
out:
	spin_unlock(&g_servers_lock);
	smbfs_put_tlink(tlink);
	return rc;
}

#ifdef CONFIG_DEBUG_LOCK_ALLOC
static struct lock_class_key cifs_key[2];
static struct lock_class_key cifs_slock_key[2];

static inline void
cifs_reclassify_socket4(struct socket *sock)
{
	struct sock *sk = sock->sk;
	BUG_ON(!sock_allow_reclassification(sk));
	sock_lock_init_class_and_name(sk, "slock-AF_INET-CIFS",
		&cifs_slock_key[0], "sk_lock-AF_INET-CIFS", &cifs_key[0]);
}

static inline void
cifs_reclassify_socket6(struct socket *sock)
{
	struct sock *sk = sock->sk;
	BUG_ON(!sock_allow_reclassification(sk));
	sock_lock_init_class_and_name(sk, "slock-AF_INET6-CIFS",
		&cifs_slock_key[1], "sk_lock-AF_INET6-CIFS", &cifs_key[1]);
}
#else
static inline void
cifs_reclassify_socket4(struct socket *sock)
{
}

static inline void
cifs_reclassify_socket6(struct socket *sock)
{
}
#endif

/* See RFC1001 section 14 on representation of Netbios names */
static void rfc1002mangle(char *target, char *source, unsigned int length)
{
	unsigned int i, j;

	for (i = 0, j = 0; i < (length); i++) {
		/* mask a nibble at a time and encode */
		target[j] = 'A' + (0x0F & (source[i] >> 4));
		target[j+1] = 'A' + (0x0F & source[i]);
		j += 2;
	}

}

static int
bind_socket(struct smbfs_server_info *server)
{
	int rc = 0;
	if (server->srcaddr.ss_family != AF_UNSPEC) {
		/* Bind to the specified local IP address */
		struct socket *socket = server->ssocket;
		rc = socket->ops->bind(socket,
				       (struct sockaddr *) &server->srcaddr,
				       sizeof(server->srcaddr));
		if (rc < 0) {
			struct sockaddr_in *saddr4;
			struct sockaddr_in6 *saddr6;
			saddr4 = (struct sockaddr_in *)&server->srcaddr;
			saddr6 = (struct sockaddr_in6 *)&server->srcaddr;
			if (saddr6->sin6_family == AF_INET6)
				smbfs_server_log(server, "Failed to bind to: %pI6c, error: %d\n",
					 &saddr6->sin6_addr, rc);
			else
				smbfs_server_log(server, "Failed to bind to: %pI4, error: %d\n",
					 &saddr4->sin_addr.s_addr, rc);
		}
	}
	return rc;
}

static int
ip_rfc1001_connect(struct smbfs_server_info *server)
{
	int rc = 0;
	
	/*
	 * Some servers require RFC1001 sessinit before sending
	 * negprot
	 *
	 * TODO: check reconnection in case where second
	 * sessinit is sent but no second negprot
	 */

	struct rfc1002_session_packet *ses_init_buf;
	struct smb_hdr *smb_buf;
	ses_init_buf = kzalloc(sizeof(struct rfc1002_session_packet),
			       GFP_KERNEL);
	if (ses_init_buf) {
		ses_init_buf->trailer.session_req.called_len = 32;

		if (server->rfc1001_name[0] != 0)
			rfc1002mangle(ses_init_buf->trailer.
				      session_req.called_name,
				      server->rfc1001_name,
				      RFC1001_NAME_LEN_NUL);
		else
			rfc1002mangle(ses_init_buf->trailer.
				      session_req.called_name,
				      DEFAULT_CIFS_CALLED_NAME,
				      RFC1001_NAME_LEN_NUL);

		ses_init_buf->trailer.session_req.calling_len = 32;

		/*
		 * calling name ends in null (byte 16) from old smb
		 * convention.
		 */
		if (server->rfc1001_name[0] != 0)
			rfc1002mangle(ses_init_buf->trailer.
				      session_req.calling_name,
				      server->rfc1001_name,
				      RFC1001_NAME_LEN_NUL);
		else
			rfc1002mangle(ses_init_buf->trailer.
				      session_req.calling_name,
				      "LINUX_CIFS_CLNT",
				      RFC1001_NAME_LEN_NUL);

		ses_init_buf->trailer.session_req.scope1 = 0;
		ses_init_buf->trailer.session_req.scope2 = 0;
		smb_buf = (struct smb_hdr *)ses_init_buf;

		/* sizeof RFC1002_SESSION_REQUEST with no scope */
		smb_buf->smb_buf_length = cpu_to_be32(0x81000044);
		rc = smb_send(server, smb_buf, 0x44);
		kfree(ses_init_buf);
		/*
		 * RFC1001 layer in at least one server
		 * requires very short break before negprot
		 * presumably because not expecting negprot
		 * to follow so fast.  This is a simple
		 * solution that works without
		 * complicating the code and causes no
		 * significant slowing down on mount
		 * for everyone else
		 */
		usleep_range(1000, 2000);
	}
	/*
	 * else the negprot may still work without this
	 * even though malloc failed
	 */

	return rc;
}

static int
generic_ip_connect(struct smbfs_server_info *server)
{
	int rc = 0;
	__be16 sport;
	int slen, sfamily;
	struct socket *socket = server->ssocket;
	struct sockaddr *saddr;

	saddr = (struct sockaddr *) &server->dstaddr;

	if (server->dstaddr.ss_family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&server->dstaddr;

		sport = ipv6->sin6_port;
		slen = sizeof(struct sockaddr_in6);
		sfamily = AF_INET6;
		smbfs_dbg("connecting to [%pI6]:%d\n", &ipv6->sin6_addr,
				ntohs(sport));
	} else {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)&server->dstaddr;

		sport = ipv4->sin_port;
		slen = sizeof(struct sockaddr_in);
		sfamily = AF_INET;
		smbfs_dbg("connecting to %pI4:%d\n", &ipv4->sin_addr,
				ntohs(sport));
	}

	if (socket == NULL) {
		rc = __sock_create(smbfs_net_ns(server), sfamily, SOCK_STREAM,
				   IPPROTO_TCP, &socket, 1);
		if (rc < 0) {
			smbfs_server_log(server, "Error %d creating socket\n", rc);
			server->ssocket = NULL;
			return rc;
		}

		/* TODO: other socket options to set KEEPALIVE, NODELAY? */
		smbfs_dbg("Socket created\n");
		server->ssocket = socket;
		socket->sk->sk_allocation = GFP_NOFS;
		if (sfamily == AF_INET6)
			cifs_reclassify_socket6(socket);
		else
			cifs_reclassify_socket4(socket);
	}

	rc = bind_socket(server);
	if (rc < 0)
		return rc;

	/*
	 * Eventually check for other socket options to change from
	 * the default. sock_setsockopt not used because it expects
	 * user space buffer
	 */
	socket->sk->sk_rcvtimeo = 7 * HZ;
	socket->sk->sk_sndtimeo = 5 * HZ;

	/* make the bufsizes depend on wsize/rsize and max requests */
	if (server->noautotune) {
		if (socket->sk->sk_sndbuf < (200 * 1024))
			socket->sk->sk_sndbuf = 200 * 1024;
		if (socket->sk->sk_rcvbuf < (140 * 1024))
			socket->sk->sk_rcvbuf = 140 * 1024;
	}

	if (server->tcp_nodelay)
		tcp_sock_set_nodelay(socket->sk);

	smbfs_dbg("sndbuf %d rcvbuf %d rcvtimeo 0x%lx\n",
		 socket->sk->sk_sndbuf,
		 socket->sk->sk_rcvbuf, socket->sk->sk_rcvtimeo);

	rc = socket->ops->connect(socket, saddr, slen,
				  server->noblockcnt ? O_NONBLOCK : 0);
	/*
	 * When mounting SMB root file systems, we do not want to block in
	 * connect. Otherwise bail out and then let cifs_reconnect() perform
	 * reconnect failover - if possible.
	 */
	if (server->noblockcnt && rc == -EINPROGRESS)
		rc = 0;
	if (rc < 0) {
		smbfs_dbg("Error %d connecting to server\n", rc);
		trace_smb3_connect_err(server->hostname, server->conn_id, &server->dstaddr, rc);
		sock_release(socket);
		server->ssocket = NULL;
		return rc;
	}
	trace_smb3_connect_done(server->hostname, server->conn_id, &server->dstaddr);
	if (sport == htons(RFC1001_PORT))
		rc = ip_rfc1001_connect(server);

	return rc;
}

static int
ip_connect(struct smbfs_server_info *server)
{
	__be16 *sport;
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&server->dstaddr;
	struct sockaddr_in *addr = (struct sockaddr_in *)&server->dstaddr;

	if (server->dstaddr.ss_family == AF_INET6)
		sport = &addr6->sin6_port;
	else
		sport = &addr->sin_port;

	if (*sport == 0) {
		int rc;

		/* try with 445 port at first */
		*sport = htons(SMB_PORT);

		rc = generic_ip_connect(server);
		if (rc >= 0)
			return rc;

		/* if it failed, try with 139 port */
		*sport = htons(RFC1001_PORT);
	}

	return generic_ip_connect(server);
}

void reset_cifs_unix_caps(unsigned int xid, struct smbfs_tcon *tcon,
			  struct cifs_sb_info *cifs_sb, struct smb3_fs_context *ctx)
{
	/*
	 * If we are reconnecting then should we check to see if
	 * any requested capabilities changed locally e.g. via
	 * remount but we can not do much about it here
	 * if they have (even if we could detect it by the following)
	 * Perhaps we could add a backpointer to array of sb from tcon
	 * or if we change to make all sb to same share the same
	 * sb as NFS - then we only have one backpointer to sb.
	 * What if we wanted to mount the server share twice once with
	 * and once without posixacls or posix paths?
	 */
	__u64 saved_cap = le64_to_cpu(tcon->fs_unix_info.Capability);

	if (ctx && ctx->no_linux_ext) {
		tcon->fs_unix_info.Capability = 0;
		clear_tcon_flag(tcon, USE_UNIX_EXT); /* Unix Extensions disabled */
		smbfs_dbg("Linux protocol extensions disabled\n");
		return;
	} else if (ctx)
		set_tcon_flag(tcon, USE_UNIX_EXT); /* Unix Extensions supported */

	if (!get_tcon_flag(tcon, USE_UNIX_EXT)) {
		smbfs_dbg("Unix extensions disabled so not set on reconnect\n");
		return;
	}

	if (!CIFSSMBQFSUnixInfo(xid, tcon)) {
		__u64 cap = le64_to_cpu(tcon->fs_unix_info.Capability);
		smbfs_dbg("unix caps which server supports %lld\n", cap);
		/*
		 * check for reconnect case in which we do not
		 * want to change the mount behavior if we can avoid it
		 */
		if (ctx == NULL) {
			/*
			 * turn off POSIX ACL and PATHNAMES if not set
			 * originally at mount time
			 */
			if ((saved_cap & CIFS_UNIX_POSIX_ACL_CAP) == 0)
				cap &= ~CIFS_UNIX_POSIX_ACL_CAP;
			if ((saved_cap & CIFS_UNIX_POSIX_PATHNAMES_CAP) == 0) {
				if (cap & CIFS_UNIX_POSIX_PATHNAMES_CAP)
					smbfs_log("POSIXPATH support change\n");
				cap &= ~CIFS_UNIX_POSIX_PATHNAMES_CAP;
			} else if ((cap & CIFS_UNIX_POSIX_PATHNAMES_CAP) == 0) {
				smbfs_log("possible reconnect error\n");
				smbfs_log("server disabled POSIX path support\n");
			}
		}

		if (cap & CIFS_UNIX_TRANSPORT_ENCRYPTION_MANDATORY_CAP)
			smbfs_log("per-share encryption not supported yet\n");

		cap &= CIFS_UNIX_CAP_MASK;
		if (ctx && ctx->no_psx_acl)
			cap &= ~CIFS_UNIX_POSIX_ACL_CAP;
		else if (CIFS_UNIX_POSIX_ACL_CAP & cap) {
			smbfs_dbg("negotiated posix acl support\n");
			if (cifs_sb)
				cifs_sb->mnt_cifs_flags |=
					CIFS_MOUNT_POSIXACL;
		}

		if (ctx && ctx->posix_paths == 0)
			cap &= ~CIFS_UNIX_POSIX_PATHNAMES_CAP;
		else if (cap & CIFS_UNIX_POSIX_PATHNAMES_CAP) {
			smbfs_dbg("negotiate posix pathnames\n");
			if (cifs_sb)
				cifs_sb->mnt_cifs_flags |=
					CIFS_MOUNT_POSIX_PATHS;
		}

		smbfs_dbg("Negotiate caps 0x%x\n", (int)cap);
#ifdef CONFIG_SMBFS_DEBUG_EXTRA
		if (cap & CIFS_UNIX_FCNTL_CAP)
			smbfs_dbg("FCNTL cap\n");
		if (cap & CIFS_UNIX_EXTATTR_CAP)
			smbfs_dbg("EXTATTR cap\n");
		if (cap & CIFS_UNIX_POSIX_PATHNAMES_CAP)
			smbfs_dbg("POSIX path cap\n");
		if (cap & CIFS_UNIX_XATTR_CAP)
			smbfs_dbg("XATTR cap\n");
		if (cap & CIFS_UNIX_POSIX_ACL_CAP)
			smbfs_dbg("POSIX ACL cap\n");
		if (cap & CIFS_UNIX_LARGE_READ_CAP)
			smbfs_dbg("very large read cap\n");
		if (cap & CIFS_UNIX_LARGE_WRITE_CAP)
			smbfs_dbg("very large write cap\n");
		if (cap & CIFS_UNIX_TRANSPORT_ENCRYPTION_CAP)
			smbfs_dbg("transport encryption cap\n");
		if (cap & CIFS_UNIX_TRANSPORT_ENCRYPTION_MANDATORY_CAP)
			smbfs_dbg("mandatory transport encryption cap\n");
#endif /* SMBFS_DEBUG_EXTRA */
		if (CIFSSMBSetFSUnixInfo(xid, tcon, cap)) {
			if (ctx == NULL)
				smbfs_dbg("resetting capabilities failed\n");
			else
				smbfs_log("Negotiating Unix capabilities with the server failed. Consider mounting with the Unix Extensions disabled if problems are found by specifying the nounix mount option.\n");

		}
	}
}

int cifs_setup_cifs_sb(struct cifs_sb_info *cifs_sb)
{
	struct smb3_fs_context *ctx = cifs_sb->ctx;

	INIT_DELAYED_WORK(&cifs_sb->prune_tlinks, smbfs_prune_tlinks);

	spin_lock_init(&cifs_sb->tlink_tree_lock);
	cifs_sb->tlink_tree = RB_ROOT;

	smbfs_dbg("file mode: %04ho, dir mode: %04ho\n", ctx->file_mode, ctx->dir_mode);

	/* this is needed for ASCII cp to Unicode converts */
	if (ctx->iocharset == NULL) {
		/* load_nls_default cannot return null */
		cifs_sb->local_nls = load_nls_default();
	} else {
		cifs_sb->local_nls = load_nls(ctx->iocharset);
		if (cifs_sb->local_nls == NULL) {
			smbfs_log("CIFS mount error: iocharset '%s' not found\n", ctx->iocharset);
			return -ELIBACC;
		}
	}
	ctx->local_nls = cifs_sb->local_nls;

	smb3_update_mnt_flags(cifs_sb);

	if (ctx->direct_io)
		smbfs_dbg("mounting share using direct i/o\n");
	if (ctx->cache_ro) {
		smbfs_log("mounting share with read only caching. Ensure that the share will not be modified while in use.\n");
		cifs_sb->mnt_cifs_flags |= CIFS_MOUNT_RO_CACHE;
	} else if (ctx->cache_rw) {
		smbfs_log("mounting share in single client RW caching mode. Ensure that no other systems will be accessing the share.\n");
		cifs_sb->mnt_cifs_flags |= (CIFS_MOUNT_RO_CACHE |
					    CIFS_MOUNT_RW_CACHE);
	}

	if ((ctx->cifs_acl) && (ctx->dynperm))
		smbfs_log("mount option dynperm ignored if cifsacl mount option supported\n");

	if (ctx->prepath) {
		cifs_sb->prepath = kstrdup(ctx->prepath, GFP_KERNEL);
		if (cifs_sb->prepath == NULL)
			return -ENOMEM;
		cifs_sb->mnt_cifs_flags |= CIFS_MOUNT_USE_PREFIX_PATH;
	}

	return 0;
}

/* Release all succeed connections */
static inline void mount_put_conns(struct mount_ctx *mnt_ctx)
{
	int rc = 0;

	if (mnt_ctx->tcon)
		smbfs_put_tcon(mnt_ctx->tcon);
	else if (mnt_ctx->ses)
		cifs_put_smb_ses(mnt_ctx->ses);
	else if (mnt_ctx->server)
		smbfs_put_server(mnt_ctx->server, 0);
	mnt_ctx->cifs_sb->mnt_cifs_flags &= ~CIFS_MOUNT_POSIX_PATHS;
	free_xid(mnt_ctx->xid);
}

/* Get connections for tcp, ses and tcon */
static int mount_get_conns(struct mount_ctx *mnt_ctx)
{
	int rc = 0;
	struct smbfs_server_info *server = NULL;
	struct smbfs_ses *ses = NULL;
	struct smbfs_tcon *tcon = NULL;
	struct smb3_fs_context *ctx = mnt_ctx->fs_ctx;
	struct cifs_sb_info *cifs_sb = mnt_ctx->cifs_sb;
	unsigned int xid;

	xid = get_xid();

	/* get a reference to a tcp session */
	server = smbfs_get_server(ctx, NULL);
	if (IS_ERR(server)) {
		rc = PTR_ERR(server);
		server = NULL;
		goto out;
	}

	/* get a reference to a SMB session */
	ses = cifs_get_smb_ses(server, ctx);
	if (IS_ERR(ses)) {
		rc = PTR_ERR(ses);
		ses = NULL;
		goto out;
	}

	if ((ctx->persistent == true) && (!(ses->server->capabilities &
					    SMB2_GLOBAL_CAP_PERSISTENT_HANDLES))) {
		smbfs_server_log(server, "persistent handles not supported by server\n");
		rc = -EOPNOTSUPP;
		goto out;
	}

	/* search for existing tcon to this server share */
	tcon = smbfs_get_tcon(ses, ctx);
	if (IS_ERR(tcon)) {
		rc = PTR_ERR(tcon);
		tcon = NULL;
		goto out;
	}

	/* if new SMB3.11 POSIX extensions are supported do not remap / and \ */
	if (get_tcon_flag(tcon, USE_POSIX_EXT))
		cifs_sb->mnt_cifs_flags |= CIFS_MOUNT_POSIX_PATHS;

	/* tell server which Unix caps we support */
	if (has_cap_unix(tcon->ses)) {
		/*
		 * reset of caps checks mount to see if unix extensions disabled
		 * for just this mount.
		 */
		reset_cifs_unix_caps(xid, tcon, cifs_sb, ctx);
		spin_lock(&g_servers_lock);
		if ((tcon->ses->server->status == SMBFS_STATUS_NEED_RECONNECT) &&
		    (le64_to_cpu(tcon->fs_unix_info.Capability) &
		     CIFS_UNIX_TRANSPORT_ENCRYPTION_MANDATORY_CAP)) {
			spin_unlock(&g_servers_lock);
			rc = -EACCES;
			goto out;
		}
		spin_unlock(&g_servers_lock);
	} else
		clear_tcon_flag(tcon, USE_UNIX_EXT);

	/* do not care if a following call succeed - informational */
	if (!get_tcon_flag(tcon, IS_PIPE) && server->ops->qfs_tcon) {
		server->ops->qfs_tcon(xid, tcon, cifs_sb);
		if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_RO_CACHE) {
			if (tcon->fs_dev_info.DeviceCharacteristics &
			    cpu_to_le32(FILE_READ_ONLY_DEVICE))
				smbfs_log("mounted to read only share\n");
			else if ((cifs_sb->mnt_cifs_flags &
				  CIFS_MOUNT_RW_CACHE) == 0)
				smbfs_log("read only mount of RW share\n");
			/* no need to log a RW mount of a typical RW share */
		}
	}

	/*
	 * Clamp the rsize/wsize mount arguments if they are too big for the server
	 * and set the rsize/wsize to the negotiated values if not passed in by
	 * the user on mount
	 */
	if ((cifs_sb->ctx->wsize == 0) ||
	    (cifs_sb->ctx->wsize > server->ops->negotiate_wsize(tcon, ctx)))
		cifs_sb->ctx->wsize = server->ops->negotiate_wsize(tcon, ctx);
	if ((cifs_sb->ctx->rsize == 0) ||
	    (cifs_sb->ctx->rsize > server->ops->negotiate_rsize(tcon, ctx)))
		cifs_sb->ctx->rsize = server->ops->negotiate_rsize(tcon, ctx);

	/*
	 * The cookie is initialized from volume info returned above.
	 * Inside cifs_fscache_get_super_cookie it checks
	 * that we do not get super cookie twice.
	 */
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_FSCACHE)
		cifs_fscache_get_super_cookie(tcon);

out:
	mnt_ctx->server = server;
	mnt_ctx->ses = ses;
	mnt_ctx->tcon = tcon;
	mnt_ctx->xid = xid;

	return rc;
}

static int mount_setup_tlink(struct cifs_sb_info *cifs_sb, struct smbfs_ses *ses,
			     struct smbfs_tcon *tcon)
{
	struct smbfs_tcon_link *tlink;

	/* hang the tcon off of the superblock */
	tlink = kzalloc(sizeof(*tlink), GFP_KERNEL);
	if (tlink == NULL)
		return -ENOMEM;

	tlink->uid = ses->linux_uid;
	tlink->tcon = tcon;
	tlink->time = jiffies;
	set_bit(TCON_LINK_MASTER, &tlink->flags);
	set_bit(TCON_LINK_IN_TREE, &tlink->flags);

	cifs_sb->master_tlink = tlink;
	spin_lock(&cifs_sb->tlink_tree_lock);
	tlink_rb_insert(&cifs_sb->tlink_tree, tlink);
	spin_unlock(&cifs_sb->tlink_tree_lock);

	queue_delayed_work(cifsiod_wq, &cifs_sb->prune_tlinks,
				TLINK_IDLE_EXPIRE);
	return 0;
}

#ifdef CONFIG_SMBFS_DFS_UPCALL
/* Get unique dfs connections */
static int mount_get_dfs_conns(struct mount_ctx *mnt_ctx)
{
	int rc;

	mnt_ctx->fs_ctx->nosharesock = true;
	rc = mount_get_conns(mnt_ctx);
	if (mnt_ctx->server) {
		smbfs_dbg("marking tcp session as a dfs connection\n");
		spin_lock(&g_servers_lock);
		mnt_ctx->server->is_dfs_conn = true;
		spin_unlock(&g_servers_lock);
	}
	return rc;
}

/*
 * cifs_build_path_to_root returns full path to root when we do not have an
 * existing connection (tcon)
 */
static char *
build_unc_path_to_root(const struct smb3_fs_context *ctx,
		       const struct cifs_sb_info *cifs_sb, bool useppath)
{
	char *full_path, *pos;
	unsigned int pplen = useppath && ctx->prepath ?
		strlen(ctx->prepath) + 1 : 0;
	unsigned int unc_len = strnlen(ctx->UNC, SMBFS_MAX_TREE_SIZE + 1);

	if (unc_len > SMBFS_MAX_TREE_SIZE)
		return ERR_PTR(-EINVAL);

	full_path = kmalloc(unc_len + pplen + 1, GFP_KERNEL);
	if (full_path == NULL)
		return ERR_PTR(-ENOMEM);

	memcpy(full_path, ctx->UNC, unc_len);
	pos = full_path + unc_len;

	if (pplen) {
		*pos = dir_sep(cifs_sb);
		memcpy(pos + 1, ctx->prepath, pplen);
		pos += pplen;
	}

	*pos = '\0'; /* add trailing null */
	convert_delimiter(full_path, dir_sep(cifs_sb));
	smbfs_dbg("full_path=%s\n", full_path);
	return full_path;
}

/*
 * expand_dfs_referral - Update cifs_sb from dfs referral path
 *
 * cifs_sb->ctx->mount_options will be (re-)allocated to a string containing updated options for the
 * submount.  Otherwise it will be left untouched.
 */
static int expand_dfs_referral(struct mount_ctx *mnt_ctx, const char *full_path,
			       struct smbfs_dfs_info *referral)
{
	int rc;
	struct cifs_sb_info *cifs_sb = mnt_ctx->cifs_sb;
	struct smb3_fs_context *ctx = mnt_ctx->fs_ctx;
	char *fake_devname = NULL, *mdata = NULL;

	mdata = cifs_compose_mount_options(cifs_sb->ctx->mount_options, full_path + 1, referral,
					   &fake_devname);
	if (IS_ERR(mdata)) {
		rc = PTR_ERR(mdata);
		mdata = NULL;
	} else {
		/*
		 * We can not clear out the whole structure since we no longer have an explicit
		 * function to parse a mount-string. Instead we need to clear out the individual
		 * fields that are no longer valid.
		 */
		kfree(ctx->prepath);
		ctx->prepath = NULL;
		rc = cifs_setup_volume_info(ctx, mdata, fake_devname);
	}
	kfree(fake_devname);
	kfree(cifs_sb->ctx->mount_options);
	cifs_sb->ctx->mount_options = mdata;

	return rc;
}
#endif

/* TODO: all callers to this are broken. We are not parsing mount_options here
 * we should pass a clone of the original context?
 */
int
cifs_setup_volume_info(struct smb3_fs_context *ctx, const char *mntopts, const char *devname)
{
	int rc;

	if (devname) {
		smbfs_dbg("devname=%s\n", devname);
		rc = smb3_parse_devname(devname, ctx);
		if (rc) {
			smbfs_log("%s: failed to parse '%s', rc=%d\n", __func__, devname, rc);
			return rc;
		}
	}

	if (mntopts) {
		char *ip;

		rc = smb3_parse_opt(mntopts, "ip", &ip);
		if (rc) {
			smbfs_log("%s: failed to parse ip options, rc=%d\n", __func__, rc);
			return rc;
		}

		rc = cifs_convert_address((struct sockaddr *)&ctx->dstaddr, ip, strlen(ip));
		kfree(ip);
		if (!rc) {
			smbfs_log("%s: failed to convert ip address\n", __func__);
			return -EINVAL;
		}
	}

	if (ctx->nullauth) {
		smbfs_dbg("Anonymous login\n");
		kfree(ctx->username);
		ctx->username = NULL;
	} else if (ctx->username) {
		/* TODO: fixme parse for domain name here */
		smbfs_dbg("Username: %s\n", ctx->username);
	} else {
		smbfs_log("No username specified\n");
	/* In userspace mount helper we can get user name from alternate
	   locations such as env variables and files on disk */
		return -EINVAL;
	}

	return 0;
}

static int
cifs_are_all_path_components_accessible(struct smbfs_server_info *server,
					unsigned int xid,
					struct smbfs_tcon *tcon,
					struct cifs_sb_info *cifs_sb,
					char *full_path,
					int added_treename)
{
	int rc;
	char *s;
	char sep, tmp;
	int skip = added_treename ? 1 : 0;

	sep = dir_sep(cifs_sb);
	s = full_path;

	rc = server->ops->is_path_accessible(xid, tcon, cifs_sb, "");
	while (rc == 0) {
		/* skip separators */
		while (*s == sep)
			s++;
		if (!*s)
			break;
		/* next separator */
		while (*s && *s != sep)
			s++;
		/*
		 * if the treename is added, we then have to skip the first
		 * part within the separators
		 */
		if (skip) {
			skip = 0;
			continue;
		}
		/*
		 * temporarily null-terminate the path at the end of
		 * the current component
		 */
		tmp = *s;
		*s = 0;
		rc = server->ops->is_path_accessible(xid, tcon, cifs_sb,
						     full_path);
		*s = tmp;
	}
	return rc;
}

/*
 * Check if path is remote (i.e. a DFS share).
 *
 * Return -EREMOTE if it is, otherwise 0 or -errno.
 */
static int is_path_remote(struct mount_ctx *mnt_ctx)
{
	int rc;
	struct cifs_sb_info *cifs_sb = mnt_ctx->cifs_sb;
	struct smbfs_server_info *server = mnt_ctx->server;
	unsigned int xid = mnt_ctx->xid;
	struct smbfs_tcon *tcon = mnt_ctx->tcon;
	struct smb3_fs_context *ctx = mnt_ctx->fs_ctx;
	char *full_path;
#ifdef CONFIG_SMBFS_DFS_UPCALL
	bool nodfs = cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NO_DFS;
#endif
	bool dfs_share = tcon->share_flags & SHI1005_FLAGS_DFS;

	if (!server->ops->is_path_accessible)
		return -EOPNOTSUPP;

	/*
	 * cifs_build_path_to_root works only when we have a valid tcon
	 */
	full_path = cifs_build_path_to_root(ctx, cifs_sb, tcon, dfs_share);
	if (full_path == NULL)
		return -ENOMEM;

	smbfs_dbg("full_path: %s\n", full_path);

	rc = server->ops->is_path_accessible(xid, tcon, cifs_sb,
					     full_path);
#ifdef CONFIG_SMBFS_DFS_UPCALL
	if (nodfs) {
		if (rc == -EREMOTE)
			rc = -EOPNOTSUPP;
		goto out;
	}

	/* path *might* exist with non-ASCII characters in DFS root
	 * try again with full path (only if nodfs is not set) */
	if (rc == -ENOENT && is_tcon_dfs(tcon))
		rc = cifs_dfs_query_info_nonascii_quirk(xid, tcon, cifs_sb,
							full_path);
#endif
	if (rc != 0 && rc != -EREMOTE)
		goto out;

	if (rc != -EREMOTE) {
		rc = cifs_are_all_path_components_accessible(server, xid, tcon,
			cifs_sb, full_path, dfs_share);
		if (rc != 0) {
			smbfs_server_log(server, "cannot query dirs between root and final path, enabling CIFS_MOUNT_USE_PREFIX_PATH\n");
			cifs_sb->mnt_cifs_flags |= CIFS_MOUNT_USE_PREFIX_PATH;
			rc = 0;
		}
	}

out:
	kfree(full_path);
	return rc;
}

#ifdef CONFIG_SMBFS_DFS_UPCALL
static void set_root_ses(struct mount_ctx *mnt_ctx)
{
	if (mnt_ctx->ses) {
		spin_lock(&g_servers_lock);
		mnt_ctx->ses->count++;
		spin_unlock(&g_servers_lock);
		dfs_cache_add_refsrv_session(&mnt_ctx->mount_id, mnt_ctx->ses);
	}
	mnt_ctx->root_ses = mnt_ctx->ses;
}

static int is_dfs_mount(struct mount_ctx *mnt_ctx, bool *isdfs, struct dfs_cache_tgt_list *root_tl)
{
	int rc;
	struct cifs_sb_info *cifs_sb = mnt_ctx->cifs_sb;
	struct smb3_fs_context *ctx = mnt_ctx->fs_ctx;

	*isdfs = true;

	rc = mount_get_conns(mnt_ctx);
	/*
	 * If called with 'nodfs' mount option, then skip DFS resolving.  Otherwise unconditionally
	 * try to get an DFS referral (even cached) to determine whether it is an DFS mount.
	 *
	 * Skip prefix path to provide support for DFS referrals from w2k8 servers which don't seem
	 * to respond with PATH_NOT_COVERED to requests that include the prefix.
	 */
	if ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NO_DFS) ||
	    dfs_cache_find(mnt_ctx->xid, mnt_ctx->ses, cifs_sb->local_nls, cifs_remap(cifs_sb),
			   ctx->UNC + 1, NULL, root_tl)) {
		if (rc)
			return rc;
		/* Check if it is fully accessible and then mount it */
		rc = is_path_remote(mnt_ctx);
		if (!rc)
			*isdfs = false;
		else if (rc != -EREMOTE)
			return rc;
	}
	return 0;
}

static int connect_dfs_target(struct mount_ctx *mnt_ctx, const char *full_path,
			      const char *ref_path, struct dfs_cache_tgt_iterator *tit)
{
	int rc;
	struct smbfs_dfs_info ref = {};
	struct cifs_sb_info *cifs_sb = mnt_ctx->cifs_sb;
	char *oldmnt = cifs_sb->ctx->mount_options;

	smbfs_dbg("full_path=%s ref_path=%s target=%s\n", full_path, ref_path,
		 dfs_cache_get_tgt_name(tit));

	rc = dfs_cache_get_tgt_referral(ref_path, tit, &ref);
	if (rc)
		goto out;

	rc = expand_dfs_referral(mnt_ctx, full_path, &ref);
	if (rc)
		goto out;

	/* Connect to new target only if we were redirected (e.g. mount options changed) */
	if (oldmnt != cifs_sb->ctx->mount_options) {
		mount_put_conns(mnt_ctx);
		rc = mount_get_dfs_conns(mnt_ctx);
	}
	if (!rc) {
		if (cifs_is_referral_server(mnt_ctx->tcon, &ref))
			set_root_ses(mnt_ctx);
		rc = dfs_cache_update_tgthint(mnt_ctx->xid, mnt_ctx->root_ses, cifs_sb->local_nls,
					      cifs_remap(cifs_sb), ref_path, tit);
	}

out:
	free_dfs_info(&ref);
	return rc;
}

static int connect_dfs_root(struct mount_ctx *mnt_ctx, struct dfs_cache_tgt_list *root_tl)
{
	int rc;
	char *full_path;
	struct cifs_sb_info *cifs_sb = mnt_ctx->cifs_sb;
	struct smb3_fs_context *ctx = mnt_ctx->fs_ctx;
	struct dfs_cache_tgt_iterator *tit;

	/* Put initial connections as they might be shared with other mounts.  We need unique dfs
	 * connections per mount to properly failover, so mount_get_dfs_conns() must be used from
	 * now on.
	 */
	mount_put_conns(mnt_ctx);
	mount_get_dfs_conns(mnt_ctx);
	set_root_ses(mnt_ctx);

	full_path = build_unc_path_to_root(ctx, cifs_sb, true);
	if (IS_ERR(full_path))
		return PTR_ERR(full_path);

	mnt_ctx->origin_fullpath = dfs_cache_canonical_path(ctx->UNC, cifs_sb->local_nls,
							    cifs_remap(cifs_sb));
	if (IS_ERR(mnt_ctx->origin_fullpath)) {
		rc = PTR_ERR(mnt_ctx->origin_fullpath);
		mnt_ctx->origin_fullpath = NULL;
		goto out;
	}

	/* Try all dfs root targets */
	for (rc = -ENOENT, tit = dfs_cache_get_tgt_iterator(root_tl);
	     tit; tit = dfs_cache_get_next_tgt(root_tl, tit)) {
		rc = connect_dfs_target(mnt_ctx, full_path, mnt_ctx->origin_fullpath + 1, tit);
		if (!rc) {
			mnt_ctx->leaf_fullpath = kstrdup(mnt_ctx->origin_fullpath, GFP_KERNEL);
			if (!mnt_ctx->leaf_fullpath)
				rc = -ENOMEM;
			break;
		}
	}

out:
	kfree(full_path);
	return rc;
}

static int __follow_dfs_link(struct mount_ctx *mnt_ctx)
{
	int rc;
	struct cifs_sb_info *cifs_sb = mnt_ctx->cifs_sb;
	struct smb3_fs_context *ctx = mnt_ctx->fs_ctx;
	char *full_path;
	struct dfs_cache_tgt_list tl = DFS_CACHE_TGT_LIST_INIT(tl);
	struct dfs_cache_tgt_iterator *tit;

	full_path = build_unc_path_to_root(ctx, cifs_sb, true);
	if (IS_ERR(full_path))
		return PTR_ERR(full_path);

	kfree(mnt_ctx->leaf_fullpath);
	mnt_ctx->leaf_fullpath = dfs_cache_canonical_path(full_path, cifs_sb->local_nls,
							  cifs_remap(cifs_sb));
	if (IS_ERR(mnt_ctx->leaf_fullpath)) {
		rc = PTR_ERR(mnt_ctx->leaf_fullpath);
		mnt_ctx->leaf_fullpath = NULL;
		goto out;
	}

	/* Get referral from dfs link */
	rc = dfs_cache_find(mnt_ctx->xid, mnt_ctx->root_ses, cifs_sb->local_nls,
			    cifs_remap(cifs_sb), mnt_ctx->leaf_fullpath + 1, NULL, &tl);
	if (rc)
		goto out;

	/* Try all dfs link targets.  If an I/O fails from currently connected DFS target with an
	 * error other than STATUS_PATH_NOT_COVERED (-EREMOTE), then retry it from other targets as
	 * specified in MS-DFSC "3.1.5.2 I/O Operation to Target Fails with an Error Other Than
	 * STATUS_PATH_NOT_COVERED."
	 */
	for (rc = -ENOENT, tit = dfs_cache_get_tgt_iterator(&tl);
	     tit; tit = dfs_cache_get_next_tgt(&tl, tit)) {
		rc = connect_dfs_target(mnt_ctx, full_path, mnt_ctx->leaf_fullpath + 1, tit);
		if (!rc) {
			rc = is_path_remote(mnt_ctx);
			if (!rc || rc == -EREMOTE)
				break;
		}
	}

out:
	kfree(full_path);
	dfs_cache_free_tgts(&tl);
	return rc;
}

static int follow_dfs_link(struct mount_ctx *mnt_ctx)
{
	int rc;
	struct cifs_sb_info *cifs_sb = mnt_ctx->cifs_sb;
	struct smb3_fs_context *ctx = mnt_ctx->fs_ctx;
	char *full_path;
	int num_links = 0;

	full_path = build_unc_path_to_root(ctx, cifs_sb, true);
	if (IS_ERR(full_path))
		return PTR_ERR(full_path);

	kfree(mnt_ctx->origin_fullpath);
	mnt_ctx->origin_fullpath = dfs_cache_canonical_path(full_path, cifs_sb->local_nls,
							    cifs_remap(cifs_sb));
	kfree(full_path);

	if (IS_ERR(mnt_ctx->origin_fullpath)) {
		rc = PTR_ERR(mnt_ctx->origin_fullpath);
		mnt_ctx->origin_fullpath = NULL;
		return rc;
	}

	do {
		rc = __follow_dfs_link(mnt_ctx);
		if (!rc || rc != -EREMOTE)
			break;
	} while (rc = -ELOOP, ++num_links < MAX_NESTED_LINKS);

	return rc;
}

/* Set up DFS referral paths for failover */
static void setup_server_referral_paths(struct mount_ctx *mnt_ctx)
{
	struct smbfs_server_info *server = mnt_ctx->server;

	mutex_lock(&server->refpath_lock);
	server->origin_fullpath = mnt_ctx->origin_fullpath;
	server->leaf_fullpath = mnt_ctx->leaf_fullpath;
	server->current_fullpath = mnt_ctx->leaf_fullpath;
	mutex_unlock(&server->refpath_lock);
	mnt_ctx->origin_fullpath = mnt_ctx->leaf_fullpath = NULL;
}

int cifs_mount(struct cifs_sb_info *cifs_sb, struct smb3_fs_context *ctx)
{
	int rc;
	struct mount_ctx mnt_ctx = { .cifs_sb = cifs_sb, .fs_ctx = ctx, };
	struct dfs_cache_tgt_list tl = DFS_CACHE_TGT_LIST_INIT(tl);
	bool isdfs;

	rc = is_dfs_mount(&mnt_ctx, &isdfs, &tl);
	if (rc)
		goto error;
	if (!isdfs)
		goto out;

	/* proceed as DFS mount */
	uuid_gen(&mnt_ctx.mount_id);
	rc = connect_dfs_root(&mnt_ctx, &tl);
	dfs_cache_free_tgts(&tl);

	if (rc)
		goto error;

	rc = is_path_remote(&mnt_ctx);
	if (rc)
		rc = follow_dfs_link(&mnt_ctx);
	if (rc)
		goto error;

	setup_server_referral_paths(&mnt_ctx);
	/*
	 * After reconnecting to a different server, unique ids won't match anymore, so we disable
	 * serverino. This prevents dentry revalidation to think the dentry are stale (ESTALE).
	 */
	cifs_autodisable_serverino(cifs_sb);
	/*
	 * Force the use of prefix path to support failover on DFS paths that resolve to targets
	 * that have different prefix paths.
	 */
	cifs_sb->mnt_cifs_flags |= CIFS_MOUNT_USE_PREFIX_PATH;
	kfree(cifs_sb->prepath);
	cifs_sb->prepath = ctx->prepath;
	ctx->prepath = NULL;
	uuid_copy(&cifs_sb->dfs_mount_id, &mnt_ctx.mount_id);

out:
	free_xid(mnt_ctx.xid);
	cifs_try_adding_channels(cifs_sb, mnt_ctx.ses);
	return mount_setup_tlink(cifs_sb, mnt_ctx.ses, mnt_ctx.tcon);

error:
	dfs_cache_put_refsrv_sessions(&mnt_ctx.mount_id);
	kfree(mnt_ctx.origin_fullpath);
	kfree(mnt_ctx.leaf_fullpath);
	mount_put_conns(&mnt_ctx);
	return rc;
}
#else
int cifs_mount(struct cifs_sb_info *cifs_sb, struct smb3_fs_context *ctx)
{
	int rc = 0;
	struct mount_ctx mnt_ctx = { .cifs_sb = cifs_sb, .fs_ctx = ctx, };

	rc = mount_get_conns(&mnt_ctx);
	if (rc)
		goto error;

	if (mnt_ctx.tcon) {
		rc = is_path_remote(&mnt_ctx);
		if (rc == -EREMOTE)
			rc = -EOPNOTSUPP;
		if (rc)
			goto error;
	}

	free_xid(mnt_ctx.xid);
	return mount_setup_tlink(cifs_sb, mnt_ctx.ses, mnt_ctx.tcon);

error:
	mount_put_conns(&mnt_ctx);
	return rc;
}
#endif

/*
 * Issue a TREE_CONNECT request.
 */
int
CIFSTCon(const unsigned int xid, struct smbfs_ses *ses,
	 const char *tree, struct smbfs_tcon *tcon,
	 const struct nls_table *nls_codepage)
{
	struct smb_hdr *smb_buffer;
	struct smb_hdr *smb_buffer_response;
	TCONX_REQ *pSMB;
	TCONX_RSP *pSMBr;
	unsigned char *bcc_ptr;
	int rc = 0;
	int length;
	__u16 bytes_left, count;

	if (ses == NULL)
		return -EIO;

	smb_buffer = cifs_buf_get();
	if (smb_buffer == NULL)
		return -ENOMEM;

	smb_buffer_response = smb_buffer;

	header_assemble(smb_buffer, SMB_COM_TREE_CONNECT_ANDX,
			NULL /*no tid */ , 4 /*wct */ );

	smb_buffer->Mid = get_next_mid(ses->server);
	smb_buffer->Uid = ses->id;
	pSMB = (TCONX_REQ *) smb_buffer;
	pSMBr = (TCONX_RSP *) smb_buffer_response;

	pSMB->AndXCommand = 0xFF;
	pSMB->Flags = cpu_to_le16(TCON_EXTENDED_SECINFO);
	bcc_ptr = &pSMB->Password[0];
	if (get_tcon_flag(tcon, IS_PIPE) ||
	    (ses->server->sec.mode & SECMODE_USER)) {
		pSMB->PasswordLength = cpu_to_le16(1);	/* minimum */
		*bcc_ptr = 0; /* password is null byte */
		bcc_ptr++;              /* skip password */
		/* already aligned so no need to do it below */
	}

	if (ses->server->sec.signing_enabled)
		smb_buffer->Flags2 |= SMBFLG2_SECURITY_SIGNATURE;

	if (ses->capabilities & CAP_STATUS32) {
		smb_buffer->Flags2 |= SMBFLG2_ERR_STATUS;
	}
	if (ses->capabilities & CAP_DFS) {
		smb_buffer->Flags2 |= SMBFLG2_DFS;
	}
	if (ses->capabilities & CAP_UNICODE) {
		smb_buffer->Flags2 |= SMBFLG2_UNICODE;
		length =
		    cifs_strtoUTF16((__le16 *) bcc_ptr, tree,
			6 /* max utf8 char length in bytes */ *
			(/* server len*/ + 256 /* share len */), nls_codepage);
		bcc_ptr += 2 * length;	/* convert num 16 bit words to bytes */
		bcc_ptr += 2;	/* skip trailing null */
	} else {		/* ASCII */
		strcpy(bcc_ptr, tree);
		bcc_ptr += strlen(tree) + 1;
	}
	strcpy(bcc_ptr, "?????");
	bcc_ptr += strlen("?????");
	bcc_ptr += 1;
	count = bcc_ptr - &pSMB->Password[0];
	be32_add_cpu(&pSMB->hdr.smb_buf_length, count);
	pSMB->ByteCount = cpu_to_le16(count);

	rc = SendReceive(xid, ses, smb_buffer, smb_buffer_response, &length,
			 0);

	/* above now done in SendReceive */
	if (rc == 0) {
		bool is_unicode;

		tcon->tid = smb_buffer_response->Tid;
		bcc_ptr = pByteArea(smb_buffer_response);
		bytes_left = get_bcc(smb_buffer_response);
		length = strnlen(bcc_ptr, bytes_left - 2);
		if (smb_buffer->Flags2 & SMBFLG2_UNICODE)
			is_unicode = true;
		else
			is_unicode = false;


		/* skip service field (NB: this field is always ASCII) */
		if (length == 3) {
			if ((bcc_ptr[0] == 'I') && (bcc_ptr[1] == 'P') &&
			    (bcc_ptr[2] == 'C')) {
				smbfs_dbg("IPC connection\n");
				set_tcon_flag(tcon, IS_IPC);
				set_tcon_flag(tcon, IS_PIPE);
			}
		} else if (length == 2) {
			if ((bcc_ptr[0] == 'A') && (bcc_ptr[1] == ':')) {
				/* the most common case */
				smbfs_dbg("disk share connection\n");
			}
		}
		bcc_ptr += length + 1;
		bytes_left -= (length + 1);
		strlcpy(tcon->tree_name, tree, sizeof(tcon->tree_name));

		/* mostly informational -- no need to fail on error here */
		kfree(tcon->native_fs);
		tcon->native_fs = cifs_strndup_from_utf16(bcc_ptr,
						      bytes_left, is_unicode,
						      nls_codepage);

		smbfs_dbg("native_fs=%s\n", tcon->native_fs);

		if ((smb_buffer_response->WordCount == 3) ||
			 (smb_buffer_response->WordCount == 7))
			/* field is in same location */
			tcon->flags = le16_to_cpu(pSMBr->OptionalSupport);
		else
			tcon->flags = 0;
		smbfs_dbg("tcon flags: 0x%lx\n", tcon->flags);
	}

	cifs_buf_release(smb_buffer);
	return rc;
}

static void delayed_free(struct rcu_head *p)
{
	struct cifs_sb_info *cifs_sb = container_of(p, struct cifs_sb_info, rcu);

	unload_nls(cifs_sb->local_nls);
	smb3_cleanup_fs_context(cifs_sb->ctx);
	kfree(cifs_sb);
}

void
cifs_umount(struct cifs_sb_info *cifs_sb)
{
	struct rb_root *root = &cifs_sb->tlink_tree;
	struct rb_node *node;
	struct smbfs_tcon_link *tlink;

	cancel_delayed_work_sync(&cifs_sb->prune_tlinks);

	spin_lock(&cifs_sb->tlink_tree_lock);
	while ((node = rb_first(root))) {
		tlink = rb_entry(node, struct smbfs_tcon_link, rbnode);
		smbfs_get_tlink(tlink);
		clear_bit(TCON_LINK_IN_TREE, &tlink->flags);
		rb_erase(node, root);

		spin_unlock(&cifs_sb->tlink_tree_lock);
		smbfs_put_tlink(tlink);
		spin_lock(&cifs_sb->tlink_tree_lock);
	}
	spin_unlock(&cifs_sb->tlink_tree_lock);

	kfree(cifs_sb->prepath);
#ifdef CONFIG_SMBFS_DFS_UPCALL
	dfs_cache_put_refsrv_sessions(&cifs_sb->dfs_mount_id);
#endif
	call_rcu(&cifs_sb->rcu, delayed_free);
}

int
cifs_negotiate_protocol(const unsigned int xid, struct smbfs_ses *ses,
			struct smbfs_server_info *server)
{
	int rc = 0;

	if (!server->ops->need_neg || !server->ops->negotiate)
		return -ENOSYS;

	/* only send once per connect */
	spin_lock(&g_servers_lock);
	if (!server->ops->need_neg(server) ||
	    server->status != SMBFS_STATUS_NEED_NEGOTIATE) {
		spin_unlock(&g_servers_lock);
		return 0;
	}
	server->status = SMBFS_STATUS_IN_NEGOTIATE;
	spin_unlock(&g_servers_lock);

	rc = server->ops->negotiate(xid, ses, server);
	if (rc == 0) {
		spin_lock(&g_servers_lock);
		if (server->status == SMBFS_STATUS_IN_NEGOTIATE)
			server->status = SMBFS_STATUS_GOOD;
		else
			rc = -EHOSTDOWN;
		spin_unlock(&g_servers_lock);
	} else {
		spin_lock(&g_servers_lock);
		if (server->status == SMBFS_STATUS_IN_NEGOTIATE)
			server->status = SMBFS_STATUS_NEED_NEGOTIATE;
		spin_unlock(&g_servers_lock);
	}

	return rc;
}

int
cifs_setup_session(const unsigned int xid, struct smbfs_ses *ses,
		   struct smbfs_server_info *server,
		   struct nls_table *nls_info)
{
	int rc = -ENOSYS;
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&server->dstaddr;
	struct sockaddr_in *addr = (struct sockaddr_in *)&server->dstaddr;
	bool is_binding = false;

	spin_lock(&g_servers_lock);
	if (server->dstaddr.ss_family == AF_INET6)
		scnprintf(ses->ip_addr, sizeof(ses->ip_addr), "%pI6", &addr6->sin6_addr);
	else
		scnprintf(ses->ip_addr, sizeof(ses->ip_addr), "%pI4", &addr->sin_addr);

	if (ses->status != SMBFS_SES_STATUS_GOOD &&
	    ses->status != SMBFS_SES_STATUS_NEW &&
	    ses->status != SMBFS_SES_STATUS_NEED_RECONNECT) {
		spin_unlock(&g_servers_lock);
		return 0;
	}

	/* only send once per connect */
	spin_lock(&ses->channel_lock);
	if (ALL_CHANNELS_GOOD(ses) ||
	    smbfs_channel_in_reconnect(ses, server)) {
		spin_unlock(&ses->channel_lock);
		spin_unlock(&g_servers_lock);
		return 0;
	}
	is_binding = !ALL_CHANNELS_NEED_RECONNECT(ses);
	smbfs_channel_set_in_reconnect(ses, server);
	spin_unlock(&ses->channel_lock);

	if (!is_binding)
		ses->status = SMBFS_SES_STATUS_IN_SETUP;
	spin_unlock(&g_servers_lock);

	if (!is_binding) {
		ses->capabilities = server->capabilities;
		if (!unix_extensions)
			ses->capabilities &= (~server->settings->cap_unix);

		if (ses->auth_key.response) {
			smbfs_dbg("Free previous auth_key.response 0x%p\n", ses->auth_key.response);
			kfree(ses->auth_key.response);
			ses->auth_key.response = NULL;
			ses->auth_key.len = 0;
		}
	}

	smbfs_dbg("Security Mode: 0x%x Capabilities: 0x%lx TimeAdjust: %d\n",
		  server->sec.mode, server->capabilities, server->time_adjust);

	if (server->ops->sess_setup)
		rc = server->ops->sess_setup(xid, ses, server, nls_info);

	if (rc) {
		smbfs_server_log(server, "Send error in SessSetup, rc=%d\n", rc);
		spin_lock(&g_servers_lock);
		if (ses->status == SMBFS_SES_STATUS_IN_SETUP)
			ses->status = SMBFS_SES_STATUS_NEED_RECONNECT;
		spin_lock(&ses->channel_lock);
		smbfs_channel_clear_in_reconnect(ses, server);
		spin_unlock(&ses->channel_lock);
		spin_unlock(&g_servers_lock);
	} else {
		spin_lock(&g_servers_lock);
		if (ses->status == SMBFS_SES_STATUS_IN_SETUP)
			ses->status = SMBFS_SES_STATUS_GOOD;
		spin_lock(&ses->channel_lock);
		smbfs_channel_clear_in_reconnect(ses, server);
		smbfs_channel_clear_need_reconnect(ses, server);
		spin_unlock(&ses->channel_lock);
		spin_unlock(&g_servers_lock);
	}

	return rc;
}

static int
cifs_set_vol_auth(struct smb3_fs_context *ctx, struct smbfs_ses *ses)
{
	ctx->sectype = ses->sectype;

	/* krb5 is special, since we don't need username or pw */
	if (ctx->sectype == SMBFS_SECURITY_KERBEROS)
		return 0;

	return cifs_set_cifscreds(ctx, ses);
}

static struct smbfs_tcon *
cifs_construct_tcon(struct cifs_sb_info *cifs_sb, kuid_t fsuid)
{
	int rc;
	struct smbfs_tcon *master_tcon = smbfs_sb_master_tcon(cifs_sb);
	struct smbfs_ses *ses;
	struct smbfs_tcon *tcon = NULL;
	struct smb3_fs_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (ctx == NULL)
		return ERR_PTR(-ENOMEM);

	ctx->local_nls = cifs_sb->local_nls;
	ctx->linux_uid = fsuid;
	ctx->cred_uid = fsuid;
	ctx->UNC = master_tcon->tree_name;
	ctx->retry = master_tcon->retry;
	ctx->nocase = get_tcon_flag(master_tcon, NOCASE);
	ctx->nohandlecache = get_tcon_flag(master_tcon, NOHANDLECACHE);
	ctx->local_lease = get_tcon_flag(master_tcon, CHECK_LOCAL_LEASE);
	ctx->no_lease = get_tcon_flag(master_tcon, NO_LEASE);
	ctx->resilient = get_tcon_flag(master_tcon, USE_RESILIENT);
	ctx->persistent = get_tcon_flag(master_tcon, USE_PERSISTENT);
	ctx->handle_timeout = master_tcon->handle_timeout;
	ctx->no_linux_ext = !get_tcon_flag(master_tcon, USE_POSIX_EXT);
	ctx->linux_ext = get_tcon_flag(master_tcon, USE_POSIX_EXT);
	ctx->sectype = master_tcon->ses->sectype;
	ctx->sign = master_tcon->ses->signing_required;
	ctx->seal = get_tcon_flag(master_tcon, USE_SEAL);
	ctx->witness = get_tcon_flag(master_tcon, USE_WITNESS);

	rc = cifs_set_vol_auth(ctx, master_tcon->ses);
	if (rc) {
		tcon = ERR_PTR(rc);
		goto out;
	}

	/* get a reference for the same TCP session */
	spin_lock(&g_servers_lock);
	++master_tcon->ses->server->count;
	spin_unlock(&g_servers_lock);

	ses = cifs_get_smb_ses(master_tcon->ses->server, ctx);
	if (IS_ERR(ses)) {
		tcon = (struct smbfs_tcon *)ses;
		smbfs_put_server(master_tcon->ses->server, 0);
		goto out;
	}

	tcon = smbfs_get_tcon(ses, ctx);
	if (IS_ERR(tcon)) {
		cifs_put_smb_ses(ses);
		goto out;
	}

	if (has_cap_unix(ses))
		reset_cifs_unix_caps(0, tcon, NULL, ctx);

out:
	kfree(ctx->username);
	kfree_sensitive(ctx->password);
	kfree(ctx);

	return tcon;
}

/* find and return a tlink with given uid */
static struct smbfs_tcon_link *
tlink_rb_search(struct rb_root *root, kuid_t uid)
{
	struct rb_node *node = root->rb_node;
	struct smbfs_tcon_link *tlink;

	while (node) {
		tlink = rb_entry(node, struct smbfs_tcon_link, rbnode);

		if (uid_gt(tlink->uid, uid))
			node = node->rb_left;
		else if (uid_lt(tlink->uid, uid))
			node = node->rb_right;
		else
			return tlink;
	}
	return NULL;
}

/* insert a tcon_link into the tree */
static void
tlink_rb_insert(struct rb_root *root, struct smbfs_tcon_link *new_tlink)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct smbfs_tcon_link *tlink;

	while (*new) {
		tlink = rb_entry(*new, struct smbfs_tcon_link, rbnode);
		parent = *new;

		if (uid_gt(tlink->uid, new_tlink->uid))
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
	}

	rb_link_node(&new_tlink->rbnode, parent, new);
	rb_insert_color(&new_tlink->rbnode, root);
}

/*
 * Find or construct an appropriate tcon given a cifs_sb and the fsuid of the
 * current task.
 *
 * If the superblock doesn't refer to a multiuser mount, then just return
 * the master tcon for the mount.
 *
 * First, search the rbtree for an existing tcon for this fsuid. If one
 * exists, then check to see if it's pending construction. If it is then wait
 * for construction to complete. Once it's no longer pending, check to see if
 * it failed and either return an error or retry construction, depending on
 * the timeout.
 *
 * If one doesn't exist then insert a new tcon_link struct into the tree and
 * try to construct a new one.
 */
struct smbfs_tcon_link *
smbfs_sb_tlink(struct cifs_sb_info *cifs_sb)
{
	int ret;
	kuid_t fsuid = current_fsuid();
	struct smbfs_tcon_link *tlink, *newtlink;

	if (!(cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MULTIUSER))
		return smbfs_get_tlink(smbfs_sb_master_tlink(cifs_sb));

	spin_lock(&cifs_sb->tlink_tree_lock);
	tlink = tlink_rb_search(&cifs_sb->tlink_tree, fsuid);
	if (tlink)
		smbfs_get_tlink(tlink);
	spin_unlock(&cifs_sb->tlink_tree_lock);

	if (tlink == NULL) {
		newtlink = kzalloc(sizeof(*tlink), GFP_KERNEL);
		if (newtlink == NULL)
			return ERR_PTR(-ENOMEM);
		newtlink->uid = fsuid;
		newtlink->tcon = ERR_PTR(-EACCES);
		set_bit(TCON_LINK_PENDING, &newtlink->flags);
		set_bit(TCON_LINK_IN_TREE, &newtlink->flags);
		smbfs_get_tlink(newtlink);

		spin_lock(&cifs_sb->tlink_tree_lock);
		/* was one inserted after previous search? */
		tlink = tlink_rb_search(&cifs_sb->tlink_tree, fsuid);
		if (tlink) {
			smbfs_get_tlink(tlink);
			spin_unlock(&cifs_sb->tlink_tree_lock);
			kfree(newtlink);
			goto wait_for_construction;
		}
		tlink = newtlink;
		tlink_rb_insert(&cifs_sb->tlink_tree, tlink);
		spin_unlock(&cifs_sb->tlink_tree_lock);
	} else {
wait_for_construction:
		ret = wait_on_bit(&tlink->flags, TCON_LINK_PENDING,
				  TASK_INTERRUPTIBLE);
		if (ret) {
			smbfs_put_tlink(tlink);
			return ERR_PTR(-ERESTARTSYS);
		}

		/* if it's good, return it */
		if (!IS_ERR(tlink->tcon))
			return tlink;

		/* return error if we tried this already recently */
		if (time_before(jiffies, tlink->time + TLINK_ERROR_EXPIRE)) {
			smbfs_put_tlink(tlink);
			return ERR_PTR(-EACCES);
		}

		if (test_and_set_bit(TCON_LINK_PENDING, &tlink->flags))
			goto wait_for_construction;
	}

	tlink->tcon = cifs_construct_tcon(cifs_sb, fsuid);
	clear_bit(TCON_LINK_PENDING, &tlink->flags);
	wake_up_bit(&tlink->flags, TCON_LINK_PENDING);

	if (IS_ERR(tlink->tcon)) {
		smbfs_put_tlink(tlink);
		return ERR_PTR(-EACCES);
	}

	return tlink;
}

#ifdef CONFIG_SMBFS_DFS_UPCALL
/* Update dfs referral path of superblock */
static int update_server_fullpath(struct smbfs_server_info *server, struct cifs_sb_info *cifs_sb,
				  const char *target)
{
	int rc = 0;
	size_t len = strlen(target);
	char *refpath, *npath;

	if (unlikely(len < 2 || *target != '\\'))
		return -EINVAL;

	if (target[1] == '\\') {
		len += 1;
		refpath = kmalloc(len, GFP_KERNEL);
		if (!refpath)
			return -ENOMEM;

		scnprintf(refpath, len, "%s", target);
	} else {
		len += sizeof("\\");
		refpath = kmalloc(len, GFP_KERNEL);
		if (!refpath)
			return -ENOMEM;

		scnprintf(refpath, len, "\\%s", target);
	}

	npath = dfs_cache_canonical_path(refpath, cifs_sb->local_nls, cifs_remap(cifs_sb));
	kfree(refpath);

	if (IS_ERR(npath)) {
		rc = PTR_ERR(npath);
	} else {
		mutex_lock(&server->refpath_lock);
		kfree(server->leaf_fullpath);
		server->leaf_fullpath = npath;
		mutex_unlock(&server->refpath_lock);
		server->current_fullpath = server->leaf_fullpath;
	}
	return rc;
}

static int target_share_matches_server(struct smbfs_server_info *server, const char *tcp_host,
				       size_t tcp_host_len, char *share, bool *target_match)
{
	int rc = 0;
	const char *dfs_host;
	size_t dfs_host_len;

	*target_match = true;
	extract_unc_hostname(share, &dfs_host, &dfs_host_len);

	/* Check if hostnames or addresses match */
	if (dfs_host_len != tcp_host_len || strncasecmp(dfs_host, tcp_host, dfs_host_len) != 0) {
		smbfs_dbg("%.*s doesn't match %.*s\n", (int)dfs_host_len, dfs_host,
						       (int)tcp_host_len, tcp_host);
		rc = match_target_ip(server, dfs_host, dfs_host_len, target_match);
		if (rc)
			smbfs_log("%s: failed to match target ip, rc=%d\n", __func__, rc);
	}
	return rc;
}

static int __tree_connect_dfs_target(const unsigned int xid, struct smbfs_tcon *tcon,
				     struct cifs_sb_info *cifs_sb, char *tree, bool islink,
				     struct dfs_cache_tgt_list *tl)
{
	int rc;
	struct smbfs_server_info *server = tcon->ses->server;
	const struct smbfs_operations *ops = server->ops;
	struct smbfs_tcon *ipc = tcon->ses->tcon_ipc;
	char *share = NULL, *prefix = NULL;
	const char *tcp_host;
	size_t tcp_host_len;
	struct dfs_cache_tgt_iterator *tit;
	bool target_match;

	extract_unc_hostname(server->hostname, &tcp_host, &tcp_host_len);

	tit = dfs_cache_get_tgt_iterator(tl);
	if (!tit) {
		rc = -ENOENT;
		goto out;
	}

	/* Try to tree connect to all dfs targets */
	for (; tit; tit = dfs_cache_get_next_tgt(tl, tit)) {
		const char *target = dfs_cache_get_tgt_name(tit);
		struct dfs_cache_tgt_list ntl = DFS_CACHE_TGT_LIST_INIT(ntl);

		kfree(share);
		kfree(prefix);
		share = prefix = NULL;

		/* Check if share matches with tcp ses */
		rc = dfs_cache_get_tgt_share(server->current_fullpath + 1, tit, &share, &prefix);
		if (rc) {
			smbfs_log("%s: failed to parse target share, rc=%d\n", __func__, rc);
			break;
		}

		rc = target_share_matches_server(server, tcp_host, tcp_host_len, share,
						 &target_match);
		if (rc)
			break;
		if (!target_match) {
			rc = -EHOSTUNREACH;
			continue;
		}

		if (ipc->need_reconnect) {
			scnprintf(tree, SMBFS_MAX_TREE_SIZE, "\\\\%s\\IPC$", server->hostname);
			rc = ops->tree_connect(xid, ipc->ses, tree, ipc, cifs_sb->local_nls);
			if (rc)
				break;
		}

		scnprintf(tree, SMBFS_MAX_TREE_SIZE, "\\%s", share);
		if (!islink) {
			rc = ops->tree_connect(xid, tcon->ses, tree, tcon, cifs_sb->local_nls);
			break;
		}
		/*
		 * If no dfs referrals were returned from link target, then just do a TREE_CONNECT
		 * to it.  Otherwise, cache the dfs referral and then mark current tcp ses for
		 * reconnect so either the demultiplex thread or the echo worker will reconnect to
		 * newly resolved target.
		 */
		if (dfs_cache_find(xid, tcon->ses, cifs_sb->local_nls, cifs_remap(cifs_sb), target,
				   NULL, &ntl)) {
			rc = ops->tree_connect(xid, tcon->ses, tree, tcon, cifs_sb->local_nls);
			if (rc)
				continue;
			rc = dfs_cache_noreq_update_tgthint(server->current_fullpath + 1, tit);
			if (!rc)
				rc = cifs_update_super_prepath(cifs_sb, prefix);
		} else {
			/* Target is another dfs share */
			rc = update_server_fullpath(server, cifs_sb, target);
			dfs_cache_free_tgts(tl);

			if (!rc) {
				rc = -EREMOTE;
				list_replace_init(&ntl.tl_list, &tl->tl_list);
			} else
				dfs_cache_free_tgts(&ntl);
		}
		break;
	}

out:
	kfree(share);
	kfree(prefix);

	return rc;
}

static int tree_connect_dfs_target(const unsigned int xid, struct smbfs_tcon *tcon,
				   struct cifs_sb_info *cifs_sb, char *tree, bool islink,
				   struct dfs_cache_tgt_list *tl)
{
	int rc;
	int num_links = 0;
	struct smbfs_server_info *server = tcon->ses->server;

	do {
		rc = __tree_connect_dfs_target(xid, tcon, cifs_sb, tree, islink, tl);
		if (!rc || rc != -EREMOTE)
			break;
	} while (rc = -ELOOP, ++num_links < MAX_NESTED_LINKS);
	/*
	 * If we couldn't tree connect to any targets from last referral path, then retry from
	 * original referral path.
	 */
	if (rc && server->current_fullpath != server->origin_fullpath) {
		server->current_fullpath = server->origin_fullpath;
		cifs_signal_cifsd_for_reconnect(server, true);
	}

	dfs_cache_free_tgts(tl);
	return rc;
}

int cifs_tree_connect(const unsigned int xid, struct smbfs_tcon *tcon, const struct nls_table *nlsc)
{
	int rc;
	struct smbfs_server_info *server = tcon->ses->server;
	const struct smbfs_operations *ops = server->ops;
	struct super_block *sb = NULL;
	struct cifs_sb_info *cifs_sb;
	struct dfs_cache_tgt_list tl = DFS_CACHE_TGT_LIST_INIT(tl);
	char *tree;
	struct smbfs_dfs_info ref = {0};

	/* only send once per connect */
	spin_lock(&g_servers_lock);
	if (tcon->ses->status != SMBFS_SES_STATUS_GOOD ||
	    (tcon->status != SMBFS_TCON_STATUS_NEW &&
	    tcon->status != SMBFS_TCON_STATUS_NEED_TCON)) {
		spin_unlock(&g_servers_lock);
		return 0;
	}
	tcon->status = SMBFS_TCON_STATUS_IN_TCON;
	spin_unlock(&g_servers_lock);

	tree = kzalloc(SMBFS_MAX_TREE_SIZE, GFP_KERNEL);
	if (!tree) {
		rc = -ENOMEM;
		goto out;
	}

	if (get_tcon_flag(tcon, IS_IPC)) {
		scnprintf(tree, SMBFS_MAX_TREE_SIZE, "\\\\%s\\IPC$", server->hostname);
		rc = ops->tree_connect(xid, tcon->ses, tree, tcon, nlsc);
		goto out;
	}

	sb = cifs_get_tcp_super(server);
	if (IS_ERR(sb)) {
		rc = PTR_ERR(sb);
		smbfs_log("%s: could not find superblock, rc=%d\n", __func__, rc);
		goto out;
	}

	cifs_sb = CIFS_SB(sb);

	/* If it is not dfs or there was no cached dfs referral, then reconnect to same share */
	if (!server->current_fullpath ||
	    dfs_cache_noreq_find(server->current_fullpath + 1, &ref, &tl)) {
		rc = ops->tree_connect(xid, tcon->ses, tcon->tree_name, tcon, cifs_sb->local_nls);
		goto out;
	}

	rc = tree_connect_dfs_target(xid, tcon, cifs_sb, tree, ref.server_type == DFS_TYPE_LINK,
				     &tl);
	free_dfs_info(&ref);

out:
	kfree(tree);
	cifs_put_tcp_super(sb);

	if (rc) {
		spin_lock(&g_servers_lock);
		if (tcon->status == SMBFS_TCON_STATUS_IN_TCON)
			tcon->status = SMBFS_TCON_STATUS_NEED_TCON;
		spin_unlock(&g_servers_lock);
	} else {
		spin_lock(&g_servers_lock);
		if (tcon->status == SMBFS_TCON_STATUS_IN_TCON)
			tcon->status = SMBFS_TCON_STATUS_GOOD;
		spin_unlock(&g_servers_lock);
		clear_tcon_flag(tcon, NEED_RECONNECT);
	}

	return rc;
}
#else
int cifs_tree_connect(const unsigned int xid, struct smbfs_tcon *tcon, const struct nls_table *nlsc)
{
	int rc;
	const struct smbfs_operations *ops = tcon->ses->server->ops;

	/* only send once per connect */
	spin_lock(&g_servers_lock);
	if (tcon->ses->status != SMBFS_SES_STATUS_GOOD ||
	    (tcon->status != SMBFS_TCON_STATUS_NEW &&
	    tcon->status != SMBFS_TCON_STATUS_NEED_TCON)) {
		spin_unlock(&g_servers_lock);
		return 0;
	}
	tcon->status = SMBFS_TCON_STATUS_IN_TCON;
	spin_unlock(&g_servers_lock);

	rc = ops->tree_connect(xid, tcon->ses, tcon->tree_name, tcon, nlsc);
	if (rc) {
		spin_lock(&g_servers_lock);
		if (tcon->status == SMBFS_TCON_STATUS_IN_TCON)
			tcon->status = SMBFS_TCON_STATUS_NEED_TCON;
		spin_unlock(&g_servers_lock);
	} else {
		spin_lock(&g_servers_lock);
		if (tcon->status == SMBFS_TCON_STATUS_IN_TCON)
			tcon->status = SMBFS_TCON_STATUS_GOOD;
		spin_unlock(&g_servers_lock);
		clear_tcon_flag(tcon, NEED_RECONNECT);
	}

	return rc;
}
#endif
