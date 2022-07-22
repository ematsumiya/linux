// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) SUSE LLC, 2022
 *
 * Author(s): Enzo Matsumiya <ematsumiya@suse.de>
 *
 * SMBFS server info definition, helpers, and related functions.
 */
#ifndef _SMBFS_SERVER_INFO_H
#define _SMBFS_SERVER_INFO_H

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/workqueue.h>
#include <linux/utsname.h>
#include <linux/sched/mm.h>
#include <linux/netfs.h>
#include <crypto/internal/hash.h>
#include <linux/scatterlist.h>
#include <uapi/linux/cifs/cifs_mount.h>

#include "../smbfs_common/smb2pdu.h"
#include "smb2pdu.h"
#include "cifs_fs_sb.h"
#include "cifsacl.h"
#include "ses.h"

#define RFC1001_NAME_LEN	15
#define RFC1001_NAME_LEN_NUL	(RFC1001_NAME_LEN + 1)

typedef enum smbfs_status {
	SMBFS_STATUS_NEW = 0,
	SMBFS_STATUS_GOOD,
	SMBFS_STATUS_EXITING,
	SMBFS_STATUS_NEED_RECONNECT,
	SMBFS_STATUS_NEED_NEGOTIATE,
	SMBFS_STATUS_IN_NEGOTIATE,
} smbfs_status_t;

/*
 * List of smbfs_server_info structures
 *
 * i.e. each of the sockets connecting our client to a distinct server
 * (IP address), is chained together by this list. The list of all SMB
 * sessions (and from that, the tree connections) can be found by iterating
 * over this list as well.
 */
struct list_head g_servers_list;

/*
 * This lock protects the g_servers_list, the list of SMB sessions per
 * server, and the list of tcon's per SMB session. It also protects
 * the reference counters for the server, SMB session, and tcon. It also
 * protects some fields in the smbfs_server_info struct such as dstaddr.
 *
 * Finally, changes to the tcon->status should be done while holding this lock.
 *
 * Generally the locks should be taken in order:
 *
 *   smbfs_server_lock before tcon->open_files_lock, and that before,
 *   file->file_info_lock since the structure order is
 *   cifs_socket -> smbfs_ses -> smbfs_tcon -> smbfs_file
 */
spinlock_t g_servers_lock;

struct smbfs_operations;
struct smbfs_server_settings;
struct smbfs_server_info {
	struct mutex lock;
	struct task_struct *task;
#ifdef CONFIG_NET_NS
	struct net *net;
#endif
	struct list_head head;
	struct list_head sessions; /* session list */
	u64 conn_id; /* connection identifier (useful for debugging) */
	unsigned int count; /* reference counter */
	u16 dialect; /* dialect index that server chose */

	char *hostname; /* hostname portion of UNC string */
	/* 15 character server name + 0x20 16th byte indicating type = srv */
	char rfc1001_name[RFC1001_NAME_LEN_NUL];

	char *smallbuf; /* pointer to current "small" buffer */
	char *bigbuf; /* pointer to current "big" buffer */

	struct smbfs_operations *ops;
	struct smbfs_server_settings *settings;
	struct smbfs_server_sec sec; /* see security.h */

	/* updates to ->status are protected by smbfs_server_lock */
	smbfs_status_t status; /* what we think the status is */

	struct socket *ssocket;
	struct sockaddr_storage dstaddr;
	struct sockaddr_storage srcaddr; /* locally bind to this IP */

	wait_queue_head_t response_q;
	wait_queue_head_t request_q; /* if more than maxmpx to server must block*/
	struct list_head pending_mids;

	unsigned long flags;
#define SMBFS_SERVER_SESS_ESTAB		0x0001 /* set when very first sess is established */
#define SMBFS_SERVER_NOBLOCKSND		0x0002 /* use blocking sendmsg */
#define SMBFS_SERVER_NOAUTOTUNE		0x0004 /* do not autotune send buf sizes */
#define SMBFS_SERVER_NOSHARESOCK	0x0008
#define SMBFS_SERVER_NOBLOCKCNT		0x0010 /* use non-blocking connect() */
#define SMBFS_SERVER_TCP_NODELAY	0x0020
#define SMBFS_SERVER_USE_OPLOCKS	0x0040 /* enable oplocks */
#define SMBFS_SERVER_USE_ECHOES		0x0080 /* enable echoes */
#define SMBFS_SERVER_HAS_LARGE_BUF	0x0100 /* is current buffer large? */
#define SMBFS_SERVER_HAS_RDMA		0x0200 /* use SMB Direct connection instead of socket */
#define SMBFS_SERVER_SIGNING_ENABLED	0x0400
#define SMBFS_SERVER_HAS_POSIX_EXT	0x0800
#ifdef CONFIG_SMBFS_SWN_UPCALL
#define SMBFS_SERVER_USE_SWN_DSTADDR	0x1000
#endif /* CONFIG_SMBFS_SWN_UPCALL */
#ifdef CONFIG_SMBFS_DFS_UPCALL
#define SMBFS_SERVER_IS_DFS		0x2000 /* is a DFS connection */
#endif /* CONFIG_SMBFS_DFS_UPCALL */

	int echo_credits; /* echo reserved slots */
	int oplock_credits; /* oplock break reserved slots */

	spinlock_t req_lock; /* protect ->in_flight and ->credits */
	u32 credits; /* number of requests to send at once */
	u32 max_credits; /* can override large 32000 default at mount */
	u32 in_flight; /* number of requests on the wire to server */
	u32 max_in_flight; /* max number of requests that were on wire */

	unsigned int nofs; /* nofs flag for memalloc_nofs_save/restore() */
	char guid[16]; /* server GUID */
	u8 client_guid[SMB2_CLIENT_GUID_SIZE]; /* client GUID */

	unsigned long capabilities; /* selective disabling of caps by SMB sess */
	unsigned long echo_interval;
	int time_adjust; /* adjust for difference in server time zone (in sec) */
	u64 current_mid; /* rotating counter, protected by g_mid_lock */
	char rfc1001_client_name[RFC1001_NAME_LEN_NUL]; /* 16th byte always NULL */
	u32 seqn; /* for signing, protected by ->lock */
	u32 reconnects; /* incremented on each reconnect */
	u64 last_resp; /* when we got last response from this server */

	u16 neg_flavor; /* negotiate response flavor */
#define	SMBFS_NEG_FLAVOR_UNENCAP 1 /* wct == 17, but no ext_sec */
#define	SMBFS_NEG_FLAVOR_EXTENDED 2 /* wct == 17, ext_sec bit set */

	/* point to the SMB Direct connection if RDMA is used instead of socket */
	struct smbd_connection *smbd_conn;

	/* only valid from demultiplex thread */
	u32 pdu_size;
	u32 total_read; /* total amount of data read in this pass */
	atomic_t in_send; /* requests trying to send */
	atomic_t in_queue; /* blocked waiting to get in sendrecv */
#ifdef CONFIG_SMBFS_STATS_EXTRA
	atomic_t num_cmds[SMB2_MAX_CMDS]; /* total requests by cmd */
	atomic_t slow_cmds[SMB2_MAX_CMDS]; /* count resps > 1 sec */
	u64 time_per_cmd[SMB2_MAX_CMDS]; /* total time per cmd */
	u32 slowest_cmd[SMB2_MAX_CMDS];
	u32 fastest_cmd[SMB2_MAX_CMDS];
#endif /* SMBFS_STATS_EXTRA */
	u32 max_read;
	u32 max_write;
	u32 min_offload;

	u32 max_reqs; /* max requests to submit */
	/*
	 * specifies the maximum message size the server can send or receive
	 * for non-raw SMBs
	 *
	 * it's returned by SMB NegotiateProtocol so it's only 0 when socket
	 * is setup (and during reconnect) before NegProt sent
	 */
	u32 max_buf;
	/*
	 * specifies the maximum message size the server can send or receive
	 * for SMB_COM_WRITE_RAW or SMB_COM_READ_RAW
	 */
	u32 max_raw;

	struct delayed_work echo;
	struct delayed_work resolve; /* dns resolution worker */
	struct delayed_work reconnect; /* reconnect workqueue job */
	struct mutex reconnect_lock; /* prevent simultaneous reconnects */

	/*
	 * Number of targets available for reconnect. The more targets
	 * the more tasks have to wait to let the demultiplex thread
	 * reconnect.
	 */
	int nr_targets;

	/*
	 * If this is a session channel, .primary holds the refcounted
	 * pointer to primary channel connection for the session.
	 */
#define IS_CHANNEL(server) (!!(server)->primary)
	struct smbfs_server_info *primary;

#ifdef CONFIG_SMBFS_SWN_UPCALL
	struct sockaddr_storage swn_dstaddr;
#endif /* CONFIG_SMBFS_SWN_UPCALL */
#ifdef CONFIG_SMBFS_DFS_UPCALL
	struct mutex refpath_lock; /* protects leaf_fullpath */
	/*
	 * Canonical DFS full paths that were used to chase referrals in
	 * mount and reconnect.
	 *
	 * origin_fullpath: first or original referral path
	 * leaf_fullpath: last referral path (might be changed due to
	 *		  nested links in reconnect)
	 * current_fullpath: pointer to either origin_fullpath or leaf_fullpath
	 *
	 * NOTE: cannot be accessed outside cifs_reconnect() and smb2_reconnect()
	 *
	 * format: \\HOST\SHARE\[OPTIONAL PATH]
	 */
	char *origin_fullpath, *leaf_fullpath, *current_fullpath;
#endif /* CONFIG_SMBFS_DFS_UPCALL */
};

struct smbfs_server_settings {
	const char *version_string;
	const u16 protocol_id;
	u16 req_capabilities;
	u16 large_lock_type;
	u16 exclusive_lock_type;
	u16 shared_lock_type;
	u16 unlock_lock_type;
	size_t header_preamble_size;
	size_t header_size;
	size_t max_header_size;
	size_t read_rsp_size;
	__le16 lock_cmd;
	u32 cap_unix;
	u32 cap_nt_find;
	u32 cap_large_files;
	u16 signing_enabled;
	u16 signing_required;
	size_t create_lease_size;
};

/* flag sans "SMBFS_SERVER_" prefix */
#define set_server_flag(_s, _flag) set_bit(SMBFS_SERVER_ ## _flag, &_s->flags)
#define get_server_flag(_s, _flag) test_bit(SMBFS_SERVER_ ## _flag, &_s->flags)
#define clear_server_flag(_s, _flag) clear_bit(SMBFS_SERVER_ ## _flag, &_s->flags)

inline bool has_cap_unix(struct smbfs_ses *ses)
{
	return ses->server->settings->cap_unix & ses->capabilities;
}

static inline size_t ntlmssp_client_name_size(const struct smbfs_ses *ses)
{
	if (WARN_ON_ONCE(!ses || !ses->server))
		return 0;

	/*
	 * Make client name no more than 15 chars when using insecure
	 * dialects as some legacy servers do require it during NTLMSSP.
	 */
	if (ses->server->dialect <= SMB20_PROT_ID)
		return min_t(size_t, sizeof(ses->client_name),
			     RFC1001_NAME_LEN_NUL);
	return sizeof(ses->client_name);
}

inline void smbfs_server_lock(struct smbfs_server_info *server)
{
	unsigned int nofs = memalloc_nofs_save();

	mutex_lock(&server->lock);
	server->nofs = nofs;
}

inline void smbfs_server_unlock(struct smbfs_server_info *server)
{
	unsigned int nofs = server->nofs;

	mutex_unlock(&server->lock);
	memalloc_nofs_restore(nofs);
}

inline u32 in_flight(struct smbfs_server_info *server)
{
	u32 n;
	spin_lock(&server->req_lock);
	n = server->in_flight;
	spin_unlock(&server->req_lock);
	return n;
}

struct smbfs_credits {
	unsigned int value;
	unsigned int instance;
};

inline bool has_credits(struct smbfs_server_info *server, int *credits,
			int cur_credits)
{
	int n;
	spin_lock(&server->req_lock);
	n = *credits;
	spin_unlock(&server->req_lock);
	return n >= cur_credits;
}

inline void add_credits(struct smbfs_server_info *server,
			const struct smbfs_credits *credits, const int optype)
{
	server->ops->add_credits(server, credits, optype);
}

inline void add_credits_and_wake(struct smbfs_server_info *server,
				 const struct smbfs_credits *credits,
				 const int optype)
{
	if (credits->value) {
		add_credits(server, credits, optype);
		wake_up(&server->request_q);
	}
}

inline void set_credits(struct smbfs_server_info *server, const int val)
{
	server->ops->set_credits(server, val);
}

inline int adjust_credits(struct smbfs_server_info *server,
			  struct smbfs_credits *credits,
			  const unsigned int val)
{
	if (server->ops->adjust_credits)
	       return server->ops->adjust_credits(server, credits, val);

	return 0;
}

inline __le64 get_next_mid64(struct smbfs_server_info *server)
{
	return cpu_to_le64(server->ops->get_next_mid(server));
}

inline __le16 get_next_mid(struct smbfs_server_info *server)
{
	u16 mid = server->ops->get_next_mid(server);

	/*
	 * The value in the SMB header should be little endian for easy
	 * on-the-wire decoding.
	 */
	return cpu_to_le16(mid);
}

inline void revert_current_mid(struct smbfs_server_info *server,
			       const u32 val)
{
	if (server->ops->revert_current_mid)
		server->ops->revert_current_mid(server, val);
}

inline void revert_current_mid_from_hdr(struct smbfs_server_info *server,
					const struct smb2_hdr *shdr)
{
	u32 num = le16_to_cpu(shdr->CreditCharge);

	return revert_current_mid(server, num > 0 ? num : 1);
}

inline void inc_in_send(struct smbfs_server_info *server)
{
	atomic_inc(&server->in_send);
}

inline void dec_in_send(struct smbfs_server_info *server)
{
	atomic_dec(&server->in_send);
}

inline void inc_in_queue(struct smbfs_server_info *server)
{
	atomic_inc(&server->in_queue);
}

inline void dec_in_queue(struct smbfs_server_info *server)
{
	atomic_dec(&server->in_queue);
}

inline bool is_smb1_server(struct smbfs_server_info *server)
{
	return !strcmp(server->settings->version_string, SMB1_VERSION_STRING);
}

#ifdef CONFIG_NET_NS
inline struct net *smbfs_net_ns(struct smbfs_server_info *server)
{
	return server->net;
}

inline void smbfs_set_net_ns(struct smbfs_server_info *server, struct net *net)
{
	server->net = net;
}
#else /* CONFIG_NET_NS */
inline struct net *smbfs_net_ns(struct smbfs_server_info *server)
{
	return &init_net;
}

inline void smbfs_set_net_ns(struct smbfs_server_info *server, struct net *net)
{
}
#endif /* CONFIG_NET_NS */
#endif /* _SMBFS_SERVER_INFO_H */
