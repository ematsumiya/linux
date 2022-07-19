// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) SUSE LLC, 2022
 * Author: Enzo Matsumiya <ematsumiya@suse.de>
 *
 * SMBFS procfs helpers and definitions.
 */
#ifndef _SMBFS_PROC_H
#define _SMBFS_PROC_H

#include <linux/fs.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include "cifspdu.h"
#include "defs.h"
#include "cifsproto.h"
#include "smbfs.h"
#include "fs_context.h"
#include "debug.h"

#ifdef CONFIG_SMBFS_DFS_UPCALL
#include "dfs_cache.h"
#endif /* CONFIG_SMBFS_DFS_UPCALL */
#ifdef CONFIG_SMBFS_SMB_DIRECT
#include "smbdirect.h"
#endif /* CONFIG_SMBFS_SMB_DIRECT */
#ifdef CONFIG_SMBFS_SWN_UPCALL
#include "cifs_swn.h"
#endif /* CONFIG_SMBFS_SWN_UPCALL */

#ifdef CONFIG_PROC_FS
/* assumes seq_file is named "m" */
#define SMBFS_PROC_PRINT(fmt, ...) seq_printf(m, fmt, ##__VA_ARGS__)
/* no do {} while (0) so we can use else */
#define SMBFS_PROC_PRINT_IF(cond, fmt, ...)				\
	if ((cond))							\
		SMBFS_PROC_PRINT(fmt, ##__VA_ARGS__)
/* prepends a comma if @sep */
#define SMBFS_PROC_PRINT_SEP(sep, fmt, ...)				\
do {									\
	if ((sep)++)							\
		SMBFS_PROC_PRINT(", " fmt, ##__VA_ARGS__);		\
	else								\
		SMBFS_PROC_PRINT(fmt, ##__VA_ARGS__);			\
} while (0)
#define SMBFS_PROC_PRINT_SEP_IF(cond, sep, fmt, ...)			\
	if ((cond))							\
		SMBFS_PROC_PRINT_SEP(sep, fmt, ##__VA_ARGS__)

#define __SMBFS_PROC_OPS_DEFINE(name)						\
static int name ## _proc_open(struct inode *inode, struct file *file)	\
{									\
	return single_open(file, name ## _proc_show, NULL);		\
}									\
static const struct proc_ops name ## _proc_ops = {			\
	.proc_open	= name ## _proc_open,				\
	.proc_read	= seq_read,					\
	.proc_lseek	= seq_lseek,					\
	.proc_release	= single_release,				\
	.proc_write	= name ## _proc_write,				\
}

/* prefixes @name with "smbfs_" */
#define SMBFS_PROC_OPS_DEFINE(name) __SMBFS_PROC_OPS_DEFINE(smbfs_ ## name)

#ifdef CONFIG_SMBFS_SMB_DIRECT
#define SMBFS_SMB_DIRECT_PROC_DEFINE(name)				\
static ssize_t name ## _proc_write(struct file *file,			\
				   const char __user *buffer,		\
				   size_t count, loff_t *ppos)		\
{									\
	int rc;								\
	rc = kstrtoint_from_user(buffer, count, 10, & name);		\
	if (rc)								\
		return rc;						\
	return count;							\
}									\
static int name ## _proc_show(struct seq_file *m, void *v)		\
{									\
	seq_printf(m, "%d\n", name);					\
	return 0;							\
}									\
__SMBFS_PROC_OPS_DEFINE(name)
#endif /* CONFIG_SMBFS_SMB_DIRECT */

static inline const char *smbfs_tcp_status_str(enum statusEnum status)
{
	switch (status) {
	case CifsNew:
		return "new";
	case CifsGood:
		return "good";
	case CifsExiting:
		return "exiting";
	case CifsNeedReconnect:
		return "need reconnect";
	case CifsNeedNegotiate:
		return "need negotiate";
	case CifsInNegotiate:
		return "in negotiate";
	default:
		return "unknown";
	}
}

static inline void smbfs_dump_tcp_status(struct seq_file *m,
					 struct TCP_Server_Info *server,
					 char *prefix)
{
	SMBFS_PROC_PRINT("%sTCP status: %s (%d), "
			 "instance: %d, local users to server: %d, sec_mode: 0x%x\n"
			 "%sreqs: in flight: %d, in send: %d, in wait: %d\n",
			 prefix, smbfs_tcp_status_str(server->tcpStatus),
			 server->tcpStatus, server->reconnect_instance,
			 server->srv_count, server->sec_mode,
			 prefix, in_flight(server),
			 atomic_read(&server->in_send),
			 atomic_read(&server->num_waiters)
	);
	SMBFS_PROC_PRINT("\n");
}

static inline void smbfs_dump_channel(struct seq_file *m, int i,
				      struct cifs_ses *ses, int srv_idx,
				      int ses_idx)
{
	struct TCP_Server_Info *server = ses->chans[i].server;

	SMBFS_PROC_PRINT("\t[server %d session %d ", srv_idx, ses_idx);
	SMBFS_PROC_PRINT_IF(!i, "primary channel]");
	else SMBFS_PROC_PRINT("channel %d]", i);

	SMBFS_PROC_PRINT("%s%s\n",
			 CIFS_CHAN_NEEDS_RECONNECT(ses, 0) ?
			 " disconnected" : "",
			 CIFS_CHAN_IN_RECONNECT(ses, 0) ?
			 " (reconnecting...)" : "");

	SMBFS_PROC_PRINT("\t\tconnection ID: 0x%llx\n", server->conn_id);
	SMBFS_PROC_PRINT("\t\tnumber of credits: %d\n", ses->server->credits);
	SMBFS_PROC_PRINT("\t\tdialect: 0x%x\n", ses->server->dialect);

	smbfs_dump_tcp_status(m, ses->server, "\t\t");
}

static inline void smbfs_dump_channels(struct seq_file *m, struct cifs_ses *ses,
				       int srv_idx, int ses_idx)
{
	int i;

	spin_lock(&ses->chan_lock);

	if (ses->chan_count > 1) {
		SMBFS_PROC_PRINT("\textra channels: %zu\n", ses->chan_count - 1);

		for (i = 1; i < ses->chan_count; i++)
			smbfs_dump_channel(m, i, ses, srv_idx, ses_idx);
	}
	SMBFS_PROC_PRINT("\n");
	spin_unlock(&ses->chan_lock);
}

static void smbfs_dump_iface(struct seq_file *m, struct cifs_server_iface *iface,
			     bool connected)
{
	struct sockaddr_in *ipv4 = (struct sockaddr_in *)&iface->sockaddr;
	struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&iface->sockaddr;
	size_t speed_mbps = 0;

	SMBFS_PROC_PRINT_IF(iface->sockaddr.ss_family == AF_INET,
			    "\t\tIPv4: %pI4 ", &ipv4->sin_addr);
	SMBFS_PROC_PRINT_IF(iface->sockaddr.ss_family == AF_INET6,
			    "\t\tIPv6: %pI6 ", &ipv6->sin6_addr);

	SMBFS_PROC_PRINT("%s\n", connected ? "(in use)" : "");

	/* ->speed is in bps, but we show in Mbps (a.k.a. human readable) */
	if (iface->speed)
		speed_mbps = iface->speed / 1000000;
	SMBFS_PROC_PRINT("\t\tspeed: %zu Mbps\n", speed_mbps);
	SMBFS_PROC_PRINT("\t\tcapabilities:");
	SMBFS_PROC_PRINT_IF(iface->rdma_capable, " RDMA");
	SMBFS_PROC_PRINT_IF(iface->rss_capable, "RSS");
	SMBFS_PROC_PRINT("\n");
}

static inline void smbfs_dump_share_caps(struct seq_file *m, struct cifs_tcon *tcon)
{
	int sep = 0;

	SMBFS_PROC_PRINT("\t\tshare capabilities: ");
	if (!tcon->capabilities) {
		SMBFS_PROC_PRINT("none\n");
		goto skip_caps;
	}

	SMBFS_PROC_PRINT_SEP_IF(tcon->capabilities & SMB2_SHARE_CAP_DFS,
				sep, "DFS");
	SMBFS_PROC_PRINT_SEP_IF(tcon->capabilities & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY,
				sep, "CONTINUOUS AVAILABILITY");
	SMBFS_PROC_PRINT_SEP_IF(tcon->capabilities & SMB2_SHARE_CAP_SCALEOUT,
				sep, "SCALEOUT");
	SMBFS_PROC_PRINT_SEP_IF(tcon->capabilities & SMB2_SHARE_CAP_CLUSTER,
				sep, "CLUSTER");
	SMBFS_PROC_PRINT_SEP_IF(tcon->capabilities & SMB2_SHARE_CAP_ASYMMETRIC,
				sep, "ASYMMETRIC");
	SMBFS_PROC_PRINT_IF(!sep, "N/A");
	SMBFS_PROC_PRINT("\n");
skip_caps:
	SMBFS_PROC_PRINT("\t\tshare flags:");
	if (!tcon->share_flags) {
		SMBFS_PROC_PRINT(" none\n");
		goto skip_flags;
	}

	sep = 0;
	SMBFS_PROC_PRINT_SEP_IF(tcon->ss_flags & SSINFO_FLAGS_ALIGNED_DEVICE,
				sep, "aligned");
	SMBFS_PROC_PRINT_SEP_IF(tcon->ss_flags & SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE,
				sep, "partition aligned");
	SMBFS_PROC_PRINT_SEP_IF(tcon->ss_flags & SSINFO_FLAGS_NO_SEEK_PENALTY,
				sep, "SSD");
	SMBFS_PROC_PRINT_SEP_IF(tcon->ss_flags & SSINFO_FLAGS_TRIM_ENABLED,
				sep, "TRIM support");
	SMBFS_PROC_PRINT_IF(!sep, " N/A");
	SMBFS_PROC_PRINT(" (0x%x)\n", tcon->share_flags);
skip_flags:
	SMBFS_PROC_PRINT_IF(tcon->perf_sector_size,
			    "\t\toptimal sector size: %d (0x%x)\n",
			    tcon->perf_sector_size,
			    tcon->perf_sector_size);
	SMBFS_PROC_PRINT("\t\tmaximal access: 0x%x\n", tcon->maximal_access);
}

static inline const char *smbfs_tid_status_str(enum tid_status_enum status)
{
	switch (status) {
	case TID_NEW:
		return "new";
	case TID_GOOD:
		return "good";
	case TID_EXITING:
		return "exiting";
	case TID_NEED_RECON:
		return "need reconnect";
	case TID_NEED_TCON:
		return "need tcon";
	case TID_IN_TCON:
		return "in tcon";
	case TID_IN_FILES_INVALIDATE:
		return "in files invalidate";
	default:
		return "unknown";
	}
}
static inline void smbfs_dump_tcon(struct seq_file *m, struct cifs_tcon *tcon)
{
	__u32 dev_info;
	__u32 dev_type;
	__u32 attrs;
	__u32 max_path_component_len;

	if (!tcon) {
		SMBFS_PROC_PRINT("none\n");
		return;
	}

	dev_info = le32_to_cpu(tcon->fsDevInfo.DeviceCharacteristics);
	dev_type = le32_to_cpu(tcon->fsDevInfo.DeviceType);
	attrs = le32_to_cpu(tcon->fsAttrInfo.Attributes);
	max_path_component_len =
		le32_to_cpu(tcon->fsAttrInfo.MaxPathNameComponentLength);

	SMBFS_PROC_PRINT("\t\t%s: %s%s\n",
			 tcon->ipc ? "IPC" : "name", tcon->treeName,
			 tcon->need_reconnect ? " (disconnected)" : "");

	SMBFS_PROC_PRINT_IF(tcon->nativeFileSystem, "\t\ttype: %s\n",
			    tcon->nativeFileSystem);
	SMBFS_PROC_PRINT("\t\ttid: 0x%x\n", tcon->tid);
	SMBFS_PROC_PRINT("\t\tstatus: %s (%d)\n",
			 smbfs_tid_status_str(tcon->status),
			 tcon->status);
	SMBFS_PROC_PRINT("\t\tmounts: %d\n", tcon->tc_count);
	SMBFS_PROC_PRINT_IF(dev_info, "\t\tdevice info: 0x%x\n", dev_info);
	SMBFS_PROC_PRINT_IF(dev_type, "\t\tdevice type: ");
	/* XXX: should we check/print all types? */
	SMBFS_PROC_PRINT_IF(dev_type == FILE_DEVICE_DISK, "DISK\n");
	else SMBFS_PROC_PRINT_IF(dev_type == FILE_DEVICE_CD_ROM, "CDROM\n");
	else SMBFS_PROC_PRINT_IF(dev_type, "0x%x\n", dev_type);

	SMBFS_PROC_PRINT_IF(attrs, "\t\tattributes: 0x%x\n", attrs);
	SMBFS_PROC_PRINT_IF(max_path_component_len,
			 "\t\tmax path component length: %d\n",
			 max_path_component_len);

	SMBFS_PROC_PRINT("\t\tserial number: ");
	SMBFS_PROC_PRINT_IF(tcon->vol_serial_number, "0x%x\n",
			    tcon->vol_serial_number);
	else SMBFS_PROC_PRINT("N/A\n");

	SMBFS_PROC_PRINT_IF((tcon->seal) ||
			    (tcon->ses->session_flags & SMB2_SESSION_FLAG_ENCRYPT_DATA) ||
			    (tcon->share_flags & SHI1005_FLAGS_ENCRYPT_DATA),
			    "\t\tencrypted: yes\n");
	SMBFS_PROC_PRINT_IF(tcon->nocase, "\t\tnocase: yes\n");
	SMBFS_PROC_PRINT("\t\t%s extensions: %s\n",
			 /* cosmetic only */
			 is_smb1_server(tcon->ses->server) ? "UNIX" : "POSIX",
			 tcon->unix_ext ? "yes" : "no");

	smbfs_dump_share_caps(m, tcon);
	
	SMBFS_PROC_PRINT_IF(tcon->use_witness, "\t\twitness: yes\n");
	SMBFS_PROC_PRINT_IF(tcon->broken_sparse_sup, "\t\tnosparse: yes\n");
	SMBFS_PROC_PRINT("\n");
}

static inline void smbfs_print_stats_smb1(struct seq_file *m, struct cifs_tcon *tcon)
{
	SMBFS_PROC_PRINT("Oplocks breaks: %d\n",
		   atomic_read(&tcon->stats.cifs_stats.num_oplock_brks));
	SMBFS_PROC_PRINT("Reads:%d, bytes: %llu\n",
		   atomic_read(&tcon->stats.cifs_stats.num_reads),
		   (long long)(tcon->bytes_read));
	SMBFS_PROC_PRINT("Writes: %d, bytes: %llu\n",
		   atomic_read(&tcon->stats.cifs_stats.num_writes),
		   (long long)(tcon->bytes_written));
	SMBFS_PROC_PRINT("Flushes: %d\n",
		   atomic_read(&tcon->stats.cifs_stats.num_flushes));
	SMBFS_PROC_PRINT("Locks: %d, hardlinks: %d, symlinks: %d\n",
		   atomic_read(&tcon->stats.cifs_stats.num_locks),
		   atomic_read(&tcon->stats.cifs_stats.num_hardlinks),
		   atomic_read(&tcon->stats.cifs_stats.num_symlinks));
	SMBFS_PROC_PRINT("Opens: %d, closes: %d, deletes: %d\n",
		   atomic_read(&tcon->stats.cifs_stats.num_opens),
		   atomic_read(&tcon->stats.cifs_stats.num_closes),
		   atomic_read(&tcon->stats.cifs_stats.num_deletes));
	SMBFS_PROC_PRINT("POSIX opens: %d, POSIX mkdirs: %d\n",
		   atomic_read(&tcon->stats.cifs_stats.num_posixopens),
		   atomic_read(&tcon->stats.cifs_stats.num_posixmkdirs));
	SMBFS_PROC_PRINT("mkdirs: %d, rmdirs: %d\n",
		   atomic_read(&tcon->stats.cifs_stats.num_mkdirs),
		   atomic_read(&tcon->stats.cifs_stats.num_rmdirs));
	SMBFS_PROC_PRINT("Renames: %d, T2 renames %d\n",
		   atomic_read(&tcon->stats.cifs_stats.num_renames),
		   atomic_read(&tcon->stats.cifs_stats.num_t2renames));
	SMBFS_PROC_PRINT("FindFirst: %d, FNext %d, FClose %d\n",
		   atomic_read(&tcon->stats.cifs_stats.num_ffirst),
		   atomic_read(&tcon->stats.cifs_stats.num_fnext),
		   atomic_read(&tcon->stats.cifs_stats.num_fclose));
}

static inline void smbfs_debug_data_features(struct seq_file *m)
{
	int sep = 0;

	SMBFS_PROC_PRINT("SMBFS version %s\n", SMBFS_VERSION);
	SMBFS_PROC_PRINT("Build features: ");

#ifdef CONFIG_SMBFS_DFS_UPCALL
	SMBFS_PROC_PRINT_SEP(sep, "DFS");
#endif
#ifdef CONFIG_SMBFS_FSCACHE
	SMBFS_PROC_PRINT_SEP(sep, "FSCACHE");
#endif
#ifdef CONFIG_SMBFS_SMB_DIRECT
	SMBFS_PROC_PRINT_SEP(sep, "SMB_DIRECT");
#endif
#ifdef CONFIG_SMBFS_STATS_EXTRA
	SMBFS_PROC_PRINT_SEP(sep, "STATS_EXTRA");
#else
	SMBFS_PROC_PRINT_SEP(sep, "STATS");
#endif
#ifdef CONFIG_SMBFS_DEBUG_EXTRA
	SMBFS_PROC_PRINT_SEP(sep, "DEBUG_EXTRA");
#elif defined(CONFIG_SMBFS_DEBUG)
	SMBFS_PROC_PRINT_SEP(sep, "DEBUG");
#endif
#ifdef CONFIG_SMBFS_ALLOW_INSECURE_LEGACY
	SMBFS_PROC_PRINT_SEP(sep, "ALLOW_INSECURE_LEGACY");
#endif
#ifdef CONFIG_SMBFS_POSIX
	SMBFS_PROC_PRINT_SEP(sep, "POSIX");
#endif
#ifdef CONFIG_SMBFS_UPCALL
	SMBFS_PROC_PRINT_SEP(sep, "UPCALL (SPNEGO)");
#endif
#ifdef CONFIG_SMBFS_XATTR
	SMBFS_PROC_PRINT_SEP(sep, "XATTR");
#endif
	SMBFS_PROC_PRINT_SEP(sep, "ACL");
#ifdef CONFIG_SMBFS_SWN_UPCALL
	SMBFS_PROC_PRINT_SEP(sep, "WITNESS");
#endif

	SMBFS_PROC_PRINT("\n");
}

static inline void smbfs_debug_data_rdma(struct seq_file *m,
					 struct TCP_Server_Info *server)
{
#ifdef CONFIG_SMBFS_SMB_DIRECT
	if (!server->rdma)
		return;

	if (!server->smbd_conn) {
		SMBFS_PROC_PRINT("\t\tSMBDirect transport not available\n");
		return;
	}

	SMBFS_PROC_PRINT("\t\tSMBDirect protocol version: 0x%x\n"
			 "\t\ttransport status: 0x%x\n",
			 server->smbd_conn->protocol,
			 server->smbd_conn->transport_status);
	SMBFS_PROC_PRINT("\t\t[conn]\n");
	SMBFS_PROC_PRINT("\t\t  receive_credit_max: 0x%x\n"
			 "\t\t  send_credit_target: 0x%x\n"
			 "\t\t  max_send_size: 0x%x\n"
			 "\t\t  max_fragmented_recv_size: 0x%x\n"
			 "\t\t  max_fragmented_send_size: 0x%x\n"
			 "\t\t  max_receive_size: 0x%x\n"
			 "\t\t  keep_alive_interval: 0x%x\n"
			 "\t\t  max_readwrite_size: 0x%x\n"
			 "\t\t  rdma_readwrite_threshold: 0x%x\n",
			 server->smbd_conn->receive_credit_max,
			 server->smbd_conn->send_credit_target,
			 server->smbd_conn->max_send_size,
			 server->smbd_conn->max_fragmented_recv_size,
			 server->smbd_conn->max_fragmented_send_size,
			 server->smbd_conn->max_receive_size,
			 server->smbd_conn->keep_alive_interval,
			 server->smbd_conn->max_readwrite_size,
			 server->smbd_conn->rdma_readwrite_threshold);
	SMBFS_PROC_PRINT("\t\t[debug]\n");
	SMBFS_PROC_PRINT("\t\t  count_get_receive_buffer: 0x%x\n"
			 "\t\t  count_put_receive_buffer: 0x%x\n"
			 "\t\t  count_send_empty: 0x%x\n",
			 server->smbd_conn->count_get_receive_buffer,
			 server->smbd_conn->count_put_receive_buffer,
			 server->smbd_conn->count_send_empty);
	SMBFS_PROC_PRINT("\t\t[read queue]\n");
	SMBFS_PROC_PRINT("\t\t  count_reassembly_queue: 0x%\n"
			 "\t\t  count_enqueue_reassembly_queue: 0x%\n"
			 "\t\t  count_dequeue_reassembly_queue: 0x%\n"
			 "\t\t  fragment_reassembly_remaining: 0x%\n"
			 "\t\t  reassembly_data_length: 0x%\n"
			 "\t\t  reassembly_queue_length: 0x%x\n",
			 server->smbd_conn->count_reassembly_queue,
			 server->smbd_conn->count_enqueue_reassembly_queue,
			 server->smbd_conn->count_dequeue_reassembly_queue,
			 server->smbd_conn->fragment_reassembly_remaining,
			 server->smbd_conn->reassembly_data_length,
			 server->smbd_conn->reassembly_queue_length);
	SMBFS_PROC_PRINT("\t\t[current credits]\n");
	SMBFS_PROC_PRINT("\t\t  send_credits: 0x%x\n"
			 "\t\t  receive_credits: 0x%x\n"
			 "\t\t  receive_credit_target: 0x%x\n",
			 atomic_read(&server->smbd_conn->send_credits),
			 atomic_read(&server->smbd_conn->receive_credits),
			 server->smbd_conn->receive_credit_target);
	SMBFS_PROC_PRINT("\t\t[pending]\n");
	SMBFS_PROC_PRINT("\t\t  send_pending: 0x%x\n",
			 atomic_read(&server->smbd_conn->send_pending));
	SMBFS_PROC_PRINT("\t\t[receive buffers]\n"
	SMBFS_PROC_PRINT("\t\t  count_receive_queue: 0x%x\n"
			 "\t\t  count_empty_packet_queue: 0x%x\n",
			 server->smbd_conn->count_receive_queue,
			 server->smbd_conn->count_empty_packet_queue);
	SMBFS_PROC_PRINT("\t\t[memory registrations]\n");
	SMBFS_PROC_PRINT("\t\t  responder_resources: 0x%x\n"
			 "\t\t  max_frmr_depth: 0x%x\n"
			 "\t\t  mr_type: 0x%x\n"
			 "\t\t  mr_ready_count: 0x%x\n"
			 "\t\t  mr_used_count: 0x%x\n",
			 server->smbd_conn->responder_resources,
			 server->smbd_conn->max_frmr_depth,
			 server->smbd_conn->mr_type);
			 atomic_read(&server->smbd_conn->mr_ready_count),
			 atomic_read(&server->smbd_conn->mr_used_count));
#endif /* CONFIG_SMBFS_SMB_DIRECT */
}

static inline void smbfs_print_ses_caps(struct seq_file *m, unsigned int caps)
{
	int sep = 0;

	if (!caps) {
		SMBFS_PROC_PRINT("none\n");
		return;
	}

	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_RAW_MODE, sep, "RAW_MODE");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_MPX_MODE, sep, "MPX_MODE");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_UNICODE, sep, "UNICODE");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_LARGE_FILES, sep, "LARGE_FILES");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_NT_SMBS, sep, "NT_SMBS");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_RPC_REMOTE_APIS, sep, "RPC_REMOTE_APIS");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_STATUS32, sep, "STATUS32");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_LEVEL_II_OPLOCKS, sep, "LEVEL_II_OPLOCKS");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_LOCK_AND_READ, sep, "LOCK_AND_READ");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_NT_FIND, sep, "NT_FIND");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_DFS, sep, "DFS");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_INFOLEVEL_PASSTHRU, sep, "INFOLEVEL_PASSTHRU");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_LARGE_READ_X, sep, "LARGE_READ_X");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_LARGE_WRITE_X, sep, "LARGE_WRITE_X");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_LWIO, sep, "LWIO");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_UNIX, sep, "UNIX");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_COMPRESSED_DATA, sep, "COMPRESSED_DATA");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_DYNAMIC_REAUTH, sep, "DYNAMIC_REAUTH");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_PERSISTENT_HANDLES, sep, "PERSISTENT_HANDLES");
	SMBFS_PROC_PRINT_SEP_IF(caps & CAP_EXTENDED_SECURITY, sep, "EXTENDED_SECURITY");
	SMBFS_PROC_PRINT_IF(!sep, "N/A");
	SMBFS_PROC_PRINT(" (0x%x)\n", caps);
}

static inline const char *smbfs_ses_status_str(enum ses_status_enum status)
{
	switch (status) {
	case SES_NEW:
		return "new";
	case SES_GOOD:
		return "good";
	case SES_EXITING:
		return "exiting";
	case SES_NEED_RECON:
		return "need reconnect";
	case SES_IN_SETUP:
		return "in setup";
	default:
		return "unknown";
	}
}

static inline void smbfs_debug_data_sessions(struct seq_file *m,
					     struct TCP_Server_Info *server,
					     int srv_idx)
{
	struct cifs_ses *ses;
	struct cifs_tcon *tcon;
	struct cifs_server_iface *iface;
	struct list_head *tcon_entry, *ses_entry;
	int ses_idx = 0, share_idx = 0, iface_idx = 0;
	int sep = 0;

	list_for_each(ses_entry, &server->smb_ses_list) {
		ses = list_entry(ses_entry, struct cifs_ses, smb_ses_list);

		SMBFS_PROC_PRINT("\t\t[server %d session %d]\n"
				 "\t\tIP address: %s\n",
				 srv_idx, ses_idx, ses->ip_addr);
		/* dump session ID helpful for use with network trace */
		SMBFS_PROC_PRINT("\t\tsession ID: 0x%llx\n", ses->Suid);
		SMBFS_PROC_PRINT("\t\tsession status: %s (%d), use count: %d\n",
				 smbfs_ses_status_str(ses->ses_status),
				 ses->ses_status, ses->ses_count);

		SMBFS_PROC_PRINT("\t\tcapabilities: ");
		smbfs_print_ses_caps(m, ses->capabilities);

		if (!ses->serverDomain || !ses->serverOS || !ses->serverNOS) {
			SMBFS_PROC_PRINT_SEP(sep, "\t\tguest: %s",
					 (ses->session_flags & SMB2_SESSION_FLAG_IS_GUEST) ?
					 "yes" : "no");
			SMBFS_PROC_PRINT_SEP(sep, "%sanonymous: %s",
					 sep ? "" : "\t\t",
					 (ses->session_flags & SMB2_SESSION_FLAG_IS_NULL) ?
					 "yes" : "no");
			SMBFS_PROC_PRINT("\n");
		} else {
			SMBFS_PROC_PRINT("\t\tdomain: %s\n"
					 "\t\tOS: %s, NOS: %s\n",
					 ses->serverDomain, ses->serverOS,
					 ses->serverNOS);
		}

		sep = 0;
		SMBFS_PROC_PRINT_SEP(sep, "\t\tsecurity: %s",
			get_security_type_str(server->ops->select_sectype(server, ses->sectype)));
		SMBFS_PROC_PRINT_SEP_IF(ses->session_flags & SMB2_SESSION_FLAG_ENCRYPT_DATA,
				        sep, "encrypted");
		SMBFS_PROC_PRINT_SEP_IF(ses->sign, sep, "signed");
		SMBFS_PROC_PRINT("\n");

		SMBFS_PROC_PRINT("\t\tuser: %d, cred user: %d\n",
				 from_kuid(&init_user_ns, ses->linux_uid),
				 from_kuid(&init_user_ns, ses->cred_uid));

		smbfs_dump_channels(m, ses, srv_idx, ses_idx);

		SMBFS_PROC_PRINT("\tshares:\n");
		SMBFS_PROC_PRINT("\t\t[server %d session %d IPC]\n",
				 srv_idx, ses_idx);
		smbfs_dump_tcon(m, ses->tcon_ipc);

		share_idx = 0;
		list_for_each(tcon_entry, &ses->tcon_list) {
			tcon = list_entry(tcon_entry, struct cifs_tcon, tcon_list);
			SMBFS_PROC_PRINT("\t\t[server %d session %d share %d]\n",
					 srv_idx, ses_idx, share_idx);
			smbfs_dump_tcon(m, tcon);
			share_idx++;
		}

		iface_idx = 0;
		spin_lock(&ses->iface_lock);
		SMBFS_PROC_PRINT_IF(ses->iface_count, "\tserver interfaces:\n");
		list_for_each_entry(iface, &ses->iface_list, iface_head) {
			SMBFS_PROC_PRINT("\t\t[server %d session %d iface %d]%s\n",
					 srv_idx, ses_idx, iface_idx,
					 !iface->is_active ? " (for cleanup)" : "");
			smbfs_dump_iface(m, iface, is_ses_using_iface(ses, iface));
			iface_idx++;
		}
		spin_unlock(&ses->iface_lock);

		ses_idx++;
	}
}

static inline void smbfs_debug_data_mids(struct seq_file *m,
					 struct TCP_Server_Info *server,
					 int srv_idx)
{
	struct mid_q_entry *mid_entry;

	spin_lock(&GlobalMid_Lock);
	if (list_empty(&server->pending_mid_q)) {
		spin_unlock(&GlobalMid_Lock);
		SMBFS_PROC_PRINT(" none\n");
		return;
	}

	list_for_each_entry(mid_entry, &server->pending_mid_q, qhead)
		SMBFS_PROC_PRINT("\t\tserver: %d, mid: %llu, state: %d, "
				 "cmd: %d, pid: %d, cbdata: 0x%p\n",
				 srv_idx, mid_entry->mid, mid_entry->mid_state,
				 le16_to_cpu(mid_entry->command),
				 mid_entry->pid, mid_entry->callback_data);
	spin_unlock(&GlobalMid_Lock);
	SMBFS_PROC_PRINT("\n");
}

/*
 * Ensure that if someone sets a MUST flag, that we disable all other MAY
 * flags except for the ones corresponding to the given MUST flag. If there are
 * multiple MUST flags, then try to prefer more secure ones.
 */
static inline void smbfs_handle_security_flags(unsigned int *flags)
{
	unsigned int signflags = *flags & CIFSSEC_MUST_SIGN;

	if ((*flags & CIFSSEC_MUST_KRB5) == CIFSSEC_MUST_KRB5)
		*flags = CIFSSEC_MUST_KRB5;
	else if ((*flags & CIFSSEC_MUST_NTLMSSP) == CIFSSEC_MUST_NTLMSSP)
		*flags = CIFSSEC_MUST_NTLMSSP;
	else if ((*flags & CIFSSEC_MUST_NTLMV2) == CIFSSEC_MUST_NTLMV2)
		*flags = CIFSSEC_MUST_NTLMV2;

	*flags |= signflags;

	if (*flags & CIFSSEC_MUST_SIGN) {
		/* requiring signing implies signing is allowed */
		*flags |= CIFSSEC_MAY_SIGN;
		smbfs_dbg("packet signing now required\n");
	} else if (!(*flags & CIFSSEC_MAY_SIGN)) {
		smbfs_dbg("packet signing disabled\n");
	}

	/* TODO: should we turn on MAY flags for other MUST options? */
}
#endif /* CONFIG_PROC_FS */
#endif /* _SMBFS_PROC_H */
