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
#include "defs.h"
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

static inline const char *smbfs_server_status_str(smbfs_status_t status)
{
	switch (status) {
	case SMBFS_STATUS_NEW:
		return "new";
	case SMBFS_STATUS_GOOD:
		return "good";
	case SMBFS_STATUS_EXITING:
		return "exiting";
	case SMBFS_STATUS_NEED_RECONNECT:
		return "need reconnect";
	case SMBFS_STATUS_NEED_NEGOTIATE:
		return "need negotiate";
	case SMBFS_STATUS_IN_NEGOTIATE:
		return "in negotiate";
	default:
		return "unknown";
	}
}

static inline void smbfs_dump_server_status(struct seq_file *m,
					 struct smbfs_server_info *server,
					 char *prefix)
{
	SMBFS_PROC_PRINT("%sTCP status: %s (%d), "
			 "instance: %d, local users to server: %d, sec_mode: 0x%x\n"
			 "%sreqs: in flight: %d, in send: %d, in wait: %d\n",
			 prefix, smbfs_server_status_str(server->status),
			 server->status, server->reconnects,
			 server->count, server->sec.mode,
			 prefix, in_flight(server),
			 atomic_read(&server->in_send),
			 atomic_read(&server->in_queue)
	);
	SMBFS_PROC_PRINT("\n");
}

static inline void smbfs_dump_channel(struct seq_file *m, int i,
				      struct smbfs_ses *ses, int srv_idx,
				      int ses_idx)
{
	struct smbfs_server_info *server = ses->channels[i].server;

	SMBFS_PROC_PRINT("\t[server %d session %d ", srv_idx, ses_idx);
	SMBFS_PROC_PRINT_IF(!i, "primary channel]");
	else SMBFS_PROC_PRINT("channel %d]", i);

	SMBFS_PROC_PRINT("%s%s\n",
			 CHANNEL_NEEDS_RECONNECT(ses, 0) ?
			 " disconnected" : "",
			 CHANNEL_IN_RECONNECT(ses, 0) ?
			 " (reconnecting...)" : "");

	SMBFS_PROC_PRINT("\t\tconnection ID: 0x%llx\n", server->conn_id);
	SMBFS_PROC_PRINT("\t\tnumber of credits: %d\n", ses->server->credits);
	SMBFS_PROC_PRINT("\t\tdialect: 0x%x\n", ses->server->dialect);

	smbfs_dump_server_status(m, ses->server, "\t\t");
}

static inline void smbfs_dump_channels(struct seq_file *m, struct smbfs_ses *ses,
				       int srv_idx, int ses_idx)
{
	int i;

	spin_lock(&ses->channel_lock);

	if (ses->channel_count > 1) {
		SMBFS_PROC_PRINT("\textra channels: %u\n", ses->channel_count - 1);

		for (i = 1; i < ses->channel_count; i++)
			smbfs_dump_channel(m, i, ses, srv_idx, ses_idx);
	}
	SMBFS_PROC_PRINT("\n");
	spin_unlock(&ses->channel_lock);
}

static void smbfs_dump_iface(struct seq_file *m, struct smbfs_server_iface *iface,
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

static inline void smbfs_dump_share_caps(struct seq_file *m, struct smbfs_tcon *tcon)
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
	SMBFS_PROC_PRINT_SEP_IF(tcon->sector_size_flags & SSINFO_FLAGS_ALIGNED_DEVICE,
				sep, "aligned");
	SMBFS_PROC_PRINT_SEP_IF(tcon->sector_size_flags & SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE,
				sep, "partition aligned");
	SMBFS_PROC_PRINT_SEP_IF(tcon->sector_size_flags & SSINFO_FLAGS_NO_SEEK_PENALTY,
				sep, "SSD");
	SMBFS_PROC_PRINT_SEP_IF(tcon->sector_size_flags & SSINFO_FLAGS_TRIM_ENABLED,
				sep, "TRIM support");
	SMBFS_PROC_PRINT_IF(!sep, " N/A");
	SMBFS_PROC_PRINT(" (0x%llx)\n", tcon->share_flags);
skip_flags:
	SMBFS_PROC_PRINT_IF(tcon->perf_sector_size,
			    "\t\toptimal sector size: %d (0x%x)\n",
			    tcon->perf_sector_size,
			    tcon->perf_sector_size);
	SMBFS_PROC_PRINT("\t\tmaximal access: 0x%x\n", tcon->maximal_access);
}

static inline const char *smbfs_tcon_status_str(smbfs_tcon_status_t status)
{
	switch (status) {
	case SMBFS_TCON_STATUS_NEW:
		return "new";
	case SMBFS_TCON_STATUS_GOOD:
		return "good";
	case SMBFS_TCON_STATUS_EXITING:
		return "exiting";
	case SMBFS_TCON_STATUS_NEED_RECONNECT:
		return "need reconnect";
	case SMBFS_TCON_STATUS_NEED_TCON:
		return "need tcon";
	case SMBFS_TCON_STATUS_IN_TCON:
		return "in tcon";
	case SMBFS_TCON_STATUS_IN_FILES_INVALIDATE:
		return "in files invalidate";
	default:
		return "unknown";
	}
}
static inline void smbfs_dump_tcon(struct seq_file *m, struct smbfs_tcon *tcon)
{
	unsigned int dev_info;
	unsigned int dev_type;
	unsigned int attrs;
	unsigned int max_path_component_len;

	if (!tcon) {
		SMBFS_PROC_PRINT("none\n");
		return;
	}

	dev_info = le32_to_cpu(tcon->fs_dev_info.DeviceCharacteristics);
	dev_type = le32_to_cpu(tcon->fs_dev_info.DeviceType);
	attrs = le32_to_cpu(tcon->fs_attr_info.Attributes);
	max_path_component_len =
		le32_to_cpu(tcon->fs_attr_info.MaxPathNameComponentLength);

	SMBFS_PROC_PRINT("\t\t%s: %s%s\n",
			 get_tcon_flag(tcon, IS_IPC) ? "IPC" : "name", tcon->tree_name,
			 get_tcon_flag(tcon, NEED_RECONNECT) ? " (disconnected)" : "");

	SMBFS_PROC_PRINT_IF(tcon->native_fs, "\t\ttype: %s\n",
			    tcon->native_fs);
	SMBFS_PROC_PRINT("\t\ttid: 0x%x\n", tcon->tid);
	SMBFS_PROC_PRINT("\t\tstatus: %s (%d)\n",
			 smbfs_tcon_status_str(tcon->status),
			 tcon->status);
	SMBFS_PROC_PRINT("\t\tmounts: %d\n", tcon->count);
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

	SMBFS_PROC_PRINT_IF((get_tcon_flag(tcon, USE_SEAL)) ||
			    (tcon->ses->flags & SMB2_SESSION_FLAG_ENCRYPT_DATA) ||
			    (tcon->share_flags & SHI1005_FLAGS_ENCRYPT_DATA),
			    "\t\tencrypted: yes\n");
	SMBFS_PROC_PRINT_IF(get_tcon_flag(tcon, NOCASE), "\t\tnocase: yes\n");
	SMBFS_PROC_PRINT("\t\t%s extensions: %s\n",
			 /* cosmetic only */
			 is_smb1_server(tcon->ses->server) ? "UNIX" : "POSIX",
			 get_tcon_flag(tcon, USE_UNIX_EXT) ? "yes" : "no");

	smbfs_dump_share_caps(m, tcon);
	
	SMBFS_PROC_PRINT_IF(get_tcon_flag(tcon, USE_WITNESS),
			    "\t\twitness: yes\n");
	SMBFS_PROC_PRINT_IF(get_tcon_flag(tcon, BROKEN_SPARSE_SUPP),
			    "\t\tnosparse: yes\n");
	SMBFS_PROC_PRINT("\n");
}

static inline void smbfs_print_stats_smb1(struct seq_file *m, struct smbfs_tcon *tcon)
{
	SMBFS_PROC_PRINT("Oplocks breaks: %d\n",
		   atomic_read(&tcon->stats.smb1.oplock_brks));
	SMBFS_PROC_PRINT("Reads:%d, bytes: %llu\n",
		   atomic_read(&tcon->stats.smb1.reads),
		   (long long)(tcon->bytes_read));
	SMBFS_PROC_PRINT("Writes: %d, bytes: %llu\n",
		   atomic_read(&tcon->stats.smb1.writes),
		   (long long)(tcon->bytes_written));
	SMBFS_PROC_PRINT("Flushes: %d\n",
		   atomic_read(&tcon->stats.smb1.flushes));
	SMBFS_PROC_PRINT("Locks: %d, hardlinks: %d, symlinks: %d\n",
		   atomic_read(&tcon->stats.smb1.locks),
		   atomic_read(&tcon->stats.smb1.hardlinks),
		   atomic_read(&tcon->stats.smb1.symlinks));
	SMBFS_PROC_PRINT("Opens: %d, closes: %d, deletes: %d\n",
		   atomic_read(&tcon->stats.smb1.opens),
		   atomic_read(&tcon->stats.smb1.closes),
		   atomic_read(&tcon->stats.smb1.deletes));
	SMBFS_PROC_PRINT("POSIX opens: %d, POSIX mkdirs: %d\n",
		   atomic_read(&tcon->stats.smb1.posixopens),
		   atomic_read(&tcon->stats.smb1.posixmkdirs));
	SMBFS_PROC_PRINT("mkdirs: %d, rmdirs: %d\n",
		   atomic_read(&tcon->stats.smb1.mkdirs),
		   atomic_read(&tcon->stats.smb1.rmdirs));
	SMBFS_PROC_PRINT("Renames: %d, T2 renames %d\n",
		   atomic_read(&tcon->stats.smb1.renames),
		   atomic_read(&tcon->stats.smb1.t2renames));
	SMBFS_PROC_PRINT("FindFirst: %d, FNext %d, FClose %d\n",
		   atomic_read(&tcon->stats.smb1.ffirst),
		   atomic_read(&tcon->stats.smb1.fnext),
		   atomic_read(&tcon->stats.smb1.fclose));
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
					 struct smbfs_server_info *server)
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

static inline const char *smbfs_ses_status_str(smbfs_ses_status_t status)
{
	switch (status) {
	case SMBFS_SES_STATUS_NEW:
		return "new";
	case SMBFS_SES_STATUS_GOOD:
		return "good";
	case SMBFS_SES_STATUS_EXITING:
		return "exiting";
	case SMBFS_SES_STATUS_NEED_RECONNECT:
		return "need reconnect";
	case SMBFS_SES_STATUS_IN_SETUP:
		return "in setup";
	default:
		return "unknown";
	}
}

static inline void smbfs_debug_data_sessions(struct seq_file *m,
					     struct smbfs_server_info *server,
					     int srv_idx)
{
	struct smbfs_ses *ses;
	struct smbfs_tcon *tcon;
	struct smbfs_server_iface *iface;
	struct list_head *tcon_entry, *ses_entry;
	int ses_idx = 0, share_idx = 0, iface_idx = 0;
	int sep = 0;

	list_for_each(ses_entry, &server->sessions) {
		ses = list_entry(ses_entry, struct smbfs_ses, head);

		SMBFS_PROC_PRINT("\t\t[server %d session %d]\n"
				 "\t\tIP address: %s\n",
				 srv_idx, ses_idx, ses->ip_addr);
		/* dump session ID helpful for use with network trace */
		SMBFS_PROC_PRINT("\t\tsession ID: 0x%llx\n", ses->id);
		SMBFS_PROC_PRINT("\t\tsession status: %s (%d), use count: %d\n",
				 smbfs_ses_status_str(ses->status),
				 ses->status, ses->count);

		SMBFS_PROC_PRINT("\t\tcapabilities: ");
		smbfs_print_ses_caps(m, ses->capabilities);

		if (!ses->server_domain || !ses->serverOS || !ses->serverNOS) {
			SMBFS_PROC_PRINT_SEP(sep, "\t\tguest: %s",
					 (ses->flags & SMB2_SESSION_FLAG_IS_GUEST) ?
					 "yes" : "no");
			SMBFS_PROC_PRINT_SEP(sep, "%sanonymous: %s",
					 sep ? "" : "\t\t",
					 (ses->flags & SMB2_SESSION_FLAG_IS_NULL) ?
					 "yes" : "no");
			SMBFS_PROC_PRINT("\n");
		} else {
			SMBFS_PROC_PRINT("\t\tdomain: %s\n"
					 "\t\tOS: %s, NOS: %s\n",
					 ses->server_domain, ses->serverOS,
					 ses->serverNOS);
		}

		sep = 0;
		SMBFS_PROC_PRINT_SEP(sep, "\t\tsecurity: %s",
			get_security_type_str(server->ops->select_sectype(server, ses->sectype)));
		SMBFS_PROC_PRINT_SEP_IF(ses->flags & SMB2_SESSION_FLAG_ENCRYPT_DATA,
				        sep, "encrypted");
		SMBFS_PROC_PRINT_SEP_IF(ses->signing_required, sep, "signed");
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
		list_for_each(tcon_entry, &ses->tcons) {
			tcon = list_entry(tcon_entry, struct smbfs_tcon, head);
			SMBFS_PROC_PRINT("\t\t[server %d session %d share %d]\n",
					 srv_idx, ses_idx, share_idx);
			smbfs_dump_tcon(m, tcon);
			share_idx++;
		}

		iface_idx = 0;
		spin_lock(&ses->iface_lock);
		SMBFS_PROC_PRINT_IF(ses->iface_count, "\tserver interfaces:\n");
		list_for_each_entry(iface, &ses->ifaces, head) {
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
					 struct smbfs_server_info *server,
					 int srv_idx)
{
	struct smbfs_mid_entry *mid_entry;

	spin_lock(&g_mid_lock);
	if (list_empty(&server->pending_mids)) {
		spin_unlock(&g_mid_lock);
		SMBFS_PROC_PRINT(" none\n");
		return;
	}

	list_for_each_entry(mid_entry, &server->pending_mids, head)
		SMBFS_PROC_PRINT("\t\tserver: %d, mid: %llu, state: %d, "
				 "cmd: %d, pid: %d, cbdata: 0x%p\n",
				 srv_idx, mid_entry->mid, mid_entry->state,
				 le16_to_cpu(mid_entry->cmd),
				 mid_entry->pid, mid_entry->callback_data);
	spin_unlock(&g_mid_lock);
	SMBFS_PROC_PRINT("\n");
}

/*
 * Ensure that if someone sets a MUST flag, that we disable all other MAY
 * flags except for the ones corresponding to the given MUST flag. If there are
 * multiple MUST flags, then try to prefer more secure ones.
 */
static inline void smbfs_handle_security_flags(unsigned int *flags)
{
	unsigned int signflags = *flags & SMBFS_SEC_MUST_SIGN;

	if ((*flags & SMBFS_SEC_MUST_KRB5) == SMBFS_SEC_MUST_KRB5)
		*flags = SMBFS_SEC_MUST_KRB5;
	else if ((*flags & SMBFS_SEC_MUST_NTLMSSP) == SMBFS_SEC_MUST_NTLMSSP)
		*flags = SMBFS_SEC_MUST_NTLMSSP;
	else if ((*flags & SMBFS_SEC_MUST_NTLMV2) == SMBFS_SEC_MUST_NTLMV2)
		*flags = SMBFS_SEC_MUST_NTLMV2;

	*flags |= signflags;

	if (*flags & SMBFS_SEC_MUST_SIGN) {
		/* requiring signing implies signing is allowed */
		*flags |= SMBFS_SEC_MAY_SIGN;
		smbfs_dbg("packet signing now required\n");
	} else if (!(*flags & SMBFS_SEC_MAY_SIGN)) {
		smbfs_dbg("packet signing disabled\n");
	}

	/* TODO: should we turn on MAY flags for other MUST options? */
}
#endif /* CONFIG_PROC_FS */
#endif /* _SMBFS_PROC_H */
