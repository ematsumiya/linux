// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (c) SUSE LLC, 2022
 *   Author: Enzo Matsumiya <ematsumiya@suse.de>
 *
 *   SMBFS procfs functions.
 */
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

#include "proc.h"

extern int log_level;

#ifdef CONFIG_PROC_FS
/* main procfs entry */
static struct proc_dir_entry *proc_fs_smbfs;

/* toggles smbfs_dump_smb() */
bool trace_smb = false;
/* toggles UNIX extensions */
bool unix_extensions = true;
/* toggles lookup cache */
bool lookup_cache = true;
/* security flags */
unsigned int security_flags = CIFSSEC_DEF;

void smbfs_print_stats(struct seq_file *m, struct cifs_tcon *tcon)
{
	int i;
	atomic_t *sent;
	atomic_t *failed;
	struct TCP_Server_Info *server = tcon->ses->server;

	SMBFS_PROC_PRINT("name: %s\n", tcon->treeName);
	SMBFS_PROC_PRINT("SMBs sent: %d\n\n", atomic_read(&tcon->num_smbs_sent));

	SMBFS_PROC_PRINT("Stats:\n");
	if (is_smb1_server(server)) {
		smbfs_print_stats_smb1(m, tcon);
		return;
	}

	sent = tcon->stats.smb2_stats.smb2_com_sent;
	failed = tcon->stats.smb2_stats.smb2_com_failed;

	/*
	 *  Can't display SMB2_NEGOTIATE, SESSION_SETUP, LOGOFF, CANCEL and ECHO
	 *  totals (requests sent) since those SMBs are per-session not per tcon
	 */
	SMBFS_PROC_PRINT("Bytes read: %llu, bytes written: %llu\n",
		   (long long)(tcon->bytes_read),
		   (long long)(tcon->bytes_written));
	SMBFS_PROC_PRINT("Open files: %d, total (local) %d open on server\n",
		   atomic_read(&tcon->num_local_opens),
		   atomic_read(&tcon->num_remote_opens));
	SMBFS_PROC_PRINT("TreeConnects: sent %d, failed %d\n",
		   atomic_read(&sent[SMB2_TREE_CONNECT_HE]),
		   atomic_read(&failed[SMB2_TREE_CONNECT_HE]));
	SMBFS_PROC_PRINT("TreeDisconnects: sent %d, failed %d\n",
		   atomic_read(&sent[SMB2_TREE_DISCONNECT_HE]),
		   atomic_read(&failed[SMB2_TREE_DISCONNECT_HE]));
	SMBFS_PROC_PRINT("Creates: sent %d, failed %d\n",
		   atomic_read(&sent[SMB2_CREATE_HE]),
		   atomic_read(&failed[SMB2_CREATE_HE]));
	SMBFS_PROC_PRINT("Closes: sent %d, failed %d\n",
		   atomic_read(&sent[SMB2_CLOSE_HE]),
		   atomic_read(&failed[SMB2_CLOSE_HE]));
	SMBFS_PROC_PRINT("Flushes: sent %d, failed %d\n",
		   atomic_read(&sent[SMB2_FLUSH_HE]),
		   atomic_read(&failed[SMB2_FLUSH_HE]));
	SMBFS_PROC_PRINT("Reads: sent %d, failed %d\n",
		   atomic_read(&sent[SMB2_READ_HE]),
		   atomic_read(&failed[SMB2_READ_HE]));
	SMBFS_PROC_PRINT("Writes: sent %d, failed %d\n",
		   atomic_read(&sent[SMB2_WRITE_HE]),
		   atomic_read(&failed[SMB2_WRITE_HE]));
	SMBFS_PROC_PRINT("Locks: sent %d, failed %d\n",
		   atomic_read(&sent[SMB2_LOCK_HE]),
		   atomic_read(&failed[SMB2_LOCK_HE]));
	SMBFS_PROC_PRINT("IOCTLs: sent %d, failed %d\n",
		   atomic_read(&sent[SMB2_IOCTL_HE]),
		   atomic_read(&failed[SMB2_IOCTL_HE]));
	SMBFS_PROC_PRINT("QueryDirectories: sent %d, failed %d\n",
		   atomic_read(&sent[SMB2_QUERY_DIRECTORY_HE]),
		   atomic_read(&failed[SMB2_QUERY_DIRECTORY_HE]));
	SMBFS_PROC_PRINT("ChangeNotifies: sent %d, failed %d\n",
		   atomic_read(&sent[SMB2_CHANGE_NOTIFY_HE]),
		   atomic_read(&failed[SMB2_CHANGE_NOTIFY_HE]));
	SMBFS_PROC_PRINT("QueryInfos: sent %d, failed %d\n",
		   atomic_read(&sent[SMB2_QUERY_INFO_HE]),
		   atomic_read(&failed[SMB2_QUERY_INFO_HE]));
	SMBFS_PROC_PRINT("SetInfos: sent %d, failed %d\n",
		   atomic_read(&sent[SMB2_SET_INFO_HE]),
		   atomic_read(&failed[SMB2_SET_INFO_HE]));
	SMBFS_PROC_PRINT("OplockBreaks: sent %d, failed %d\n",
		   atomic_read(&sent[SMB2_OPLOCK_BREAK_HE]),
		   atomic_read(&failed[SMB2_OPLOCK_BREAK_HE]));

#ifdef CONFIG_SMBFS_STATS_EXTRA
	SMBFS_PROC_PRINT("Total time spent processing by command "
			 "(in jiffies (%d per second)):\n\n", HZ);

	SMBFS_PROC_PRINT("  SMB CMD\tNumber\tTotal Time\tFastest\tSlowest\n");
	SMBFS_PROC_PRINT("  -------\t------\t----------\t-------\t-------\n");
	for (i = 0; i < NUMBER_OF_SMB2_COMMANDS; i++)
		SMBFS_PROC_PRINT("  %d\t\t%d\t%llu\t\t%u\t%u\n", i,
				 atomic_read(&server->num_cmds[i]),
				 server->time_per_cmd[i],
				 server->fastest_cmd[i],
				 server->slowest_cmd[i]);
	SMBFS_PROC_PRINT("\n");
	for (i = 0; i < NUMBER_OF_SMB2_COMMANDS; i++)
		SMBFS_PROC_PRINT_IF(atomic_read(&server->smb2slowcmd[i]),
				    "%d slow responses from %s for command %d\n",
				    atomic_read(&server->smb2slowcmd[i]),
				    server->hostname, i);
	SMBFS_PROC_PRINT("\n");
#endif /* CONFIG_SMBFS_STATS_EXTRA */
}

static inline void smbfs_print_fileinfo(struct seq_file *m,
					struct cifs_tcon *tcon,
					struct cifsFileInfo *cfile)
{
	SMBFS_PROC_PRINT("0x%x 0x%llx 0x%x %d %d %d 0x%pd", tcon->tid,
			 cfile->fid.persistent_fid, cfile->f_flags, cfile->count,
			 cfile->pid, from_kuid(&init_user_ns, cfile->uid),
			 cfile->dentry);
#ifdef CONFIG_SMBFS_DEBUG_EXTRA
	SMBFS_PROC_PRINT(" %llu", cfile->fid.mid);
#endif /* CONFIG_SMBFS_DEBUG_EXTRA */
	SMBFS_PROC_PRINT("\n");
}

static inline void smbfs_clear_stats_smb1(struct cifs_tcon *tcon)
{
	atomic_set(&tcon->stats.cifs_stats.num_writes, 0);
	atomic_set(&tcon->stats.cifs_stats.num_reads, 0);
	atomic_set(&tcon->stats.cifs_stats.num_flushes, 0);
	atomic_set(&tcon->stats.cifs_stats.num_oplock_brks, 0);
	atomic_set(&tcon->stats.cifs_stats.num_opens, 0);
	atomic_set(&tcon->stats.cifs_stats.num_posixopens, 0);
	atomic_set(&tcon->stats.cifs_stats.num_posixmkdirs, 0);
	atomic_set(&tcon->stats.cifs_stats.num_closes, 0);
	atomic_set(&tcon->stats.cifs_stats.num_deletes, 0);
	atomic_set(&tcon->stats.cifs_stats.num_mkdirs, 0);
	atomic_set(&tcon->stats.cifs_stats.num_rmdirs, 0);
	atomic_set(&tcon->stats.cifs_stats.num_renames, 0);
	atomic_set(&tcon->stats.cifs_stats.num_t2renames, 0);
	atomic_set(&tcon->stats.cifs_stats.num_ffirst, 0);
	atomic_set(&tcon->stats.cifs_stats.num_fnext, 0);
	atomic_set(&tcon->stats.cifs_stats.num_fclose, 0);
	atomic_set(&tcon->stats.cifs_stats.num_hardlinks, 0);
	atomic_set(&tcon->stats.cifs_stats.num_symlinks, 0);
	atomic_set(&tcon->stats.cifs_stats.num_locks, 0);
	atomic_set(&tcon->stats.cifs_stats.num_acl_get, 0);
	atomic_set(&tcon->stats.cifs_stats.num_acl_set, 0);
}

static inline void smbfs_clear_stats(struct cifs_tcon *tcon)
{
	int i;

	atomic_set(&tcon->num_smbs_sent, 0);

	spin_lock(&tcon->stat_lock);
	tcon->bytes_read = 0;
	tcon->bytes_written = 0;
	spin_unlock(&tcon->stat_lock);

	if (is_smb1_server(tcon->ses->server)) {
		smbfs_clear_stats_smb1(tcon);
		return;
	}

	for (i = 0; i < NUMBER_OF_SMB2_COMMANDS; i++) {
		atomic_set(&tcon->stats.smb2_stats.smb2_com_sent[i], 0);
		atomic_set(&tcon->stats.smb2_stats.smb2_com_failed[i], 0);
	}
}

static int smbfs_open_files_proc_show(struct seq_file *m, void *v)
{
	struct TCP_Server_Info *server;
	struct cifs_ses *ses;
	struct cifs_tcon *tcon;
	struct cifsFileInfo *cfile;

	SMBFS_PROC_PRINT("# Version: 1\n");
	SMBFS_PROC_PRINT("# Format:\n");
	SMBFS_PROC_PRINT("# <tree id> <persistent fid> <flags> <count> <pid> "
			 "<uid> <filename>");
#ifdef CONFIG_SMBFS_DEBUG_EXTRA
	SMBFS_PROC_PRINT(" <mid>");
#endif /* CONFIG_SMBFS_DEBUG_EXTRA */
	SMBFS_PROC_PRINT("\n");

	spin_lock(&cifs_tcp_ses_lock);
	list_for_each_entry(server, &cifs_tcp_ses_list, tcp_ses_list) {
		list_for_each_entry(ses, &server->smb_ses_list, smb_ses_list) {
			list_for_each_entry(tcon, &ses->tcon_list, tcon_list) {
				spin_lock(&tcon->open_file_lock);
				list_for_each_entry(cfile, &tcon->openFileList, tlist)
					smbfs_print_fileinfo(m, tcon, cfile);
				spin_unlock(&tcon->open_file_lock);
			} /* tcon_list */
		} /* smb_ses_list */
	} /* tcp_ses_list */
	spin_unlock(&cifs_tcp_ses_lock);
	return 0;
}

static int smbfs_debug_data_proc_show(struct seq_file *m, void *v)
{
	struct TCP_Server_Info *server;
	int srv_idx, sep = 0;

	SMBFS_PROC_PRINT("Internal SMBFS data structures\n"
			 "------------------------------\n");
	smbfs_debug_data_features(m);

	SMBFS_PROC_PRINT("CIFSMaxBufSize: %d\n", CIFSMaxBufSize);
	SMBFS_PROC_PRINT("Active VFS requests: %d\n\n", GlobalTotalActiveXid);

	srv_idx = 0;
	spin_lock(&cifs_tcp_ses_lock);
	SMBFS_PROC_PRINT("servers:%s\n",
			 list_empty(&cifs_tcp_ses_list) ? " none" : "");

	list_for_each_entry(server, &cifs_tcp_ses_list, tcp_ses_list) {
		/* channel info will be printed as a part of sessions below */
		if (CIFS_SERVER_IS_CHAN(server))
			continue;

		SMBFS_PROC_PRINT("\t[server %d]\n"
				 "\thostname: %s\n"
				 "\tconnection ID: 0x%llx\n"
				 "\tdialect: 0x%x\n"
				 "\tnumber of credits: %d\n",
				 srv_idx, server->hostname ?: "N/A",
				 server->conn_id, server->dialect,
				 server->credits);
#ifdef CONFIG_SMBFS_SMB_DIRECT
		smbfs_debug_data_rdma(m, server);
#endif

		SMBFS_PROC_PRINT("\tcompression: ");
		SMBFS_PROC_PRINT_SEP_IF(server->compress_algorithm == SMB3_COMPRESS_LZNT1,
				        sep, "COMPRESS_LZNT1");
		else SMBFS_PROC_PRINT_SEP_IF(server->compress_algorithm == SMB3_COMPRESS_LZ77,
					     sep, "COMPRESS_LZ77");
		else SMBFS_PROC_PRINT_SEP_IF(server->compress_algorithm == SMB3_COMPRESS_LZ77_HUFF,
					     sep, "COMPRESS_LZ77_HUFF");
		else SMBFS_PROC_PRINT("none");
		SMBFS_PROC_PRINT("\n");

		SMBFS_PROC_PRINT("\tfeatures: ");
		SMBFS_PROC_PRINT_SEP_IF(server->sign, sep, "signed");
		SMBFS_PROC_PRINT_SEP_IF(server->posix_ext_supported, sep, "POSIX");
		SMBFS_PROC_PRINT_SEP_IF(server->nosharesock, sep, "nosharesock");
		SMBFS_PROC_PRINT_SEP_IF(server->rdma, sep, "RDMA");
		SMBFS_PROC_PRINT("\n");
		sep = 0;

		smbfs_dump_tcp_status(m, server, "\t");

		SMBFS_PROC_PRINT("\tsessions:\n");
		smbfs_debug_data_sessions(m, server, srv_idx);
		SMBFS_PROC_PRINT("\n");

		SMBFS_PROC_PRINT("\tMIDs:\n");
		smbfs_debug_data_mids(m, server, srv_idx);
		SMBFS_PROC_PRINT("--\n");
	}
	spin_unlock(&cifs_tcp_ses_lock);

#ifdef CONFIG_SMBFS_SWN_UPCALL
	cifs_swn_dump(m);
#endif /* CONFIG_SMBFS_SWN_UPCALL */

	/* TODO: add code to dump additional info such as TCP session info now */
	return 0;
}

static ssize_t smbfs_stats_proc_write(struct file *file,
				      const char __user *buffer, size_t count,
				      loff_t *ppos)
{
	int rc;
	bool bv;
	struct TCP_Server_Info *server;
	struct cifs_ses *ses;
	struct cifs_tcon *tcon;
#ifdef CONFIG_SMBFS_STATS_EXTRA
	int i;
#endif /* CONFIG_SMBFS_STATS_EXTRA */

	rc = kstrtobool_from_user(buffer, count, &bv);
	if (rc)
		return rc;

#ifdef CONFIG_SMBFS_STATS_EXTRA
	atomic_set(&totBufAllocCount, 0);
	atomic_set(&totSmBufAllocCount, 0);
#endif /* CONFIG_SMBFS_STATS_EXTRA */
	atomic_set(&tcpSesReconnectCount, 0);
	atomic_set(&tconInfoReconnectCount, 0);

	spin_lock(&GlobalMid_Lock);
	GlobalMaxActiveXid = 0;
	GlobalCurrentXid = 0;
	spin_unlock(&GlobalMid_Lock);

	spin_lock(&cifs_tcp_ses_lock);
	list_for_each_entry(server, &cifs_tcp_ses_list, tcp_ses_list) {
		server->max_in_flight = 0;

		list_for_each_entry(ses, &server->smb_ses_list, smb_ses_list)
			list_for_each_entry(tcon, &ses->tcon_list, tcon_list)
				smbfs_clear_stats(tcon);

#ifdef CONFIG_SMBFS_STATS_EXTRA
		for (i = 0; i < NUMBER_OF_SMB2_COMMANDS; i++) {
			atomic_set(&server->num_cmds[i], 0);
			atomic_set(&server->smb2slowcmd[i], 0);
			server->time_per_cmd[i] = 0;
			server->slowest_cmd[i] = 0;
			server->fastest_cmd[0] = 0;
		}
#endif /* CONFIG_SMBFS_STATS_EXTRA */
	}
	spin_unlock(&cifs_tcp_ses_lock);

	return count;
}

static int smbfs_stats_proc_show(struct seq_file *m, void *v)
{
	int srv_idx, ses_idx, share_idx;
	struct TCP_Server_Info *server;
	struct cifs_ses *ses;
	struct cifs_tcon *tcon;

	SMBFS_PROC_PRINT("Resources in use\n"
			 "----------------\n");
	SMBFS_PROC_PRINT("SMBFS session: %d\n",
			 sesInfoAllocCount.counter);
	SMBFS_PROC_PRINT("Shares (unique mount targets): %d\n",
			 tconInfoAllocCount.counter);
	SMBFS_PROC_PRINT("SMB request/response buffers: %d, pool size: %d\n",
			 bufAllocCount.counter,
			 cifs_min_rcv + tcpSesAllocCount.counter);
	SMBFS_PROC_PRINT("SMB small request/response buffers: %d, pool size: %d\n",
			 smBufAllocCount.counter, cifs_min_small);
#ifdef CONFIG_SMBFS_STATS_EXTRA
	SMBFS_PROC_PRINT("Total allocations: large %d, small %d\n",
			 atomic_read(&totBufAllocCount),
			 atomic_read(&totSmBufAllocCount));
#endif /* CONFIG_SMBFS_STATS_EXTRA */

	SMBFS_PROC_PRINT("Operations (MIDs): %d\n\n", atomic_read(&midCount));
	SMBFS_PROC_PRINT("Sessions: %d\n"
			 "Share reconnects: %d\n",
			 tcpSesReconnectCount.counter,
			 tconInfoReconnectCount.counter);
	SMBFS_PROC_PRINT("Total VFS operations: %d, maximum at one time: %d\n",
			 GlobalCurrentXid, GlobalMaxActiveXid);

	srv_idx = ses_idx = share_idx = 0;

	spin_lock(&cifs_tcp_ses_lock);
	list_for_each_entry(server, &cifs_tcp_ses_list, tcp_ses_list) {
		SMBFS_PROC_PRINT("Max requests in flight: %d\n\n",
				 server->max_in_flight);

		list_for_each_entry(ses, &server->smb_ses_list, smb_ses_list) {
			list_for_each_entry(tcon, &ses->tcon_list, tcon_list) {
				SMBFS_PROC_PRINT("[share %d]%s\n", share_idx,
						 tcon->need_reconnect ?
						 " (disconnected)" : "");
				smbfs_print_stats(m, tcon);
				share_idx++;
			}
			ses_idx++;
		}
		SMBFS_PROC_PRINT("\n");
		srv_idx++;
	}
	spin_unlock(&cifs_tcp_ses_lock);

	return 0;
}

static int smbfs_log_level_proc_show(struct seq_file *m, void *v)
{
	SMBFS_PROC_PRINT("%d\n", log_level);
	return 0;
}

static ssize_t smbfs_log_level_proc_write(struct file *file,
					  const char __user *buffer,
					  size_t count, loff_t *ppos)
{
	char c[2] = { '\0' };
	bool bv;
	int rc;

	rc = get_user(c[0], buffer);
	if (rc)
		return rc;

	if (strtobool(c, &bv) == 0)
		log_level = (int)bv;
	else if ((c[0] > '1') && (c[0] <= '9'))
		log_level = (int)(c[0] - '0'); /* see debug.h for meanings */
	else
		return -EINVAL;

	return count;
}

static int smbfs_unix_extensions_proc_show(struct seq_file *m, void *v)
{
	SMBFS_PROC_PRINT("%d\n", unix_extensions);
	return 0;
}

static ssize_t smbfs_unix_extensions_proc_write(struct file *file,
						const char __user *buffer,
						size_t count, loff_t *ppos)
{
	int rc;

	rc = kstrtobool_from_user(buffer, count, &unix_extensions);
	if (rc)
		return rc;

	return count;
}

static int smbfs_lookup_cache_proc_show(struct seq_file *m, void *v)
{
	SMBFS_PROC_PRINT("%d\n", lookup_cache);
	return 0;
}

static ssize_t smbfs_lookup_cache_proc_write(struct file *file,
					     const char __user *buffer,
					     size_t count, loff_t *ppos)
{
	int rc;

	rc = kstrtobool_from_user(buffer, count, &lookup_cache);
	if (rc)
		return rc;

	return count;
}

static int smbfs_trace_smb_proc_show(struct seq_file *m, void *v)
{
	SMBFS_PROC_PRINT("%d\n", trace_smb);
	return 0;
}

static ssize_t smbfs_trace_smb_proc_write(struct file *file,
					  const char __user *buffer,
					  size_t count, loff_t *ppos)
{
	int rc;

	rc = kstrtobool_from_user(buffer, count, &trace_smb);
	if (rc)
		return rc;

	return count;
}

static int smbfs_security_flags_proc_show(struct seq_file *m, void *v)
{
	SMBFS_PROC_PRINT("0x%x\n", security_flags);
	return 0;
}

static ssize_t smbfs_security_flags_proc_write(struct file *file,
					       const char __user *buffer,
					       size_t count, loff_t *ppos)
{
	int rc;
	bool bv;
	unsigned int flags;
	char flags_string[12];

	if ((count < 1) || (count > 11))
		return -EINVAL;

	memset(flags_string, 0, 12);

	if (copy_from_user(flags_string, buffer, count))
		return -EFAULT;

	if (count < 3) {
		/* single char or single char followed by null */
		rc = strtobool(flags_string, &bv);
		if (rc || !isdigit(flags_string[0]))
			goto invalid_flags;

		security_flags = bv ? CIFSSEC_MAX : CIFSSEC_DEF;
		return count;
	}

	/* else we have a number */
	rc = kstrtouint(flags_string, 0, &flags);
	if (rc)
		goto invalid_flags;

	if (!flags)
		goto invalid_flags;

	smbfs_dbg("sec flags: 0x%x\n", flags);

	if (flags & ~CIFSSEC_MASK) {
		smbfs_log("Unsupported security flags: 0x%x\n",
			  flags & ~CIFSSEC_MASK);
		return -EINVAL;
	}

	smbfs_handle_security_flags(&flags);

	/* flags look ok - update the global security_flags */
	security_flags = flags;

	return count;

invalid_flags:
	smbfs_log("Invalid security flags '%s'\n", flags_string);
	return -EINVAL;
}

/* To make it easier to debug, can help to show mount params */
static int smbfs_mount_params_proc_show(struct seq_file *m, void *v)
{
	const struct fs_parameter_spec *p;
	const char *type;

	for (p = smb3_fs_parameters; p->name; p++) {
		/* cannot use switch with pointers... */
		if (!p->type) {
			if (p->flags == fs_param_neg_with_no)
				type = "noflag";
			else
				type = "flag";
		} else if (p->type == fs_param_is_bool)
			type = "bool";
		else if (p->type == fs_param_is_u32)
			type = "u32";
		else if (p->type == fs_param_is_u64)
			type = "u64";
		else if (p->type == fs_param_is_string)
			type = "string";
		else
			type = "unknown";

		SMBFS_PROC_PRINT("%s:%s\n", p->name, type);
	}

	return 0;
}

static int smbfs_mount_params_proc_open(struct inode *inode, struct file *file)
{
       return single_open(file, smbfs_mount_params_proc_show, NULL);
}

static const struct proc_ops smbfs_mount_params_proc_ops = {
	.proc_open	= smbfs_mount_params_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	/* no need for write for now */
};

SMBFS_PROC_OPS_DEFINE(log_level);
SMBFS_PROC_OPS_DEFINE(trace_smb);
SMBFS_PROC_OPS_DEFINE(stats);
SMBFS_PROC_OPS_DEFINE(security_flags);
/* TODO: rename this to posix_extensions after module split (cifs/SMB2+) */
SMBFS_PROC_OPS_DEFINE(unix_extensions);
SMBFS_PROC_OPS_DEFINE(lookup_cache);
#ifdef CONFIG_SMBFS_SMB_DIRECT
/* SMB Direct procfs entries */
SMBFS_SMB_DIRECT_PROC_DEFINE(rdma_readwrite_threshold);
SMBFS_SMB_DIRECT_PROC_DEFINE(smbd_max_frmr_depth);
SMBFS_SMB_DIRECT_PROC_DEFINE(smbd_keep_alive_interval);
SMBFS_SMB_DIRECT_PROC_DEFINE(smbd_max_receive_size);
SMBFS_SMB_DIRECT_PROC_DEFINE(smbd_max_fragmented_recv_size);
SMBFS_SMB_DIRECT_PROC_DEFINE(smbd_max_send_size);
SMBFS_SMB_DIRECT_PROC_DEFINE(smbd_send_credit_target);
SMBFS_SMB_DIRECT_PROC_DEFINE(smbd_receive_credit_max);
#endif /* CONFIG_SMBFS_SMB_DIRECT */

#define SMBFS_PROC_CREATE_RW(name) \
	proc_create(#name, 0644, proc_fs_smbfs, &smbfs_ ## name ## _proc_ops)
#define SMBFS_PROC_CREATE_RO(name) \
	proc_create(#name, 0444, proc_fs_smbfs, &smbfs_ ## name ## _proc_ops)
#define SMBFS_PROC_CREATE_SINGLE(name, mode) \
	proc_create_single(#name, mode, proc_fs_smbfs, &smbfs_ ## name ## _proc_show)

void smbfs_proc_init(void)
{
	proc_fs_smbfs = proc_mkdir("fs/smbfs", NULL);
	if (!proc_fs_smbfs) {
		pr_warn("%s: proc_mkdir() failed\n", __func__);
		return;
	}

	SMBFS_PROC_CREATE_SINGLE(debug_data, 0);
	SMBFS_PROC_CREATE_SINGLE(open_files, 0400);
	SMBFS_PROC_CREATE_RW(log_level);
	SMBFS_PROC_CREATE_RW(trace_smb);
	SMBFS_PROC_CREATE_RW(stats);
	SMBFS_PROC_CREATE_RW(security_flags);
	SMBFS_PROC_CREATE_RW(unix_extensions);
	SMBFS_PROC_CREATE_RW(lookup_cache);
	SMBFS_PROC_CREATE_RO(mount_params);
#ifdef CONFIG_SMBFS_DFS_UPCALL
	/* TODO: move dfscache_proc_ops here */
	proc_create("dfscache", 0644, proc_fs_smbfs, &dfscache_proc_ops);
#endif /* CONFIG_SMBFS_DFS_UPCALL */
#ifdef CONFIG_SMBFS_SMB_DIRECT
	SMBFS_PROC_CREATE_RW(rdma_readwrite_threshold);
	SMBFS_PROC_CREATE_RW(smbd_max_frmr_depth);
	SMBFS_PROC_CREATE_RW(smbd_keep_alive_interval);
	SMBFS_PROC_CREATE_RW(smbd_max_receive_size);
	SMBFS_PROC_CREATE_RW(smbd_max_fragmented_recv_size);
	SMBFS_PROC_CREATE_RW(smbd_max_send_size);
	SMBFS_PROC_CREATE_RW(smbd_send_credit_target);
	SMBFS_PROC_CREATE_RW(smbd_receive_credit_max);
#endif /* CONFIG_SMBFS_SMB_DIRECT */
}

void smbfs_proc_clean(void)
{
	if (!proc_fs_smbfs)
		return;

	remove_proc_entry("debug_data", proc_fs_smbfs);
	remove_proc_entry("open_files", proc_fs_smbfs);
	remove_proc_entry("log_level", proc_fs_smbfs);
	remove_proc_entry("trace_smb", proc_fs_smbfs);
	remove_proc_entry("stats", proc_fs_smbfs);
	remove_proc_entry("security_flags", proc_fs_smbfs);
	remove_proc_entry("unix_extensions", proc_fs_smbfs);
	remove_proc_entry("lookup_cache", proc_fs_smbfs);
	remove_proc_entry("mount_params", proc_fs_smbfs);
#ifdef CONFIG_SMBFS_DFS_UPCALL
	remove_proc_entry("dfscache", proc_fs_smbfs);
#endif /* CONFIG_SMBFS_DFS_UPCALL */
#ifdef CONFIG_SMBFS_SMB_DIRECT
	remove_proc_entry("rdma_readwrite_threshold", proc_fs_smbfs);
	remove_proc_entry("smbd_max_frmr_depth", proc_fs_smbfs);
	remove_proc_entry("smbd_keep_alive_interval", proc_fs_smbfs);
	remove_proc_entry("smbd_max_receive_size", proc_fs_smbfs);
	remove_proc_entry("smbd_max_fragmented_recv_size", proc_fs_smbfs);
	remove_proc_entry("smbd_max_send_size", proc_fs_smbfs);
	remove_proc_entry("smbd_send_credit_target", proc_fs_smbfs);
	remove_proc_entry("smbd_receive_credit_max", proc_fs_smbfs);
#endif /* CONFIG_SMBFS_SMB_DIRECT */
	remove_proc_entry("fs/smbfs", NULL);
}
#else
inline void smbfs_proc_init(void) {}
inline void smbfs_proc_clean(void) {}
#endif /* CONFIG_PROC_FS */
