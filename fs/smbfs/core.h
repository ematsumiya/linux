// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) SUSE LLC, 2022
 *
 * Author(s): Enzo Matsumiya <ematsumiya@suse.de>
 *
 * Core definitions for SMBFS module.
 */
#ifndef _SMBFS_CORE_H
#define _SMBFS_CORE_H

#include "server_info.h"

struct smbfs_mid_entry;
struct smbfs_server_info;
struct smbfs_file_info;
struct smbfs_ses;
struct smbfs_tcon;
struct smbfs_dfs_info;
struct smbfs_fattr;
struct smb3_fs_context;
struct smbfs_fid;
struct smbfs_readdata;
struct smbfs_writedata;
struct smbfs_io_parms;
struct smbfs_search_info;
struct smbfs_inode_info;
struct smbfs_open_parms;
struct smbfs_credits;

struct smbfs_operations {
	int (*send_cancel)(struct smbfs_server_info *, struct smb_rqst *,
			   struct smbfs_mid_entry *);
	bool (*compare_fids)(struct smbfs_file_info *, struct smbfs_file_info *);
	/* setup request: allocate mid, sign message */
	struct smbfs_mid_entry *(*setup_request)(struct smbfs_ses *,
						 struct smbfs_server_info *,
						 struct smb_rqst *);
	/* setup async request: allocate mid, sign message */
	struct smbfs_mid_entry *(*setup_async_request)(struct smbfs_server_info *,
						       struct smb_rqst *);
	/* check response: verify signature, map error */
	int (*check_receive)(struct smbfs_mid_entry *, struct smbfs_server_info *,
			     bool);
	void (*add_credits)(struct smbfs_server_info *server,
			    const struct smbfs_credits *credits,
			    const int optype);
	void (*set_credits)(struct smbfs_server_info *, const int);
	int * (*get_credits_field)(struct smbfs_server_info *, const int);
	unsigned int (*get_credits)(struct smbfs_mid_entry *);
	unsigned long (*get_next_mid)(struct smbfs_server_info *);
	void (*revert_current_mid)(struct smbfs_server_info *server,
				   const unsigned int val);
	/* data offset from read response message */
	unsigned int (*read_data_offset)(char *);
	/*
	 * Data length from read response message
	 * When in_remaining is true, the returned data length is in
	 * message field DataRemaining for out-of-band data read (e.g through
	 * Memory Registration RDMA write in SMBD).
	 * Otherwise, the returned data length is in message field DataLength.
	 */
	unsigned int (*read_data_length)(char *, bool in_remaining);
	/* map SMB to linux error */
	int (*map_error)(char *, bool);
	/* find mid corresponding to the response message */
	struct smbfs_mid_entry * (*find_mid)(struct smbfs_server_info *, char *);
	/* verify the message */
	int (*check_message)(char *, unsigned int, struct smbfs_server_info *);
	bool (*is_oplock_break)(char *, struct smbfs_server_info *);
	int (*handle_cancelled_mid)(struct smbfs_mid_entry *,
				    struct smbfs_server_info *);
	void (*downgrade_oplock)(struct smbfs_server_info *server,
				 struct smbfs_inode_info *smb_i, unsigned int oplock,
				 unsigned int epoch, bool *purge_cache);
	/* process transaction2 response */
	bool (*check_trans2)(struct smbfs_mid_entry *,
			     struct smbfs_server_info *, char *);
	/* check if we need to negotiate */
	bool (*need_neg)(struct smbfs_server_info *);
	/* negotiate to the server */
	int (*negotiate)(const unsigned int xid, struct smbfs_ses *ses,
			 struct smbfs_server_info *server);
	/* set negotiated write size */
	unsigned int (*negotiate_wsize)(struct smbfs_tcon *tcon,
					struct smb3_fs_context *ctx);
	/* set negotiated read size */
	unsigned int (*negotiate_rsize)(struct smbfs_tcon *tcon,
					struct smb3_fs_context *ctx);
	/* setup SMB sessionn */
	int (*sess_setup)(const unsigned int, struct smbfs_ses *,
			  struct smbfs_server_info *server,
			  const struct nls_table *);
	/* close SMB session */
	int (*logoff)(const unsigned int, struct smbfs_ses *);
	/* connect to a server share */
	int (*tree_connect)(const unsigned int, struct smbfs_ses *, const char *,
			    struct smbfs_tcon *, const struct nls_table *);
	/* close tree connecion */
	int (*tree_disconnect)(const unsigned int, struct smbfs_tcon *);
	/* get DFS referrals */
	int (*get_dfs_refer)(const unsigned int, struct smbfs_ses *,
			     const char *, struct smbfs_dfs_info **,
			     unsigned int *, const struct nls_table *, int);
	/* informational QFS call */
	void (*qfs_tcon)(const unsigned int, struct smbfs_tcon *,
			 struct cifs_sb_info *);
	/* check if a path is accessible or not */
	int (*is_path_accessible)(const unsigned int, struct smbfs_tcon *,
				  struct cifs_sb_info *, const char *);
	/* query path data from the server */
	int (*query_path_info)(const unsigned int, struct smbfs_tcon *,
			       struct cifs_sb_info *, const char *,
			       FILE_ALL_INFO *, bool *, bool *);
	/* query file data from the server */
	int (*query_file_info)(const unsigned int, struct smbfs_tcon *,
			       struct smbfs_fid *, FILE_ALL_INFO *);
	/* query reparse tag from srv to determine which type of special file */
	int (*query_reparse_tag)(const unsigned int xid, struct smbfs_tcon *tcon,
				 struct cifs_sb_info *cifs_sb, const char *path,
				 unsigned int *reparse_tag);
	/* get server index number */
	int (*get_srv_inum)(const unsigned int, struct smbfs_tcon *,
			    struct cifs_sb_info *, const char *,
			    unsigned long *id, FILE_ALL_INFO *);
	/* set size by path */
	int (*set_path_size)(const unsigned int, struct smbfs_tcon *,
			     const char *, u64, struct cifs_sb_info *, bool);
	/* set size by file handle */
	int (*set_file_size)(const unsigned int, struct smbfs_tcon *,
			     struct smbfs_file_info *, u64, bool);
	/* set attributes */
	int (*set_file_info)(struct inode *, const char *, FILE_BASIC_INFO *,
			     const unsigned int);
	int (*set_compression)(const unsigned int, struct smbfs_tcon *,
			       struct smbfs_file_info *);
	/* check if we can send an echo or nor */
	bool (*can_echo)(struct smbfs_server_info *);
	/* send echo request */
	int (*echo)(struct smbfs_server_info *);
	/* create directory */
	int (*posix_mkdir)(const unsigned int xid, struct inode *inode,
			   umode_t mode, struct smbfs_tcon *tcon,
			   const char *full_path,
			   struct cifs_sb_info *cifs_sb);
	int (*mkdir)(const unsigned int xid, struct inode *inode, umode_t mode,
		     struct smbfs_tcon *tcon, const char *name,
		     struct cifs_sb_info *sb);
	/* set info on created directory */
	void (*mkdir_setinfo)(struct inode *, const char *,
			      struct cifs_sb_info *, struct smbfs_tcon *,
			      const unsigned int);
	/* remove directory */
	int (*rmdir)(const unsigned int, struct smbfs_tcon *, const char *,
		     struct cifs_sb_info *);
	/* unlink file */
	int (*unlink)(const unsigned int, struct smbfs_tcon *, const char *,
		      struct cifs_sb_info *);
	/* open, rename and delete file */
	int (*rename_pending_delete)(const char *, struct dentry *,
				     const unsigned int);
	/* send rename request */
	int (*rename)(const unsigned int, struct smbfs_tcon *, const char *,
		      const char *, struct cifs_sb_info *);
	/* send create hardlink request */
	int (*create_hardlink)(const unsigned int, struct smbfs_tcon *,
			       const char *, const char *,
			       struct cifs_sb_info *);
	/* query symlink target */
	int (*query_symlink)(const unsigned int, struct smbfs_tcon *,
			     struct cifs_sb_info *, const char *,
			     char **, bool);
	/* open a file for non-posix mounts */
	int (*open)(const unsigned int, struct smbfs_open_parms *,
		    unsigned int *, FILE_ALL_INFO *);
	/* set fid protocol-specific info */
	void (*set_fid)(struct smbfs_file_info *, struct smbfs_fid *, u32);
	/* close a file */
	void (*close)(const unsigned int, struct smbfs_tcon *,
		      struct smbfs_fid *);
	/* close a file, returning file attributes and timestamps */
	void (*close_getattr)(const unsigned int xid, struct smbfs_tcon *tcon,
		      struct smbfs_file_info *pfile_info);
	/* send a flush request to the server */
	int (*flush)(const unsigned int, struct smbfs_tcon *, struct smbfs_fid *);
	/* async read from the server */
	int (*async_readv)(struct smbfs_readdata *);
	/* async write to the server */
	int (*async_writev)(struct smbfs_writedata *,
			    void (*release)(struct kref *));
	/* sync read from the server */
	int (*sync_read)(const unsigned int, struct smbfs_fid *,
			 struct smbfs_io_parms *, unsigned int *, char **, int *);
	/* sync write to the server */
	int (*sync_write)(const unsigned int, struct smbfs_fid *,
			  struct smbfs_io_parms *, unsigned int *, struct kvec *,
			  unsigned long);
	/* open dir, start readdir */
	int (*query_dir_first)(const unsigned int, struct smbfs_tcon *,
			       const char *, struct cifs_sb_info *,
			       struct smbfs_fid *, u16,
			       struct smbfs_search_info *);
	/* continue readdir */
	int (*query_dir_next)(const unsigned int, struct smbfs_tcon *,
			      struct smbfs_fid *,
			      u16, struct smbfs_search_info *srch_inf);
	/* close dir */
	int (*close_dir)(const unsigned int, struct smbfs_tcon *,
			 struct smbfs_fid *);
	/* calculate a size of SMB message */
	unsigned int (*calc_smb_size)(void *buf, struct smbfs_server_info *ptcpi);
	/* check for STATUS_PENDING and process the response if yes */
	bool (*is_status_pending)(char *buf, struct smbfs_server_info *server);
	/* check for STATUS_NETWORK_SESSION_EXPIRED */
	bool (*is_session_expired)(char *);
	/* send oplock break response */
	int (*oplock_response)(struct smbfs_tcon *, struct smbfs_fid *,
			       struct smbfs_inode_info *);
	/* query remote filesystem */
	int (*queryfs)(const unsigned int, struct smbfs_tcon *,
		       struct cifs_sb_info *, struct kstatfs *);
	/* send mandatory brlock to the server */
	int (*mand_lock)(const unsigned int, struct smbfs_file_info *, u64,
			 u64, u32, int, int, bool);
	/* unlock range of mandatory locks */
	int (*mand_unlock_range)(struct smbfs_file_info *, struct file_lock *,
				 const unsigned int);
	/* push brlocks from the cache to the server */
	int (*push_mand_locks)(struct smbfs_file_info *);
	/* get lease key of the inode */
	void (*get_lease_key)(struct inode *, struct smbfs_fid *);
	/* set lease key of the inode */
	void (*set_lease_key)(struct inode *, struct smbfs_fid *);
	/* generate new lease key */
	void (*new_lease_key)(struct smbfs_fid *);
	int (*generate_signingkey)(struct smbfs_ses *ses,
				   struct smbfs_server_info *);
	int (*calc_signature)(struct smb_rqst *, struct smbfs_server_info *,
			      bool);
	int (*set_integrity)(const unsigned int, struct smbfs_tcon *,
			     struct smbfs_file_info *);
	int (*enum_snapshots)(const unsigned int, struct smbfs_tcon *,
			      struct smbfs_file_info *, void __user *);
	int (*notify)(const unsigned int, struct file *, void __user *);
	int (*query_mf_symlink)(unsigned int, struct smbfs_tcon *,
				struct cifs_sb_info *, const unsigned char *,
				char *, unsigned int *);
	int (*create_mf_symlink)(unsigned int, struct smbfs_tcon *,
				 struct cifs_sb_info *, const unsigned char *,
				 char *, unsigned int *);
	/* if we can do cache read operations */
	bool (*is_read_op)(u32);
	/* set oplock level for the inode */
	void (*set_oplock_level)(struct smbfs_inode_info *, u32, unsigned int,
				 bool *);
	/* create lease context buffer for CREATE request */
	char * (*create_lease_buf)(u8 *, u8);
	/* parse lease context buffer and return oplock/epoch info */
	u8 (*parse_lease_buf)(void *, unsigned int *, char *);
	ssize_t (*copychunk_range)(const unsigned int, struct smbfs_file_info *,
				   struct smbfs_file_info *, u64, u64, u64);
	int (*duplicate_extents)(const unsigned int, struct smbfs_file_info *,
				 struct smbfs_file_info *, u64, u64, u64);
	int (*validate_negotiate)(const unsigned int, struct smbfs_tcon *);
	ssize_t (*query_all_eas)(const unsigned int, struct smbfs_tcon *,
				 const unsigned char *, const unsigned char *,
				 char *, size_t, struct cifs_sb_info *);
	int (*set_ea)(const unsigned int, struct smbfs_tcon *, const char *,
		      const char *, const void *, const u16,
		      const struct nls_table *, struct cifs_sb_info *);
	struct cifs_ntsd *(*get_acl)(struct cifs_sb_info *, struct inode *,
				     const char *, unsigned int *, u32);
	struct cifs_ntsd *(*get_acl_by_fid)(struct cifs_sb_info *,
			   const struct smbfs_fid *, unsigned int *, u32);
	int (*set_acl)(struct cifs_ntsd *, u32, struct inode *, const char *, int);
	/* writepages retry size */
	unsigned int (*wp_retry_size)(struct inode *);
	/* get mtu credits */
	int (*wait_mtu_credits)(struct smbfs_server_info *, unsigned int,
				unsigned int *, struct smbfs_credits *);
	/* adjust previously taken mtu credits to request size */
	int (*adjust_credits)(struct smbfs_server_info *, struct smbfs_credits *,
			      const unsigned int);
	/* check if we need to issue closedir */
	bool (*dir_needs_close)(struct smbfs_file_info *);
	long (*fallocate)(struct file *, struct smbfs_tcon *, int, loff_t, loff_t);
	/* init transform request - used for encryption for now */
	int (*init_transform_rq)(struct smbfs_server_info *, int,
				 struct smb_rqst *, struct smb_rqst *);
	int (*is_transform_hdr)(void *);
	int (*receive_transform)(struct smbfs_server_info *,
				 struct smbfs_mid_entry **, char **, int *);
	smbfs_security_t (*select_sectype)(struct smbfs_server_info *,
			  smbfs_security_t);
	int (*next_header)(char *);
	/* ioctl passthrough for query_info */
	int (*ioctl_query_info)(const unsigned int, struct smbfs_tcon *,
				struct cifs_sb_info *, __le16 *, int, unsigned long);
	/* make unix special files (block, char, fifo, socket) */
	int (*make_node)(unsigned int, struct inode *, struct dentry *,
			 struct smbfs_tcon *, const char *, umode_t, dev_t);
	/* version specific fiemap implementation */
	int (*fiemap)(struct smbfs_tcon *, struct smbfs_file_info *,
		      struct fiemap_extent_info *, u64, u64);
	/* version specific llseek implementation */
	loff_t (*llseek)(struct file *, struct smbfs_tcon *, loff_t, int);
	/* Check for STATUS_IO_TIMEOUT */
	bool (*is_status_io_timeout)(char *);
	/* Check for STATUS_NETWORK_NAME_DELETED */
	void (*is_network_name_deleted)(char *, struct smbfs_server_info *);
};

struct smbfs_mnt_data {
	struct cifs_sb_info *sb;
	struct smbfs_fs_context *ctx;
	unsigned long flags;
};

static inline unsigned int get_rfc1002_len(void *buf)
{
	return be32_to_cpu(*((__be32 *)buf)) & 0xffffff;
}

static inline void inc_rfc1001_len(void *buf, unsigned int count)
{
	be32_add_cpu((__be32 *)buf, count);
}

static inline char dir_sep(const struct cifs_sb_info *sb)
{
	if (sb->mnt_cifs_flags & CIFS_MOUNT_POSIX_PATHS)
		return '/';
	else
		return '\\';
}

static inline void convert_delimiter(char *path, char delim)
{
	char old_delim, *pos;

	if (delim == '/')
		old_delim = '\\';
	else
		old_delim = '/';

	pos = path;
	while ((pos = strchr(pos, old_delim)))
		*pos = delim;
}

static inline bool is_interrupt_error(int error)
{
	switch (error) {
	case -EINTR:
	case -ERESTARTSYS:
	case -ERESTARTNOHAND:
	case -ERESTARTNOINTR:
		return true;
	}
	return false;
}

static inline bool is_retryable_error(int error)
{
	if (is_interrupt_error(error) || error == -EAGAIN)
		return true;
	return false;
}

/*
 * Operations for different SMB versions
 */
#define SMB1_VERSION_STRING		"1.0"
#define SMB20_VERSION_STRING		"2.0"
#ifdef CONFIG_SMBFS_ALLOW_INSECURE_LEGACY
extern struct smbfs_operations smb1_ops;
extern struct smbfs_server_settings smb1_settings;
extern struct smbfs_operations smb20_ops;
extern struct smbfs_server_settings smb20_settings;
#endif /* CONFIG_SMBFS_ALLOW_INSECURE_LEGACY */
#define SMB21_VERSION_STRING		"2.1"
extern struct smbfs_operations smb21_ops;
extern struct smbfs_server_settings smb21_settings;
#define SMBDEFAULT_VERSION_STRING	"default"
extern struct smbfs_server_settings smbfs_default_settings;
#define SMB3ANY_VERSION_STRING		"3"
extern struct smbfs_server_settings smb3any_settings;
#define SMB30_VERSION_STRING		"3.0"
extern struct smbfs_operations smb30_ops;
extern struct smbfs_server_settings smb30_settings;
#define SMB302_VERSION_STRING		"3.02"
#define ALT_SMB302_VERSION_STRING	"3.0.2"
extern struct smbfs_server_settings smb302_settings;
#define SMB311_VERSION_STRING		"3.1.1"
#define ALT_SMB311_VERSION_STRING	"3.11"
extern struct smbfs_operations smb311_ops;
extern struct smbfs_server_settings smb311_settings;
#endif /* _SMBFS_CORE_H */
