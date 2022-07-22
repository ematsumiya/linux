// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) SUSE LLC, 2022
 *
 * Author(s): Enzo Matsumiya <ematsumiya@suse.de>
 *
 * File (file_info), inode (inode_info), dir, fid, deferred close, and etc
 * goes here.
*/
#ifndef _SMBFS_FILE_H
#define _SMBFS_FILE_H

#define SMBFS_MAX_REOPEN_RETRIES	5 /* maximum attempts to reopen a file */

/*
 * Common struct for holding inode info when searching for or updating an
 * inode with new info
 */
#define SMBFS_FATTR_DFS_REFERRAL	0x01
#define SMBFS_FATTR_DELETE_PENDING	0x02
#define SMBFS_FATTR_NEED_REVAL		0x04
#define SMBFS_FATTR_INO_COLLISION	0x08
#define SMBFS_FATTR_UNKNOWN_NLINK	0x10
#define SMBFS_FATTR_FAKE_ROOT_INO	0x20

struct smbfs_file_info;
struct work_struct;

extern struct workqueue_struct *fileinfo_put_wq;
extern struct workqueue_struct *deferredclose_wq;
void smbfs_deferred_work_close(struct work_struct *work);

struct smbfs_file_info *smbfs_get_file_info(struct smbfs_file_info *fi);
void _smbfs_put_file_info(struct smbfs_file_info *fi, bool wait_oplock,
			  bool offload);
void smbfs_put_file_info(struct smbfs_file_info *fi);

struct smbfs_fattr {
	unsigned long flags;
	u32 smb1_attrs;
	u64 id; /* unique ID */
	u64 eof;
	u64 bytes;
	u64 createtime;
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
	dev_t rdev;
	u32 nlink;
	u32 dtype;
	struct timespec64 atime;
	struct timespec64 mtime;
	struct timespec64 ctime;
	u32 tag;
};

struct smbfs_cached_dir_entry {
	struct list_head head;
	char *name;
	int len;
	loff_t pos;

	struct smbfs_fattr fattr;
};

struct smbfs_cached_dir_entries {
	struct mutex lock;

	struct list_head entries;

	bool is_valid;
	bool is_failed;

	/*
	 * Only used to make sure we only take entries
	 * from a single context. Never dereferenced.
	 */
	struct dir_context *ctx;
	int pos; /* expected ctx->pos */
};

struct smbfs_cached_fid {
	struct mutex lock;

	bool is_valid; /* do we have a useable root fid? */
	bool file_all_info_is_valid;
	bool has_lease;

	u64 time; /* when lease was taken (in jiffies) */

	struct kref refcount;
	struct smbfs_fid *fid;
	struct smbfs_tcon *tcon;
	struct dentry *dentry;

	struct work_struct lease_break;
	struct smb2_file_all_info file_all_info;
	struct smbfs_cached_dir_entries dir_entries;
};

struct smbfs_pending_open {
	struct list_head head;
	struct smbfs_tcon_link *tlink;
	u8 lease_key[16];
	u32 oplock;
};

struct smbfs_deferred_close {
	struct list_head head;
	struct smbfs_tcon_link *tlink;
	u16 net_fid;
	u64 persistent_fid;
	u64 volatile_fid;
};

/*
 * This info hangs off the smbfs_file_info structure.
 * This is used to track byte stream locks on the file.
 */
struct smbfs_lock_info {
	struct list_head head;
	struct list_head blocked; /* locks blocked on this */
	wait_queue_head_t block_q;
	u64 offset;
	size_t len;
	u32 pid;
	u16 type;
	unsigned long flags;
};

/*
 * One of these for each open instance of a file.
 */
struct smbfs_search_info {
	loff_t index_of_last_entry;
	u16 entries_in_buffer;
	u16 info_level;
	u32 resume_key;
	char *network_buf_start;
	char *search_entries_start;
	char *last_entry;
	const char *presume_name;
	u32 resume_name_len;
	bool is_end;
	bool is_empty;
	bool is_unicode;
	bool is_smallbuf; /* so we know which buf_release function to call */
};

struct smbfs_open_parms {
	struct smbfs_tcon *tcon;
	struct cifs_sb_info *sb;
	int disposition;
	int desired_access;
	int create_options;
	const char *path;
	struct smbfs_fid *fid;
	umode_t mode;
	bool reconnect;
};

struct smbfs_fid {
	u16 net_fid;
	u64 persistent_fid; /* persist file id for smb2 */
	u64 volatile_fid; /* volatile file id for smb2 */
	u8 lease_key[SMB2_LEASE_KEY_SIZE]; /* lease key for smb2 */
	u8 create_guid[16];
	u32 access;
	struct smbfs_pending_open *pending_open;
	u64 epoch;
#ifdef CONFIG_SMBFS_DEBUG_EXTRA
	u64 mid;
#endif /* CONFIG_SMBFS_DEBUG_EXTRA */
	bool purge_cache;
};

struct smbfs_fid_locks {
	struct list_head head;
	struct smbfs_file_info *fi; /* fid that owns locks */
	struct list_head locks; /* locks held by fid above */
};

struct smbfs_file_info {
	u32 count;
	spinlock_t fi_lock;

	/* following two lists are protected by tcon->open_files_lock */
	struct list_head tcon_head; /* file instance for tcon */
	struct list_head inode_head; /* file instance for inode */
	struct list_head reconnect_head; /* reconnect list */

	/* lock list below protected by smbfs_inode_info->rw_lock */
	struct smbfs_fid_locks *fid_locks; /* brlocks held by this fid */
	kuid_t uid; /* allows finding which FileInfo structure */
	u32 pid; /* process id who opened file */
	struct smbfs_fid fid; /* file id from remote */
	struct dentry *dentry;
	struct smbfs_tcon_link *tlink;
	unsigned int f_flags; /* "struct file" f_flags */
	bool is_invalid_handle; /* file closed via session abend */
	bool is_swapfile;
	bool oplock_break_cancelled;
	u32 oplock_epoch; /* epoch from the lease break */
	u32 oplock_level; /* oplock/lease level from the lease break */

	struct mutex fh_lock; /* prevents reopen race after dead ses*/
	struct smbfs_search_info search_info;

	struct work_struct oplock_break; /* work for oplock breaks */
	struct work_struct put; /* work for the final part of _put */

	struct delayed_work deferred;
	bool deferred_close_scheduled; /* flag to indicate close is scheduled */
};

struct netfs_inode;
/* one of these for each file inode */
struct smbfs_inode_info {
	struct netfs_inode netfs; /* netfslib context and vfs inode */
	bool can_cache_brl;
	struct list_head locks; /* locks helb by this inode */
	/*
	 * NOTE: Some code paths call down_read(rw_lock) twice, so
	 * we must always use cifs_down_write() instead of down_write()
	 * for this semaphore to avoid deadlocks.
	 */
	struct rw_semaphore rw_lock; /* protect the fields above */

	/* TODO: add in lists for dirty pages i.e. write caching info
	 * for oplock */
	struct list_head open_files;
	spinlock_t open_files_lock; /* protects open_files */

	u32 smb1_attrs; /* e.g. DOS archive bit, sparse, compressed, system */
	u32 oplock; /* oplock/lease level we have */
	u64 epoch; /* used to track lease state changes */

	unsigned long flags;
#define SMBFS_INODE_PENDING_OPLOCK_BREAK	0x0 /* oplock break in progress */
#define SMBFS_INODE_PENDING_WRITERS		0x1 /* Writes in progress */
#define SMBFS_INODE_FLAG_UNUSED			0x2 /* Unused flag */
#define SMBFS_INODE_DELETE_PENDING		0x3 /* delete pending on server */
#define SMBFS_INODE_INVALID_MAPPING		0x4 /* pagecache is invalid */
#define SMBFS_INODE_LOCK			0x5 /* lock bit for synchronization */
#define SMBFS_INODE_MODIFIED_ATTR		0x6 /* Indicate change in mtime/ctime */
#define SMBFS_INODE_CLOSE_ON_LOCK		0x7 /* Not to defer the close when lock is set */

	spinlock_t writers_lock;
	u32 writers; /* number of writers on this inode */
	u64 time; /* jiffies of last update of inode */
	u64 server_eof; /* current file size on server, protected by i_lock */
	u64 id; /* server inode number, unique */
	u64 create_time; /* creation time on server */
	u8 lease_key[SMB2_LEASE_KEY_SIZE]; /* lease key for this inode */
	struct list_head deferred_closes; /* list of deferred closes */
	spinlock_t deferred_lock; /* protection on deferred list */
	bool lease_granted; /* flag to indicate whether lease or oplock is granted */
};

struct smbfs_close_cancelled_open {
	struct smbfs_fid fid;
	struct smbfs_tcon *tcon;
	struct work_struct work;
	u64 mid;
	u16 cmd;
};

/* for pending dnotify requests */
struct smbfs_dir_notify_req {
	struct list_head head;
	__le16 pid;
	__le16 pid_high;
	u16 mid;
	u16 tid;
	u16 uid;
	u16 net_fid;
	u32 filter; /* CompletionFilter (for multishot) */
	int multishot;
	struct file *pfile;
};

struct smbfs_file_list {
	struct list_head head;
	struct smbfs_file_info *fi;
};

/*
 * Take a reference on the file private data. Must be called with
 * fi->file_info_lock held.
 */
static inline void get_file_info_locked(struct smbfs_file_info *fi)
{
	++fi->count;
}

static inline struct smbfs_inode_info *SMBFS_I(struct inode *inode)
{
	return container_of(inode, struct smbfs_inode_info, netfs.inode);
}

static inline struct cifs_sb_info *CIFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct cifs_sb_info *CIFS_FILE_SB(struct file *file)
{
	return CIFS_SB(file_inode(file)->i_sb);
}


static inline size_t flock_len(struct file_lock *fl)
{
	return fl->fl_end == OFFSET_MAX ? 0 : fl->fl_end - fl->fl_start + 1;
}
#endif /* _SMBFS_FILE_H */
