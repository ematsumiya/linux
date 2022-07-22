// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) SUSE LLC, 2022
 *
 * Author(s): Enzo Matsumiya <ematsumiya@suse.de>
 *
 * SMBFS tree connection definition, helpers, and related functions.
*/
#ifndef _SMBFS_TCON_H
#define _SMBFS_TCON_H

#include "file.h"
#include "defs.h"
#include "ses.h"

#define SMBFS_MAX_TREE_SIZE (2 + CIFS_NI_MAXHOST + 1 + CIFS_MAX_SHARE_LEN + 1)

extern struct smbfs_tcon_link *smbfs_sb_tlink(struct cifs_sb_info *sb);
extern struct smbfs_tcon *smbfs_sb_master_tcon(struct cifs_sb_info *sb);

struct smbfs_tcon *tcon_info_alloc(void);
void tcon_info_free(struct smbfs_tcon *tcon);
struct smbfs_tcon *smbfs_get_tcon(struct smbfs_ses *ses,
				  struct smb3_fs_context *ctx);
void smbfs_put_tcon(struct smbfs_tcon *tcon);
struct smbfs_tcon_link *smbfs_get_tlink(struct smbfs_tcon_link *tlink);
void smbfs_put_tlink(struct smbfs_tcon_link *tlink);
void smbfs_prune_tlinks(struct work_struct *work);

typedef enum smbfs_tcon_status {
	SMBFS_TCON_STATUS_NEW = 0,
	SMBFS_TCON_STATUS_GOOD,
	SMBFS_TCON_STATUS_EXITING,
	SMBFS_TCON_STATUS_NEED_RECONNECT,
	SMBFS_TCON_STATUS_NEED_TCON,
	SMBFS_TCON_STATUS_IN_TCON,
	SMBFS_TCON_STATUS_NEED_FILES_INVALIDATE, /* currently unused */
	SMBFS_TCON_STATUS_IN_FILES_INVALIDATE,
} smbfs_tcon_status_t;

/* one of these for each connection to a resource on a particular session */
struct smbfs_tcon {
	struct list_head head;
	u32 count;

	smbfs_tcon_status_t status;
	struct list_head to_reconnect; /* reconnect list */

	atomic_t local_opens; /* count of all opens including disconnected */
	atomic_t remote_opens; /* count of all network opens on server */
	struct list_head open_files;
	spinlock_t open_files_lock; /* protects list above */

	struct smbfs_ses *ses; /* pointer to session associated with */
	char tree_name[SMBFS_MAX_TREE_SIZE + 1]; /* UNC name of resource in ASCII */
	char *native_fs;
	char *password; /* for share-level security */
	u32 tid; /* 4 byte tree id */

	unsigned long flags; /* optional support bits */

	unsigned long internal_flags; /* internal use only, replace old bool values */
#define SMBFS_TCON_IS_IPC		0x00001
#define SMBFS_TCON_IS_PIPE		0x00002
#define SMBFS_TCON_IS_PRINT		0x00004
#define SMBFS_TCON_NOCASE		0x00008
#define SMBFS_TCON_NOHANDLECACHE	0x00010 /* if strange server resource prob can turn off */
#define SMBFS_TCON_NO_LEASE		0x00020 /* do not request leases on files or directories */
#define SMBFS_TCON_CHECK_LOCAL_LEASE	0x00040 /* check leases (only) on local system not remote */
#define SMBFS_TCON_BROKEN_POSIX_OPEN	0x00080 /* e.g. Samba server versions < 3.3.2, 3.2.9 */
#define SMBFS_TCON_BROKEN_SPARSE_SUPP	0x00100 /* if server or share does not support sparse */
#define SMBFS_TCON_NEED_RECONNECT	0x00200 /* connection reset, tid now invalid */
#define SMBFS_TCON_NEED_REOPEN_FILES	0x00400 /* need to reopen tcon file handles */
#define SMBFS_TCON_USE_RESILIENT	0x00800 /* use resilient instead of durable handles */
#define SMBFS_TCON_USE_PERSISTENT	0x01000 /* use persistent instead of durable handles */
#define SMBFS_TCON_USE_SEAL		0x02000 /* transport encryption for this mounted share */
#define SMBFS_TCON_USE_UNIX_EXT		0x04000 /* if false disable Linux extensions
						   to CIFS protocol for this mount,
						   even if server would support */
#define SMBFS_TCON_USE_POSIX_EXT	0x08000 /* if true SMB3.11 posix extensions enabled */
#define SMBFS_TCON_USE_WITNESS		0x10000 /* use witness protocol */

	bool retry;

	spinlock_t stats_lock; /* protects the stats fields below */
	atomic_t smbs_sent;
	union {
		struct {
			atomic_t writes;
			atomic_t reads;
			atomic_t flushes;
			atomic_t oplock_brks;
			atomic_t opens;
			atomic_t closes;
			atomic_t deletes;
			atomic_t mkdirs;
			atomic_t posixopens;
			atomic_t posixmkdirs;
			atomic_t rmdirs;
			atomic_t renames;
			atomic_t t2renames;
			atomic_t ffirst;
			atomic_t fnext;
			atomic_t fclose;
			atomic_t hardlinks;
			atomic_t symlinks;
			atomic_t locks;
			atomic_t acl_get;
			atomic_t acl_set;
		} smb1;
		struct {
			atomic_t sent[SMB2_MAX_CMDS];
			atomic_t failed[SMB2_MAX_CMDS];
		} smb2;
	} stats;
	u64 bytes_read;
	u64 bytes_written;

	FILE_SYSTEM_DEVICE_INFO fs_dev_info;
	FILE_SYSTEM_ATTRIBUTE_INFO fs_attr_info; /* ok if fs name truncated */
	FILE_SYSTEM_UNIX_INFO fs_unix_info;

	__le32 capabilities; /* see fs/smbfs_common/smb2pdu.h */
	u64 share_flags; /* see fs/smbfs_common/smb2pdu.h */

	u32 maximal_access;
	u32 vol_serial_number;
	__le64 vol_create_time;
	u64 snapshot_time; /* for timewarp tokens - timestamp of snapshot */
	u32 handle_timeout; /* persistent and durable handle timeout (in ms) */
	u64 sector_size_flags; /* sector size flags */
	u32 perf_sector_size; /* best sector size for perf */
	u32 max_chunks;
	u32 max_bytes_chunk;
	u32 max_bytes_copy;
#ifdef CONFIG_SMBFS_FSCACHE
	u64 resource_id; /* server resource id */
	struct fscache_volume *fscache; /* cookie for share */
#endif
	struct list_head pending_opens; /* list of incomplete opens */
	struct smbfs_cached_fid crfid; /* cached root fid */
	/* TODO: add field for back pointer to sb struct(s)? */
#ifdef CONFIG_SMBFS_DFS_UPCALL
	struct list_head cache_update; /* cache update list */
#endif
	struct delayed_work query_interfaces; /* query interfaces worker */
};

/* flag sans "SMBFS_TCON_" prefix */
#define set_tcon_flag(_t, _flag) \
	set_bit(SMBFS_TCON_ ## _flag, &_t->internal_flags)
#define get_tcon_flag(_t, _flag) \
	test_bit(SMBFS_TCON_ ## _flag, &_t->internal_flags)
#define clear_tcon_flag(_t, _flag) \
	clear_bit(SMBFS_TCON_ ## _flag, &_t->internal_flags)

static inline void stats_bytes_read(struct smbfs_tcon *tcon, u64 bytes)
{
	spin_lock(&tcon->stats_lock);
	tcon->bytes_read += bytes;
	spin_unlock(&tcon->stats_lock);
}

static inline void stats_bytes_written(struct smbfs_tcon *tcon, u64 bytes)
{
	if (bytes) {
		spin_lock(&tcon->stats_lock);
		tcon->bytes_written += bytes;
		spin_unlock(&tcon->stats_lock);
	}
}

/*
 * This is a refcounted and timestamped container for a tcon pointer. The
 * container holds a tcon reference. It is considered safe to free one of
 * these when ->count goes to 0. ->time is the time of the last "get" on the
 * container.
 */
struct smbfs_tcon_link {
	struct smbfs_tcon *tcon;
	struct rb_node rbnode;
	atomic_t count;
	kuid_t uid;
	unsigned long flags;
#define TCON_LINK_MASTER 0
#define TCON_LINK_PENDING 1
#define TCON_LINK_IN_TREE 2
	unsigned long time;
};

inline struct smbfs_tcon *tlink_tcon(struct smbfs_tcon_link *tlink)
{
	return tlink->tcon;
}

inline struct smbfs_tcon_link *smbfs_sb_master_tlink(struct cifs_sb_info *sb)
{
	return sb->master_tlink;
}

struct smbfs_tcon *smbfs_sb_master_tcon(struct cifs_sb_info *sb)
{
	return tlink_tcon(smbfs_sb_master_tlink(sb));
}
#endif /* _SMBFS_TCON_H */
