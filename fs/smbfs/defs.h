// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) International Business Machines  Corp., 2002,2008
 * Copyright (c) SUSE LLC, 2022
 *
 * Author(s): Steve French <sfrench@us.ibm.com>
 *            Jeremy Allison <jra@samba.org>
 *            Enzo Matsumiya <ematsumiya@suse.de>
 *
 * Generic, global definitions, and function prototypes for SMBFS module.
 */
#ifndef _SMBFS_DEFS_H
#define _SMBFS_DEFS_H

struct statfs;
struct smb_rqst;
struct smb3_fs_context;

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/nls.h>
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
#include "cifspdu.h"
#include "ses.h"
#include "tcon.h"
#include "mid.h"
#include "trace.h"
#ifdef CONFIG_SMBFS_DFS_UPCALL
#include "dfs_cache.h"
#endif /* CONFIG_SMBFS_DFS_UPCALL */

/* when changing internal version, update following two lines at same time */
#define SMBFS_PRODUCT_BUILD 37
#define SMBFS_VERSION   "2.37"

#define SMB_PORT		445
#define SMB_PATH_MAX		260
#define RFC1001_PORT		139

/*
 * The sizes of various internal tables and strings
 */
#define SMBFS_MAX_COMPOUND		5 /* max number of PDUs in one compound */

#define SMBFS_HEADER_SIZE(server) (server->settings->header_size)
#define SMBFS_MAX_HEADER_SIZE(server) \
	(server->settings->max_header_size)

/*
 * Default number of credits to keep available for SMB3.
 *
 * This value is chosen somewhat arbitrarily. The Windows client
 * defaults to 128 credits, the Windows server allows clients up to
 * 512 credits (or 8K for later versions), and the NetApp server
 * does not limit clients at all.  Choose a high enough default value
 * such that the client shouldn't limit performance, but allow mount
 * to override (until you approach 64K, where we limit credits to 65000
 * to reduce possibility of seeing more server credit overflow bugs.
 */
#define SMBFS_MAX_CREDITS_AVAILABLE 32000

#define SMBFS_SERVER_NAME_LEN		80 /* max length of IP addr as a string
					      (including ipv6 and sctp) */
#define SMBFS_SERVER_NAME_LEN_NUL	(SERVER_NAME_LEN + 1)
#define SMBFS_ECHO_INTERVAL_MIN		1 /* echo interval (in seconds) */
#define SMBFS_ECHO_INTERVAL_MAX		600
#define SMBFS_ECHO_INTERVAL_DEF		60
#define SMBFS_DNS_RESOLVE_INTERVAL_MIN	120 /* DNS resolution interval (in seconds) */
#define SMBFS_DNS_RESOLVE_INTERVAL_DEF	600
#define SMBFS_INTERFACE_POLL_INTERVAL	600 /* multichannel query server interfaces
					       interval (in seconds) */

#ifndef XATTR_DOS_ATTRIB
#define XATTR_DOS_ATTRIB "user.DOSATTRIB"
#endif

/* cifs_get_writable_file() flags */
#define FIND_WR_ANY		0x0
#define FIND_WR_FSUID_ONLY	0x1
#define FIND_WR_WITH_DELETE	0x2

/* Types of response buffer returned from SendReceive2 */
#define SMBFS_NO_BUFFER		0 /* response buffer not returned */
#define SMBFS_SMALL_BUFFER	1
#define SMBFS_LARGE_BUFFER	2
#define SMBFS_IOVEC		4 /* array of response buffers */

/* Type of Request to SendReceive2 */
#define SMBFS_BLOCKING_OP		1 /* operation can block */
#define SMBFS_NON_BLOCKING		2 /* do not block waiting for credits */
#define SMBFS_TIMEOUT_MASK		0x03 /* only one of above set in req */
#define SMBFS_LOG_ERROR			0x10 /* log NT STATUS if non-zero */
#define SMBFS_LARGE_BUF_OP		0x20 /* large request buffer */
#define SMBFS_NO_RSP_BUF		0x40 /* no response buffer required */

/* Type of request operation */
#define SMBFS_ECHO_OP			0x0080 /* echo request */
#define SMBFS_OBREAK_OP			0x0100 /* oplock break request */
#define SMBFS_NEG_OP			0x0200 /* negotiate request */
#define SMBFS_CP_CREATE_CLOSE_OP	0x0400 /* compound create+close request */
/* Lower bitmask values are reserved by others below. */
#define SMBFS_SESS_OP			0x2000 /* session setup request */
#define SMBFS_OP_MASK			0x2780 /* mask request type */

#define SMBFS_HAS_CREDITS		0x0400 /* already has credits */
#define SMBFS_TRANSFORM_REQ		0x0800 /* transform request before sending */
#define SMBFS_NO_SRV_RSP		0x1000 /* there is no server response */

/*
 * Superblock mount flags (for SMBFS)
 */
#define CIFS_MOUNT_MASK \
	(CIFS_MOUNT_NO_PERM | CIFS_MOUNT_SET_UID | \
	 CIFS_MOUNT_SERVER_INUM | CIFS_MOUNT_DIRECT_IO | \
	 CIFS_MOUNT_NO_XATTR | CIFS_MOUNT_MAP_SPECIAL_CHR | \
	 CIFS_MOUNT_MAP_SFM_CHR | CIFS_MOUNT_UNX_EMUL | CIFS_MOUNT_NO_BRL | \
	 CIFS_MOUNT_CIFS_ACL | CIFS_MOUNT_OVERR_UID | \
	 CIFS_MOUNT_OVERR_GID | CIFS_MOUNT_DYNPERM | \
	 CIFS_MOUNT_NOPOSIXBRL | CIFS_MOUNT_NOSSYNC | CIFS_MOUNT_FSCACHE | \
	 CIFS_MOUNT_MF_SYMLINKS | CIFS_MOUNT_MULTIUSER | \
	 CIFS_MOUNT_STRICT_IO | CIFS_MOUNT_CIFS_BACKUPUID | \
	 CIFS_MOUNT_CIFS_BACKUPGID | CIFS_MOUNT_UID_FROM_ACL | \
	 CIFS_MOUNT_NO_HANDLE_CACHE | CIFS_MOUNT_NO_DFS | \
	 CIFS_MOUNT_MODE_FROM_SID | CIFS_MOUNT_RO_CACHE | CIFS_MOUNT_RW_CACHE)

/*
 * Superblock mount flags (s_flags, for VFS)
 */
#define SMBFS_MS_MASK (SB_RDONLY | SB_MANDLOCK | SB_NOEXEC | SB_NOSUID | \
		       SB_NODEV | SB_SYNCHRONOUS)

#define SMBFS_CACHE_FLAG_READ		1
#define SMBFS_CACHE_FLAG_HANDLE		2
#define SMBFS_CACHE_FLAG_WRITE		4
#define SMBFS_CACHE_FLAG_RH \
	(SMBFS_CACHE_FLAG_READ | SMBFS_CACHE_FLAG_HANDLE)
#define SMBFS_CACHE_FLAG_RW \
	(SMBFS_CACHE_FLAG_READ | SMBFS_CACHE_FLAG_WRITE)
#define SMBFS_CACHE_FLAG_RHW \
	(SMBFS_CACHE_FLAG_RW | SMBFS_CACHE_FLAG_HANDLE)

#define SMBFS_CACHE_READ(smb_i) \
	((smb_i->oplock & SMBFS_CACHE_FLAG_READ) || \
	 (CIFS_SB(smb_i->netfs.inode.i_sb)->mnt_cifs_flags & CIFS_MOUNT_RO_CACHE))
#define SMBFS_CACHE_HANDLE(smb_i) \
	(smb_i->oplock & SMBFS_CACHE_FLAG_HANDLE)
#define SMBFS_CACHE_WRITE(smb_i) \
	((smb_i->oplock & SMBFS_CACHE_FLAG_WRITE) || \
	 (CIFS_SB(smb_i->netfs.inode.i_sb)->mnt_cifs_flags & CIFS_MOUNT_RW_CACHE))

#define SMBFS_OPLOCK_NO_CHANGE 0xfe
#define ACL_NO_MODE ((umode_t)(-1))

struct smbfs_cred {
	unsigned int uid;
	unsigned int gid;
	unsigned int mode;
	unsigned int count;
	struct cifs_sid osid;
	struct cifs_sid gsid;
	struct cifs_ntace *ntaces;
	struct cifs_ace *aces;
};

/*
 * A smb_rqst represents a complete request to be issued to a server. It's
 * formed by a kvec array, followed by an array of pages. Page data is assumed
 * to start at the beginning of the first page.
 */
struct smb_rqst {
	struct kvec	*rq_iov; /* array of kvecs */
	unsigned int	rq_nvec; /* number of kvecs in array */
	struct page	**rq_pages; /* pointer to array of page ptrs */
	unsigned int	rq_offset; /* the offset to the 1st page */
	unsigned int	rq_npages; /* number pages in array */
	unsigned int	rq_pagesz; /* page size to use */
	unsigned int	rq_tailsz; /* length of last page */
};

struct smbfs_server_iface {
	struct list_head head;
	struct kref refcount;

	struct sockaddr_storage sockaddr;
	size_t speed;
	bool is_active; /* unset if non existent */
	bool rss_capable;
	bool rdma_capable;
};

/* release iface when last ref is dropped */
static inline void release_iface(struct kref *ref)
{
	struct smbfs_server_iface *iface = container_of(ref,
						        struct smbfs_server_iface,
						        refcount);
	list_del_init(&iface->head);
	kfree(iface);
}

/*
 * Compare two interfaces a and b.
 *
 * Return 0 if everything matches.
 * Return 1 if @a has higher link speed, or RDMA capable, or RSS capable.
 * Return -1 otherwise.
 */
static inline int iface_cmp(struct smbfs_server_iface *a,
			    struct smbfs_server_iface *b)
{
	int rc = 0;

	WARN_ON(!a || !b);
	if (a->speed == b->speed &&
	    a->rdma_capable == b->rdma_capable &&
	    a->rss_capable == b->rss_capable) {
		rc = memcmp(&a->sockaddr, &b->sockaddr, sizeof(a->sockaddr));
		return !rc ? 0 : (rc > 0 ? 1 : -1);
	}

	if (a->speed > b->speed ||
	    a->rdma_capable > b->rdma_capable ||
	    a->rss_capable > b->rss_capable)
		return 1;

	return -1;
}

struct smbfs_io_parms {
	u16 net_fid;
	unsigned long persistent_fid; /* persist file id for smb2 */
	unsigned long volatile_fid; /* volatile file id for smb2 */
	unsigned int pid;
	unsigned long offset;
	unsigned int len;
	struct smbfs_tcon *tcon;
	struct smbfs_server_info *server;
};

struct smbfs_aio_ctx {
	struct kref refcount;
	struct list_head rw_list;
	struct mutex lock;
	struct completion done;

	struct iov_iter iter;
	struct kiocb *iocb;
	struct smbfs_file_info *fi;
	struct bio_vec *bv;
	loff_t pos;
	unsigned int npages;
	ssize_t rc;
	unsigned int len;
	unsigned int total_len;
	bool should_dirty;
	/*
	 * Indicates if this aio_ctx is for direct_io,
	 * if yes, iter is a copy of the user passed iov_iter
	 */
	bool direct_io;
};

/* asynchronous read support */
struct smbfs_readdata {
	struct kref refcount;
	struct list_head head;
	struct completion done;
	struct smbfs_file_info *fi;
	struct address_space *mapping;
	struct smbfs_aio_ctx *ctx;
	unsigned long offset;
	unsigned int bytes;
	unsigned int got_bytes;
	pid_t pid;
	int result;
	struct work_struct work;
	int (*read_into_pages)(struct smbfs_server_info *server,
			       struct smbfs_readdata *rdata,
			       unsigned int len);
	int (*copy_into_pages)(struct smbfs_server_info *server,
				struct smbfs_readdata *rdata,
				struct iov_iter *iter);
	struct kvec iov[2];
	struct smbfs_server_info *server;
#ifdef CONFIG_SMBFS_SMB_DIRECT
	struct smbd_mr *mr;
#endif
	unsigned int pagesz;
	unsigned int page_offset;
	unsigned int tailsz;
	struct smbfs_credits credits;
	unsigned int nr_pages;
	struct page **pages;
};

/* asynchronous write support */
struct smbfs_writedata {
	struct kref refcount;
	struct list_head head;
	struct completion done;
	enum writeback_sync_modes sync_mode;
	struct work_struct work;
	struct smbfs_file_info *fi;
	struct smbfs_aio_ctx *ctx;
	unsigned long offset;
	pid_t pid;
	unsigned int bytes;
	int result;
	struct smbfs_server_info *server;
#ifdef CONFIG_SMBFS_SMB_DIRECT
	struct smbd_mr *mr;
#endif
	unsigned int pagesz;
	unsigned int page_offset;
	unsigned int tailsz;
	struct smbfs_credits credits;
	unsigned int nr_pages;
	struct page **pages;
};

/*
 * Locking notes
 *
 * All updates to global variables and lists should be protected by spinlocks
 * or semaphores.
 *
 * Spinlocks
 * ---------
 * g_mid_lock protects:
 * - list operations on pending_mids and oplockQ
 * - updates to XID counters, multiplex id, and SMB sequence numbers
 * - list operations on global DnotifyReqList
 * - updates to ses->status and smbfs_server_info->status
 * - updates to server->current_mid
 *
 * smbfs_server_lock (server_info.h):
 * - protects list operations on tcp and SMB session lists
 *
 * tcon->open_files_lock: protects the list of open files hanging off the tcon
 * inode->open_files_lock: protects the open_files hanging off the inode
 * smb_f->file_info_lock: protects counters and fields in cifs file struct
 * f_owner.lock: protects certain per file struct operations
 * mapping->page_lock: protects certain per page operations
 *
 * Note that the smbfs_tcon.open_files_lock should be taken _before_, not
 * after the smbfs_inode_info.open_files_lock.
 *
 * Semaphores
 * ----------
 * smbfs_inode_info->rw_lock: protects the list of locks held by the inode
 */

/*
 * Global transaction id (XID) information
 */
unsigned int g_current_xid;
unsigned int g_total_active_xid;
unsigned int g_max_active_xid;
spinlock_t g_mid_lock; /* protects above & list operations */

/*
 * Global counters, updated atomically
 */
atomic_t g_ses_alloc_count;
atomic_t g_tcon_alloc_count;
atomic_t g_server_next_id;
atomic_t g_server_alloc_count;
atomic_t g_server_reconnect_count;
atomic_t g_tcon_reconnect_count;

/*
 * Global debug counters
 */
atomic_t g_buf_alloc_count; /* current number allocated  */
#ifdef CONFIG_SMBFS_STATS_EXTRA
atomic_t g_total_buf_alloc_count; /* total allocated over all time */
atomic_t g_total_smallbuf_alloc_count;
extern unsigned int g_slow_rsp_threshold; /* number of secs before logging */
#endif
atomic_t g_smallbuf_alloc_count;
atomic_t g_mid_count;

/*
 * Misc globals
 */
extern bool enable_oplocks; /* enable or disable oplocks */
extern unsigned int max_buf_size; /* max size not including hdr */
extern unsigned int min_rcv; /* min size of big ntwrk buf pool */
extern unsigned int min_small; /* min size of small buf pool */
extern unsigned int max_pending; /* max requests at once to server*/
extern bool disable_legacy_dialects; /* forbid vers=1.0 and vers=2.0 mounts */

void smbfs_oplock_break(struct work_struct *work);
void smbfs_queue_oplock_break(struct smbfs_file_info *smb_f);

extern const struct slow_work_ops smbfs_oplock_break_ops;
extern struct workqueue_struct *cifsiod_wq;
extern struct workqueue_struct *decrypt_wq;
extern struct workqueue_struct *oplockd_wq;
extern unsigned int smbfs_lock_secret;

/*
 * All Prototypes
 */
extern struct smb_hdr *cifs_buf_get(void);
extern void cifs_buf_release(void *);
extern struct smb_hdr *cifs_small_buf_get(void);
extern void cifs_small_buf_release(void *);
extern void free_rsp_buf(int, void *);
extern int smb_send(struct smbfs_server_info *, struct smb_hdr *, unsigned int);
extern int init_cifs_idmap(void);
extern void exit_cifs_idmap(void);
extern int init_cifs_spnego(void);
extern void exit_cifs_spnego(void);
extern const char *build_path_from_dentry(struct dentry *, void *);
extern char *build_path_from_dentry_optional_prefix(struct dentry *, void *, bool);

static inline void *alloc_dentry_path(void)
{
	return __getname();
}

static inline void free_dentry_path(void *page)
{
	if (page)
		__putname(page);
}

extern char *cifs_build_path_to_root(struct smb3_fs_context *,
				     struct cifs_sb_info *, struct smbfs_tcon *,
				     int);
extern char *build_wildcard_path_from_dentry(struct dentry *);
extern char *cifs_compose_mount_options(const char *, const char *,
					const struct smbfs_dfs_info *, char **);
extern struct smbfs_mid_entry *AllocMidQEntry(const struct smb_hdr *,
					      struct smbfs_server_info *);
extern void DeleteMidQEntry(struct smbfs_mid_entry *);
extern void cifs_delete_mid(struct smbfs_mid_entry *);
extern void cifs_mid_q_entry_release(struct smbfs_mid_entry *);
extern void cifs_wake_up_task(struct smbfs_mid_entry *);
extern int cifs_handle_standard(struct smbfs_server_info *,
				struct smbfs_mid_entry *);
extern int smb3_parse_devname(const char *, struct smb3_fs_context *);
extern int smb3_parse_opt(const char *, const char *, char **);
extern bool cifs_match_ipaddr(struct sockaddr *, struct sockaddr *);
extern int cifs_discard_remaining_data(struct smbfs_server_info *);
extern int cifs_call_async(struct smbfs_server_info *, struct smb_rqst *,
			mid_receive_t *, mid_complete_t *, mid_handle_t *,
			void *, const int, const struct smbfs_credits *);
extern struct smbfs_server_info *cifs_pick_channel(struct smbfs_ses *);
extern int cifs_send_recv(const unsigned int xid, struct smbfs_ses *,
			  struct smbfs_server_info *, struct smb_rqst *, int *,
			  const int, struct kvec *);
extern int compound_send_recv(const unsigned int xid, struct smbfs_ses *ses,
			      struct smbfs_server_info *,
			      const int, const int,
			      struct smb_rqst *, int *,
			      struct kvec *);
extern int SendReceive(const unsigned int, struct smbfs_ses *, struct smb_hdr *,
		       struct smb_hdr *, int *, const int);
extern int SendReceiveNoRsp(const unsigned int, struct smbfs_ses *, char *, int);
extern struct smbfs_mid_entry *cifs_setup_request(struct smbfs_ses *,
						  struct smbfs_server_info *,
						  struct smb_rqst *);
extern struct smbfs_mid_entry *cifs_setup_async_request(struct smbfs_server_info *,
							struct smb_rqst *);
extern int cifs_check_receive(struct smbfs_mid_entry *,
			      struct smbfs_server_info *, bool);
extern int cifs_wait_mtu_credits(struct smbfs_server_info *, unsigned int,
				 unsigned int *, struct smbfs_credits *);
extern int SendReceive2(const unsigned int, struct smbfs_ses *, struct kvec *,
			int, int *, const int flags, struct kvec *);
extern int SendReceiveBlockingLock(const unsigned int, struct smbfs_tcon *,
				   struct smb_hdr *, struct smb_hdr *, int *);
void cifs_signal_cifsd_for_reconnect(struct smbfs_server_info *, bool);
void cifs_mark_server_conns_for_reconnect(struct smbfs_server_info *, bool);
extern int cifs_reconnect(struct smbfs_server_info *, bool);
extern int checkSMB(char *, unsigned int, struct smbfs_server_info *);
extern bool is_valid_oplock_break(char *, struct smbfs_server_info *);
extern bool backup_cred(struct cifs_sb_info *);
extern bool is_size_safe_to_change(struct smbfs_inode_info *, u64);
extern void cifs_update_eof(struct smbfs_inode_info *, loff_t, unsigned int);
extern struct smbfs_file_info *find_writable_file(struct smbfs_inode_info *, int);
extern int cifs_get_writable_file(struct smbfs_inode_info *, int,
				  struct smbfs_file_info **);
extern int cifs_get_writable_path(struct smbfs_tcon *, const char *name,
				  int flags,
				  struct smbfs_file_info **ret_file);
extern struct smbfs_file_info *find_readable_file(struct smbfs_inode_info *, bool);
extern int cifs_get_readable_path(struct smbfs_tcon *tcon, const char *name,
				  struct smbfs_file_info **ret_file);
extern unsigned int smbCalcSize(void *buf, struct smbfs_server_info *server);
extern int decode_negTokenInit(unsigned char *security_blob, int,
			struct smbfs_server_info *server);
extern int cifs_convert_address(struct sockaddr *dst, const char *src, int len);
extern void cifs_set_port(struct sockaddr *addr, const unsigned short int port);
extern int map_smb_to_linux_error(char *buf, bool logErr);
extern int map_and_check_smb_error(struct smbfs_mid_entry *, bool logErr);
extern void header_assemble(struct smb_hdr *, char,
			    const struct smbfs_tcon *, int);
extern int small_smb_init_no_tc(const int smb_cmd, const int wct,
				struct smbfs_ses *ses,
				void **request_buf);
extern smbfs_security_t select_sectype(struct smbfs_server_info *server,
				smbfs_security_t requested);
extern int CIFS_SessSetup(const unsigned int xid, struct smbfs_ses *ses,
			  struct smbfs_server_info *server,
			  const struct nls_table *nls_cp);
extern struct timespec64 cifs_NTtimeToUnix(__le64 utc_nanoseconds_since_1601);
extern u64 cifs_UnixTimeToNT(struct timespec64);
extern struct timespec64 cnvrtDosUnixTm(__le16 le_date, __le16 le_time,
				      int offset);
extern void cifs_set_oplock_level(struct smbfs_inode_info *smb_i, unsigned int oplock);
extern int cifs_get_writer(struct smbfs_inode_info *smb_i);
extern void cifs_put_writer(struct smbfs_inode_info *smb_i);
extern void cifs_done_oplock_break(struct smbfs_inode_info *smb_i);
extern int cifs_unlock_range(struct smbfs_file_info *smb_f,
			     struct file_lock *flock, const unsigned int xid);
extern int cifs_push_mandatory_locks(struct smbfs_file_info *smb_f);

extern void cifs_down_write(struct rw_semaphore *sem);
extern struct smbfs_file_info *cifs_new_fileinfo(struct smbfs_fid *fid,
					      struct file *file,
					      struct smbfs_tcon_link *tlink,
					      unsigned int oplock);
extern int cifs_posix_open(const char *full_path, struct inode **inode,
			   struct super_block *sb, int mode,
			   unsigned int f_flags, unsigned int *oplock, __u16 *net_fid,
			   unsigned int xid);
void cifs_fill_id(struct super_block *sb, struct smbfs_fattr *fattr);
extern void cifs_unix_basic_to_fattr(struct smbfs_fattr *fattr,
				     FILE_UNIX_BASIC_INFO *info,
				     struct cifs_sb_info *cifs_sb);
extern void cifs_dir_info_to_fattr(struct smbfs_fattr *, FILE_DIRECTORY_INFO *,
					struct cifs_sb_info *);
extern int smbfs_fattr_to_inode(struct inode *inode, struct smbfs_fattr *fattr);
extern struct inode *cifs_iget(struct super_block *sb,
			       struct smbfs_fattr *fattr);

extern int cifs_get_inode_info(struct inode **inode, const char *full_path,
			       FILE_ALL_INFO *data, struct super_block *sb,
			       int xid, const struct smbfs_fid *fid);
extern int smb311_posix_get_inode_info(struct inode **pinode, const char *search_path,
			struct super_block *sb, unsigned int xid);
extern int cifs_get_inode_info_unix(struct inode **pinode,
			const unsigned char *search_path,
			struct super_block *sb, unsigned int xid);
extern int cifs_set_file_info(struct inode *inode, struct iattr *attrs,
			      unsigned int xid, const char *full_path, unsigned int dosattr);
extern int cifs_rename_pending_delete(const char *full_path,
				      struct dentry *dentry,
				      const unsigned int xid);
extern int sid_to_id(struct cifs_sb_info *cifs_sb, struct cifs_sid *psid,
				struct smbfs_fattr *fattr, uint sidtype);
extern int cifs_acl_to_fattr(struct cifs_sb_info *cifs_sb,
			      struct smbfs_fattr *fattr, struct inode *inode,
			      bool get_mode_from_special_sid,
			      const char *path, const struct smbfs_fid *pfid);
extern int id_mode_to_cifs_acl(struct inode *, const char *, u64 *, kuid_t, kgid_t);
extern struct cifs_ntsd *get_cifs_acl(struct cifs_sb_info *, struct inode *,
				      const char *, unsigned int *, u32);
extern struct cifs_ntsd *get_cifs_acl_by_fid(struct cifs_sb_info *,
				const struct smbfs_fid *, unsigned int *, u32);
extern int set_cifs_acl(struct cifs_ntsd *, __u32, struct inode *,
				const char *, int);
extern unsigned int setup_authusers_ACE(struct cifs_ace *pace);
extern unsigned int setup_special_mode_ACE(struct cifs_ace *pace, u64 nmode);
extern unsigned int setup_special_user_owner_ACE(struct cifs_ace *pace);

extern void dequeue_mid(struct smbfs_mid_entry *mid);
extern int cifs_read_from_socket(struct smbfs_server_info *server, char *buf,
			         unsigned int to_read);
extern ssize_t cifs_discard_from_socket(struct smbfs_server_info *server,
					size_t to_read);
extern int cifs_read_page_from_socket(struct smbfs_server_info *server,
					struct page *page,
					unsigned int page_offset,
					unsigned int to_read);
extern int cifs_setup_cifs_sb(struct cifs_sb_info *cifs_sb);
extern int cifs_match_super(struct super_block *, void *);
extern int cifs_mount(struct cifs_sb_info *cifs_sb, struct smb3_fs_context *ctx);
extern void cifs_umount(struct cifs_sb_info *);
extern void cifs_mark_open_files_invalid(struct smbfs_tcon *tcon);
extern void cifs_reopen_persistent_handles(struct smbfs_tcon *tcon);

extern bool cifs_find_lock_conflict(struct smbfs_file_info *smb_f, u64 offset,
				    u64 length, __u8 type, __u16 flags,
				    struct smbfs_lock_info **conf_lock,
				    int rw_check);
extern void cifs_add_pending_open(struct smbfs_fid *fid,
				  struct smbfs_tcon_link *tlink,
				  struct smbfs_pending_open *open);
extern void cifs_add_pending_open_locked(struct smbfs_fid *fid,
					 struct smbfs_tcon_link *tlink,
					 struct smbfs_pending_open *open);
extern void cifs_del_pending_open(struct smbfs_pending_open *open);

extern bool cifs_is_deferred_close(struct smbfs_file_info *smb_f,
				struct smbfs_deferred_close **dclose);

extern void cifs_add_deferred_close(struct smbfs_file_info *smb_f,
				struct smbfs_deferred_close *dclose);

extern void cifs_del_deferred_close(struct smbfs_file_info *smb_f);

extern void cifs_close_deferred_file(struct smbfs_inode_info *cifs_inode);

extern void cifs_close_all_deferred_files(struct smbfs_tcon *smbfs_tcon);

extern void cifs_close_deferred_file_under_dentry(struct smbfs_tcon *smbfs_tcon,
				const char *path);
extern struct smbfs_server_info *
smbfs_get_server(struct smb3_fs_context *ctx,
		     struct smbfs_server_info *primary_server);
extern void smbfs_put_server(struct smbfs_server_info *server,
				 int from_reconnect);

#if IS_ENABLED(CONFIG_SMBFS_DFS_UPCALL)
extern void cifs_dfs_release_automount_timer(void);
#else /* ! IS_ENABLED(CONFIG_SMBFS_DFS_UPCALL) */
#define cifs_dfs_release_automount_timer()	do { } while (0)
#endif /* ! IS_ENABLED(CONFIG_SMBFS_DFS_UPCALL) */

void smbfs_proc_init(void);
void smbfs_proc_clean(void);

extern void cifs_move_llist(struct list_head *source, struct list_head *dest);
extern void cifs_free_llist(struct list_head *llist);
extern void cifs_del_lock_waiters(struct smbfs_lock_info *lock);

extern int cifs_tree_connect(const unsigned int xid, struct smbfs_tcon *tcon,
			     const struct nls_table *nlsc);

extern int cifs_negotiate_protocol(const unsigned int xid,
				   struct smbfs_ses *ses,
				   struct smbfs_server_info *server);
extern int cifs_setup_session(const unsigned int xid, struct smbfs_ses *ses,
			      struct smbfs_server_info *server,
			      struct nls_table *nls_info);
extern int cifs_enable_signing(struct smbfs_server_info *server, bool mnt_sign_required);
extern int CIFSSMBNegotiate(const unsigned int xid,
			    struct smbfs_ses *ses,
			    struct smbfs_server_info *server);

extern int CIFSTCon(const unsigned int xid, struct smbfs_ses *ses,
		    const char *tree, struct smbfs_tcon *tcon,
		    const struct nls_table *);

extern int CIFSFindFirst(const unsigned int xid, struct smbfs_tcon *tcon,
		const char *searchName, struct cifs_sb_info *cifs_sb,
		__u16 *searchHandle, __u16 search_flags,
		struct smbfs_search_info *psrch_inf,
		bool msearch);

extern int CIFSFindNext(const unsigned int xid, struct smbfs_tcon *tcon,
		__u16 searchHandle, __u16 search_flags,
		struct smbfs_search_info *psrch_inf);

extern int CIFSFindClose(const unsigned int xid, struct smbfs_tcon *tcon,
			const __u16 search_handle);

extern int CIFSSMBQFileInfo(const unsigned int xid, struct smbfs_tcon *tcon,
			u16 net_fid, FILE_ALL_INFO *pFindData);
extern int CIFSSMBQPathInfo(const unsigned int xid, struct smbfs_tcon *tcon,
			    const char *search_Name, FILE_ALL_INFO *data,
			    int legacy /* whether to use old info level */,
			    const struct nls_table *nls_codepage, int remap);
extern int SMBQueryInformation(const unsigned int xid, struct smbfs_tcon *tcon,
			       const char *search_name, FILE_ALL_INFO *data,
			       const struct nls_table *nls_codepage, int remap);

extern int CIFSSMBUnixQFileInfo(const unsigned int xid, struct smbfs_tcon *tcon,
			u16 net_fid, FILE_UNIX_BASIC_INFO *pFindData);
extern int CIFSSMBUnixQPathInfo(const unsigned int xid,
			struct smbfs_tcon *tcon,
			const unsigned char *searchName,
			FILE_UNIX_BASIC_INFO *pFindData,
			const struct nls_table *nls_codepage, int remap);

extern int CIFSGetDFSRefer(const unsigned int xid, struct smbfs_ses *ses,
			   const char *search_name,
			   struct smbfs_dfs_info **target_nodes,
			   unsigned int *num_of_nodes,
			   const struct nls_table *nls_codepage, int remap);

extern int parse_dfs_referrals(struct get_dfs_referral_rsp *rsp, unsigned int rsp_size,
			       unsigned int *num_of_nodes,
			       struct smbfs_dfs_info **target_nodes,
			       const struct nls_table *nls_codepage, int remap,
			       const char *searchName, bool is_unicode);
extern void reset_cifs_unix_caps(unsigned int xid, struct smbfs_tcon *tcon,
				 struct cifs_sb_info *cifs_sb,
				 struct smb3_fs_context *ctx);
extern int CIFSSMBQFSInfo(const unsigned int xid, struct smbfs_tcon *tcon,
			struct kstatfs *FSData);
extern int SMBOldQFSInfo(const unsigned int xid, struct smbfs_tcon *tcon,
			struct kstatfs *FSData);
extern int CIFSSMBSetFSUnixInfo(const unsigned int xid, struct smbfs_tcon *tcon,
			u64 cap);

extern int CIFSSMBQFSAttributeInfo(const unsigned int xid,
			struct smbfs_tcon *tcon);
extern int CIFSSMBQFSDeviceInfo(const unsigned int xid, struct smbfs_tcon *tcon);
extern int CIFSSMBQFSUnixInfo(const unsigned int xid, struct smbfs_tcon *tcon);
extern int CIFSSMBQFSPosixInfo(const unsigned int xid, struct smbfs_tcon *tcon,
			struct kstatfs *FSData);

extern int CIFSSMBSetPathInfo(const unsigned int xid, struct smbfs_tcon *tcon,
			const char *fileName, const FILE_BASIC_INFO *data,
			const struct nls_table *nls_codepage,
			struct cifs_sb_info *cifs_sb);
extern int CIFSSMBSetFileInfo(const unsigned int xid, struct smbfs_tcon *tcon,
			const FILE_BASIC_INFO *data, __u16 fid,
			unsigned int pid_of_opener);
extern int CIFSSMBSetFileDisposition(const unsigned int, struct smbfs_tcon *,
				     bool, __u16, unsigned int);
extern int CIFSSMBSetEOF(const unsigned int, struct smbfs_tcon *,
			 const char *, u64, struct cifs_sb_info *, bool);
extern int CIFSSMBSetFileSize(const unsigned int, struct smbfs_tcon *,
			      struct smbfs_file_info *, u64, bool);

struct cifs_unix_set_info_args {
	__u64	ctime;
	__u64	atime;
	__u64	mtime;
	__u64	mode;
	kuid_t	uid;
	kgid_t	gid;
	dev_t	device;
};

extern int CIFSSMBUnixSetFileInfo(const unsigned int xid,
				  struct smbfs_tcon *tcon,
				  const struct cifs_unix_set_info_args *args,
				  u16 fid, unsigned int pid_of_opener);

extern int CIFSSMBUnixSetPathInfo(const unsigned int xid,
				  struct smbfs_tcon *tcon, const char *file_name,
				  const struct cifs_unix_set_info_args *args,
				  const struct nls_table *nls_codepage,
				  int remap);

extern int CIFSSMBMkDir(const unsigned int xid, struct inode *inode,
			umode_t mode, struct smbfs_tcon *tcon,
			const char *name, struct cifs_sb_info *cifs_sb);
extern int CIFSSMBRmDir(const unsigned int xid, struct smbfs_tcon *tcon,
			const char *name, struct cifs_sb_info *cifs_sb);
extern int CIFSPOSIXDelFile(const unsigned int xid, struct smbfs_tcon *tcon,
			const char *name, __u16 type,
			const struct nls_table *nls_codepage,
			int remap_special_chars);
extern int CIFSSMBDelFile(const unsigned int xid, struct smbfs_tcon *tcon,
			  const char *name, struct cifs_sb_info *cifs_sb);
extern int CIFSSMBRename(const unsigned int xid, struct smbfs_tcon *tcon,
			 const char *from_name, const char *to_name,
			 struct cifs_sb_info *cifs_sb);
extern int CIFSSMBRenameOpenFile(const unsigned int xid, struct smbfs_tcon *tcon,
				 int net_fid, const char *target_name,
				 const struct nls_table *nls_codepage,
				 int remap_special_chars);
extern int CIFSCreateHardLink(const unsigned int xid, struct smbfs_tcon *tcon,
			      const char *from_name, const char *to_name,
			      struct cifs_sb_info *cifs_sb);
extern int CIFSUnixCreateHardLink(const unsigned int xid,
			struct smbfs_tcon *tcon,
			const char *fromName, const char *toName,
			const struct nls_table *nls_codepage,
			int remap_special_chars);
extern int CIFSUnixCreateSymLink(const unsigned int xid,
			struct smbfs_tcon *tcon,
			const char *fromName, const char *toName,
			const struct nls_table *nls_codepage, int remap);
extern int CIFSSMBUnixQuerySymLink(const unsigned int xid,
			struct smbfs_tcon *tcon,
			const unsigned char *searchName, char **syminfo,
			const struct nls_table *nls_codepage, int remap);
extern int CIFSSMBQuerySymLink(const unsigned int xid, struct smbfs_tcon *tcon,
			       __u16 fid, char **symlinkinfo,
			       const struct nls_table *nls_codepage);
extern int CIFSSMB_set_compression(const unsigned int xid,
				   struct smbfs_tcon *tcon, __u16 fid);
extern int CIFS_open(const unsigned int xid, struct smbfs_open_parms *oparms,
		     int *oplock, FILE_ALL_INFO *buf);
extern int SMBLegacyOpen(const unsigned int xid, struct smbfs_tcon *tcon,
			const char *fileName, const int disposition,
			const int access_flags, const int omode,
			__u16 *net_fid, int *pOplock, FILE_ALL_INFO *,
			const struct nls_table *nls_codepage, int remap);
extern int CIFSPOSIXCreate(const unsigned int xid, struct smbfs_tcon *tcon,
			unsigned int posix_flags, u64 mode, __u16 *net_fid,
			FILE_UNIX_BASIC_INFO *pRetData,
			unsigned int *pOplock, const char *name,
			const struct nls_table *nls_codepage, int remap);
extern int CIFSSMBClose(const unsigned int xid, struct smbfs_tcon *tcon,
			const int smb_file_id);

extern int CIFSSMBFlush(const unsigned int xid, struct smbfs_tcon *tcon,
			const int smb_file_id);

extern int CIFSSMBRead(const unsigned int xid, struct smbfs_io_parms *io_parms,
			unsigned int *nbytes, char **buf,
			int *return_buf_type);
extern int CIFSSMBWrite(const unsigned int xid, struct smbfs_io_parms *io_parms,
			unsigned int *nbytes, const char *buf);
extern int CIFSSMBWrite2(const unsigned int xid, struct smbfs_io_parms *io_parms,
			unsigned int *nbytes, struct kvec *iov, const int nvec);
extern int CIFSGetSrvInodeNumber(const unsigned int xid, struct smbfs_tcon *tcon,
				 const char *search_name, u64 *inode_number,
				 const struct nls_table *nls_codepage,
				 int remap);

extern int cifs_lockv(const unsigned int xid, struct smbfs_tcon *tcon,
		      const __u16 net_fid, const __u8 lock_type,
		      const unsigned int num_unlock, const unsigned int num_lock,
		      LOCKING_ANDX_RANGE *buf);
extern int CIFSSMBLock(const unsigned int xid, struct smbfs_tcon *tcon,
			const __u16 net_fid, const unsigned int netpid, const u64 len,
			const u64 offset, const unsigned int numUnlock,
			const unsigned int numLock, const __u8 lockType,
			const bool waitFlag, const __u8 oplock_level);
extern int CIFSSMBPosixLock(const unsigned int xid, struct smbfs_tcon *tcon,
			const __u16 smb_file_id, const unsigned int netpid,
			const loff_t start_offset, const u64 len,
			struct file_lock *, const __u16 lock_type,
			const bool waitFlag);
extern int CIFSSMBTDis(const unsigned int xid, struct smbfs_tcon *tcon);
extern int CIFSSMBEcho(struct smbfs_server_info *server);
extern int CIFSSMBLogoff(const unsigned int xid, struct smbfs_ses *ses);

extern struct smbfs_ses *sesInfoAlloc(void);
extern void sesInfoFree(struct smbfs_ses *);
extern struct smbfs_tcon *smbfs_tcon_alloc(void);
extern void smbfs_tcon_free(struct smbfs_tcon *);

extern int cifs_sign_rqst(struct smb_rqst *rqst, struct smbfs_server_info *server,
		   unsigned int *pexpected_response_sequence_number);
extern int cifs_sign_smbv(struct kvec *iov, int n_vec, struct smbfs_server_info *,
			  unsigned int *);
extern int cifs_sign_smb(struct smb_hdr *, struct smbfs_server_info *, unsigned int *);
extern int cifs_verify_signature(struct smb_rqst *rqst,
				 struct smbfs_server_info *server,
				unsigned int expected_sequence_number);
extern int setup_ntlmv2_rsp(struct smbfs_ses *, const struct nls_table *);
extern void cifs_crypto_secmech_release(struct smbfs_server_info *server);
extern int calc_seckey(struct smbfs_ses *);
extern int generate_smb30signingkey(struct smbfs_ses *ses,
				    struct smbfs_server_info *server);
extern int generate_smb311signingkey(struct smbfs_ses *ses,
				     struct smbfs_server_info *server);

extern int CIFSSMBCopy(unsigned int xid,
			struct smbfs_tcon *source_tcon,
			const char *fromName,
			const __u16 target_tid,
			const char *toName, const int flags,
			const struct nls_table *nls_codepage,
			int remap_special_chars);
extern ssize_t CIFSSMBQAllEAs(const unsigned int xid, struct smbfs_tcon *tcon,
			const unsigned char *searchName,
			const unsigned char *ea_name, char *EAData,
			size_t bufsize, struct cifs_sb_info *cifs_sb);
extern int CIFSSMBSetEA(const unsigned int xid, struct smbfs_tcon *tcon,
		const char *fileName, const char *ea_name,
		const void *ea_value, const __u16 ea_value_len,
		const struct nls_table *nls_codepage,
		struct cifs_sb_info *cifs_sb);
extern int CIFSSMBGetCIFSACL(const unsigned int xid, struct smbfs_tcon *tcon,
			__u16 fid, struct cifs_ntsd **acl_inf, unsigned int *buflen);
extern int CIFSSMBSetCIFSACL(const unsigned int, struct smbfs_tcon *, __u16,
			struct cifs_ntsd *, __u32, int);
extern int CIFSSMBGetPosixACL(const unsigned int xid, struct smbfs_tcon *tcon,
		const unsigned char *searchName,
		char *acl_inf, const int buflen, const int acl_type,
		const struct nls_table *nls_codepage, int remap_special_chars);
extern int CIFSSMBSetPosixACL(const unsigned int xid, struct smbfs_tcon *tcon,
		const unsigned char *fileName,
		const char *local_acl, const int buflen, const int acl_type,
		const struct nls_table *nls_codepage, int remap_special_chars);
extern int CIFSGetExtAttr(const unsigned int xid, struct smbfs_tcon *tcon,
			const int net_fid, u64 *pExtAttrBits, u64 *pMask);
extern void cifs_autodisable_serverino(struct cifs_sb_info *cifs_sb);
extern bool couldbe_mf_symlink(const struct smbfs_fattr *fattr);
extern int check_mf_symlink(unsigned int xid, struct smbfs_tcon *tcon,
			      struct cifs_sb_info *cifs_sb,
			      struct smbfs_fattr *fattr,
			      const unsigned char *path);
extern int E_md4hash(const unsigned char *passwd, unsigned char *p16,
			const struct nls_table *codepage);

extern int
cifs_setup_volume_info(struct smb3_fs_context *ctx, const char *mntopts, const char *devname);

extern struct smbfs_server_info *
smbfs_find_server(struct smb3_fs_context *ctx);

extern void cifs_put_smb_ses(struct smbfs_ses *ses);

extern struct smbfs_ses *
cifs_get_smb_ses(struct smbfs_server_info *server, struct smb3_fs_context *ctx);

void smbfs_readdata_release(struct kref *refcount);
int cifs_async_readv(struct smbfs_readdata *rdata);
int cifs_readv_receive(struct smbfs_server_info *server, struct smbfs_mid_entry *mid);

int cifs_async_writev(struct smbfs_writedata *wdata,
		      void (*release)(struct kref *kref));
void cifs_writev_complete(struct work_struct *work);
struct smbfs_writedata *smbfs_writedata_alloc(unsigned int nr_pages,
						work_func_t complete);
struct smbfs_writedata *smbfs_writedata_direct_alloc(struct page **pages,
						work_func_t complete);
void smbfs_writedata_release(struct kref *refcount);
int cifs_query_mf_symlink(unsigned int xid, struct smbfs_tcon *tcon,
			  struct cifs_sb_info *cifs_sb,
			  const unsigned char *path, char *pbuf,
			  unsigned int *pbytes_read);
int cifs_create_mf_symlink(unsigned int xid, struct smbfs_tcon *tcon,
			   struct cifs_sb_info *cifs_sb,
			   const unsigned char *path, char *pbuf,
			   unsigned int *pbytes_written);
int __cifs_calc_signature(struct smb_rqst *rqst,
			struct smbfs_server_info *server, char *signature,
			struct shash_desc *shash);
smbfs_security_t cifs_select_sectype(struct smbfs_server_info *,
					smbfs_security_t);
struct smbfs_aio_ctx *smbfs_aio_ctx_alloc(void);
void smbfs_aio_ctx_release(struct kref *refcount);
int setup_aio_ctx_iter(struct smbfs_aio_ctx *ctx, struct iov_iter *iter, int rw);
void smb2_cached_lease_break(struct work_struct *work);

int cifs_alloc_hash(const char *name, struct crypto_shash **shash,
		    struct smbfs_sec_desc **sec_desc_);
void cifs_free_hash(struct crypto_shash **shash, struct smbfs_sec_desc **sec_desc_);

extern void rqst_page_get_length(struct smb_rqst *rqst, unsigned int page,
				unsigned int *len, unsigned int *offset);
struct smbfs_channel *
smbfs_ses_find_chan(struct smbfs_ses *ses, struct smbfs_server_info *server);
int cifs_try_adding_channels(struct cifs_sb_info *cifs_sb, struct smbfs_ses *ses);
bool is_server_using_iface(struct smbfs_server_info *server,
			   struct smbfs_server_iface *iface);
bool is_ses_using_iface(struct smbfs_ses *ses, struct smbfs_server_iface *iface);
void smbfs_ses_mark_for_reconnect(struct smbfs_ses *ses);

unsigned int
smbfs_ses_get_chan_index(struct smbfs_ses *ses,
			struct smbfs_server_info *server);
void
smbfs_channel_set_in_reconnect(struct smbfs_ses *ses,
			     struct smbfs_server_info *server);
void
smbfs_channel_clear_in_reconnect(struct smbfs_ses *ses,
			       struct smbfs_server_info *server);
bool
smbfs_channel_in_reconnect(struct smbfs_ses *ses,
			  struct smbfs_server_info *server);
void
smbfs_channel_set_need_reconnect(struct smbfs_ses *ses,
			     struct smbfs_server_info *server);
void
smbfs_channel_clear_need_reconnect(struct smbfs_ses *ses,
			       struct smbfs_server_info *server);
bool
smbfs_channel_needs_reconnect(struct smbfs_ses *ses,
			  struct smbfs_server_info *server);
bool
smbfs_channel_is_iface_active(struct smbfs_ses *ses,
			  struct smbfs_server_info *server);
int
smbfs_channel_update_iface(struct smbfs_ses *ses, struct smbfs_server_info *server);
int
SMB3_request_interfaces(const unsigned int xid, struct smbfs_tcon *tcon);

void extract_unc_hostname(const char *unc, const char **h, size_t *len);
int copy_path_name(char *dst, const char *src);
int smb2_parse_query_directory(struct smbfs_tcon *tcon, struct kvec *rsp_iov,
			       int resp_buftype,
			       struct smbfs_search_info *srch_inf);

struct super_block *cifs_get_tcp_super(struct smbfs_server_info *server);
void cifs_put_tcp_super(struct super_block *sb);
int cifs_update_super_prepath(struct cifs_sb_info *cifs_sb, char *prefix);
char *extract_hostname(const char *unc);
char *extract_sharename(const char *unc);

#ifdef CONFIG_SMBFS_DFS_UPCALL
static inline int get_dfs_path(const unsigned int xid, struct smbfs_ses *ses,
			       const char *old_path,
			       const struct nls_table *nls_codepage,
			       struct smbfs_dfs_info *referral, int remap)
{
	return dfs_cache_find(xid, ses, nls_codepage, remap, old_path,
			      referral, NULL);
}

int match_target_ip(struct smbfs_server_info *server,
		    const char *share, size_t share_len,
		    bool *result);

int cifs_dfs_query_info_nonascii_quirk(const unsigned int xid,
				       struct smbfs_tcon *tcon,
				       struct cifs_sb_info *cifs_sb,
				       const char *dfs_link_path);
#endif

static inline int cifs_create_options(struct cifs_sb_info *cifs_sb, int options)
{
	if (cifs_sb && (backup_cred(cifs_sb)))
		return options | CREATE_OPEN_BACKUP_INTENT;
	else
		return options;
}

struct super_block *cifs_get_tcon_super(struct smbfs_tcon *tcon);
void smbfs_put_tcon_super(struct super_block *sb);
#endif /* _SMBFS_DEFS_H */
