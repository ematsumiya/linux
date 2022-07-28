/* SPDX-License-Identifier: LGPL-2.1 */
/*
 *
 *   Copyright (c) International Business Machines  Corp., 2002,2008
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *
 */
#ifndef _CIFSPROTO_H
#define _CIFSPROTO_H
#include <linux/nls.h>
#include "trace.h"
#ifdef CONFIG_CIFS_DFS_UPCALL
#include "dfs_cache.h"
#endif

struct statfs;
struct smb_rqst;
struct smb3_fs_context;

/*
 *****************************************************************
 * All Prototypes
 *****************************************************************
 */

extern struct smb_hdr *cifs_buf_get(void);
extern void cifs_buf_release(void *);
extern struct smb_hdr *cifs_small_buf_get(void);
extern void cifs_small_buf_release(void *);
extern void free_rsp_buf(int, void *);
extern int smb_send(struct TCP_Server_Info *, struct smb_hdr *,
			unsigned int /* length */);
extern unsigned int _get_xid(void);
extern void _free_xid(unsigned int);
#define get_xid()							\
({									\
	unsigned int __xid = _get_xid();				\
	cifs_dbg(FYI, "VFS: in %s as Xid: %u with uid: %d\n",		\
		 __func__, __xid,					\
		 from_kuid(&init_user_ns, current_fsuid()));		\
	trace_smb3_enter(__xid, __func__);				\
	__xid;								\
})

#define free_xid(curr_xid)						\
do {									\
	_free_xid(curr_xid);						\
	cifs_dbg(FYI, "VFS: leaving %s (xid = %u) rc = %d\n",		\
		 __func__, curr_xid, (int)rc);				\
	if (rc)								\
		trace_smb3_exit_err(curr_xid, __func__, (int)rc);	\
	else								\
		trace_smb3_exit_done(curr_xid, __func__);		\
} while (0)
extern int init_cifs_idmap(void);
extern void exit_cifs_idmap(void);
extern int init_cifs_spnego(void);
extern void exit_cifs_spnego(void);
extern const char *build_path_from_dentry(struct dentry *, void *);
extern char *build_path_from_dentry_optional_prefix(struct dentry *direntry,
						    void *page, bool prefix);
static inline void *alloc_dentry_path(void)
{
	return __getname();
}

static inline void free_dentry_path(void *page)
{
	if (page)
		__putname(page);
}

extern char *cifs_build_path_to_root(struct smb3_fs_context *ctx,
				     struct cifs_sb_info *cifs_sb,
				     struct cifs_tcon *tcon,
				     int add_treename);
extern void DeleteMidQEntry(struct mid_q_entry *midEntry);
extern void cifs_delete_mid(struct mid_q_entry *mid);
extern void cifs_mid_q_entry_release(struct mid_q_entry *midEntry);
extern void cifs_wake_up_task(struct mid_q_entry *mid);
extern int cifs_handle_standard(struct TCP_Server_Info *server,
				struct mid_q_entry *mid);
extern int smb3_parse_devname(const char *devname, struct smb3_fs_context *ctx);
extern int smb3_parse_opt(const char *options, const char *key, char **val);
extern bool cifs_match_ipaddr(struct sockaddr *srcaddr, struct sockaddr *rhs);
extern int cifs_discard_remaining_data(struct TCP_Server_Info *server);
extern int cifs_call_async(struct TCP_Server_Info *server,
			struct smb_rqst *rqst,
			mid_receive_t *receive, mid_callback_t *callback,
			mid_handle_t *handle, void *cbdata, const int flags,
			const struct cifs_credits *exist_credits);
extern struct TCP_Server_Info *cifs_pick_channel(struct cifs_ses *ses);
extern int cifs_send_recv(const unsigned int xid, struct cifs_ses *ses,
			  struct TCP_Server_Info *server,
			  struct smb_rqst *rqst, int *resp_buf_type,
			  const int flags, struct kvec *resp_iov);
extern int compound_send_recv(const unsigned int xid, struct cifs_ses *ses,
			      struct TCP_Server_Info *server,
			      const int flags, const int num_rqst,
			      struct smb_rqst *rqst, int *resp_buf_type,
			      struct kvec *resp_iov);
extern int SendReceive(const unsigned int /* xid */ , struct cifs_ses *,
			struct smb_hdr * /* input */ ,
			struct smb_hdr * /* out */ ,
			int * /* bytes returned */ , const int);
extern int cifs_wait_mtu_credits(struct TCP_Server_Info *server,
				 unsigned int size, unsigned int *num,
				 struct cifs_credits *credits);
extern int SendReceive2(const unsigned int /* xid */ , struct cifs_ses *,
			struct kvec *, int /* nvec to send */,
			int * /* type of buf returned */, const int flags,
			struct kvec * /* resp vec */);
void
cifs_signal_cifsd_for_reconnect(struct TCP_Server_Info *server,
				      bool all_channels);
void
cifs_mark_tcp_ses_conns_for_reconnect(struct TCP_Server_Info *server,
				      bool mark_smb_session);
extern int cifs_reconnect(struct TCP_Server_Info *server,
			  bool mark_smb_session);
extern bool backup_cred(struct cifs_sb_info *);
extern struct cifsFileInfo *find_writable_file(struct cifsInodeInfo *, int);
extern int cifs_get_writable_path(struct cifs_tcon *tcon, const char *name,
				  int flags,
				  struct cifsFileInfo **ret_file);
extern struct cifsFileInfo *find_readable_file(struct cifsInodeInfo *, bool);
extern int cifs_get_readable_path(struct cifs_tcon *tcon, const char *name,
				  struct cifsFileInfo **ret_file);
extern unsigned int smbCalcSize(void *buf, struct TCP_Server_Info *server);
extern int decode_negTokenInit(unsigned char *security_blob, int length,
			struct TCP_Server_Info *server);
extern int cifs_convert_address(struct sockaddr *dst, const char *src, int len);
extern void cifs_set_port(struct sockaddr *addr, const unsigned short int port);
extern int map_smb_to_linux_error(char *buf, bool logErr);
extern int map_and_check_smb_error(struct mid_q_entry *mid, bool logErr);
extern void header_assemble(struct smb_hdr *, char /* command */ ,
			    const struct cifs_tcon *, int /* length of
			    fixed section (word count) in two byte units */);
extern int small_smb_init_no_tc(const int smb_cmd, const int wct,
				struct cifs_ses *ses,
				void **request_buf);
extern enum securityEnum select_sectype(struct TCP_Server_Info *server,
				enum securityEnum requested);
extern int CIFS_SessSetup(const unsigned int xid, struct cifs_ses *ses,
			  struct TCP_Server_Info *server,
			  const struct nls_table *nls_cp);
extern struct timespec64 cifs_NTtimeToUnix(__le64 utc_nanoseconds_since_1601);
extern u64 cifs_UnixTimeToNT(struct timespec64);
extern struct timespec64 cnvrtDosUnixTm(__le16 le_date, __le16 le_time,
				      int offset);
extern void cifs_set_oplock_level(struct cifsInodeInfo *cinode, __u32 oplock);
extern int cifs_get_writer(struct cifsInodeInfo *cinode);
extern void cifs_put_writer(struct cifsInodeInfo *cinode);
extern void cifs_done_oplock_break(struct cifsInodeInfo *cinode);
void cifs_fill_uniqueid(struct super_block *sb, struct cifs_fattr *fattr);

extern unsigned int setup_authusers_ACE(struct cifs_ace *pace);
extern unsigned int setup_special_mode_ACE(struct cifs_ace *pace, __u64 nmode);
extern unsigned int setup_special_user_owner_ACE(struct cifs_ace *pace);

extern void dequeue_mid(struct mid_q_entry *mid, bool malformed);
extern int cifs_read_from_socket(struct TCP_Server_Info *server, char *buf,
			         unsigned int to_read);
extern ssize_t cifs_discard_from_socket(struct TCP_Server_Info *server,
					size_t to_read);
extern int cifs_read_page_from_socket(struct TCP_Server_Info *server,
					struct page *page,
					unsigned int page_offset,
					unsigned int to_read);
extern int cifs_setup_cifs_sb(struct cifs_sb_info *cifs_sb);
extern int cifs_match_super(struct super_block *, void *);
extern int cifs_mount(struct cifs_sb_info *cifs_sb, struct smb3_fs_context *ctx);
extern void cifs_umount(struct cifs_sb_info *);
extern void cifs_mark_open_files_invalid(struct cifs_tcon *tcon);
extern void cifs_reopen_persistent_handles(struct cifs_tcon *tcon);

extern void cifs_add_pending_open(struct cifs_fid *fid,
				  struct tcon_link *tlink,
				  struct cifs_pending_open *open);
extern void cifs_add_pending_open_locked(struct cifs_fid *fid,
					 struct tcon_link *tlink,
					 struct cifs_pending_open *open);
extern void cifs_del_pending_open(struct cifs_pending_open *open);

extern bool cifs_is_deferred_close(struct cifsFileInfo *cfile,
				struct cifs_deferred_close **dclose);

extern void cifs_add_deferred_close(struct cifsFileInfo *cfile,
				struct cifs_deferred_close *dclose);

extern void cifs_del_deferred_close(struct cifsFileInfo *cfile);

extern void cifs_close_deferred_file(struct cifsInodeInfo *cifs_inode);

extern void cifs_close_all_deferred_files(struct cifs_tcon *cifs_tcon);

extern void cifs_close_deferred_file_under_dentry(struct cifs_tcon *cifs_tcon,
				const char *path);
extern struct TCP_Server_Info *
cifs_get_tcp_session(struct smb3_fs_context *ctx,
		     struct TCP_Server_Info *primary_server);
extern void cifs_put_tcp_session(struct TCP_Server_Info *server,
				 int from_reconnect);
extern void cifs_put_tcon(struct cifs_tcon *tcon);

#if IS_ENABLED(CONFIG_CIFS_DFS_UPCALL)
extern void cifs_dfs_release_automount_timer(void);
#else /* ! IS_ENABLED(CONFIG_CIFS_DFS_UPCALL) */
#define cifs_dfs_release_automount_timer()	do { } while (0)
#endif /* ! IS_ENABLED(CONFIG_CIFS_DFS_UPCALL) */

void cifs_proc_init(void);
void cifs_proc_clean(void);

extern void cifs_move_llist(struct list_head *source, struct list_head *dest);
extern void cifs_free_llist(struct list_head *llist);
extern void cifs_del_lock_waiters(struct cifsLockInfo *lock);

extern int cifs_tree_connect(const unsigned int xid, struct cifs_tcon *tcon,
			     const struct nls_table *nlsc);

extern int cifs_negotiate_protocol(const unsigned int xid,
				   struct cifs_ses *ses,
				   struct TCP_Server_Info *server);
extern int cifs_setup_session(const unsigned int xid, struct cifs_ses *ses,
			      struct TCP_Server_Info *server,
			      struct nls_table *nls_info);
extern int cifs_enable_signing(struct TCP_Server_Info *server, bool mnt_sign_required);

extern int CIFSTCon(const unsigned int xid, struct cifs_ses *ses,
		    const char *tree, struct cifs_tcon *tcon,
		    const struct nls_table *);

extern int parse_dfs_referrals(struct get_dfs_referral_rsp *rsp, u32 rsp_size,
			       unsigned int *num_of_nodes,
			       struct dfs_info3_param **target_nodes,
			       const struct nls_table *nls_codepage, int remap,
			       const char *searchName, bool is_unicode);
extern void reset_cifs_unix_caps(unsigned int xid, struct cifs_tcon *tcon,
				 struct cifs_sb_info *cifs_sb,
				 struct smb3_fs_context *ctx);
extern int CIFSSMBSetFSUnixInfo(const unsigned int xid, struct cifs_tcon *tcon,
			__u64 cap);

struct cifs_unix_set_info_args {
	__u64	ctime;
	__u64	atime;
	__u64	mtime;
	__u64	mode;
	kuid_t	uid;
	kgid_t	gid;
	dev_t	device;
};

extern void sesInfoFree(struct cifs_ses *);
extern struct cifs_tcon *tconInfoAlloc(void);
extern void tconInfoFree(struct cifs_tcon *);

extern int cifs_sign_rqst(struct smb_rqst *rqst, struct TCP_Server_Info *server,
		   __u32 *pexpected_response_sequence_number);
extern int cifs_sign_smbv(struct kvec *iov, int n_vec, struct TCP_Server_Info *,
			  __u32 *);
extern int cifs_sign_smb(struct smb_hdr *, struct TCP_Server_Info *, __u32 *);
extern int cifs_verify_signature(struct smb_rqst *rqst,
				 struct TCP_Server_Info *server,
				__u32 expected_sequence_number);
extern int setup_ntlmv2_rsp(struct cifs_ses *, const struct nls_table *);
extern void cifs_crypto_secmech_release(struct TCP_Server_Info *server);
extern int calc_seckey(struct cifs_ses *);
extern int generate_smb30signingkey(struct cifs_ses *ses,
				    struct TCP_Server_Info *server);
extern int generate_smb311signingkey(struct cifs_ses *ses,
				     struct TCP_Server_Info *server);

extern void cifs_autodisable_serverino(struct cifs_sb_info *cifs_sb);
extern int E_md4hash(const unsigned char *passwd, unsigned char *p16,
			const struct nls_table *codepage);

extern int
cifs_setup_volume_info(struct smb3_fs_context *ctx, const char *mntopts, const char *devname);

extern struct TCP_Server_Info *
cifs_find_tcp_session(struct smb3_fs_context *ctx);

extern void cifs_put_smb_ses(struct cifs_ses *ses);

extern struct cifs_ses *
cifs_get_smb_ses(struct TCP_Server_Info *server, struct smb3_fs_context *ctx);

void cifs_readdata_release(struct kref *refcount);
int cifs_async_readv(struct cifs_readdata *rdata);
int cifs_readv_receive(struct TCP_Server_Info *server, struct mid_q_entry *mid);

int cifs_async_writev(struct cifs_writedata *wdata,
		      void (*release)(struct kref *kref));
void cifs_writev_complete(struct work_struct *work);
struct cifs_writedata *cifs_writedata_alloc(unsigned int nr_pages,
						work_func_t complete);
struct cifs_writedata *cifs_writedata_direct_alloc(struct page **pages,
						work_func_t complete);
void cifs_writedata_release(struct kref *refcount);
int cifs_query_mf_symlink(unsigned int xid, struct cifs_tcon *tcon,
			  struct cifs_sb_info *cifs_sb,
			  const unsigned char *path, char *pbuf,
			  unsigned int *pbytes_read);
int cifs_create_mf_symlink(unsigned int xid, struct cifs_tcon *tcon,
			   struct cifs_sb_info *cifs_sb,
			   const unsigned char *path, char *pbuf,
			   unsigned int *pbytes_written);
int __cifs_calc_signature(struct smb_rqst *rqst,
			struct TCP_Server_Info *server, char *signature,
			struct shash_desc *shash);
enum securityEnum cifs_select_sectype(struct TCP_Server_Info *,
					enum securityEnum);
struct cifs_aio_ctx *cifs_aio_ctx_alloc(void);
void cifs_aio_ctx_release(struct kref *refcount);
int setup_aio_ctx_iter(struct cifs_aio_ctx *ctx, struct iov_iter *iter, int rw);
void smb2_cached_lease_break(struct work_struct *work);

int cifs_alloc_hash(const char *name, struct crypto_shash **shash,
		    struct sdesc **sdesc);
void cifs_free_hash(struct crypto_shash **shash, struct sdesc **sdesc);

extern void rqst_page_get_length(struct smb_rqst *rqst, unsigned int page,
				unsigned int *len, unsigned int *offset);
struct cifs_chan *
cifs_ses_find_chan(struct cifs_ses *ses, struct TCP_Server_Info *server);
int cifs_try_adding_channels(struct cifs_sb_info *cifs_sb, struct cifs_ses *ses);
bool is_server_using_iface(struct TCP_Server_Info *server,
			   struct cifs_server_iface *iface);
bool is_ses_using_iface(struct cifs_ses *ses, struct cifs_server_iface *iface);
void cifs_ses_mark_for_reconnect(struct cifs_ses *ses);

unsigned int
cifs_ses_get_chan_index(struct cifs_ses *ses,
			struct TCP_Server_Info *server);
void
cifs_chan_set_in_reconnect(struct cifs_ses *ses,
			     struct TCP_Server_Info *server);
void
cifs_chan_clear_in_reconnect(struct cifs_ses *ses,
			       struct TCP_Server_Info *server);
bool
cifs_chan_in_reconnect(struct cifs_ses *ses,
			  struct TCP_Server_Info *server);
void
cifs_chan_set_need_reconnect(struct cifs_ses *ses,
			     struct TCP_Server_Info *server);
void
cifs_chan_clear_need_reconnect(struct cifs_ses *ses,
			       struct TCP_Server_Info *server);
bool
cifs_chan_needs_reconnect(struct cifs_ses *ses,
			  struct TCP_Server_Info *server);
bool
cifs_chan_is_iface_active(struct cifs_ses *ses,
			  struct TCP_Server_Info *server);
int
cifs_chan_update_iface(struct cifs_ses *ses, struct TCP_Server_Info *server);
int
SMB3_request_interfaces(const unsigned int xid, struct cifs_tcon *tcon);

void extract_unc_hostname(const char *unc, const char **h, size_t *len);
int copy_path_name(char *dst, const char *src);
int smb2_parse_query_directory(struct cifs_tcon *tcon, struct kvec *rsp_iov,
			       int resp_buftype,
			       struct cifs_search_info *srch_inf);

struct super_block *cifs_get_tcp_super(struct TCP_Server_Info *server);
void cifs_put_tcp_super(struct super_block *sb);
int cifs_update_super_prepath(struct cifs_sb_info *cifs_sb, char *prefix);
char *extract_hostname(const char *unc);
char *extract_sharename(const char *unc);

#ifdef CONFIG_CIFS_DFS_UPCALL
static inline int get_dfs_path(const unsigned int xid, struct cifs_ses *ses,
			       const char *old_path,
			       const struct nls_table *nls_codepage,
			       struct dfs_info3_param *referral, int remap)
{
	return dfs_cache_find(xid, ses, nls_codepage, remap, old_path,
			      referral, NULL);
}

int match_target_ip(struct TCP_Server_Info *server,
		    const char *share, size_t share_len,
		    bool *result);

int cifs_dfs_query_info_nonascii_quirk(const unsigned int xid,
				       struct cifs_tcon *tcon,
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

struct super_block *cifs_get_tcon_super(struct cifs_tcon *tcon);
void cifs_put_tcon_super(struct super_block *sb);

#endif			/* _CIFSPROTO_H */
