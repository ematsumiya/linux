/* SPDX-License-Identifier: LGPL-2.1 */
/*
 *
 *   Copyright (c) International Business Machines  Corp., 2002,2008
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *
 */
#ifndef _SMB1_PROTO_H
#define _SMB1_PROTO_H
#include <linux/nls.h>

/* extern void renew_parental_timestamps(struct dentry *direntry);*/
extern struct mid_q_entry *AllocMidQEntry(const struct smb_hdr *smb_buffer,
					struct TCP_Server_Info *server);
extern struct mid_q_entry *AllocMidQEntry(const struct smb_hdr *smb_buffer,
					struct TCP_Server_Info *server);
extern int SendReceiveNoRsp(const unsigned int xid, struct cifs_ses *ses,
			    char *in_buf, int flags);
extern struct mid_q_entry *cifs_setup_request(struct cifs_ses *,
				struct TCP_Server_Info *,
				struct smb_rqst *);
extern struct mid_q_entry *cifs_setup_async_request(struct TCP_Server_Info *,
						struct smb_rqst *);
extern int cifs_check_receive(struct mid_q_entry *mid,
			struct TCP_Server_Info *server, bool log_error);
extern int SendReceiveBlockingLock(const unsigned int xid,
			struct cifs_tcon *ptcon,
			struct smb_hdr *in_buf ,
			struct smb_hdr *out_buf,
			int *bytes_returned);
extern int checkSMB(char *buf, unsigned int len, struct TCP_Server_Info *srvr);
extern bool is_valid_oplock_break(char *, struct TCP_Server_Info *);
extern bool is_size_safe_to_change(struct cifsInodeInfo *, __u64 eof);
extern void cifs_update_eof(struct cifsInodeInfo *cifsi, loff_t offset,
			    unsigned int bytes_written);
extern void cifs_update_eof(struct cifsInodeInfo *cifsi, loff_t offset,
			    unsigned int bytes_written);
extern int cifs_get_writable_file(struct cifsInodeInfo *cifs_inode,
				  int flags,
				  struct cifsFileInfo **ret_file);
extern int cifs_unlock_range(struct cifsFileInfo *cfile,
			     struct file_lock *flock, const unsigned int xid);
extern int cifs_push_mandatory_locks(struct cifsFileInfo *cfile);

extern void cifs_down_write(struct rw_semaphore *sem);
extern struct cifsFileInfo *cifs_new_fileinfo(struct cifs_fid *fid,
					      struct file *file,
					      struct tcon_link *tlink,
					      __u32 oplock);
extern int cifs_posix_open(const char *full_path, struct inode **inode,
			   struct super_block *sb, int mode,
			   unsigned int f_flags, __u32 *oplock, __u16 *netfid,
			   unsigned int xid);
extern void cifs_unix_basic_to_fattr(struct cifs_fattr *fattr,
				     FILE_UNIX_BASIC_INFO *info,
				     struct cifs_sb_info *cifs_sb);
extern void cifs_dir_info_to_fattr(struct cifs_fattr *, FILE_DIRECTORY_INFO *,
					struct cifs_sb_info *);
extern int cifs_fattr_to_inode(struct inode *inode, struct cifs_fattr *fattr);
extern struct inode *cifs_iget(struct super_block *sb,
			       struct cifs_fattr *fattr);
extern struct inode *cifs_iget(struct super_block *sb,
			       struct cifs_fattr *fattr);
extern int cifs_get_inode_info(struct inode **inode, const char *full_path,
			       FILE_ALL_INFO *data, struct super_block *sb,
			       int xid, const struct cifs_fid *fid);
extern int cifs_get_inode_info_unix(struct inode **pinode,
			const unsigned char *search_path,
			struct super_block *sb, unsigned int xid);
extern int smb311_posix_get_inode_info(struct inode **pinode, const char *search_path,
			struct super_block *sb, unsigned int xid);
extern int cifs_get_inode_info_unix(struct inode **pinode,
			const unsigned char *search_path,
			struct super_block *sb, unsigned int xid);
extern int cifs_set_file_info(struct inode *inode, struct iattr *attrs,
			      unsigned int xid, const char *full_path, __u32 dosattr);
extern int cifs_rename_pending_delete(const char *full_path,
				      struct dentry *dentry,
				      const unsigned int xid);
extern int sid_to_id(struct cifs_sb_info *cifs_sb, struct cifs_sid *psid,
				struct cifs_fattr *fattr, uint sidtype);
extern int cifs_acl_to_fattr(struct cifs_sb_info *cifs_sb,
			      struct cifs_fattr *fattr, struct inode *inode,
			      bool get_mode_from_special_sid,
			      const char *path, const struct cifs_fid *pfid);
extern int id_mode_to_cifs_acl(struct inode *inode, const char *path, __u64 *pnmode,
					kuid_t uid, kgid_t gid);
extern struct cifs_ntsd *get_cifs_acl(struct cifs_sb_info *, struct inode *,
				      const char *, u32 *, u32);
extern struct cifs_ntsd *get_cifs_acl_by_fid(struct cifs_sb_info *,
				const struct cifs_fid *, u32 *, u32);
extern struct cifs_ntsd *get_cifs_acl_by_fid(struct cifs_sb_info *,
				const struct cifs_fid *, u32 *, u32);
extern int set_cifs_acl(struct cifs_ntsd *, __u32, struct inode *,
				const char *, int);
extern bool cifs_find_lock_conflict(struct cifsFileInfo *cfile, __u64 offset,
				    __u64 length, __u8 type, __u16 flags,
				    struct cifsLockInfo **conf_lock,
				    int rw_check);
extern int CIFSSMBNegotiate(const unsigned int xid,
			    struct cifs_ses *ses,
			    struct TCP_Server_Info *server);
extern int CIFSFindFirst(const unsigned int xid, struct cifs_tcon *tcon,
		const char *searchName, struct cifs_sb_info *cifs_sb,
		__u16 *searchHandle, __u16 search_flags,
		struct cifs_search_info *psrch_inf,
		bool msearch);
extern int CIFSFindNext(const unsigned int xid, struct cifs_tcon *tcon,
		__u16 searchHandle, __u16 search_flags,
		struct cifs_search_info *psrch_inf);
extern int CIFSFindClose(const unsigned int xid, struct cifs_tcon *tcon,
			const __u16 search_handle);
extern int CIFSSMBQFileInfo(const unsigned int xid, struct cifs_tcon *tcon,
			u16 netfid, FILE_ALL_INFO *pFindData);
extern int CIFSSMBQPathInfo(const unsigned int xid, struct cifs_tcon *tcon,
			    const char *search_Name, FILE_ALL_INFO *data,
			    int legacy /* whether to use old info level */,
			    const struct nls_table *nls_codepage, int remap);
extern int SMBQueryInformation(const unsigned int xid, struct cifs_tcon *tcon,
			       const char *search_name, FILE_ALL_INFO *data,
			       const struct nls_table *nls_codepage, int remap);
extern int CIFSSMBUnixQFileInfo(const unsigned int xid, struct cifs_tcon *tcon,
			u16 netfid, FILE_UNIX_BASIC_INFO *pFindData);
extern int CIFSSMBUnixQPathInfo(const unsigned int xid,
			struct cifs_tcon *tcon,
			const unsigned char *searchName,
			FILE_UNIX_BASIC_INFO *pFindData,
			const struct nls_table *nls_codepage, int remap);
extern int CIFSGetDFSRefer(const unsigned int xid, struct cifs_ses *ses,
			   const char *search_name,
			   struct dfs_info3_param **target_nodes,
			   unsigned int *num_of_nodes,
			   const struct nls_table *nls_codepage, int remap);
extern int CIFSSMBQFSInfo(const unsigned int xid, struct cifs_tcon *tcon,
			struct kstatfs *FSData);
extern int SMBOldQFSInfo(const unsigned int xid, struct cifs_tcon *tcon,
			struct kstatfs *FSData);
extern int CIFSSMBQFSAttributeInfo(const unsigned int xid,
			struct cifs_tcon *tcon);
extern int CIFSSMBQFSDeviceInfo(const unsigned int xid, struct cifs_tcon *tcon);
extern int CIFSSMBQFSUnixInfo(const unsigned int xid, struct cifs_tcon *tcon);
extern int CIFSSMBQFSPosixInfo(const unsigned int xid, struct cifs_tcon *tcon,
			struct kstatfs *FSData);
extern int CIFSSMBSetPathInfo(const unsigned int xid, struct cifs_tcon *tcon,
			const char *fileName, const FILE_BASIC_INFO *data,
			const struct nls_table *nls_codepage,
			struct cifs_sb_info *cifs_sb);
extern int CIFSSMBSetFileInfo(const unsigned int xid, struct cifs_tcon *tcon,
			const FILE_BASIC_INFO *data, __u16 fid,
			__u32 pid_of_opener);
extern int CIFSSMBSetFileDisposition(const unsigned int xid,
				     struct cifs_tcon *tcon,
				     bool delete_file, __u16 fid,
				     __u32 pid_of_opener);
extern int CIFSSMBSetEOF(const unsigned int xid, struct cifs_tcon *tcon,
			 const char *file_name, __u64 size,
			 struct cifs_sb_info *cifs_sb, bool set_allocation);
extern int CIFSSMBSetFileSize(const unsigned int xid, struct cifs_tcon *tcon,
			      struct cifsFileInfo *cfile, __u64 size,
			      bool set_allocation);
extern int CIFSSMBUnixSetFileInfo(const unsigned int xid,
				  struct cifs_tcon *tcon,
				  const struct cifs_unix_set_info_args *args,
				  u16 fid, u32 pid_of_opener);
extern int CIFSSMBUnixSetPathInfo(const unsigned int xid,
				  struct cifs_tcon *tcon, const char *file_name,
				  const struct cifs_unix_set_info_args *args,
				  const struct nls_table *nls_codepage,
				  int remap);
extern int CIFSSMBMkDir(const unsigned int xid, struct inode *inode,
			umode_t mode, struct cifs_tcon *tcon,
			const char *name, struct cifs_sb_info *cifs_sb);
extern int CIFSSMBRmDir(const unsigned int xid, struct cifs_tcon *tcon,
			const char *name, struct cifs_sb_info *cifs_sb);
extern int CIFSPOSIXDelFile(const unsigned int xid, struct cifs_tcon *tcon,
			const char *name, __u16 type,
			const struct nls_table *nls_codepage,
			int remap_special_chars);
extern int CIFSSMBDelFile(const unsigned int xid, struct cifs_tcon *tcon,
			  const char *name, struct cifs_sb_info *cifs_sb);
extern int CIFSSMBRename(const unsigned int xid, struct cifs_tcon *tcon,
			 const char *from_name, const char *to_name,
			 struct cifs_sb_info *cifs_sb);
extern int CIFSSMBRenameOpenFile(const unsigned int xid, struct cifs_tcon *tcon,
				 int netfid, const char *target_name,
				 const struct nls_table *nls_codepage,
				 int remap_special_chars);
extern int CIFSSMBRenameOpenFile(const unsigned int xid, struct cifs_tcon *tcon,
				 int netfid, const char *target_name,
				 const struct nls_table *nls_codepage,
				 int remap_special_chars);
extern int CIFSCreateHardLink(const unsigned int xid, struct cifs_tcon *tcon,
			      const char *from_name, const char *to_name,
			      struct cifs_sb_info *cifs_sb);
extern int CIFSUnixCreateHardLink(const unsigned int xid,
			struct cifs_tcon *tcon,
			const char *fromName, const char *toName,
			const struct nls_table *nls_codepage,
			int remap_special_chars);
extern int CIFSUnixCreateSymLink(const unsigned int xid,
			struct cifs_tcon *tcon,
			const char *fromName, const char *toName,
			const struct nls_table *nls_codepage, int remap);
extern int CIFSSMBUnixQuerySymLink(const unsigned int xid,
			struct cifs_tcon *tcon,
			const unsigned char *searchName, char **syminfo,
			const struct nls_table *nls_codepage, int remap);
extern int CIFSSMBQuerySymLink(const unsigned int xid, struct cifs_tcon *tcon,
			       __u16 fid, char **symlinkinfo,
			       const struct nls_table *nls_codepage);
extern int CIFSSMB_set_compression(const unsigned int xid,
				   struct cifs_tcon *tcon, __u16 fid);
extern int CIFS_open(const unsigned int xid, struct cifs_open_parms *oparms,
		     int *oplock, FILE_ALL_INFO *buf);
extern int SMBLegacyOpen(const unsigned int xid, struct cifs_tcon *tcon,
			const char *fileName, const int disposition,
			const int access_flags, const int omode,
			__u16 *netfid, int *pOplock, FILE_ALL_INFO *,
			const struct nls_table *nls_codepage, int remap);
extern int CIFSPOSIXCreate(const unsigned int xid, struct cifs_tcon *tcon,
			u32 posix_flags, __u64 mode, __u16 *netfid,
			FILE_UNIX_BASIC_INFO *pRetData,
			__u32 *pOplock, const char *name,
			const struct nls_table *nls_codepage, int remap);
extern int CIFSSMBClose(const unsigned int xid, struct cifs_tcon *tcon,
			const int smb_file_id);
extern int CIFSSMBFlush(const unsigned int xid, struct cifs_tcon *tcon,
			const int smb_file_id);
extern int CIFSSMBRead(const unsigned int xid, struct cifs_io_parms *io_parms,
			unsigned int *nbytes, char **buf,
			int *return_buf_type);
extern int CIFSSMBWrite(const unsigned int xid, struct cifs_io_parms *io_parms,
			unsigned int *nbytes, const char *buf);
extern int CIFSSMBWrite2(const unsigned int xid, struct cifs_io_parms *io_parms,
			unsigned int *nbytes, struct kvec *iov, const int nvec);
extern int CIFSSMBWrite2(const unsigned int xid, struct cifs_io_parms *io_parms,
			unsigned int *nbytes, struct kvec *iov, const int nvec);
extern int CIFSGetSrvInodeNumber(const unsigned int xid, struct cifs_tcon *tcon,
				 const char *search_name, __u64 *inode_number,
				 const struct nls_table *nls_codepage,
				 int remap);
extern int cifs_lockv(const unsigned int xid, struct cifs_tcon *tcon,
		      const __u16 netfid, const __u8 lock_type,
		      const __u32 num_unlock, const __u32 num_lock,
		      LOCKING_ANDX_RANGE *buf);
extern int CIFSSMBLock(const unsigned int xid, struct cifs_tcon *tcon,
			const __u16 netfid, const __u32 netpid, const __u64 len,
			const __u64 offset, const __u32 numUnlock,
			const __u32 numLock, const __u8 lockType,
			const bool waitFlag, const __u8 oplock_level);
extern int CIFSSMBPosixLock(const unsigned int xid, struct cifs_tcon *tcon,
			const __u16 smb_file_id, const __u32 netpid,
			const loff_t start_offset, const __u64 len,
			struct file_lock *, const __u16 lock_type,
			const bool waitFlag);
extern int CIFSSMBTDis(const unsigned int xid, struct cifs_tcon *tcon);
extern int CIFSSMBEcho(struct TCP_Server_Info *server);
extern int CIFSSMBEcho(struct TCP_Server_Info *server);
extern int CIFSSMBLogoff(const unsigned int xid, struct cifs_ses *ses);
extern int CIFSSMBLogoff(const unsigned int xid, struct cifs_ses *ses);

extern struct cifs_ses *sesInfoAlloc(void);
extern int CIFSSMBCopy(unsigned int xid,
			struct cifs_tcon *source_tcon,
			const char *fromName,
			const __u16 target_tid,
			const char *toName, const int flags,
			const struct nls_table *nls_codepage,
			int remap_special_chars);
extern ssize_t CIFSSMBQAllEAs(const unsigned int xid, struct cifs_tcon *tcon,
			const unsigned char *searchName,
			const unsigned char *ea_name, char *EAData,
			size_t bufsize, struct cifs_sb_info *cifs_sb);
extern int CIFSSMBSetEA(const unsigned int xid, struct cifs_tcon *tcon,
		const char *fileName, const char *ea_name,
		const void *ea_value, const __u16 ea_value_len,
		const struct nls_table *nls_codepage,
		struct cifs_sb_info *cifs_sb);
extern int CIFSSMBGetCIFSACL(const unsigned int xid, struct cifs_tcon *tcon,
			__u16 fid, struct cifs_ntsd **acl_inf, __u32 *buflen);
extern int CIFSSMBSetCIFSACL(const unsigned int, struct cifs_tcon *, __u16,
			struct cifs_ntsd *, __u32, int);
extern int CIFSSMBGetPosixACL(const unsigned int xid, struct cifs_tcon *tcon,
		const unsigned char *searchName,
		char *acl_inf, const int buflen, const int acl_type,
		const struct nls_table *nls_codepage, int remap_special_chars);
extern int CIFSSMBSetPosixACL(const unsigned int xid, struct cifs_tcon *tcon,
		const unsigned char *fileName,
		const char *local_acl, const int buflen, const int acl_type,
		const struct nls_table *nls_codepage, int remap_special_chars);
extern int CIFSGetExtAttr(const unsigned int xid, struct cifs_tcon *tcon,
			const int netfid, __u64 *pExtAttrBits, __u64 *pMask);
extern bool couldbe_mf_symlink(const struct cifs_fattr *fattr);
extern int check_mf_symlink(unsigned int xid, struct cifs_tcon *tcon,
			      struct cifs_sb_info *cifs_sb,
			      struct cifs_fattr *fattr,
			      const unsigned char *path);
extern int check_mf_symlink(unsigned int xid, struct cifs_tcon *tcon,
			      struct cifs_sb_info *cifs_sb,
			      struct cifs_fattr *fattr,
			      const unsigned char *path);
#endif /* _SMB1_PROTO_H */
