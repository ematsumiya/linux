// SPDX-License-Identifier: LGPL-2.1
/*
 * Directory search handling
 *
 * Copyright (c) International Business Machines Corp., 2004, 2008
 * Copyright (c) Red Hat, Inc., 2011
 * Author(s): Steve French <sfrench@us.ibm.com>
*/
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include "cifspdu.h"
#include "defs.h"
#include "defs.h"
#include "cifs_unicode.h"
#include "debug.h"
#include "cifs_fs_sb.h"
#include "smbfs.h"
#include "smb2proto.h"
#include "fs_context.h"

/*
 * To be safe - for UCS to UTF-8 with strings loaded with the rare long
 * characters alloc more to account for such multibyte target UTF-8
 * characters.
 */
#define UNICODE_NAME_MAX ((4 * NAME_MAX) + 2)

#ifdef CONFIG_SMBFS_DEBUG_EXTRA
static void dump_cifs_file_struct(struct file *file, char *label)
{
	struct smbfs_file_info *cf;

	if (file) {
		cf = file->private_data;
		if (cf == NULL) {
			smbfs_dbg("empty cifs private file data\n");
			return;
		}
		if (cf->is_invalid_handle)
			smbfs_dbg("Invalid handle\n");
		if (cf->srch_inf.is_end)
			smbfs_dbg("end of search\n");
		if (cf->srch_inf.emptyDir)
			smbfs_dbg("empty dir\n");
	}
}
#else
static inline void dump_cifs_file_struct(struct file *file, char *label)
{
}
#endif /* SMBFS_DEBUG_EXTRA */

/*
 * Attempt to preload the dcache with the results from the FIND_FIRST/NEXT
 *
 * Find the dentry that matches "name". If there isn't one, create one. If it's
 * a negative dentry or the id or filetype(mode) changed,
 * then drop it and recreate it.
 */
static void
cifs_prime_dcache(struct dentry *parent, struct qstr *name,
		    struct smbfs_fattr *fattr)
{
	struct dentry *dentry, *alias;
	struct inode *inode;
	struct super_block *sb = parent->d_sb;
	struct cifs_sb_info *cifs_sb = CIFS_SB(sb);
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wq);

	smbfs_dbg("for %s\n", name->name);

	dentry = d_hash_and_lookup(parent, name);
	if (!dentry) {
		/*
		 * If we know that the inode will need to be revalidated
		 * immediately, then don't create a new dentry for it.
		 * We'll end up doing an on the wire call either way and
		 * this spares us an invalidation.
		 */
		if (fattr->flags & SMBFS_FATTR_NEED_REVAL)
			return;
retry:
		dentry = d_alloc_parallel(parent, name, &wq);
	}
	if (IS_ERR(dentry))
		return;
	if (!d_in_lookup(dentry)) {
		inode = d_inode(dentry);
		if (inode) {
			if (d_mountpoint(dentry)) {
				dput(dentry);
				return;
			}
			/*
			 * If we're generating inode numbers, then we don't
			 * want to clobber the existing one with the one that
			 * the readdir code created.
			 */
			if (!(cifs_sb->mnt_cifs_flags & CIFS_MOUNT_SERVER_INUM))
				fattr->id = SMBFS_I(inode)->id;

			/* update inode in place
			 * if both i_ino and i_mode didn't change */
			if (SMBFS_I(inode)->id == fattr->id &&
			    smbfs_fattr_to_inode(inode, fattr) == 0) {
				dput(dentry);
				return;
			}
		}
		d_invalidate(dentry);
		dput(dentry);
		goto retry;
	} else {
		inode = cifs_iget(sb, fattr);
		if (!inode)
			inode = ERR_PTR(-ENOMEM);
		alias = d_splice_alias(inode, dentry);
		d_lookup_done(dentry);
		if (alias && !IS_ERR(alias))
			dput(alias);
	}
	dput(dentry);
}

static bool reparse_file_needs_reval(const struct smbfs_fattr *fattr)
{
	if (!(fattr->smb1_attrs & ATTR_REPARSE))
		return false;
	/*
	 * The DFS tags should be only intepreted by server side as per
	 * MS-FSCC 2.1.2.1, but let's include them anyway.
	 *
	 * Besides, if cf_cifstag is unset (0), then we still need it to be
	 * revalidated to know exactly what reparse point it is.
	 */
	switch (fattr->cifstag) {
	case IO_REPARSE_TAG_DFS:
	case IO_REPARSE_TAG_DFSR:
	case IO_REPARSE_TAG_SYMLINK:
	case IO_REPARSE_TAG_NFS:
	case 0:
		return true;
	}
	return false;
}

static void
cifs_fill_common_info(struct smbfs_fattr *fattr, struct cifs_sb_info *cifs_sb)
{
	fattr->uid = cifs_sb->ctx->linux_uid;
	fattr->gid = cifs_sb->ctx->linux_gid;

	/*
	 * The IO_REPARSE_TAG_LX_ tags originally were used by WSL but they
	 * are preferred by the Linux client in some cases since, unlike
	 * the NFS reparse tag (or EAs), they don't require an extra query
	 * to determine which type of special file they represent.
	 * TODO: go through all documented reparse tags to see if we can
	 * reasonably map some of them to directories vs. files vs. symlinks
	 */
	if (fattr->smb1_attrs & ATTR_DIRECTORY) {
		fattr->mode = S_IFDIR | cifs_sb->ctx->dir_mode;
		fattr->dtype = DT_DIR;
	} else if (fattr->cifstag == IO_REPARSE_TAG_LX_SYMLINK) {
		fattr->mode |= S_IFLNK | cifs_sb->ctx->file_mode;
		fattr->dtype = DT_LNK;
	} else if (fattr->cifstag == IO_REPARSE_TAG_LX_FIFO) {
		fattr->mode |= S_IFIFO | cifs_sb->ctx->file_mode;
		fattr->dtype = DT_FIFO;
	} else if (fattr->cifstag == IO_REPARSE_TAG_AF_UNIX) {
		fattr->mode |= S_IFSOCK | cifs_sb->ctx->file_mode;
		fattr->dtype = DT_SOCK;
	} else if (fattr->cifstag == IO_REPARSE_TAG_LX_CHR) {
		fattr->mode |= S_IFCHR | cifs_sb->ctx->file_mode;
		fattr->dtype = DT_CHR;
	} else if (fattr->cifstag == IO_REPARSE_TAG_LX_BLK) {
		fattr->mode |= S_IFBLK | cifs_sb->ctx->file_mode;
		fattr->dtype = DT_BLK;
	} else { /* TODO: should we mark some other reparse points (like DFSR) as directories? */
		fattr->mode = S_IFREG | cifs_sb->ctx->file_mode;
		fattr->dtype = DT_REG;
	}

	/*
	 * We need to revalidate it further to make a decision about whether it
	 * is a symbolic link, DFS referral or a reparse point with a direct
	 * access like junctions, deduplicated files, NFS symlinks.
	 */
	if (reparse_file_needs_reval(fattr))
		fattr->flags |= SMBFS_FATTR_NEED_REVAL;

	/* non-unix readdir doesn't provide nlink */
	fattr->flags |= SMBFS_FATTR_UNKNOWN_NLINK;

	if (fattr->smb1_attrs & ATTR_READONLY)
		fattr->mode &= ~S_IWUGO;

	/*
	 * We of course don't get ACL info in FIND_FIRST/NEXT results, so
	 * mark it for revalidation so that "ls -l" will look right. It might
	 * be super-slow, but if we don't do this then the ownership of files
	 * may look wrong since the inodes may not have timed out by the time
	 * "ls" does a stat() call on them.
	 */
	if ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_CIFS_ACL) ||
	    (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MODE_FROM_SID))
		fattr->flags |= SMBFS_FATTR_NEED_REVAL;

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_UNX_EMUL &&
	    fattr->smb1_attrs & ATTR_SYSTEM) {
		if (fattr->eof == 0)  {
			fattr->mode &= ~S_IFMT;
			fattr->mode |= S_IFIFO;
			fattr->dtype = DT_FIFO;
		} else {
			/*
			 * trying to get the type and mode via SFU can be slow,
			 * so just call those regular files for now, and mark
			 * for reval
			 */
			fattr->flags |= SMBFS_FATTR_NEED_REVAL;
		}
	}
}

/* Fill a smbfs_fattr struct with info from SMB_FIND_FILE_POSIX_INFO. */
static void
cifs_posix_to_fattr(struct smbfs_fattr *fattr, struct smb2_posix_info *info,
		    struct cifs_sb_info *cifs_sb)
{
	struct smb2_posix_info_parsed parsed;

	posix_info_parse(info, NULL, &parsed);

	memset(fattr, 0, sizeof(*fattr));
	fattr->id = le64_to_cpu(info->Inode);
	fattr->bytes = le64_to_cpu(info->AllocationSize);
	fattr->eof = le64_to_cpu(info->EndOfFile);

	fattr->atime = cifs_NTtimeToUnix(info->LastAccessTime);
	fattr->mtime = cifs_NTtimeToUnix(info->LastWriteTime);
	fattr->ctime = cifs_NTtimeToUnix(info->CreationTime);

	fattr->nlink = le32_to_cpu(info->HardLinks);
	fattr->smb1_attrs = le32_to_cpu(info->DosAttributes);

	/*
	 * Since we set the inode type below we need to mask off
	 * to avoid strange results if bits set above.
	 * XXX: why not make server&client use the type bits?
	 */
	fattr->mode = le32_to_cpu(info->Mode) & ~S_IFMT;

	smbfs_dbg("posix fattr: dev %d, reparse %d, mode %o\n",
		 le32_to_cpu(info->DeviceId),
		 le32_to_cpu(info->ReparseTag),
		 le32_to_cpu(info->Mode));

	if (fattr->smb1_attrs & ATTR_DIRECTORY) {
		fattr->mode |= S_IFDIR;
		fattr->dtype = DT_DIR;
	} else {
		/*
		 * mark anything that is not a dir as regular
		 * file. special files should have the REPARSE
		 * attribute and will be marked as needing revaluation
		 */
		fattr->mode |= S_IFREG;
		fattr->dtype = DT_REG;
	}

	if (reparse_file_needs_reval(fattr))
		fattr->flags |= SMBFS_FATTR_NEED_REVAL;

	sid_to_id(cifs_sb, &parsed.owner, fattr, SIDOWNER);
	sid_to_id(cifs_sb, &parsed.group, fattr, SIDGROUP);
}

static void __dir_info_to_fattr(struct smbfs_fattr *fattr, const void *info)
{
	const FILE_DIRECTORY_INFO *fi = info;

	memset(fattr, 0, sizeof(*fattr));
	fattr->smb1_attrs = le32_to_cpu(fi->ExtFileAttributes);
	fattr->eof = le64_to_cpu(fi->EndOfFile);
	fattr->bytes = le64_to_cpu(fi->AllocationSize);
	fattr->createtime = le64_to_cpu(fi->CreationTime);
	fattr->atime = cifs_NTtimeToUnix(fi->LastAccessTime);
	fattr->ctime = cifs_NTtimeToUnix(fi->ChangeTime);
	fattr->mtime = cifs_NTtimeToUnix(fi->LastWriteTime);
}

void
cifs_dir_info_to_fattr(struct smbfs_fattr *fattr, FILE_DIRECTORY_INFO *info,
		       struct cifs_sb_info *cifs_sb)
{
	__dir_info_to_fattr(fattr, info);
	cifs_fill_common_info(fattr, cifs_sb);
}

static void cifs_fulldir_info_to_fattr(struct smbfs_fattr *fattr,
				       SEARCH_ID_FULL_DIR_INFO *info,
				       struct cifs_sb_info *cifs_sb)
{
	__dir_info_to_fattr(fattr, info);

	/* See MS-FSCC 2.4.19 FileIdFullDirectoryInformation */
	if (fattr->smb1_attrs & ATTR_REPARSE)
		fattr->cifstag = le32_to_cpu(info->EaSize);
	cifs_fill_common_info(fattr, cifs_sb);
}

static void
cifs_std_info_to_fattr(struct smbfs_fattr *fattr, FIND_FILE_STANDARD_INFO *info,
		       struct cifs_sb_info *cifs_sb)
{
	int offset = smbfs_sb_master_tcon(cifs_sb)->ses->server->time_adjust;

	memset(fattr, 0, sizeof(*fattr));
	fattr->atime = cnvrtDosUnixTm(info->LastAccessDate,
					    info->LastAccessTime, offset);
	fattr->ctime = cnvrtDosUnixTm(info->LastWriteDate,
					    info->LastWriteTime, offset);
	fattr->mtime = cnvrtDosUnixTm(info->LastWriteDate,
					    info->LastWriteTime, offset);

	fattr->smb1_attrs = le16_to_cpu(info->Attributes);
	fattr->bytes = le32_to_cpu(info->AllocationSize);
	fattr->eof = le32_to_cpu(info->DataSize);

	cifs_fill_common_info(fattr, cifs_sb);
}

/* TODO: eventually need to add the following helper function to
      resolve NT_STATUS_STOPPED_ON_SYMLINK return code when
      we try to do FindFirst on (NTFS) directory symlinks */
/*
int get_symlink_reparse_path(char *full_path, struct cifs_sb_info *cifs_sb,
			     unsigned int xid)
*/

static int
_initiate_cifs_search(const unsigned int xid, struct file *file,
		     const char *full_path)
{
	__u16 search_flags;
	int rc = 0;
	struct smbfs_file_info *cifsFile;
	struct cifs_sb_info *cifs_sb = CIFS_FILE_SB(file);
	struct smbfs_tcon_link *tlink = NULL;
	struct smbfs_tcon *tcon;
	struct smbfs_server_info *server;

	if (file->private_data == NULL) {
		tlink = smbfs_sb_tlink(cifs_sb);
		if (IS_ERR(tlink))
			return PTR_ERR(tlink);

		cifsFile = kzalloc(sizeof(struct smbfs_file_info), GFP_KERNEL);
		if (cifsFile == NULL) {
			rc = -ENOMEM;
			goto error_exit;
		}
		spin_lock_init(&cifsFile->file_info_lock);
		file->private_data = cifsFile;
		cifsFile->tlink = cifs_get_tlink(tlink);
		tcon = tlink_tcon(tlink);
	} else {
		cifsFile = file->private_data;
		tcon = tlink_tcon(cifsFile->tlink);
	}

	server = tcon->ses->server;

	if (!server->ops->query_dir_first) {
		rc = -ENOSYS;
		goto error_exit;
	}

	cifsFile->is_invalid_handle = true;
	cifsFile->srch_inf.is_end = false;

	smbfs_dbg("Full path: %s start at: %lld\n", full_path, file->f_pos);

ffirst_retry:
	/* test for Unix extensions */
	/* but now check for them on the share/mount not on the SMB session */
	if (get_tcon_flag(tcon, USE_UNIX_EXT))
		cifsFile->srch_inf.info_level = SMB_FIND_FILE_UNIX;
	else if (get_tcon_flag(tcon, USE_POSIX_EXT))
		cifsFile->srch_inf.info_level = SMB_FIND_FILE_POSIX_INFO;
	else if ((tcon->ses->capabilities &
		  tcon->ses->server->settings->cap_nt_find) == 0) {
		cifsFile->srch_inf.info_level = SMB_FIND_FILE_INFO_STANDARD;
	} else if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_SERVER_INUM) {
		cifsFile->srch_inf.info_level = SMB_FIND_FILE_ID_FULL_DIR_INFO;
	} else /* not srvinos - FIXME: add check for backlevel? */ {
		cifsFile->srch_inf.info_level = SMB_FIND_FILE_DIRECTORY_INFO;
	}

	search_flags = CIFS_SEARCH_CLOSE_AT_END | CIFS_SEARCH_RETURN_RESUME;
	if (backup_cred(cifs_sb))
		search_flags |= CIFS_SEARCH_BACKUP_SEARCH;

	rc = server->ops->query_dir_first(xid, tcon, full_path, cifs_sb,
					  &cifsFile->fid, search_flags,
					  &cifsFile->srch_inf);

	if (rc == 0)
		cifsFile->is_invalid_handle = false;
	/* TODO: call get_symlink_reparse_path and retry with new path */
	else if ((rc == -EOPNOTSUPP) &&
		(cifs_sb->mnt_cifs_flags & CIFS_MOUNT_SERVER_INUM)) {
		cifs_sb->mnt_cifs_flags &= ~CIFS_MOUNT_SERVER_INUM;
		goto ffirst_retry;
	}
error_exit:
	smbfs_put_tlink(tlink);
	return rc;
}

static int
initiate_cifs_search(const unsigned int xid, struct file *file,
		     const char *full_path)
{
	int rc, retry_count = 0;

	do {
		rc = _initiate_cifs_search(xid, file, full_path);
		/*
		 * If we don't have enough credits to start reading the
		 * directory just try again after short wait.
		 */
		if (rc != -EDEADLK)
			break;

		usleep_range(512, 2048);
	} while (retry_count++ < 5);

	return rc;
}

/* return length of unicode string in bytes */
static int cifs_unicode_bytelen(const char *str)
{
	int len;
	const __le16 *ustr = (const __le16 *)str;

	for (len = 0; len <= PATH_MAX; len++) {
		if (ustr[len] == 0)
			return len << 1;
	}
	smbfs_dbg("Unicode string longer than PATH_MAX found\n");
	return len << 1;
}

static char *nxt_dir_entry(char *old_entry, char *end_of_smb, int level)
{
	char *new_entry;
	FILE_DIRECTORY_INFO *pDirInfo = (FILE_DIRECTORY_INFO *)old_entry;

	if (level == SMB_FIND_FILE_INFO_STANDARD) {
		FIND_FILE_STANDARD_INFO *pfData;
		pfData = (FIND_FILE_STANDARD_INFO *)pDirInfo;

		new_entry = old_entry + sizeof(FIND_FILE_STANDARD_INFO) +
				pfData->FileNameLength;
	} else {
		u32 next_offset = le32_to_cpu(pDirInfo->NextEntryOffset);

		if (old_entry + next_offset < old_entry) {
			smbfs_log("Invalid offset %u\n", next_offset);
			return NULL;
		}
		new_entry = old_entry + next_offset;
	}
	smbfs_dbg("new entry 0x%p, old entry 0x%p\n", new_entry, old_entry);
	/* validate that new_entry is not past end of SMB */
	if (new_entry >= end_of_smb) {
		smbfs_log("search entry 0x%p began after end of SMB 0x%p, old entry 0x%p\n",
			  new_entry, end_of_smb, old_entry);
		return NULL;
	} else if (((level == SMB_FIND_FILE_INFO_STANDARD) && (new_entry + sizeof(FIND_FILE_STANDARD_INFO) > end_of_smb)) ||
		    ((level != SMB_FIND_FILE_INFO_STANDARD) && (new_entry + sizeof(FILE_DIRECTORY_INFO) > end_of_smb)))  {
		smbfs_log("search entry 0x%p extends after end of SMB 0x%p\n",
			  new_entry, end_of_smb);
		return NULL;
	} else
		return new_entry;

}

struct cifs_dirent {
	const char	*name;
	size_t		namelen;
	u32		resume_key;
	u64		ino;
};

static void cifs_fill_dirent_posix(struct cifs_dirent *de,
				   const struct smb2_posix_info *info)
{
	struct smb2_posix_info_parsed parsed;

	/* payload should have already been checked at this point */
	if (posix_info_parse(info, NULL, &parsed) < 0) {
		smbfs_log("Invalid POSIX info payload\n");
		return;
	}

	de->name = parsed.name;
	de->namelen = parsed.name_len;
	de->resume_key = info->Ignored;
	de->ino = le64_to_cpu(info->Inode);
}

static void cifs_fill_dirent_unix(struct cifs_dirent *de,
		const FILE_UNIX_INFO *info, bool is_unicode)
{
	de->name = &info->FileName[0];
	if (is_unicode)
		de->namelen = cifs_unicode_bytelen(de->name);
	else
		de->namelen = strnlen(de->name, PATH_MAX);
	de->resume_key = info->ResumeKey;
	de->ino = le64_to_cpu(info->basic.UniqueId);
}

static void cifs_fill_dirent_dir(struct cifs_dirent *de,
		const FILE_DIRECTORY_INFO *info)
{
	de->name = &info->FileName[0];
	de->namelen = le32_to_cpu(info->FileNameLength);
	de->resume_key = info->FileIndex;
}

static void cifs_fill_dirent_full(struct cifs_dirent *de,
		const FILE_FULL_DIRECTORY_INFO *info)
{
	de->name = &info->FileName[0];
	de->namelen = le32_to_cpu(info->FileNameLength);
	de->resume_key = info->FileIndex;
}

static void cifs_fill_dirent_search(struct cifs_dirent *de,
		const SEARCH_ID_FULL_DIR_INFO *info)
{
	de->name = &info->FileName[0];
	de->namelen = le32_to_cpu(info->FileNameLength);
	de->resume_key = info->FileIndex;
	de->ino = le64_to_cpu(info->UniqueId);
}

static void cifs_fill_dirent_both(struct cifs_dirent *de,
		const FILE_BOTH_DIRECTORY_INFO *info)
{
	de->name = &info->FileName[0];
	de->namelen = le32_to_cpu(info->FileNameLength);
	de->resume_key = info->FileIndex;
}

static void cifs_fill_dirent_std(struct cifs_dirent *de,
		const FIND_FILE_STANDARD_INFO *info)
{
	de->name = &info->FileName[0];
	/* one byte length, no endianess conversion */
	de->namelen = info->FileNameLength;
	de->resume_key = info->ResumeKey;
}

static int cifs_fill_dirent(struct cifs_dirent *de, const void *info,
		u16 level, bool is_unicode)
{
	memset(de, 0, sizeof(*de));

	switch (level) {
	case SMB_FIND_FILE_POSIX_INFO:
		cifs_fill_dirent_posix(de, info);
		break;
	case SMB_FIND_FILE_UNIX:
		cifs_fill_dirent_unix(de, info, is_unicode);
		break;
	case SMB_FIND_FILE_DIRECTORY_INFO:
		cifs_fill_dirent_dir(de, info);
		break;
	case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
		cifs_fill_dirent_full(de, info);
		break;
	case SMB_FIND_FILE_ID_FULL_DIR_INFO:
		cifs_fill_dirent_search(de, info);
		break;
	case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
		cifs_fill_dirent_both(de, info);
		break;
	case SMB_FIND_FILE_INFO_STANDARD:
		cifs_fill_dirent_std(de, info);
		break;
	default:
		smbfs_dbg("Unknown findfirst level %d\n", level);
		return -EINVAL;
	}

	return 0;
}

#define UNICODE_DOT cpu_to_le16(0x2e)

/* return 0 if no match and 1 for . (current directory) and 2 for .. (parent) */
static int cifs_entry_is_dot(struct cifs_dirent *de, bool is_unicode)
{
	int rc = 0;

	if (!de->name)
		return 0;

	if (is_unicode) {
		__le16 *ufilename = (__le16 *)de->name;
		if (de->namelen == 2) {
			/* check for . */
			if (ufilename[0] == UNICODE_DOT)
				rc = 1;
		} else if (de->namelen == 4) {
			/* check for .. */
			if (ufilename[0] == UNICODE_DOT &&
			    ufilename[1] == UNICODE_DOT)
				rc = 2;
		}
	} else /* ASCII */ {
		if (de->namelen == 1) {
			if (de->name[0] == '.')
				rc = 1;
		} else if (de->namelen == 2) {
			if (de->name[0] == '.' && de->name[1] == '.')
				rc = 2;
		}
	}

	return rc;
}

/* Check if directory that we are searching has changed so we can decide
   whether we can use the cached search results from the previous search */
static int is_dir_changed(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct smbfs_inode_info *cifsInfo = SMBFS_I(inode);

	if (cifsInfo->time == 0)
		return 1; /* directory was changed, perhaps due to unlink */
	else
		return 0;

}

static int cifs_save_resume_key(const char *current_entry,
	struct smbfs_file_info *file_info)
{
	struct cifs_dirent de;
	int rc;

	rc = cifs_fill_dirent(&de, current_entry, file_info->srch_inf.info_level,
			      file_info->srch_inf.unicode);
	if (!rc) {
		file_info->srch_inf.presume_name = de.name;
		file_info->srch_inf.resume_name_len = de.namelen;
		file_info->srch_inf.resume_key = de.resume_key;
	}
	return rc;
}

/*
 * Find the corresponding entry in the search. Note that the SMB server returns
 * search entries for . and .. which complicates logic here if we choose to
 * parse for them and we do not assume that they are located in the findfirst
 * return buffer. We start counting in the buffer with entry 2 and increment for
 * every entry (do not increment for . or .. entry).
 */
static int
find_cifs_entry(const unsigned int xid, struct smbfs_tcon *tcon, loff_t pos,
		struct file *file, const char *full_path,
		char **current_entry, int *num_to_ret)
{
	__u16 search_flags;
	int rc = 0;
	int pos_in_buf = 0;
	loff_t first_entry_in_buffer;
	loff_t index_to_find = pos;
	struct smbfs_file_info *smb_f = file->private_data;
	struct cifs_sb_info *cifs_sb = CIFS_FILE_SB(file);
	struct smbfs_server_info *server = tcon->ses->server;
	/* check if index in the buffer */

	if (!server->ops->query_dir_first || !server->ops->query_dir_next)
		return -ENOSYS;

	if ((smb_f == NULL) || (current_entry == NULL) || (num_to_ret == NULL))
		return -ENOENT;

	*current_entry = NULL;
	first_entry_in_buffer = smb_f->srch_inf.index_of_last_entry -
					smb_f->srch_inf.entries_in_buffer;

	/*
	 * If first entry in buf is zero then is first buffer
	 * in search response data which means it is likely . and ..
	 * will be in this buffer, although some servers do not return
	 * . and .. for the root of a drive and for those we need
	 * to start two entries earlier.
	 */

	dump_cifs_file_struct(file, "In fce ");
	if (((index_to_find < smb_f->srch_inf.index_of_last_entry) &&
	     is_dir_changed(file)) || (index_to_find < first_entry_in_buffer)) {
		/* close and restart search */
		smbfs_dbg("search backing up - close and restart search\n");
		spin_lock(&smb_f->file_info_lock);
		if (server->ops->dir_needs_close(smb_f)) {
			smb_f->is_invalid_handle = true;
			spin_unlock(&smb_f->file_info_lock);
			if (server->ops->close_dir)
				server->ops->close_dir(xid, tcon, &smb_f->fid);
		} else
			spin_unlock(&smb_f->file_info_lock);
		if (smb_f->srch_inf.network_buf_start) {
			smbfs_dbg("freeing SMB ff cache buf on search rewind\n");
			if (smb_f->srch_inf.smallBuf)
				cifs_small_buf_release(smb_f->srch_inf.
						network_buf_start);
			else
				cifs_buf_release(smb_f->srch_inf.
						network_buf_start);
			smb_f->srch_inf.network_buf_start = NULL;
		}
		rc = initiate_cifs_search(xid, file, full_path);
		if (rc) {
			smbfs_dbg("error %d reinitiating a search on rewind\n",
				 rc);
			return rc;
		}
		/* FindFirst/Next set last_entry to NULL on malformed reply */
		if (smb_f->srch_inf.last_entry)
			cifs_save_resume_key(smb_f->srch_inf.last_entry, smb_f);
	}

	search_flags = CIFS_SEARCH_CLOSE_AT_END | CIFS_SEARCH_RETURN_RESUME;
	if (backup_cred(cifs_sb))
		search_flags |= CIFS_SEARCH_BACKUP_SEARCH;

	while ((index_to_find >= smb_f->srch_inf.index_of_last_entry) &&
	       (rc == 0) && !smb_f->srch_inf.is_end) {
		smbfs_dbg("calling findnext2\n");
		rc = server->ops->query_dir_next(xid, tcon, &smb_f->fid,
						 search_flags,
						 &smb_f->srch_inf);
		/* FindFirst/Next set last_entry to NULL on malformed reply */
		if (smb_f->srch_inf.last_entry)
			cifs_save_resume_key(smb_f->srch_inf.last_entry, smb_f);
		if (rc)
			return -ENOENT;
	}
	if (index_to_find < smb_f->srch_inf.index_of_last_entry) {
		/* we found the buffer that contains the entry */
		/* scan and find it */
		int i;
		char *cur_ent;
		char *end_of_smb;

		if (smb_f->srch_inf.network_buf_start == NULL) {
			smbfs_log("network_buf_start is NULL during readdir\n");
			return -EIO;
		}

		end_of_smb = smb_f->srch_inf.network_buf_start +
			server->ops->calc_smb_size(
					smb_f->srch_inf.network_buf_start,
					server);

		cur_ent = smb_f->srch_inf.search_entries_start;
		first_entry_in_buffer = smb_f->srch_inf.index_of_last_entry
					- smb_f->srch_inf.entries_in_buffer;
		pos_in_buf = index_to_find - first_entry_in_buffer;
		smbfs_dbg("found entry - pos_in_buf %d\n", pos_in_buf);

		for (i = 0; (i < (pos_in_buf)) && (cur_ent != NULL); i++) {
			/* go entry by entry figuring out which is first */
			cur_ent = nxt_dir_entry(cur_ent, end_of_smb,
						smb_f->srch_inf.info_level);
		}
		if ((cur_ent == NULL) && (i < pos_in_buf)) {
			/* TODO: fixme - check if we should flag this error */
			smbfs_log("reached end of buf searching for pos in buf %d index to find %lld rc %d\n",
				 pos_in_buf, index_to_find, rc);
		}
		rc = 0;
		*current_entry = cur_ent;
	} else {
		smbfs_dbg("index not in buffer - could not findnext into it\n");
		return 0;
	}

	if (pos_in_buf >= smb_f->srch_inf.entries_in_buffer) {
		smbfs_dbg("can not return entries pos_in_buf beyond last\n");
		*num_to_ret = 0;
	} else
		*num_to_ret = smb_f->srch_inf.entries_in_buffer - pos_in_buf;

	return rc;
}

static bool emit_cached_dirents(struct cached_dirents *cde,
				struct dir_context *ctx)
{
	struct cached_dirent *dirent;
	int rc;

	list_for_each_entry(dirent, &cde->entries, entry) {
		if (ctx->pos >= dirent->pos)
			continue;
		ctx->pos = dirent->pos;
		rc = dir_emit(ctx, dirent->name, dirent->namelen,
			      dirent->fattr.id,
			      dirent->fattr.dtype);
		if (!rc)
			return rc;
	}
	return true;
}

static void update_cached_dirents_count(struct cached_dirents *cde,
					struct dir_context *ctx)
{
	if (cde->ctx != ctx)
		return;
	if (cde->is_valid || cde->is_failed)
		return;

	cde->pos++;
}

static void finished_cached_dirents_count(struct cached_dirents *cde,
					struct dir_context *ctx)
{
	if (cde->ctx != ctx)
		return;
	if (cde->is_valid || cde->is_failed)
		return;
	if (ctx->pos != cde->pos)
		return;

	cde->is_valid = 1;
}

static void add_cached_dirent(struct cached_dirents *cde,
			      struct dir_context *ctx,
			      const char *name, int namelen,
			      struct smbfs_fattr *fattr)
{
	struct cached_dirent *de;

	if (cde->ctx != ctx)
		return;
	if (cde->is_valid || cde->is_failed)
		return;
	if (ctx->pos != cde->pos) {
		cde->is_failed = 1;
		return;
	}
	de = kzalloc(sizeof(*de), GFP_ATOMIC);
	if (de == NULL) {
		cde->is_failed = 1;
		return;
	}
	de->namelen = namelen;
	de->name = kstrndup(name, namelen, GFP_ATOMIC);
	if (de->name == NULL) {
		kfree(de);
		cde->is_failed = 1;
		return;
	}
	de->pos = ctx->pos;

	memcpy(&de->fattr, fattr, sizeof(struct smbfs_fattr));

	list_add_tail(&de->entry, &cde->entries);
}

static bool cifs_dir_emit(struct dir_context *ctx,
			  const char *name, int namelen,
			  struct smbfs_fattr *fattr,
			  struct smbfs_cached_fid *cfid)
{
	bool rc;
	ino_t ino = cifs_id_to_ino_t(fattr->id);

	rc = dir_emit(ctx, name, namelen, ino, fattr->dtype);
	if (!rc)
		return rc;

	if (cfid) {
		mutex_lock(&cfid->dir_entries.lock);
		add_cached_dirent(&cfid->dir_entries, ctx, name, namelen,
				  fattr);
		mutex_unlock(&cfid->dir_entries.lock);
	}

	return rc;
}

static int cifs_filldir(char *find_entry, struct file *file,
			struct dir_context *ctx,
			char *scratch_buf, unsigned int max_len,
			struct smbfs_cached_fid *cfid)
{
	struct smbfs_file_info *file_info = file->private_data;
	struct super_block *sb = file_inode(file)->i_sb;
	struct cifs_sb_info *cifs_sb = CIFS_SB(sb);
	struct cifs_dirent de = { NULL, };
	struct smbfs_fattr fattr;
	struct qstr name;
	int rc = 0;

	rc = cifs_fill_dirent(&de, find_entry, file_info->srch_inf.info_level,
			      file_info->srch_inf.unicode);
	if (rc)
		return rc;

	if (de.namelen > max_len) {
		smbfs_log("bad search response length %zd past smb end\n",
			 de.namelen);
		return -EINVAL;
	}

	/* skip . and .. since we added them first */
	if (cifs_entry_is_dot(&de, file_info->srch_inf.unicode))
		return 0;

	if (file_info->srch_inf.unicode) {
		struct nls_table *nlt = cifs_sb->local_nls;
		int map_type;

		map_type = cifs_remap(cifs_sb);
		name.name = scratch_buf;
		name.len =
			cifs_from_utf16((char *)name.name, (__le16 *)de.name,
					UNICODE_NAME_MAX,
					min_t(size_t, de.namelen,
					      (size_t)max_len), nlt, map_type);
		name.len -= nls_nullsize(nlt);
	} else {
		name.name = de.name;
		name.len = de.namelen;
	}

	switch (file_info->srch_inf.info_level) {
	case SMB_FIND_FILE_POSIX_INFO:
		cifs_posix_to_fattr(&fattr,
				    (struct smb2_posix_info *)find_entry,
				    cifs_sb);
		break;
	case SMB_FIND_FILE_UNIX:
		cifs_unix_basic_to_fattr(&fattr,
					 &((FILE_UNIX_INFO *)find_entry)->basic,
					 cifs_sb);
		break;
	case SMB_FIND_FILE_INFO_STANDARD:
		cifs_std_info_to_fattr(&fattr,
				       (FIND_FILE_STANDARD_INFO *)find_entry,
				       cifs_sb);
		break;
	case SMB_FIND_FILE_ID_FULL_DIR_INFO:
		cifs_fulldir_info_to_fattr(&fattr,
					   (SEARCH_ID_FULL_DIR_INFO *)find_entry,
					   cifs_sb);
		break;
	default:
		cifs_dir_info_to_fattr(&fattr,
				       (FILE_DIRECTORY_INFO *)find_entry,
				       cifs_sb);
		break;
	}

	if (de.ino && (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_SERVER_INUM)) {
		fattr.id = de.ino;
	} else {
		fattr.id = iunique(sb, ROOT_I);
		cifs_autodisable_serverino(cifs_sb);
	}

	if ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MF_SYMLINKS) &&
	    couldbe_mf_symlink(&fattr))
		/*
		 * trying to get the type and mode can be slow,
		 * so just call those regular files for now, and mark
		 * for reval
		 */
		fattr.flags |= SMBFS_FATTR_NEED_REVAL;

	cifs_prime_dcache(file_dentry(file), &name, &fattr);

	return !cifs_dir_emit(ctx, name.name, name.len,
			      &fattr, cfid);
}


int cifs_readdir(struct file *file, struct dir_context *ctx)
{
	int rc = 0;
	unsigned int xid;
	int i;
	struct smbfs_tcon_link *tlink = NULL;
	struct smbfs_tcon *tcon;
	struct smbfs_file_info *cifsFile;
	char *current_entry;
	int num_to_fill = 0;
	char *tmp_buf = NULL;
	char *end_of_smb;
	unsigned int max_len;
	const char *full_path;
	void *page = alloc_dentry_path();
	struct smbfs_cached_fid *cfid = NULL;
	struct cifs_sb_info *cifs_sb = CIFS_FILE_SB(file);

	xid = get_xid();

	full_path = build_path_from_dentry(file_dentry(file), page);
	if (IS_ERR(full_path)) {
		rc = PTR_ERR(full_path);
		goto rddir2_exit;
	}

	if (file->private_data == NULL) {
		tlink = smbfs_sb_tlink(cifs_sb);
		if (IS_ERR(tlink))
			goto cache_not_found;
		tcon = tlink_tcon(tlink);
	} else {
		cifsFile = file->private_data;
		tcon = tlink_tcon(cifsFile->tlink);
	}

	rc = open_cached_dir(xid, tcon, full_path, cifs_sb, &cfid);
	smbfs_put_tlink(tlink);
	if (rc)
		goto cache_not_found;

	mutex_lock(&cfid->dir_entries.lock);
	/*
	 * If this was reading from the start of the directory
	 * we need to initialize scanning and storing the
	 * directory content.
	 */
	if (ctx->pos == 0 && cfid->dir_entries.ctx == NULL) {
		cfid->dir_entries.ctx = ctx;
		cfid->dir_entries.pos = 2;
	}
	/*
	 * If we already have the entire directory cached then
	 * we can just serve the cache.
	 */
	if (cfid->dir_entries.is_valid) {
		if (!dir_emit_dots(file, ctx)) {
			mutex_unlock(&cfid->dir_entries.lock);
			goto rddir2_exit;
		}
		emit_cached_dirents(&cfid->dir_entries, ctx);
		mutex_unlock(&cfid->dir_entries.lock);
		goto rddir2_exit;
	}
	mutex_unlock(&cfid->dir_entries.lock);

	/* Drop the cache while calling initiate_cifs_search and
	 * find_cifs_entry in case there will be reconnects during
	 * query_directory.
	 */
	close_cached_dir(cfid);
	cfid = NULL;

 cache_not_found:
	/*
	 * Ensure FindFirst doesn't fail before doing filldir() for '.' and
	 * '..'. Otherwise we won't be able to notify VFS in case of failure.
	 */
	if (file->private_data == NULL) {
		rc = initiate_cifs_search(xid, file, full_path);
		smbfs_dbg("initiate cifs search rc %d\n", rc);
		if (rc)
			goto rddir2_exit;
	}

	if (!dir_emit_dots(file, ctx))
		goto rddir2_exit;

	/* 1) If search is active,
		is in current search buffer?
		if it before then restart search
		if after then keep searching till find it */
	cifsFile = file->private_data;
	if (cifsFile->srch_inf.is_end) {
		if (cifsFile->srch_inf.emptyDir) {
			smbfs_dbg("End of search, empty dir\n");
			rc = 0;
			goto rddir2_exit;
		}
	} /* else {
		cifsFile->is_invalid_handle = true;
		tcon->ses->server->close(xid, tcon, &cifsFile->fid);
	} */

	tcon = tlink_tcon(cifsFile->tlink);
	rc = find_cifs_entry(xid, tcon, ctx->pos, file, full_path,
			     &current_entry, &num_to_fill);
	open_cached_dir(xid, tcon, full_path, cifs_sb, &cfid);
	if (rc) {
		smbfs_dbg("fce error %d\n", rc);
		goto rddir2_exit;
	} else if (current_entry != NULL) {
		smbfs_dbg("entry %lld found\n", ctx->pos);
	} else {
		if (cfid) {
			mutex_lock(&cfid->dir_entries.lock);
			finished_cached_dirents_count(&cfid->dir_entries, ctx);
			mutex_unlock(&cfid->dir_entries.lock);
		}
		smbfs_dbg("Could not find entry\n");
		goto rddir2_exit;
	}
	smbfs_dbg("loop through %d times filling dir for net buf 0x%p\n",
		 num_to_fill, cifsFile->srch_inf.network_buf_start);
	max_len = tcon->ses->server->ops->calc_smb_size(
			cifsFile->srch_inf.network_buf_start,
			tcon->ses->server);
	end_of_smb = cifsFile->srch_inf.network_buf_start + max_len;

	tmp_buf = kmalloc(UNICODE_NAME_MAX, GFP_KERNEL);
	if (tmp_buf == NULL) {
		rc = -ENOMEM;
		goto rddir2_exit;
	}

	for (i = 0; i < num_to_fill; i++) {
		if (current_entry == NULL) {
			/* evaluate whether this case is an error */
			smbfs_log("past SMB end,  num to fill %d i %d\n",
				 num_to_fill, i);
			break;
		}
		/*
		 * if buggy server returns . and .. late do we want to
		 * check for that here?
		 */
		*tmp_buf = 0;
		rc = cifs_filldir(current_entry, file, ctx,
				  tmp_buf, max_len, cfid);
		if (rc) {
			if (rc > 0)
				rc = 0;
			break;
		}

		ctx->pos++;
		if (cfid) {
			mutex_lock(&cfid->dir_entries.lock);
			update_cached_dirents_count(&cfid->dir_entries, ctx);
			mutex_unlock(&cfid->dir_entries.lock);
		}

		if (ctx->pos ==
			cifsFile->srch_inf.index_of_last_entry) {
			smbfs_dbg("last entry in buf at pos %lld %s\n",
				 ctx->pos, tmp_buf);
			cifs_save_resume_key(current_entry, cifsFile);
			break;
		} else
			current_entry =
				nxt_dir_entry(current_entry, end_of_smb,
					cifsFile->srch_inf.info_level);
	}
	kfree(tmp_buf);

rddir2_exit:
	if (cfid)
		close_cached_dir(cfid);
	free_dentry_path(page);
	free_xid(xid);
	return rc;
}
