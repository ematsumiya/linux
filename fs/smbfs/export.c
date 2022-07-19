// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) International Business Machines Corp., 2007
 * Author(s): Steve French <sfrench@us.ibm.com>
 *
 * Common Internet FileSystem (CIFS) client
 *
 * Operations related to support for exporting files via NFSD
*/

 /*
  * See Documentation/filesystems/nfs/exporting.rst
  * and examples in fs/exportfs
  *
  * Since cifs is a network file system, an "fsid" must be included for
  * any nfs exports file entries which refer to cifs paths.  In addition
  * the cifs mount must be mounted with the "serverino" option (ie use stable
  * server inode numbers instead of locally generated temporary ones).
  * Although cifs inodes do not use generation numbers (have generation number
  * of zero) - the inode number alone should be good enough for simple cases
  * in which users want to export cifs shares with NFS. The decode and encode
  * could be improved by using a new routine which expects 64 bit inode numbers
  * instead of the default 32 bit routines in fs/exportfs
  *
  */

#include <linux/fs.h>
#include <linux/exportfs.h>
#include "defs.h"
#include "debug.h"
#include "smbfs.h"

#ifdef CONFIG_SMBFS_NFSD_EXPORT
static struct dentry *cifs_get_parent(struct dentry *dentry)
{
	/* TODO: need to add code here eventually to enable export via NFSD */
	smbfs_dbg("get parent for 0x%p\n", dentry);
	return ERR_PTR(-EACCES);
}

const struct export_operations cifs_export_ops = {
	.get_parent = cifs_get_parent,
/*	Following five export operations are unneeded so far and can default:
	.get_dentry =
	.get_name =
	.find_exported_dentry =
	.decode_fh =
	.encode_fs =  */
};

#endif /* CONFIG_SMBFS_NFSD_EXPORT */

