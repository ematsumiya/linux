/* SPDX-License-Identifier: LGPL-2.1 */
/*
 *   Copyright (c) International Business Machines  Corp., 2009, 2013
 *                 Etersoft, 2012
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *              Pavel Shilovsky (pshilovsky@samba.org) 2012
 */
#ifndef _CIFS_IDMAP_H
#define _CIFS_IDMAP_H

#include <linux/keyctl.h>
#include <linux/key-type.h>
#include <keys/user-type.h>

#define NUM_AUTHS (6)	/* number of authority fields */
#define SID_MAX_SUB_AUTHORITIES (15) /* max number of sub authority fields */

extern const struct cred *root_cred;
extern struct key_type cifs_idmap_key_type;

struct cifs_sid {
	__u8 revision; /* revision level */
	__u8 num_subauth;
	__u8 authority[NUM_AUTHS];
	__le32 sub_auth[SID_MAX_SUB_AUTHORITIES]; /* sub_auth[num_subauth] */
} __attribute__((packed));

/* size of a struct cifs_sid, sans sub_auth array */
#define CIFS_SID_BASE_SIZE (1 + 1 + NUM_AUTHS)

/* security id for everyone/world system group */
static const struct cifs_sid sid_everyone = {
	1, 1, {0, 0, 0, 0, 0, 1}, {0} };
/* security id for Authenticated Users system group */
static const struct cifs_sid sid_authusers = {
	1, 1, {0, 0, 0, 0, 0, 5}, {cpu_to_le32(11)} };

/* S-1-22-1 Unmapped Unix users */
static const struct cifs_sid sid_unix_users = {1, 1, {0, 0, 0, 0, 0, 22},
		{cpu_to_le32(1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-22-2 Unmapped Unix groups */
static const struct cifs_sid sid_unix_groups = { 1, 1, {0, 0, 0, 0, 0, 22},
		{cpu_to_le32(2), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/*
 * See https://technet.microsoft.com/en-us/library/hh509017(v=ws.10).aspx
 */

/* S-1-5-88 MS NFS and Apple style UID/GID/mode */

/* S-1-5-88-1 Unix uid */
static const struct cifs_sid sid_unix_NFS_users = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-5-88-2 Unix gid */
static const struct cifs_sid sid_unix_NFS_groups = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(2), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-5-88-3 Unix mode */
static const struct cifs_sid sid_unix_NFS_mode = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(3), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };
#endif /* _CIFS_IDMAP_H */
