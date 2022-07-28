// SPDX-License-Identifier: LGPL-2.1
/*
 *
 *   Copyright (C) International Business Machines  Corp., 2002,2011
 *                 Etersoft, 2012
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *              Pavel Shilovsky (pshilovsky@samba.org) 2012
 *
 */
#include <linux/ctype.h>
#include "globals.h"
#include "prototypes.h"
#include "smb2proto.h"
#include "debug.h"
#include "unicode.h"
#include "status.h"
#include "globals.h"
#include "nterr.h"

/* Note: caller must free return buffer */
__le16 *
cifs_convert_path_to_utf16(const char *from, struct cifs_sb_info *cifs_sb)
{
	int len;
	const char *start_of_path;
	__le16 *to;
	int map_type;

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MAP_SFM_CHR)
		map_type = SFM_MAP_UNI_RSVD;
	else if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MAP_SPECIAL_CHR)
		map_type = SFU_MAP_UNI_RSVD;
	else
		map_type = NO_MAP_UNI_RSVD;

	/* Windows doesn't allow paths beginning with \ */
	if (from[0] == '\\')
		start_of_path = from + 1;

	/* SMB311 POSIX extensions paths do not include leading slash */
	else if (cifs_sb_master_tlink(cifs_sb) &&
		 cifs_sb_master_tcon(cifs_sb)->posix_extensions &&
		 (from[0] == '/')) {
		start_of_path = from + 1;
	} else
		start_of_path = from;

	to = cifs_strndup_to_utf16(start_of_path, PATH_MAX, &len,
				   cifs_sb->local_nls, map_type);
	return to;
}

/**
 * smb311_update_preauth_hash - update @ses hash with the packet data in @iov
 *
 * Assumes @iov does not contain the rfc1002 length and iov[0] has the
 * SMB2 header.
 *
 * @ses:	server session structure
 * @server:	pointer to server info
 * @iov:	array containing the SMB request we will send to the server
 * @nvec:	number of array entries for the iov
 */
int
smb311_update_preauth_hash(struct cifs_ses *ses, struct TCP_Server_Info *server,
			   struct kvec *iov, int nvec)
{
	int i, rc;
	struct sdesc *d;
	struct smb2_hdr *hdr;

	hdr = (struct smb2_hdr *)iov[0].iov_base;
	/* neg prot are always taken */
	if (hdr->Command == SMB2_NEGOTIATE)
		goto ok;

	/*
	 * If we process a command which wasn't a negprot it means the
	 * neg prot was already done, so the server dialect was set
	 * and we can test it. Preauth requires 3.1.1 for now.
	 */
	if (server->dialect != SMB311_PROT_ID)
		return 0;

	if (hdr->Command != SMB2_SESSION_SETUP)
		return 0;

	/* skip last sess setup response */
	if ((hdr->Flags & SMB2_FLAGS_SERVER_TO_REDIR)
	    && (hdr->Status == NT_STATUS_OK
		|| (hdr->Status !=
		    cpu_to_le32(NT_STATUS_MORE_PROCESSING_REQUIRED))))
		return 0;

ok:
	rc = smb311_crypto_shash_allocate(server);
	if (rc)
		return rc;

	d = server->secmech.sdescsha512;
	rc = crypto_shash_init(&d->shash);
	if (rc) {
		cifs_dbg(VFS, "%s: Could not init sha512 shash\n", __func__);
		return rc;
	}

	rc = crypto_shash_update(&d->shash, ses->preauth_sha_hash,
				 SMB2_PREAUTH_HASH_SIZE);
	if (rc) {
		cifs_dbg(VFS, "%s: Could not update sha512 shash\n", __func__);
		return rc;
	}

	for (i = 0; i < nvec; i++) {
		rc = crypto_shash_update(&d->shash,
					 iov[i].iov_base, iov[i].iov_len);
		if (rc) {
			cifs_dbg(VFS, "%s: Could not update sha512 shash\n",
				 __func__);
			return rc;
		}
	}

	rc = crypto_shash_final(&d->shash, ses->preauth_sha_hash);
	if (rc) {
		cifs_dbg(VFS, "%s: Could not finalize sha512 shash\n",
			 __func__);
		return rc;
	}

	return 0;
}
