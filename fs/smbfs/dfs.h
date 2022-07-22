// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) SUSE LLC, 2022
 *
 * Author(s): Enzo Matsumiya <ematsumiya@suse.de>
 *
 * SMBFS DFS structures and helpers.
*/
#ifndef _SMBFS_DFS_H
#define _SMBFS_DFS_H

#include "tcon.h"
#include "server_info.h"
#include "ses.h"

struct smbfs_dfs_info {
	int flags; /* DFSREF_REFERRAL_SERVER, DFSREF_STORAGE_SERVER*/
	int path_consumed;
	int server_type;
	int ref_flag;
	char *path_name;
	char *node_name;
	int ttl;
};

static inline void free_dfs_info(struct smbfs_dfs_info *info)
{
	if (info) {
		kfree(info->path_name);
		kfree(info->node_name);
	}
}

static inline void free_dfs_info_array(struct smbfs_dfs_info *infos, int count)
{
	int i;

	if (!count || !infos)
		return;
	
	for (i = 0; i < count; i++) {
		kfree(infos[i].path_name);
		kfree(infos[i].node_name);
	}
	kfree(infos);
}

static inline bool is_tcon_dfs(struct smbfs_tcon *tcon)
{
	/*
	 * For SMB1, see MS-CIFS 2.4.55 SMB_COM_TREE_CONNECT_ANDX (0x75) and
	 * MS-CIFS 3.3.4.4 DFS Subsystem Notifies That a Share Is a DFS Share.
	 *
	 * For SMB2+, see MS-SMB2 2.2.10 SMB2 TREE_CONNECT Response and
	 * MS-SMB2 3.3.4.14 Server Application Updates a Share.
	 */
	if (!tcon || !tcon->ses || !tcon->ses->server)
		return false;
	return is_smb1_server(tcon->ses->server) ?
		tcon->flags & SMB_SHARE_IS_IN_DFS :
		tcon->share_flags & (SHI1005_FLAGS_DFS | SHI1005_FLAGS_DFS_ROOT);
}

static inline bool is_referral_server(struct smbfs_tcon *tcon,
				      const struct smbfs_dfs_info *ref)
{
	/*
	 * Check if all targets are capable of handling DFS referrals as per
	 * MS-DFSC 2.2.4 RESP_GET_DFS_REFERRAL.
	 */
	return is_tcon_dfs(tcon) ||
	       (ref && (ref->flags & DFSREF_REFERRAL_SERVER));
}


#endif /* _SMBFS_DFS_H */
