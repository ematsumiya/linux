// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) SUSE LLC, 2022
 *
 * Author(s): Enzo Matsumiya <ematsumiya@suse.de>
 *
 * SMBFS tree connection definition, helpers, and related functions.
*/
#include <linux/types.h>

#include "cifs_swn.h"
#include "fs_context.h"
#include "smbfs.h"
#include "defs.h"
#include "debug.h"
#include "tcon.h"

extern void smb2_query_server_interfaces(struct work_struct *work);
extern struct workqueue_struct *cifsiod_wq;

struct smbfs_tcon *smbfs_tcon_alloc(void)
{
	struct smbfs_tcon *tcon;

	tcon = kzalloc(sizeof(*tcon), GFP_KERNEL);
	if (!tcon)
		return NULL;

	tcon->crfid.fid = kzalloc(sizeof(*tcon->crfid.fid), GFP_KERNEL);
	if (!tcon->crfid.fid) {
		kfree(tcon);
		return NULL;
	}

	INIT_LIST_HEAD(&tcon->crfid.dir_entries.entries);
	mutex_init(&tcon->crfid.dir_entries.lock);

	atomic_inc(&g_tcon_alloc_count);
	tcon->status = SMBFS_TCON_STATUS_NEW;
	++tcon->count;

	INIT_LIST_HEAD(&tcon->open_files);
	INIT_LIST_HEAD(&tcon->head);

	spin_lock_init(&tcon->open_files_lock);
	mutex_init(&tcon->crfid.lock);
	spin_lock_init(&tcon->stats_lock);

	atomic_set(&tcon->local_opens, 0);
	atomic_set(&tcon->remote_opens, 0);

	return tcon;
}

void smbfs_tcon_free(struct smbfs_tcon *tcon)
{
	if (!tcon)
		return;

	atomic_dec(&g_tcon_alloc_count);
	kfree(tcon->native_fs);
	kfree_sensitive(tcon->password);
	kfree(tcon->crfid.fid);
	kfree(tcon);
}

static inline int match_tcon(struct smbfs_tcon *tcon,
			     struct smb3_fs_context *ctx)
{
	if (tcon->status == SMBFS_TCON_STATUS_EXITING)
		return 0;
	if (strncmp(tcon->tree_name, ctx->UNC, SMBFS_MAX_TREE_SIZE))
		return 0;
	if (get_tcon_flag(tcon, USE_SEAL) != ctx->seal)
		return 0;
	if (tcon->snapshot_time != ctx->snapshot_time)
		return 0;
	if (tcon->handle_timeout != ctx->handle_timeout)
		return 0;
	if (tcon->no_lease != ctx->no_lease)
		return 0;
	if (tcon->nodelete != ctx->nodelete)
		return 0;
	return 1;
}

static struct smbfs_tcon *smbfs_find_tcon(struct smbfs_ses *ses,
					  struct smb3_fs_context *ctx)
{
	struct smbfs_tcon *tcon;

	spin_lock(&g_servers_lock);
	list_for_each_entry(tcon, &ses->tcons, head) {
		if (!match_tcon(tcon, ctx))
			continue;
		++tcon->count;
		spin_unlock(&g_servers_lock);
		return tcon;
	}
	spin_unlock(&g_servers_lock);
	return NULL;
}

void smbfs_put_tcon(struct smbfs_tcon *tcon)
{
	unsigned int xid;
	struct smbfs_ses *ses;

	/*
	 * IPC tcon share the lifetime of their session and are
	 * destroyed in the session put function
	 */
	if (!tcon || get_tcon_flag(tcon, IS_IPC))
		return;

	ses = tcon->ses;
	smbfs_dbg("tcon count=%d\n", tcon->count);
	spin_lock(&g_servers_lock);
	if (--tcon->count > 0) {
		spin_unlock(&g_servers_lock);
		return;
	}

	/* count can never go negative */
	WARN_ON(tcon->count < 0);

	list_del_init(&tcon->head);
	spin_unlock(&g_servers_lock);

	/* cancel polling of interfaces */
	cancel_delayed_work_sync(&tcon->query_interfaces);

	if (get_tcon_flag(tcon, USE_WITNESS)) {
		int rc;

		rc = cifs_swn_unregister(tcon);
		if (rc < 0)
			smbfs_log("%s: failed to unregister for witness notifications, rc=%d\n",
				  __func__, rc);
	}

	xid = get_xid();
	if (ses->server->ops->tree_disconnect)
		ses->server->ops->tree_disconnect(xid, tcon);
	_free_xid(xid);

	cifs_fscache_release_super_cookie(tcon);
	tcon_info_free(tcon);
	cifs_put_smb_ses(ses);
}

/**
 * smbfs_get_tcon - get a tcon matching @ctx data from @ses
 * @ses: smb session to issue the request on
 * @ctx: the superblock configuration context to use for building the
 *
 * - tcon refcount is the number of mount points using the tcon.
 * - ses refcount is the number of tcon using the session.
 *
 * 1. This function assumes it is being called from cifs_mount() where
 *    we already got a session reference (ses refcount +1).
 *
 * 2. Since we're in the context of adding a mount point, the end
 *    result should be either:
 *
 * a) a new tcon already allocated with refcount=1 (1 mount point) and
 *    its session refcount incremented (1 new tcon). This +1 was
 *    already done in (1).
 *
 * b) an existing tcon with refcount+1 (add a mount point to it) and
 *    identical ses refcount (no new tcon). Because of (1) we need to
 *    decrement the ses refcount.
 */
struct smbfs_tcon *smbfs_get_tcon(struct smbfs_ses *ses,
				  struct smb3_fs_context *ctx)
{
	int rc, xid;
	struct smbfs_tcon *tcon;

	tcon = smbfs_find_tcon(ses, ctx);
	if (tcon) {
		/*
		 * tcon has refcount already incremented but we need to
		 * decrement extra ses reference gotten by caller (case b)
		 */
		smbfs_dbg("Found match on UNC path\n");
		cifs_put_smb_ses(ses);
		return tcon;
	}

	if (!ses->server->ops->tree_connect) {
		rc = -ENOSYS;
		goto out_fail;
	}

	tcon = smbfs_tcon_alloc();
	if (tcon == NULL) {
		rc = -ENOMEM;
		goto out_fail;
	}

	if (ctx->snapshot_time) {
		if (ses->server->settings->protocol_id == 0) {
			smbfs_log("Use SMB2 or later for snapshot mount option\n");
			rc = -EOPNOTSUPP;
			goto out_fail;
		} else
			tcon->snapshot_time = ctx->snapshot_time;
	}

	if (ctx->handle_timeout) {
		if (ses->server->settings->protocol_id == 0) {
			smbfs_log("Use SMB2.1 or later for handle timeout option\n");
			rc = -EOPNOTSUPP;
			goto out_fail;
		} else
			tcon->handle_timeout = ctx->handle_timeout;
	}

	tcon->ses = ses;
	if (ctx->password) {
		tcon->password = kstrdup(ctx->password, GFP_KERNEL);
		if (!tcon->password) {
			rc = -ENOMEM;
			goto out_fail;
		}
	}

	if (ctx->seal) {
		if (ses->server->settings->protocol_id == 0) {
			smbfs_log("SMB3 or later required for encryption\n");
			rc = -EOPNOTSUPP;
			goto out_fail;
		} else if (tcon->ses->server->capabilities & 
			   SMB2_GLOBAL_CAP_ENCRYPTION)
			set_tcon_flag(tcon, USE_SEAL);
		else {
			smbfs_log("Encryption is not supported on share\n");
			rc = -EOPNOTSUPP;
			goto out_fail;
		}
	}

	if (ctx->linux_ext) {
		if (ses->server->posix_ext_supported) {
			set_tcon_flag(tcon, USE_POSIX_EXT);
			pr_warn_once("SMB3.11 POSIX Extensions are experimental\n");
		} else if ((ses->server->settings->protocol_id == SMB311_PROT_ID) ||
		    (strcmp(ses->server->settings->version_string,
		     SMB3ANY_VERSION_STRING) == 0) ||
		    (strcmp(ses->server->settings->version_string,
		     SMBDEFAULT_VERSION_STRING) == 0)) {
			smbfs_log("Server does not support mounting with posix SMB3.11 extensions\n");
			rc = -EOPNOTSUPP;
			goto out_fail;
		} else {
			smbfs_log("Check vers= mount option. SMB3.11 "
				"disabled but required for POSIX extensions\n");
			rc = -EOPNOTSUPP;
			goto out_fail;
		}
	}

	xid = get_xid();
	rc = ses->server->ops->tree_connect(xid, ses, ctx->UNC, tcon,
					    ctx->local_nls);
	free_xid(xid);
	smbfs_dbg("Tcon rc=%d\n", rc);
	if (rc)
		goto out_fail;

	tcon->use_persistent = false;
	/* check if SMB2 or later, CIFS does not support persistent handles */
	if (ctx->persistent) {
		if (ses->server->settings->protocol_id == 0) {
			smbfs_log("SMB3 or later required for persistent handles\n");
			rc = -EOPNOTSUPP;
			goto out_fail;
		} else if (ses->server->capabilities &
			   SMB2_GLOBAL_CAP_PERSISTENT_HANDLES)
			tcon->use_persistent = true;
		else /* persistent handles requested but not supported */ {
			smbfs_log("Persistent handles not supported on share\n");
			rc = -EOPNOTSUPP;
			goto out_fail;
		}
	} else if ((tcon->capabilities & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY)
	     && (ses->server->capabilities & SMB2_GLOBAL_CAP_PERSISTENT_HANDLES)
	     && (ctx->nopersistent == false)) {
		smbfs_dbg("enabling persistent handles\n");
		tcon->use_persistent = true;
	} else if (ctx->resilient) {
		if (ses->server->settings->protocol_id == 0) {
			smbfs_log("SMB2.1 or later required for resilient handles\n");
			rc = -EOPNOTSUPP;
			goto out_fail;
		}
		tcon->use_resilient = true;
	}

	clear_tcon_flag(tcon, USE_WITNESS);
	if (IS_ENABLED(CONFIG_SMBFS_SWN_UPCALL) && ctx->witness) {
		if (ses->server->settings->protocol_id >= SMB30_PROT_ID) {
			if (tcon->capabilities & SMB2_SHARE_CAP_CLUSTER) {
				/*
				 * Set witness in use flag in first place
				 * to retry registration in the echo task
				 */
				set_tcon_flag(tcon, USE_WITNESS);
				/* And try to register immediately */
				rc = cifs_swn_register(tcon);
				if (rc < 0) {
					smbfs_log("Failed to register for witness notifications: %d\n", rc);
					goto out_fail;
				}
			} else {
				/* TODO: try to extend for non-cluster uses (eg multichannel) */
				smbfs_log("witness requested on mount but no CLUSTER capability on share\n");
				rc = -EOPNOTSUPP;
				goto out_fail;
			}
		} else {
			smbfs_log("SMB3 or later required for witness option\n");
			rc = -EOPNOTSUPP;
			goto out_fail;
		}
	}

	/* If the user really knows what they are doing they can override */
	if (tcon->share_flags & SMB2_SHAREFLAG_NO_CACHING) {
		if (ctx->cache_ro)
			smbfs_log("cache=ro requested on mount but NO_CACHING flag set on share\n");
		else if (ctx->cache_rw)
			smbfs_log("cache=singleclient requested on mount but NO_CACHING flag set on share\n");
	}

	if (ctx->no_lease) {
		if (ses->server->settings->protocol_id == 0) {
			smbfs_log("SMB2 or later required for nolease option\n");
			rc = -EOPNOTSUPP;
			goto out_fail;
		} else
			tcon->no_lease = ctx->no_lease;
	}

	/*
	 * We can have only one retry value for a connection to a share so for
	 * resources mounted more than once to the same server share the last
	 * value passed in for the retry flag is used.
	 */
	tcon->retry = ctx->retry;
	clear_tcon_flag(tcon, NOCASE);
	if (ctx->nocase)
		set_tcon_flag(tcon, NOCASE);
	clear_tcon_flag(tcon, BROKEN_SPARSE_SUPP);
	if (ctx->no_sparse)
		set_tcon_flag(tcon, BROKEN_SPARSE_SUPP);
	if (ses->server->capabilities & SMB2_GLOBAL_CAP_DIRECTORY_LEASING) {
		clear_tcon_flag(tcon, NOHANDLECACHE);
		if (ctx->nohandlecache)
			set_tcon_flag(tcon, NOHANDLECACHE);
	} else {
		set_tcon_flag(tcon, NOHANDLECACHE);
	}
	tcon->nodelete = ctx->nodelete;
	tcon->local_lease = ctx->local_lease;
	INIT_LIST_HEAD(&tcon->pending_opens);

	/* schedule query interfaces poll */
	INIT_DELAYED_WORK(&tcon->query_interfaces,
			  smb2_query_server_interfaces);
	queue_delayed_work(cifsiod_wq, &tcon->query_interfaces,
			   (SMBFS_INTERFACE_POLL_INTERVAL * HZ));

	spin_lock(&g_servers_lock);
	list_add(&tcon->head, &ses->tcons);
	spin_unlock(&g_servers_lock);

	return tcon;

out_fail:
	tcon_info_free(tcon);
	return ERR_PTR(rc);
}

struct smbfs_tcon_link *smbfs_get_tlink(struct smbfs_tcon_link *tlink)
{
	if (tlink && !IS_ERR(tlink))
		atomic_inc(&tlink->count);
	return tlink;
}

void smbfs_put_tlink(struct smbfs_tcon_link *tlink)
{
	if (!tlink || IS_ERR(tlink))
		return;

	if (!atomic_dec_and_test(&tlink->count) ||
	    test_bit(TCON_LINK_IN_TREE, &tlink->flags)) {
		tlink->time = jiffies;
		return;
	}

	if (!IS_ERR(tlink_tcon(tlink)))
		smbfs_put_tcon(tlink_tcon(tlink));
	kfree(tlink);
	return;
}

/*
 * periodic workqueue job that scans tcon_tree for a superblock and closes
 * out tcons.
 */
void smbfs_prune_tlinks(struct work_struct *work)
{
	struct cifs_sb_info *cifs_sb = container_of(work, struct cifs_sb_info,
						    prune_tlinks.work);
	struct rb_root *root = &cifs_sb->tlink_tree;
	struct rb_node *node;
	struct rb_node *tmp;
	struct smbfs_tcon_link *tlink;

	/*
	 * Because we drop the spinlock in the loop in order to put the tlink
	 * it's not guarded against removal of links from the tree. The only
	 * places that remove entries from the tree are this function and
	 * umounts. Because this function is non-reentrant and is canceled
	 * before umount can proceed, this is safe.
	 */
	spin_lock(&cifs_sb->tlink_tree_lock);
	node = rb_first(root);
	while (node != NULL) {
		tmp = node;
		node = rb_next(tmp);
		tlink = rb_entry(tmp, struct smbfs_tcon_link, rbnode);

		if (test_bit(TCON_LINK_MASTER, &tlink->flags) ||
		    atomic_read(&tlink->count) != 0 ||
		    time_after(tlink->time + TLINK_IDLE_EXPIRE, jiffies))
			continue;

		smbfs_get_tlink(tlink);
		clear_bit(TCON_LINK_IN_TREE, &tlink->flags);
		rb_erase(tmp, root);

		spin_unlock(&cifs_sb->tlink_tree_lock);
		smbfs_put_tlink(tlink);
		spin_lock(&cifs_sb->tlink_tree_lock);
	}
	spin_unlock(&cifs_sb->tlink_tree_lock);

	queue_delayed_work(cifsiod_wq, &cifs_sb->prune_tlinks, TLINK_IDLE_EXPIRE);
}
