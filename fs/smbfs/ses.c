// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) SUSE LLC, 2022
 *
 * Author(s): Enzo Matsumiya <ematsumiya@suse.de>
 *
 * SMBFS session definition, helpers, and related functions.
*/
#include "server_info.h"
#include "debug.h"
#include "ses.h"

struct smbfs_ses *smbfs_ses_alloc(void)
{
	struct smbfs_ses *ses;

	ses = kzalloc(sizeof(struct smbfs_ses), GFP_KERNEL);
	if (ses) {
		atomic_inc(&g_ses_alloc_count);
		ses->status = SMBFS_SES_STATUS_NEW;
		++ses->count;
		INIT_LIST_HEAD(&ses->head);
		INIT_LIST_HEAD(&ses->tcons);
		mutex_init(&ses->lock);
		spin_lock_init(&ses->iface_lock);
		INIT_LIST_HEAD(&ses->ifaces);
		spin_lock_init(&ses->channel_lock);
	}
	return ses;
}

void smbfs_ses_free(struct smbfs_ses *ses)
{
	struct smbfs_server_iface *iface, *tmp;

	if (ses == NULL) {
		smbfs_dbg("null buffer passed to sesInfoFree\n");
		return;
	}

	atomic_dec(&g_ses_alloc_count);
	kfree(ses->serverOS);
	kfree(ses->server_domain);
	kfree(ses->serverNOS);
	kfree_sensitive(ses->password);
	kfree(ses->user_name);
	kfree(ses->domain_name);
	kfree_sensitive(ses->auth_key.response);
	spin_lock(&ses->iface_lock);
	list_for_each_entry_safe(iface, tmp, &ses->ifaces, head)
		kref_put(&iface->refcount, release_iface);
	spin_unlock(&ses->iface_lock);
	kfree_sensitive(ses);
}

