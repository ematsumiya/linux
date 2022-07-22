// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) International Business Machines Corp., 2002,2008
 * Author(s): Steve French <sfrench@us.ibm.com>
*/

#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/mempool.h>
#include <linux/vmalloc.h>
#include "cifspdu.h"
#include "defs.h"
#include "debug.h"
#include "smberr.h"
#include "nterr.h"
#include "cifs_unicode.h"
#include "smb2pdu.h"
#include "smbfs.h"
#ifdef CONFIG_SMBFS_DFS_UPCALL
#include "dns_resolve.h"
#endif
#include "fs_context.h"
#include "server_info.h"
#include "mid.h"
#include "defs.h"

extern mempool_t *cifs_sm_req_poolp;
extern mempool_t *cifs_req_poolp;

/* The xid serves as a useful identifier for each incoming vfs request,
   in a similar way to the mid which is useful to track each sent smb,
   and CurrentXid can also provide a running counter (although it
   will eventually wrap past zero) of the total vfs operations handled
   since the cifs fs was mounted */


struct smb_hdr *
cifs_buf_get(void)
{
	struct smb_hdr *ret_buf = NULL;
	/*
	 * SMB2 header is bigger than CIFS one - no problems to clean some
	 * more bytes for CIFS.
	 */
	size_t buf_size = sizeof(struct smb2_hdr);

	/*
	 * We could use negotiated size instead of max_msgsize -
	 * but it may be more efficient to always alloc same size
	 * albeit slightly larger than necessary and maxbuffersize
	 * defaults to this and can not be bigger.
	 */
	ret_buf = mempool_alloc(cifs_req_poolp, GFP_NOFS);

	/* clear the first few header bytes */
	/* for most paths, more is cleared in header_assemble */
	memset(ret_buf, 0, buf_size + 3);
	atomic_inc(&g_buf_alloc_count);
#ifdef CONFIG_SMBFS_STATS_EXTRA
	atomic_inc(&g_total_buf_alloc_count);
#endif /* CONFIG_SMBFS_STATS_EXTRA */

	return ret_buf;
}

void
cifs_buf_release(void *buf_to_free)
{
	if (buf_to_free == NULL)
		return;

	mempool_free(buf_to_free, cifs_req_poolp);

	atomic_dec(&g_buf_alloc_count);
	return;
}

struct smb_hdr *
cifs_small_buf_get(void)
{
	struct smb_hdr *ret_buf = NULL;

	/*
	 * We could use negotiated size instead of max_msgsize -
	 * but it may be more efficient to always alloc same size
	 * albeit slightly larger than necessary and maxbuffersize
	 * defaults to this and can not be bigger
	 */
	ret_buf = mempool_alloc(cifs_sm_req_poolp, GFP_NOFS);
	/* No need to clear memory here, cleared in header assemble */
	atomic_inc(&g_smallbuf_alloc_count);
#ifdef CONFIG_SMBFS_STATS_EXTRA
	atomic_inc(&g_total_smallbuf_alloc_count);
#endif /* CONFIG_SMBFS_STATS_EXTRA */

	return ret_buf;
}

void
cifs_small_buf_release(void *buf_to_free)
{

	if (buf_to_free == NULL) {
		smbfs_dbg("null buffer passed to cifs_small_buf_release\n");
		return;
	}
	mempool_free(buf_to_free, cifs_sm_req_poolp);

	atomic_dec(&g_smallbuf_alloc_count);
	return;
}

void
free_rsp_buf(int resp_buftype, void *rsp)
{
	if (resp_buftype == SMBFS_SMALL_BUFFER)
		cifs_small_buf_release(rsp);
	else if (resp_buftype == SMBFS_LARGE_BUFFER)
		cifs_buf_release(rsp);
}

/* NB: MID can not be set if treeCon not passed in, in that
   case it is responsbility of caller to set the mid */
void
header_assemble(struct smb_hdr *buffer, char smb_command /* command */ ,
		const struct smbfs_tcon *treeCon, int word_count
		/* length of fixed section (word count) in two byte units  */)
{
	char *temp = (char *) buffer;

	memset(temp, 0, 256); /* bigger than MAX_CIFS_HDR_SIZE */

	buffer->smb_buf_length = cpu_to_be32(
	    (2 * word_count) + sizeof(struct smb_hdr) -
	    4 /*  RFC 1001 length field does not count */  +
	    2 /* for bcc field itself */) ;

	buffer->Protocol[0] = 0xFF;
	buffer->Protocol[1] = 'S';
	buffer->Protocol[2] = 'M';
	buffer->Protocol[3] = 'B';
	buffer->Command = smb_command;
	buffer->Flags = 0x00;	/* case sensitive */
	buffer->Flags2 = SMBFLG2_KNOWS_LONG_NAMES;
	buffer->Pid = cpu_to_le16((__u16)current->tgid);
	buffer->PidHigh = cpu_to_le16((__u16)(current->tgid >> 16));
	if (treeCon) {
		buffer->Tid = treeCon->tid;
		if (treeCon->ses) {
			if (treeCon->ses->capabilities & CAP_UNICODE)
				buffer->Flags2 |= SMBFLG2_UNICODE;
			if (treeCon->ses->capabilities & CAP_STATUS32)
				buffer->Flags2 |= SMBFLG2_ERR_STATUS;

			/* Uid is not converted */
			buffer->Uid = treeCon->ses->id;
			if (treeCon->ses->server)
				buffer->Mid = get_next_mid(treeCon->ses->server);
		}
		if (treeCon->flags & SMB_SHARE_IS_IN_DFS)
			buffer->Flags2 |= SMBFLG2_DFS;
		if (get_tcon_flag(treeCon, NOCASE))
			buffer->Flags  |= SMBFLG_CASELESS;
		if ((treeCon->ses) && (treeCon->ses->server))
			if (treeCon->ses->server->sec.signing_enabled)
				buffer->Flags2 |= SMBFLG2_SECURITY_SIGNATURE;
	}

/*  endian conversion of flags is now done just before sending */
	buffer->WordCount = (char) word_count;
	return;
}

static int
check_smb_hdr(struct smb_hdr *smb)
{
	/* does it have the right SMB "signature" ? */
	if (*(__le32 *) smb->Protocol != cpu_to_le32(0x424d53ff)) {
		smbfs_log("Bad protocol string signature header 0x%x\n",
			 *(unsigned int *)smb->Protocol);
		return 1;
	}

	/* if it's a response then accept */
	if (smb->Flags & SMBFLG_RESPONSE)
		return 0;

	/* only one valid case where server sends us request */
	if (smb->Command == SMB_COM_LOCKING_ANDX)
		return 0;

	smbfs_log("Server sent request, not response. mid=%u\n",
		 get_mid(smb));
	return 1;
}

int
checkSMB(char *buf, unsigned int total_read, struct smbfs_server_info *server)
{
	struct smb_hdr *smb = (struct smb_hdr *)buf;
	__u32 rfclen = be32_to_cpu(smb->smb_buf_length);
	__u32 clc_len;  /* calculated length */
	smbfs_dbg("checkSMB Length: 0x%x, smb_buf_length: 0x%x\n",
		 total_read, rfclen);

	/* is this frame too small to even get to a BCC? */
	if (total_read < 2 + sizeof(struct smb_hdr)) {
		if ((total_read >= sizeof(struct smb_hdr) - 1)
			    && (smb->Status.CifsError != 0)) {
			/* it's an error return */
			smb->WordCount = 0;
			/* some error cases do not return wct and bcc */
			return 0;
		} else if ((total_read == sizeof(struct smb_hdr) + 1) &&
				(smb->WordCount == 0)) {
			char *tmp = (char *)smb;
			/* Need to work around a bug in two servers here */
			/* First, check if the part of bcc they sent was zero */
			if (tmp[sizeof(struct smb_hdr)] == 0) {
				/* some servers return only half of bcc
				 * on simple responses (wct, bcc both zero)
				 * in particular have seen this on
				 * ulogoffX and FindClose. This leaves
				 * one byte of bcc potentially unitialized
				 */
				/* zero rest of bcc */
				tmp[sizeof(struct smb_hdr)+1] = 0;
				return 0;
			}
			smbfs_log("rcvd invalid byte count (bcc)\n");
		} else {
			smbfs_log("Length less than smb header size\n");
		}
		return -EIO;
	}

	/* otherwise, there is enough to get to the BCC */
	if (check_smb_hdr(smb))
		return -EIO;
	clc_len = smbCalcSize(smb, server);

	if (4 + rfclen != total_read) {
		smbfs_log("Length read does not match RFC1001 length %d\n",
			 rfclen);
		return -EIO;
	}

	if (4 + rfclen != clc_len) {
		__u16 mid = get_mid(smb);
		/* check if bcc wrapped around for large read responses */
		if ((rfclen > 64 * 1024) && (rfclen > clc_len)) {
			/* check if lengths match mod 64K */
			if (((4 + rfclen) & 0xFFFF) == (clc_len & 0xFFFF))
				return 0; /* bcc wrapped */
		}
		smbfs_dbg("Calculated size %u vs length %u mismatch for mid=%u\n",
			 clc_len, 4 + rfclen, mid);

		if (4 + rfclen < clc_len) {
			smbfs_log("RFC1001 size %u smaller than SMB for mid=%u\n",
				 rfclen, mid);
			return -EIO;
		} else if (rfclen > clc_len + 512) {
			/*
			 * Some servers (Windows XP in particular) send more
			 * data than the lengths in the SMB packet would
			 * indicate on certain calls (byte range locks and
			 * trans2 find first calls in particular). While the
			 * client can handle such a frame by ignoring the
			 * trailing data, we choose limit the amount of extra
			 * data to 512 bytes.
			 */
			smbfs_log("RFC1001 size %u more than 512 bytes larger than SMB for mid=%u\n",
				 rfclen, mid);
			return -EIO;
		}
	}
	return 0;
}

bool
is_valid_oplock_break(char *buffer, struct smbfs_server_info *server)
{
	struct smb_hdr *buf = (struct smb_hdr *)buffer;
	struct smb_com_lock_req *pSMB = (struct smb_com_lock_req *)buf;
	struct smbfs_ses *ses;
	struct smbfs_tcon *tcon;
	struct smbfs_inode_info *pCifsInode;
	struct smbfs_file_info *netfile;

	smbfs_dbg("Checking for oplock break or dnotify response\n");
	if ((pSMB->hdr.Command == SMB_COM_NT_TRANSACT) &&
	   (pSMB->hdr.Flags & SMBFLG_RESPONSE)) {
		struct smb_com_transaction_change_notify_rsp *pSMBr =
			(struct smb_com_transaction_change_notify_rsp *)buf;
		struct file_notify_information *pnotify;
		__u32 data_offset = 0;
		size_t len = server->total_read - sizeof(pSMBr->hdr.smb_buf_length);

		if (get_bcc(buf) > sizeof(struct file_notify_information)) {
			data_offset = le32_to_cpu(pSMBr->DataOffset);

			if (data_offset >
			    len - sizeof(struct file_notify_information)) {
				smbfs_dbg("Invalid data_offset %u\n",
					 data_offset);
				return true;
			}
			pnotify = (struct file_notify_information *)
				((char *)&pSMBr->hdr.Protocol + data_offset);
			smbfs_dbg("dnotify on %s Action: 0x%x\n",
				 pnotify->FileName, pnotify->Action);
			return true;
		}
		if (pSMBr->hdr.Status.CifsError) {
			smbfs_dbg("notify err 0x%x\n",
				 pSMBr->hdr.Status.CifsError);
			return true;
		}
		return false;
	}
	if (pSMB->hdr.Command != SMB_COM_LOCKING_ANDX)
		return false;
	if (pSMB->hdr.Flags & SMBFLG_RESPONSE) {
		/* no sense logging error on invalid handle on oplock
		   break - harmless race between close request and oplock
		   break response is expected from time to time writing out
		   large dirty files cached on the client */
		if ((NT_STATUS_INVALID_HANDLE) ==
		   le32_to_cpu(pSMB->hdr.Status.CifsError)) {
			smbfs_dbg("Invalid handle on oplock break\n");
			return true;
		} else if (ERRbadfid ==
		   le16_to_cpu(pSMB->hdr.Status.DosError.Error)) {
			return true;
		} else {
			return false; /* on valid oplock brk we get "request" */
		}
	}
	if (pSMB->hdr.WordCount != 8)
		return false;

	smbfs_dbg("oplock type 0x%x level 0x%x\n",
		 pSMB->LockType, pSMB->OplockLevel);
	if (!(pSMB->LockType & LOCKING_ANDX_OPLOCK_RELEASE))
		return false;

	/* look up tcon based on tid & uid */
	spin_lock(&g_servers_lock);
	list_for_each_entry(ses, &server->sessions, head) {
		list_for_each_entry(tcon, &ses->tcons, head) {
			if (tcon->tid != buf->Tid)
				continue;

			cifs_stats_inc(&tcon->stats.smb1.oplock_brks);
			spin_lock(&tcon->open_files_lock);
			list_for_each_entry(netfile, &tcon->open_files, tcon_head) {
				if (pSMB->Fid != netfile->fid.net_fid)
					continue;

				smbfs_dbg("file id match, oplock break\n");
				pCifsInode = SMBFS_I(d_inode(netfile->dentry));

				set_bit(CIFS_INODE_PENDING_OPLOCK_BREAK,
					&pCifsInode->flags);

				netfile->oplock_epoch = 0;
				netfile->oplock_level = pSMB->OplockLevel;
				netfile->oplock_break_cancelled = false;
				cifs_queue_oplock_break(netfile);

				spin_unlock(&tcon->open_files_lock);
				spin_unlock(&g_servers_lock);
				return true;
			}
			spin_unlock(&tcon->open_files_lock);
			spin_unlock(&g_servers_lock);
			smbfs_dbg("No matching file for oplock break\n");
			return true;
		}
	}
	spin_unlock(&g_servers_lock);
	smbfs_dbg("Can not process oplock break for non-existent connection\n");
	return true;
}

void
cifs_autodisable_serverino(struct cifs_sb_info *cifs_sb)
{
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_SERVER_INUM) {
		struct smbfs_tcon *tcon = NULL;

		if (cifs_sb->master_tlink)
			tcon = smbfs_sb_master_tcon(cifs_sb);

		cifs_sb->mnt_cifs_flags &= ~CIFS_MOUNT_SERVER_INUM;
		cifs_sb->mnt_cifs_serverino_autodisabled = true;
		smbfs_log("Autodisabling the use of server inode numbers on %s\n",
			 tcon ? tcon->tree_name : "new server");
		smbfs_log("The server doesn't seem to support them properly or the files might be on different servers (DFS)\n");
		smbfs_log("Hardlinks will not be recognized on this mount. Consider mounting with the \"noserverino\" option to silence this message.\n");

	}
}

void cifs_set_oplock_level(struct smbfs_inode_info *smb_i, __u32 oplock)
{
	oplock &= 0xF;

	if (oplock == OPLOCK_EXCLUSIVE) {
		smb_i->oplock = SMBFS_CACHE_WRITE_FLG | SMBFS_CACHE_READ_FLG;
		smbfs_dbg("Exclusive Oplock granted on inode 0x%p\n",
			 &smb_i->netfs.inode);
	} else if (oplock == OPLOCK_READ) {
		smb_i->oplock = SMBFS_CACHE_READ_FLG;
		smbfs_dbg("Level II Oplock granted on inode 0x%p\n",
			 &smb_i->netfs.inode);
	} else
		smb_i->oplock = 0;
}

/*
 * We wait for oplock breaks to be processed before we attempt to perform
 * writes.
 */
int cifs_get_writer(struct smbfs_inode_info *smb_i)
{
	int rc;

start:
	rc = wait_on_bit(&smb_i->flags, CIFS_INODE_PENDING_OPLOCK_BREAK,
			 TASK_KILLABLE);
	if (rc)
		return rc;

	spin_lock(&smb_i->writers_lock);
	if (!smb_i->writers)
		set_bit(SMBFS_INODE_PENDING_WRITERS, &smb_i->flags);
	smb_i->writers++;
	/* Check to see if we have started servicing an oplock break */
	if (test_bit(CIFS_INODE_PENDING_OPLOCK_BREAK, &smb_i->flags)) {
		smb_i->writers--;
		if (smb_i->writers == 0) {
			clear_bit(SMBFS_INODE_PENDING_WRITERS, &smb_i->flags);
			wake_up_bit(&smb_i->flags, SMBFS_INODE_PENDING_WRITERS);
		}
		spin_unlock(&smb_i->writers_lock);
		goto start;
	}
	spin_unlock(&smb_i->writers_lock);
	return 0;
}

void cifs_put_writer(struct smbfs_inode_info *smb_i)
{
	spin_lock(&smb_i->writers_lock);
	smb_i->writers--;
	if (smb_i->writers == 0) {
		clear_bit(SMBFS_INODE_PENDING_WRITERS, &smb_i->flags);
		wake_up_bit(&smb_i->flags, SMBFS_INODE_PENDING_WRITERS);
	}
	spin_unlock(&smb_i->writers_lock);
}

/**
 * cifs_queue_oplock_break - queue the oplock break handler for smb_f
 * @smb_f: The file to break the oplock on
 *
 * This function is called from the demultiplex thread when it
 * receives an oplock break for @smb_f.
 *
 * Assumes the tcon->open_files_lock is held.
 * Assumes smb_f->file_info_lock is NOT held.
 */
void cifs_queue_oplock_break(struct smbfs_file_info *smb_f)
{
	/*
	 * Bump the handle refcount now while we hold the
	 * open_files_lock to enforce the validity of it for the oplock
	 * break handler. The matching put is done at the end of the
	 * handler.
	 */
	smbfs_file_info_get(smb_f);

	queue_work(cifsoplockd_wq, &smb_f->oplock_break);
}

void cifs_done_oplock_break(struct smbfs_inode_info *smb_i)
{
	clear_bit(CIFS_INODE_PENDING_OPLOCK_BREAK, &smb_i->flags);
	wake_up_bit(&smb_i->flags, CIFS_INODE_PENDING_OPLOCK_BREAK);
}

bool
backup_cred(struct cifs_sb_info *cifs_sb)
{
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_CIFS_BACKUPUID) {
		if (uid_eq(cifs_sb->ctx->backupuid, current_fsuid()))
			return true;
	}
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_CIFS_BACKUPGID) {
		if (in_group_p(cifs_sb->ctx->backupgid))
			return true;
	}

	return false;
}

void
cifs_del_pending_open(struct smbfs_pending_open *open)
{
	spin_lock(&tlink_tcon(open->tlink)->open_files_lock);
	list_del(&open->olist);
	spin_unlock(&tlink_tcon(open->tlink)->open_files_lock);
}

void
cifs_add_pending_open_locked(struct smbfs_fid *fid, struct smbfs_tcon_link *tlink,
			     struct smbfs_pending_open *open)
{
	memcpy(open->lease_key, fid->lease_key, SMB2_LEASE_KEY_SIZE);
	open->oplock = SMBFS_OPLOCK_NO_CHANGE;
	open->tlink = tlink;
	fid->pending_open = open;
	list_add_tail(&open->olist, &tlink_tcon(tlink)->pending_opens);
}

void
cifs_add_pending_open(struct smbfs_fid *fid, struct smbfs_tcon_link *tlink,
		      struct smbfs_pending_open *open)
{
	spin_lock(&tlink_tcon(tlink)->open_files_lock);
	cifs_add_pending_open_locked(fid, tlink, open);
	spin_unlock(&tlink_tcon(open->tlink)->open_files_lock);
}

/*
 * Critical section which runs after acquiring deferred_lock.
 * As there is no reference count on smbfs_deferred_close, pdclose
 * should not be used outside deferred_lock.
 */
bool
cifs_is_deferred_close(struct smbfs_file_info *smb_f, struct smbfs_deferred_close **pdclose)
{
	struct smbfs_deferred_close *dclose;

	list_for_each_entry(dclose, &SMBFS_I(d_inode(smb_f->dentry))->deferred_closes, dlist) {
		if ((dclose->net_fid == smb_f->fid.net_fid) &&
			(dclose->persistent_fid == smb_f->fid.persistent_fid) &&
			(dclose->volatile_fid == smb_f->fid.volatile_fid)) {
			*pdclose = dclose;
			return true;
		}
	}
	return false;
}

/*
 * Critical section which runs after acquiring deferred_lock.
 */
void
cifs_add_deferred_close(struct smbfs_file_info *smb_f, struct smbfs_deferred_close *dclose)
{
	bool is_deferred = false;
	struct smbfs_deferred_close *pdclose;

	is_deferred = cifs_is_deferred_close(smb_f, &pdclose);
	if (is_deferred) {
		kfree(dclose);
		return;
	}

	dclose->tlink = smb_f->tlink;
	dclose->net_fid = smb_f->fid.net_fid;
	dclose->persistent_fid = smb_f->fid.persistent_fid;
	dclose->volatile_fid = smb_f->fid.volatile_fid;
	list_add_tail(&dclose->dlist, &SMBFS_I(d_inode(smb_f->dentry))->deferred_closes);
}

/*
 * Critical section which runs after acquiring deferred_lock.
 */
void
cifs_del_deferred_close(struct smbfs_file_info *smb_f)
{
	bool is_deferred = false;
	struct smbfs_deferred_close *dclose;

	is_deferred = cifs_is_deferred_close(smb_f, &dclose);
	if (!is_deferred)
		return;
	list_del(&dclose->dlist);
	kfree(dclose);
}

void
cifs_close_deferred_file(struct smbfs_inode_info *smb_i)
{
	struct smbfs_file_info *smb_f = NULL;
	struct smbfs_file_list *tmp_list, *tmp_next_list;
	struct list_head file_head;

	if (cifs_inode == NULL)
		return;

	INIT_LIST_HEAD(&file_head);
	spin_lock(&smb_i->open_files_lock);
	list_for_each_entry(smb_f, &smb_i->open_files, inode_head) {
		if (delayed_work_pending(&smb_f->deferred)) {
			if (cancel_delayed_work(&smb_f->deferred)) {
				tmp_list = kmalloc(sizeof(struct smbfs_file_list), GFP_ATOMIC);
				if (tmp_list == NULL)
					break;
				tmp_list->fi = smb_f;
				list_add_tail(&tmp_list->head, &file_head);
			}
		}
	}
	spin_unlock(&smb_i->open_files_lock);

	list_for_each_entry_safe(tmp_list, tmp_next_list, &file_head, list) {
		_smbfs_file_info_put(tmp_list->fi, true, false);
		list_del(&tmp_list->head);
		kfree(tmp_list);
	}
}

void
cifs_close_all_deferred_files(struct smbfs_tcon *tcon)
{
	struct smbfs_file_info *smb_f;
	struct smbfs_file_list *tmp_list, *tmp_next_list;
	struct list_head file_head;
	struct list_head *tmp;

	INIT_LIST_HEAD(&file_head);
	spin_lock(&tcon->open_files_lock);
	list_for_each_entry(smb_f, &tcon->open_files, tcon_head) {
		if (delayed_work_pending(&smb_f->deferred)) {
			if (cancel_delayed_work(&smb_f->deferred)) {
				tmp_list = kmalloc(sizeof(struct smbfs_file_list), GFP_ATOMIC);
				if (tmp_list == NULL)
					break;
				tmp_list->fi = smb_f;
				list_add_tail(&tmp_list->head, &file_head);
			}
		}
	}
	spin_unlock(&tcon->open_files_lock);

	list_for_each_entry_safe(tmp_list, tmp_next_list, &file_head, head) {
		_smbfs_file_info_put(tmp_list->fi, true, false);
		list_del(&tmp_list->head);
		kfree(tmp_list);
	}
}
void
cifs_close_deferred_file_under_dentry(struct smbfs_tcon *tcon, const char *path)
{
	struct smbfs_file_list *tmp_list, *tmp_next_list;
	struct list_head file_head;
	struct smbfs_file_info *smb_f;
	const char *full_path;
	void *page;

	INIT_LIST_HEAD(&file_head);
	page = alloc_dentry_path();
	spin_lock(&tcon->open_files_lock);
	list_for_each_entry(smb_f, &tcon->open_files, tcon_head) {
		full_path = build_path_from_dentry(smb_f->dentry, page);
		if (strstr(full_path, path)) {
			if (delayed_work_pending(&smb_f->deferred)) {
				if (cancel_delayed_work(&smb_f->deferred)) {
					tmp_list = kmalloc(sizeof(struct smbfs_file_list), GFP_ATOMIC);
					if (tmp_list == NULL)
						break;
					tmp_list->fi = smb_f;
					list_add_tail(&tmp_list->head, &file_head);
				}
			}
		}
	}
	spin_unlock(&tcon->open_files_lock);

	list_for_each_entry_safe(tmp_list, tmp_next_list, &file_head, head) {
		_smbfs_file_info_put(tmp_list->fi, true, false);
		list_del(&tmp_list->head);
		kfree(tmp_list);
	}
	free_dentry_path(page);
}

/* parses DFS refferal V3 structure
 * caller is responsible for freeing target_nodes
 * returns:
 * - on success - 0
 * - on failure - errno
 */
int
parse_dfs_referrals(struct get_dfs_referral_rsp *rsp, u32 rsp_size,
		    unsigned int *num_of_nodes,
		    struct smbfs_dfs_info **target_nodes,
		    const struct nls_table *nls_codepage, int remap,
		    const char *searchName, bool is_unicode)
{
	int i, rc = 0;
	char *data_end;
	struct dfs_referral_level_3 *ref;

	*num_of_nodes = le16_to_cpu(rsp->NumberOfReferrals);

	if (*num_of_nodes < 1) {
		smbfs_log("num_referrals: must be at least > 0, but we get num_referrals = %d\n",
			 *num_of_nodes);
		rc = -EINVAL;
		goto parse_DFS_referrals_exit;
	}

	ref = (struct dfs_referral_level_3 *) &(rsp->referrals);
	if (ref->VersionNumber != cpu_to_le16(3)) {
		smbfs_log("Referrals of V%d version are not supported, should be V3\n",
			 le16_to_cpu(ref->VersionNumber));
		rc = -EINVAL;
		goto parse_DFS_referrals_exit;
	}

	/* get the upper boundary of the resp buffer */
	data_end = (char *)rsp + rsp_size;

	smbfs_dbg("num_referrals: %d dfs flags: 0x%x ...\n",
		 *num_of_nodes, le32_to_cpu(rsp->DFSFlags));

	*target_nodes = kcalloc(*num_of_nodes, sizeof(struct smbfs_dfs_info),
				GFP_KERNEL);
	if (*target_nodes == NULL) {
		rc = -ENOMEM;
		goto parse_DFS_referrals_exit;
	}

	/* collect necessary data from referrals */
	for (i = 0; i < *num_of_nodes; i++) {
		char *temp;
		int max_len;
		struct smbfs_dfs_info *node = (*target_nodes)+i;

		node->flags = le32_to_cpu(rsp->DFSFlags);
		if (is_unicode) {
			__le16 *tmp = kmalloc(strlen(searchName)*2 + 2,
						GFP_KERNEL);
			if (tmp == NULL) {
				rc = -ENOMEM;
				goto parse_DFS_referrals_exit;
			}
			cifsConvertToUTF16((__le16 *) tmp, searchName,
					   PATH_MAX, nls_codepage, remap);
			node->path_consumed = cifs_utf16_bytes(tmp,
					le16_to_cpu(rsp->PathConsumed),
					nls_codepage);
			kfree(tmp);
		} else
			node->path_consumed = le16_to_cpu(rsp->PathConsumed);

		node->server_type = le16_to_cpu(ref->ServerType);
		node->ref_flag = le16_to_cpu(ref->ReferralEntryFlags);

		/* copy DfsPath */
		temp = (char *)ref + le16_to_cpu(ref->DfsPathOffset);
		max_len = data_end - temp;
		node->path_name = cifs_strndup_from_utf16(temp, max_len,
						is_unicode, nls_codepage);
		if (!node->path_name) {
			rc = -ENOMEM;
			goto parse_DFS_referrals_exit;
		}

		/* copy link target UNC */
		temp = (char *)ref + le16_to_cpu(ref->NetworkAddressOffset);
		max_len = data_end - temp;
		node->node_name = cifs_strndup_from_utf16(temp, max_len,
						is_unicode, nls_codepage);
		if (!node->node_name) {
			rc = -ENOMEM;
			goto parse_DFS_referrals_exit;
		}

		node->ttl = le32_to_cpu(ref->TimeToLive);

		ref++;
	}

parse_DFS_referrals_exit:
	if (rc) {
		free_dfs_info_array(*target_nodes, *num_of_nodes);
		*target_nodes = NULL;
		*num_of_nodes = 0;
	}
	return rc;
}

struct smbfs_aio_ctx *
smbfs_aio_ctx_alloc(void)
{
	struct smbfs_aio_ctx *ctx;

	/*
	 * Must use kzalloc to initialize ctx->bv to NULL and ctx->direct_io
	 * to false so that we know when we have to unreference pages within
	 * smbfs_aio_ctx_release()
	 */
	ctx = kzalloc(sizeof(struct smbfs_aio_ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	INIT_LIST_HEAD(&ctx->rw_list);
	mutex_init(&ctx->lock);
	init_completion(&ctx->done);
	kref_init(&ctx->refcount);
	return ctx;
}

void
smbfs_aio_ctx_release(struct kref *refcount)
{
	struct smbfs_aio_ctx *ctx = container_of(refcount,
					struct smbfs_aio_ctx, refcount);

	smbfs_file_info_put(ctx->fi);

	/*
	 * ctx->bv is only set if setup_aio_ctx_iter() was call successfuly
	 * which means that iov_iter_get_pages() was a success and thus that
	 * we have taken reference on pages.
	 */
	if (ctx->bv) {
		unsigned i;

		for (i = 0; i < ctx->npages; i++) {
			if (ctx->should_dirty)
				set_page_dirty(ctx->bv[i].bv_page);
			put_page(ctx->bv[i].bv_page);
		}
		kvfree(ctx->bv);
	}

	kfree(ctx);
}

#define CIFS_AIO_KMALLOC_LIMIT (1024 * 1024)

int
setup_aio_ctx_iter(struct smbfs_aio_ctx *ctx, struct iov_iter *iter, int rw)
{
	ssize_t rc;
	unsigned int cur_npages;
	unsigned int npages = 0;
	unsigned int i;
	size_t len;
	size_t count = iov_iter_count(iter);
	unsigned int saved_len;
	size_t start;
	unsigned int max_pages = iov_iter_npages(iter, INT_MAX);
	struct page **pages = NULL;
	struct bio_vec *bv = NULL;

	if (iov_iter_is_kvec(iter)) {
		memcpy(&ctx->iter, iter, sizeof(*iter));
		ctx->len = count;
		iov_iter_advance(iter, count);
		return 0;
	}

	if (array_size(max_pages, sizeof(*bv)) <= CIFS_AIO_KMALLOC_LIMIT)
		bv = kmalloc_array(max_pages, sizeof(*bv), GFP_KERNEL);

	if (!bv) {
		bv = vmalloc(array_size(max_pages, sizeof(*bv)));
		if (!bv)
			return -ENOMEM;
	}

	if (array_size(max_pages, sizeof(*pages)) <= CIFS_AIO_KMALLOC_LIMIT)
		pages = kmalloc_array(max_pages, sizeof(*pages), GFP_KERNEL);

	if (!pages) {
		pages = vmalloc(array_size(max_pages, sizeof(*pages)));
		if (!pages) {
			kvfree(bv);
			return -ENOMEM;
		}
	}

	saved_len = count;

	while (count && npages < max_pages) {
		rc = iov_iter_get_pages(iter, pages, count, max_pages, &start);
		if (rc < 0) {
			smbfs_log("Couldn't get user pages (rc=%zd)\n", rc);
			break;
		}

		if (rc > count) {
			smbfs_log("get pages rc=%zd more than %zu\n", rc,
				 count);
			break;
		}

		iov_iter_advance(iter, rc);
		count -= rc;
		rc += start;
		cur_npages = DIV_ROUND_UP(rc, PAGE_SIZE);

		if (npages + cur_npages > max_pages) {
			smbfs_log("out of vec array capacity (%u vs %u)\n",
				 npages + cur_npages, max_pages);
			break;
		}

		for (i = 0; i < cur_npages; i++) {
			len = rc > PAGE_SIZE ? PAGE_SIZE : rc;
			bv[npages + i].bv_page = pages[i];
			bv[npages + i].bv_offset = start;
			bv[npages + i].bv_len = len - start;
			rc -= len;
			start = 0;
		}

		npages += cur_npages;
	}

	kvfree(pages);
	ctx->bv = bv;
	ctx->len = saved_len - count;
	ctx->npages = npages;
	iov_iter_bvec(&ctx->iter, rw, ctx->bv, npages, ctx->len);
	return 0;
}

/**
 * cifs_alloc_hash - allocate hash and hash context together
 * @name: The name of the crypto hash algo
 * @shash: Where to put the pointer to the hash algo
 * @sec_desc: Where to put the pointer to the hash descriptor
 *
 * The caller has to make sure @sec_desc is initialized to either NULL or
 * a valid context. Both can be freed via cifs_free_hash().
 */
int
cifs_alloc_hash(const char *name,
		struct crypto_shash **shash, struct smbfs_sec_desc **sec_desc)
{
	int rc = 0;
	size_t size;

	if (*sec_desc != NULL)
		return 0;

	*shash = crypto_alloc_shash(name, 0, 0);
	if (IS_ERR(*shash)) {
		smbfs_log("Could not allocate crypto %s\n", name);
		rc = PTR_ERR(*shash);
		*shash = NULL;
		*sec_desc = NULL;
		return rc;
	}

	size = sizeof(struct shash_desc) + crypto_shash_descsize(*shash);
	*sec_desc = kmalloc(size, GFP_KERNEL);
	if (*sec_desc == NULL) {
		smbfs_log("no memory left to allocate crypto %s\n", name);
		crypto_free_shash(*shash);
		*shash = NULL;
		return -ENOMEM;
	}

	(*sec_desc)->shash.tfm = *shash;
	return 0;
}

/**
 * cifs_free_hash - free hash and hash context together
 * @shash: Where to find the pointer to the hash algo
 * @sec_desc: Where to find the pointer to the hash descriptor
 *
 * Freeing a NULL hash or context is safe.
 */
void
cifs_free_hash(struct crypto_shash **shash, struct smbfs_sec_desc **sec_desc)
{
	kfree(*sec_desc);
	*sec_desc = NULL;
	if (*shash)
		crypto_free_shash(*shash);
	*shash = NULL;
}

/**
 * rqst_page_get_length - obtain the length and offset for a page in smb_rqst
 * @rqst: The request descriptor
 * @page: The index of the page to query
 * @len: Where to store the length for this page:
 * @offset: Where to store the offset for this page
 */
void rqst_page_get_length(struct smb_rqst *rqst, unsigned int page,
				unsigned int *len, unsigned int *offset)
{
	*len = rqst->rq_pagesz;
	*offset = (page == 0) ? rqst->rq_offset : 0;

	if (rqst->rq_npages == 1 || page == rqst->rq_npages-1)
		*len = rqst->rq_tailsz;
	else if (page == 0)
		*len = rqst->rq_pagesz - rqst->rq_offset;
}

void extract_unc_hostname(const char *unc, const char **h, size_t *len)
{
	const char *end;

	/* skip initial slashes */
	while (*unc && (*unc == '\\' || *unc == '/'))
		unc++;

	end = unc;

	while (*end && !(*end == '\\' || *end == '/'))
		end++;

	*h = unc;
	*len = end - unc;
}

/**
 * copy_path_name - copy src path to dst, possibly truncating
 * @dst: The destination buffer
 * @src: The source name
 *
 * returns number of bytes written (including trailing nul)
 */
int copy_path_name(char *dst, const char *src)
{
	int name_len;

	/*
	 * PATH_MAX includes nul, so if strlen(src) >= PATH_MAX it
	 * will truncate and strlen(dst) will be PATH_MAX-1
	 */
	name_len = strscpy(dst, src, PATH_MAX);
	if (WARN_ON_ONCE(name_len < 0))
		name_len = PATH_MAX-1;

	/* we count the trailing nul */
	name_len++;
	return name_len;
}

struct super_cb_data {
	void *data;
	struct super_block *sb;
};

static void tcp_super_cb(struct super_block *sb, void *arg)
{
	struct super_cb_data *sd = arg;
	struct smbfs_server_info *server = sd->data;
	struct cifs_sb_info *cifs_sb;
	struct smbfs_tcon *tcon;

	if (sd->sb)
		return;

	cifs_sb = CIFS_SB(sb);
	tcon = smbfs_sb_master_tcon(cifs_sb);
	if (tcon->ses->server == server)
		sd->sb = sb;
}

static struct super_block *__cifs_get_super(void (*f)(struct super_block *, void *),
					    void *data)
{
	struct super_cb_data sd = {
		.data = data,
		.sb = NULL,
	};
	struct file_system_type **fs_type = (struct file_system_type *[]) {
		&cifs_fs_type, &smb3_fs_type, NULL,
	};

	for (; *fs_type; fs_type++) {
		iterate_supers_type(*fs_type, f, &sd);
		if (sd.sb) {
			/*
			 * Grab an active reference in order to prevent automounts (DFS links)
			 * of expiring and then freeing up our cifs superblock pointer while
			 * we're doing failover.
			 */
			cifs_sb_active(sd.sb);
			return sd.sb;
		}
	}
	return ERR_PTR(-EINVAL);
}

static void __cifs_put_super(struct super_block *sb)
{
	if (!IS_ERR_OR_NULL(sb))
		cifs_sb_deactive(sb);
}

struct super_block *cifs_get_tcp_super(struct smbfs_server_info *server)
{
	return __cifs_get_super(tcp_super_cb, server);
}

void cifs_put_tcp_super(struct super_block *sb)
{
	__cifs_put_super(sb);
}

#ifdef CONFIG_SMBFS_DFS_UPCALL
int match_target_ip(struct smbfs_server_info *server,
		    const char *share, size_t share_len,
		    bool *result)
{
	int rc;
	char *target, *tip = NULL;
	struct sockaddr tipaddr;

	*result = false;

	target = kzalloc(share_len + 3, GFP_KERNEL);
	if (!target) {
		rc = -ENOMEM;
		goto out;
	}

	scnprintf(target, share_len + 3, "\\\\%.*s", (int)share_len, share);

	smbfs_dbg("target name: %s\n", target + 2);

	rc = dns_resolve_server_name_to_ip(target, &tip, NULL);
	if (rc < 0)
		goto out;

	smbfs_dbg("target ip: %s\n", tip);

	if (!cifs_convert_address(&tipaddr, tip, strlen(tip))) {
		smbfs_log("%s: failed to convert target ip address\n", __func__);
		rc = -EINVAL;
		goto out;
	}

	*result = cifs_match_ipaddr((struct sockaddr *)&server->dstaddr,
				    &tipaddr);
	smbfs_dbg("ip addresses match: %u\n", *result);
	rc = 0;

out:
	kfree(target);
	kfree(tip);

	return rc;
}

int cifs_update_super_prepath(struct cifs_sb_info *cifs_sb, char *prefix)
{
	kfree(cifs_sb->prepath);

	if (prefix && *prefix) {
		cifs_sb->prepath = kstrdup(prefix, GFP_ATOMIC);
		if (!cifs_sb->prepath)
			return -ENOMEM;

		convert_delimiter(cifs_sb->prepath, dir_sep(cifs_sb));
	} else
		cifs_sb->prepath = NULL;

	cifs_sb->mnt_cifs_flags |= CIFS_MOUNT_USE_PREFIX_PATH;
	return 0;
}

/** cifs_dfs_query_info_nonascii_quirk
 * Handle weird Windows SMB server behaviour. It responds with
 * STATUS_OBJECT_NAME_INVALID code to SMB2 QUERY_INFO request
 * for "\<server>\<dfsname>\<linkpath>" DFS reference,
 * where <dfsname> contains non-ASCII unicode symbols.
 *
 * Check such DFS reference.
 */
int cifs_dfs_query_info_nonascii_quirk(const unsigned int xid,
				       struct smbfs_tcon *tcon,
				       struct cifs_sb_info *cifs_sb,
				       const char *linkpath)
{
	char *treename, *dfspath, sep;
	int treenamelen, linkpathlen, rc;

	treename = tcon->tree_name;
	/* MS-DFSC: All paths in REQ_GET_DFS_REFERRAL and RESP_GET_DFS_REFERRAL
	 * messages MUST be encoded with exactly one leading backslash, not two
	 * leading backslashes.
	 */
	sep = dir_sep(cifs_sb);
	if (treename[0] == sep && treename[1] == sep)
		treename++;
	linkpathlen = strlen(linkpath);
	treenamelen = strnlen(treename, SMBFS_MAX_TREE_SIZE + 1);
	dfspath = kzalloc(treenamelen + linkpathlen + 1, GFP_KERNEL);
	if (!dfspath)
		return -ENOMEM;
	if (treenamelen)
		memcpy(dfspath, treename, treenamelen);
	memcpy(dfspath + treenamelen, linkpath, linkpathlen);
	rc = dfs_cache_find(xid, tcon->ses, cifs_sb->local_nls,
			    cifs_remap(cifs_sb), dfspath, NULL, NULL);

	smbfs_dbg("dfs_cache_find returned %d\n", rc);
	if (rc == 0) {
		smbfs_dbg("DFS ref '%s' is found, emulate -EREMOTE\n", dfspath);
		rc = -EREMOTE;
	}

	kfree(dfspath);
	return rc;
}
#endif
