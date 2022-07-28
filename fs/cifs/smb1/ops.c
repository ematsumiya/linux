// SPDX-License-Identifier: GPL-2.0-only
/*
 *  SMB1 (CIFS) version specific operations
 *
 *  Copyright (c) 2012, Jeff Layton <jlayton@redhat.com>
 */

#include <linux/pagemap.h>
#include <linux/vfs.h>
#include <uapi/linux/magic.h>
#include "../globals.h"
#include "prototypes.h"
#include "../debug.h"
#include "pdu.h"
#include "../unicode.h"
#include "fs_context.h"

/*
 * An NT cancel request header looks just like the original request except:
 *
 * The Command is SMB_COM_NT_CANCEL
 * The WordCount is zeroed out
 * The ByteCount is zeroed out
 *
 * This function mangles an existing request buffer into a
 * SMB_COM_NT_CANCEL request and then sends it.
 */
static int
send_nt_cancel(struct TCP_Server_Info *server, struct smb_rqst *rqst,
	       struct mid_q_entry *mid)
{
	int rc = 0;
	struct smb_hdr *in_buf = (struct smb_hdr *)rqst->rq_iov[0].iov_base;

	/* -4 for RFC1001 length and +2 for BCC field */
	in_buf->smb_buf_length = cpu_to_be32(sizeof(struct smb_hdr) - 4  + 2);
	in_buf->Command = SMB_COM_NT_CANCEL;
	in_buf->WordCount = 0;
	put_bcc(0, in_buf);

	cifs_server_lock(server);
	rc = cifs_sign_smb(in_buf, server, &mid->sequence_number);
	if (rc) {
		cifs_server_unlock(server);
		return rc;
	}

	/*
	 * The response to this call was already factored into the sequence
	 * number when the call went out, so we must adjust it back downward
	 * after signing here.
	 */
	--server->sequence_number;
	rc = smb_send(server, in_buf, be32_to_cpu(in_buf->smb_buf_length));
	if (rc < 0)
		server->sequence_number--;

	cifs_server_unlock(server);

	cifs_dbg(FYI, "issued NT_CANCEL for mid %u, rc = %d\n",
		 get_mid(in_buf), rc);

	return rc;
}

static bool
cifs_compare_fids(struct cifsFileInfo *ob1, struct cifsFileInfo *ob2)
{
	return ob1->fid.netfid == ob2->fid.netfid;
}

static unsigned int
cifs_read_data_offset(char *buf)
{
	READ_RSP *rsp = (READ_RSP *)buf;
	return le16_to_cpu(rsp->DataOffset);
}

static unsigned int
cifs_read_data_length(char *buf, bool in_remaining)
{
	READ_RSP *rsp = (READ_RSP *)buf;
	/* It's a bug reading remaining data for SMB1 packets */
	WARN_ON(in_remaining);
	return (le16_to_cpu(rsp->DataLengthHigh) << 16) +
	       le16_to_cpu(rsp->DataLength);
}

static struct mid_q_entry *
cifs_find_mid(struct TCP_Server_Info *server, char *buffer)
{
	struct smb_hdr *buf = (struct smb_hdr *)buffer;
	struct mid_q_entry *mid;

	spin_lock(&GlobalMid_Lock);
	list_for_each_entry(mid, &server->pending_mid_q, qhead) {
		if (compare_mid(mid->mid, buf) &&
		    mid->mid_state == MID_REQUEST_SUBMITTED &&
		    le16_to_cpu(mid->command) == buf->Command) {
			kref_get(&mid->refcount);
			spin_unlock(&GlobalMid_Lock);
			return mid;
		}
	}
	spin_unlock(&GlobalMid_Lock);
	return NULL;
}

static void
cifs_add_credits(struct TCP_Server_Info *server,
		 const struct cifs_credits *credits, const int optype)
{
	spin_lock(&server->req_lock);
	server->credits += credits->value;
	server->in_flight--;
	spin_unlock(&server->req_lock);
	wake_up(&server->request_q);
}

static void
cifs_set_credits(struct TCP_Server_Info *server, const int val)
{
	spin_lock(&server->req_lock);
	server->credits = val;
	server->oplocks = val > 1 ? enable_oplocks : false;
	spin_unlock(&server->req_lock);
}

static int *
cifs_get_credits_field(struct TCP_Server_Info *server, const int optype)
{
	return &server->credits;
}

static unsigned int
cifs_get_credits(struct mid_q_entry *mid)
{
	return 1;
}

/*
 * Find a free multiplex id (SMB mid). Otherwise there could be
 * mid collisions which might cause problems, demultiplexing the
 * wrong response to this request. Multiplex ids could collide if
 * one of a series requests takes much longer than the others, or
 * if a very large number of long lived requests (byte range
 * locks or FindNotify requests) are pending. No more than
 * 64K-1 requests can be outstanding at one time. If no
 * mids are available, return zero. A future optimization
 * could make the combination of mids and uid the key we use
 * to demultiplex on (rather than mid alone).
 * In addition to the above check, the cifs demultiplex
 * code already used the command code as a secondary
 * check of the frame and if signing is negotiated the
 * response would be discarded if the mid were the same
 * but the signature was wrong. Since the mid is not put in the
 * pending queue until later (when it is about to be dispatched)
 * we do have to limit the number of outstanding requests
 * to somewhat less than 64K-1 although it is hard to imagine
 * so many threads being in the vfs at one time.
 */
static __u64
cifs_get_next_mid(struct TCP_Server_Info *server)
{
	__u64 mid = 0;
	__u16 last_mid, cur_mid;
	bool collision, reconnect = false;

	spin_lock(&GlobalMid_Lock);

	/* mid is 16 bit only for CIFS/SMB */
	cur_mid = (__u16)((server->CurrentMid) & 0xffff);
	/* we do not want to loop forever */
	last_mid = cur_mid;
	cur_mid++;
	/* avoid 0xFFFF MID */
	if (cur_mid == 0xffff)
		cur_mid++;

	/*
	 * This nested loop looks more expensive than it is.
	 * In practice the list of pending requests is short,
	 * fewer than 50, and the mids are likely to be unique
	 * on the first pass through the loop unless some request
	 * takes longer than the 64 thousand requests before it
	 * (and it would also have to have been a request that
	 * did not time out).
	 */
	while (cur_mid != last_mid) {
		struct mid_q_entry *mid_entry;
		unsigned int num_mids;

		collision = false;
		if (cur_mid == 0)
			cur_mid++;

		num_mids = 0;
		list_for_each_entry(mid_entry, &server->pending_mid_q, qhead) {
			++num_mids;
			if (mid_entry->mid == cur_mid &&
			    mid_entry->mid_state == MID_REQUEST_SUBMITTED) {
				/* This mid is in use, try a different one */
				collision = true;
				break;
			}
		}

		/*
		 * if we have more than 32k mids in the list, then something
		 * is very wrong. Possibly a local user is trying to DoS the
		 * box by issuing long-running calls and SIGKILL'ing them. If
		 * we get to 2^16 mids then we're in big trouble as this
		 * function could loop forever.
		 *
		 * Go ahead and assign out the mid in this situation, but force
		 * an eventual reconnect to clean out the pending_mid_q.
		 */
		if (num_mids > 32768)
			reconnect = true;

		if (!collision) {
			mid = (__u64)cur_mid;
			server->CurrentMid = mid;
			break;
		}
		cur_mid++;
	}
	spin_unlock(&GlobalMid_Lock);

	if (reconnect) {
		cifs_signal_cifsd_for_reconnect(server, false);
	}

	return mid;
}

/*
	return codes:
		0	not a transact2, or all data present
		>0	transact2 with that much data missing
		-EINVAL	invalid transact2
 */
static int
check2ndT2(char *buf)
{
	struct smb_hdr *pSMB = (struct smb_hdr *)buf;
	struct smb_t2_rsp *pSMBt;
	int remaining;
	__u16 total_data_size, data_in_this_rsp;

	if (pSMB->Command != SMB_COM_TRANSACTION2)
		return 0;

	/* check for plausible wct, bcc and t2 data and parm sizes */
	/* check for parm and data offset going beyond end of smb */
	if (pSMB->WordCount != 10) { /* coalesce_t2 depends on this */
		cifs_dbg(FYI, "Invalid transact2 word count\n");
		return -EINVAL;
	}

	pSMBt = (struct smb_t2_rsp *)pSMB;

	total_data_size = get_unaligned_le16(&pSMBt->t2_rsp.TotalDataCount);
	data_in_this_rsp = get_unaligned_le16(&pSMBt->t2_rsp.DataCount);

	if (total_data_size == data_in_this_rsp)
		return 0;
	else if (total_data_size < data_in_this_rsp) {
		cifs_dbg(FYI, "total data %d smaller than data in frame %d\n",
			 total_data_size, data_in_this_rsp);
		return -EINVAL;
	}

	remaining = total_data_size - data_in_this_rsp;

	cifs_dbg(FYI, "missing %d bytes from transact2, check next response\n",
		 remaining);
	if (total_data_size > CIFSMaxBufSize) {
		cifs_dbg(VFS, "TotalDataSize %d is over maximum buffer %d\n",
			 total_data_size, CIFSMaxBufSize);
		return -EINVAL;
	}
	return remaining;
}

static int
coalesce_t2(char *second_buf, struct smb_hdr *target_hdr)
{
	struct smb_t2_rsp *pSMBs = (struct smb_t2_rsp *)second_buf;
	struct smb_t2_rsp *pSMBt  = (struct smb_t2_rsp *)target_hdr;
	char *data_area_of_tgt;
	char *data_area_of_src;
	int remaining;
	unsigned int byte_count, total_in_tgt;
	__u16 tgt_total_cnt, src_total_cnt, total_in_src;

	src_total_cnt = get_unaligned_le16(&pSMBs->t2_rsp.TotalDataCount);
	tgt_total_cnt = get_unaligned_le16(&pSMBt->t2_rsp.TotalDataCount);

	if (tgt_total_cnt != src_total_cnt)
		cifs_dbg(FYI, "total data count of primary and secondary t2 differ source=%hu target=%hu\n",
			 src_total_cnt, tgt_total_cnt);

	total_in_tgt = get_unaligned_le16(&pSMBt->t2_rsp.DataCount);

	remaining = tgt_total_cnt - total_in_tgt;

	if (remaining < 0) {
		cifs_dbg(FYI, "Server sent too much data. tgt_total_cnt=%hu total_in_tgt=%u\n",
			 tgt_total_cnt, total_in_tgt);
		return -EPROTO;
	}

	if (remaining == 0) {
		/* nothing to do, ignore */
		cifs_dbg(FYI, "no more data remains\n");
		return 0;
	}

	total_in_src = get_unaligned_le16(&pSMBs->t2_rsp.DataCount);
	if (remaining < total_in_src)
		cifs_dbg(FYI, "transact2 2nd response contains too much data\n");

	/* find end of first SMB data area */
	data_area_of_tgt = (char *)&pSMBt->hdr.Protocol +
				get_unaligned_le16(&pSMBt->t2_rsp.DataOffset);

	/* validate target area */
	data_area_of_src = (char *)&pSMBs->hdr.Protocol +
				get_unaligned_le16(&pSMBs->t2_rsp.DataOffset);

	data_area_of_tgt += total_in_tgt;

	total_in_tgt += total_in_src;
	/* is the result too big for the field? */
	if (total_in_tgt > USHRT_MAX) {
		cifs_dbg(FYI, "coalesced DataCount too large (%u)\n",
			 total_in_tgt);
		return -EPROTO;
	}
	put_unaligned_le16(total_in_tgt, &pSMBt->t2_rsp.DataCount);

	/* fix up the BCC */
	byte_count = get_bcc(target_hdr);
	byte_count += total_in_src;
	/* is the result too big for the field? */
	if (byte_count > USHRT_MAX) {
		cifs_dbg(FYI, "coalesced BCC too large (%u)\n", byte_count);
		return -EPROTO;
	}
	put_bcc(byte_count, target_hdr);

	byte_count = be32_to_cpu(target_hdr->smb_buf_length);
	byte_count += total_in_src;
	/* don't allow buffer to overflow */
	if (byte_count > CIFSMaxBufSize + MAX_CIFS_HDR_SIZE - 4) {
		cifs_dbg(FYI, "coalesced BCC exceeds buffer size (%u)\n",
			 byte_count);
		return -ENOBUFS;
	}
	target_hdr->smb_buf_length = cpu_to_be32(byte_count);

	/* copy second buffer into end of first buffer */
	memcpy(data_area_of_tgt, data_area_of_src, total_in_src);

	if (remaining != total_in_src) {
		/* more responses to go */
		cifs_dbg(FYI, "waiting for more secondary responses\n");
		return 1;
	}

	/* we are done */
	cifs_dbg(FYI, "found the last secondary response\n");
	return 0;
}

static void
cifs_downgrade_oplock(struct TCP_Server_Info *server,
		      struct cifsInodeInfo *cinode, __u32 oplock,
		      unsigned int epoch, bool *purge_cache)
{
	cifs_set_oplock_level(cinode, oplock);
}

static bool
cifs_check_trans2(struct mid_q_entry *mid, struct TCP_Server_Info *server,
		  char *buf, int malformed)
{
	if (malformed)
		return false;
	if (check2ndT2(buf) <= 0)
		return false;
	mid->multiRsp = true;
	if (mid->resp_buf) {
		/* merge response - fix up 1st*/
		malformed = coalesce_t2(buf, mid->resp_buf);
		if (malformed > 0)
			return true;
		/* All parts received or packet is malformed. */
		mid->multiEnd = true;
		dequeue_mid(mid, malformed);
		return true;
	}
	if (!server->large_buf) {
		/*FIXME: switch to already allocated largebuf?*/
		cifs_dbg(VFS, "1st trans2 resp needs bigbuf\n");
	} else {
		/* Have first buffer */
		mid->resp_buf = buf;
		mid->large_buf = true;
		server->bigbuf = NULL;
	}
	return true;
}

static bool
cifs_need_neg(struct TCP_Server_Info *server)
{
	return server->maxBuf == 0;
}

static int
cifs_negotiate(const unsigned int xid,
	       struct cifs_ses *ses,
	       struct TCP_Server_Info *server)
{
	int rc;
	rc = CIFSSMBNegotiate(xid, ses, server);
	if (rc == -EAGAIN) {
		/* retry only once on 1st time connection */
		set_credits(server, 1);
		rc = CIFSSMBNegotiate(xid, ses, server);
		if (rc == -EAGAIN)
			rc = -EHOSTDOWN;
	}
	return rc;
}

static unsigned int
cifs_negotiate_wsize(struct cifs_tcon *tcon, struct smb3_fs_context *ctx)
{
	__u64 unix_cap = le64_to_cpu(tcon->fsUnixInfo.Capability);
	struct TCP_Server_Info *server = tcon->ses->server;
	unsigned int wsize;

	/* start with specified wsize, or default */
	if (ctx->wsize)
		wsize = ctx->wsize;
	else if (tcon->unix_ext && (unix_cap & CIFS_UNIX_LARGE_WRITE_CAP))
		wsize = CIFS_DEFAULT_IOSIZE;
	else
		wsize = CIFS_DEFAULT_NON_POSIX_WSIZE;

	/* can server support 24-bit write sizes? (via UNIX extensions) */
	if (!tcon->unix_ext || !(unix_cap & CIFS_UNIX_LARGE_WRITE_CAP))
		wsize = min_t(unsigned int, wsize, CIFS_MAX_RFC1002_WSIZE);

	/*
	 * no CAP_LARGE_WRITE_X or is signing enabled without CAP_UNIX set?
	 * Limit it to max buffer offered by the server, minus the size of the
	 * WRITEX header, not including the 4 byte RFC1001 length.
	 */
	if (!(server->capabilities & CAP_LARGE_WRITE_X) ||
	    (!(server->capabilities & CAP_UNIX) && server->sign))
		wsize = min_t(unsigned int, wsize,
				server->maxBuf - sizeof(WRITE_REQ) + 4);

	/* hard limit of CIFS_MAX_WSIZE */
	wsize = min_t(unsigned int, wsize, CIFS_MAX_WSIZE);

	return wsize;
}

static unsigned int
cifs_negotiate_rsize(struct cifs_tcon *tcon, struct smb3_fs_context *ctx)
{
	__u64 unix_cap = le64_to_cpu(tcon->fsUnixInfo.Capability);
	struct TCP_Server_Info *server = tcon->ses->server;
	unsigned int rsize, defsize;

	/*
	 * Set default value...
	 *
	 * HACK alert! Ancient servers have very small buffers. Even though
	 * MS-CIFS indicates that servers are only limited by the client's
	 * bufsize for reads, testing against win98se shows that it throws
	 * INVALID_PARAMETER errors if you try to request too large a read.
	 * OS/2 just sends back short reads.
	 *
	 * If the server doesn't advertise CAP_LARGE_READ_X, then assume that
	 * it can't handle a read request larger than its MaxBufferSize either.
	 */
	if (tcon->unix_ext && (unix_cap & CIFS_UNIX_LARGE_READ_CAP))
		defsize = CIFS_DEFAULT_IOSIZE;
	else if (server->capabilities & CAP_LARGE_READ_X)
		defsize = CIFS_DEFAULT_NON_POSIX_RSIZE;
	else
		defsize = server->maxBuf - sizeof(READ_RSP);

	rsize = ctx->rsize ? ctx->rsize : defsize;

	/*
	 * no CAP_LARGE_READ_X? Then MS-CIFS states that we must limit this to
	 * the client's MaxBufferSize.
	 */
	if (!(server->capabilities & CAP_LARGE_READ_X))
		rsize = min_t(unsigned int, CIFSMaxBufSize, rsize);

	/* hard limit of CIFS_MAX_RSIZE */
	rsize = min_t(unsigned int, rsize, CIFS_MAX_RSIZE);

	return rsize;
}

static void
cifs_qfs_tcon(const unsigned int xid, struct cifs_tcon *tcon,
	      struct cifs_sb_info *cifs_sb)
{
	CIFSSMBQFSDeviceInfo(xid, tcon);
	CIFSSMBQFSAttributeInfo(xid, tcon);
}

static int
cifs_is_path_accessible(const unsigned int xid, struct cifs_tcon *tcon,
			struct cifs_sb_info *cifs_sb, const char *full_path)
{
	int rc;
	FILE_ALL_INFO *file_info;

	file_info = kmalloc(sizeof(FILE_ALL_INFO), GFP_KERNEL);
	if (file_info == NULL)
		return -ENOMEM;

	rc = CIFSSMBQPathInfo(xid, tcon, full_path, file_info,
			      0 /* not legacy */, cifs_sb->local_nls,
			      cifs_remap(cifs_sb));

	if (rc == -EOPNOTSUPP || rc == -EINVAL)
		rc = SMBQueryInformation(xid, tcon, full_path, file_info,
				cifs_sb->local_nls, cifs_remap(cifs_sb));
	kfree(file_info);
	return rc;
}

static int
cifs_query_path_info(const unsigned int xid, struct cifs_tcon *tcon,
		     struct cifs_sb_info *cifs_sb, const char *full_path,
		     FILE_ALL_INFO *data, bool *adjustTZ, bool *symlink)
{
	int rc;

	*symlink = false;

	/* could do find first instead but this returns more info */
	rc = CIFSSMBQPathInfo(xid, tcon, full_path, data, 0 /* not legacy */,
			      cifs_sb->local_nls, cifs_remap(cifs_sb));
	/*
	 * BB optimize code so we do not make the above call when server claims
	 * no NT SMB support and the above call failed at least once - set flag
	 * in tcon or mount.
	 */
	if ((rc == -EOPNOTSUPP) || (rc == -EINVAL)) {
		rc = SMBQueryInformation(xid, tcon, full_path, data,
					 cifs_sb->local_nls,
					 cifs_remap(cifs_sb));
		*adjustTZ = true;
	}

	if (!rc && (le32_to_cpu(data->Attributes) & ATTR_REPARSE)) {
		int tmprc;
		int oplock = 0;
		struct cifs_fid fid;
		struct cifs_open_parms oparms;

		oparms.tcon = tcon;
		oparms.cifs_sb = cifs_sb;
		oparms.desired_access = FILE_READ_ATTRIBUTES;
		oparms.create_options = cifs_create_options(cifs_sb, 0);
		oparms.disposition = FILE_OPEN;
		oparms.path = full_path;
		oparms.fid = &fid;
		oparms.reconnect = false;

		/* Need to check if this is a symbolic link or not */
		tmprc = CIFS_open(xid, &oparms, &oplock, NULL);
		if (tmprc == -EOPNOTSUPP)
			*symlink = true;
		else if (tmprc == 0)
			CIFSSMBClose(xid, tcon, fid.netfid);
	}

	return rc;
}

static int
cifs_get_srv_inum(const unsigned int xid, struct cifs_tcon *tcon,
		  struct cifs_sb_info *cifs_sb, const char *full_path,
		  u64 *uniqueid, FILE_ALL_INFO *data)
{
	/*
	 * We can not use the IndexNumber field by default from Windows or
	 * Samba (in ALL_INFO buf) but we can request it explicitly. The SNIA
	 * CIFS spec claims that this value is unique within the scope of a
	 * share, and the windows docs hint that it's actually unique
	 * per-machine.
	 *
	 * There may be higher info levels that work but are there Windows
	 * server or network appliances for which IndexNumber field is not
	 * guaranteed unique?
	 */
	return CIFSGetSrvInodeNumber(xid, tcon, full_path, uniqueid,
				     cifs_sb->local_nls,
				     cifs_remap(cifs_sb));
}

static int
cifs_query_file_info(const unsigned int xid, struct cifs_tcon *tcon,
		     struct cifs_fid *fid, FILE_ALL_INFO *data)
{
	return CIFSSMBQFileInfo(xid, tcon, fid->netfid, data);
}

static void
cifs_clear_stats(struct cifs_tcon *tcon)
{
	atomic_set(&tcon->stats.cifs_stats.num_writes, 0);
	atomic_set(&tcon->stats.cifs_stats.num_reads, 0);
	atomic_set(&tcon->stats.cifs_stats.num_flushes, 0);
	atomic_set(&tcon->stats.cifs_stats.num_oplock_brks, 0);
	atomic_set(&tcon->stats.cifs_stats.num_opens, 0);
	atomic_set(&tcon->stats.cifs_stats.num_posixopens, 0);
	atomic_set(&tcon->stats.cifs_stats.num_posixmkdirs, 0);
	atomic_set(&tcon->stats.cifs_stats.num_closes, 0);
	atomic_set(&tcon->stats.cifs_stats.num_deletes, 0);
	atomic_set(&tcon->stats.cifs_stats.num_mkdirs, 0);
	atomic_set(&tcon->stats.cifs_stats.num_rmdirs, 0);
	atomic_set(&tcon->stats.cifs_stats.num_renames, 0);
	atomic_set(&tcon->stats.cifs_stats.num_t2renames, 0);
	atomic_set(&tcon->stats.cifs_stats.num_ffirst, 0);
	atomic_set(&tcon->stats.cifs_stats.num_fnext, 0);
	atomic_set(&tcon->stats.cifs_stats.num_fclose, 0);
	atomic_set(&tcon->stats.cifs_stats.num_hardlinks, 0);
	atomic_set(&tcon->stats.cifs_stats.num_symlinks, 0);
	atomic_set(&tcon->stats.cifs_stats.num_locks, 0);
	atomic_set(&tcon->stats.cifs_stats.num_acl_get, 0);
	atomic_set(&tcon->stats.cifs_stats.num_acl_set, 0);
}

static void
cifs_print_stats(struct seq_file *m, struct cifs_tcon *tcon)
{
	seq_printf(m, " Oplocks breaks: %d",
		   atomic_read(&tcon->stats.cifs_stats.num_oplock_brks));
	seq_printf(m, "\nReads:  %d Bytes: %llu",
		   atomic_read(&tcon->stats.cifs_stats.num_reads),
		   (long long)(tcon->bytes_read));
	seq_printf(m, "\nWrites: %d Bytes: %llu",
		   atomic_read(&tcon->stats.cifs_stats.num_writes),
		   (long long)(tcon->bytes_written));
	seq_printf(m, "\nFlushes: %d",
		   atomic_read(&tcon->stats.cifs_stats.num_flushes));
	seq_printf(m, "\nLocks: %d HardLinks: %d Symlinks: %d",
		   atomic_read(&tcon->stats.cifs_stats.num_locks),
		   atomic_read(&tcon->stats.cifs_stats.num_hardlinks),
		   atomic_read(&tcon->stats.cifs_stats.num_symlinks));
	seq_printf(m, "\nOpens: %d Closes: %d Deletes: %d",
		   atomic_read(&tcon->stats.cifs_stats.num_opens),
		   atomic_read(&tcon->stats.cifs_stats.num_closes),
		   atomic_read(&tcon->stats.cifs_stats.num_deletes));
	seq_printf(m, "\nPosix Opens: %d Posix Mkdirs: %d",
		   atomic_read(&tcon->stats.cifs_stats.num_posixopens),
		   atomic_read(&tcon->stats.cifs_stats.num_posixmkdirs));
	seq_printf(m, "\nMkdirs: %d Rmdirs: %d",
		   atomic_read(&tcon->stats.cifs_stats.num_mkdirs),
		   atomic_read(&tcon->stats.cifs_stats.num_rmdirs));
	seq_printf(m, "\nRenames: %d T2 Renames %d",
		   atomic_read(&tcon->stats.cifs_stats.num_renames),
		   atomic_read(&tcon->stats.cifs_stats.num_t2renames));
	seq_printf(m, "\nFindFirst: %d FNext %d FClose %d",
		   atomic_read(&tcon->stats.cifs_stats.num_ffirst),
		   atomic_read(&tcon->stats.cifs_stats.num_fnext),
		   atomic_read(&tcon->stats.cifs_stats.num_fclose));
}

static void
cifs_mkdir_setinfo(struct inode *inode, const char *full_path,
		   struct cifs_sb_info *cifs_sb, struct cifs_tcon *tcon,
		   const unsigned int xid)
{
	FILE_BASIC_INFO info;
	struct cifsInodeInfo *cifsInode;
	u32 dosattrs;
	int rc;

	memset(&info, 0, sizeof(info));
	cifsInode = CIFS_I(inode);
	dosattrs = cifsInode->cifsAttrs|ATTR_READONLY;
	info.Attributes = cpu_to_le32(dosattrs);
	rc = CIFSSMBSetPathInfo(xid, tcon, full_path, &info, cifs_sb->local_nls,
				cifs_sb);
	if (rc == 0)
		cifsInode->cifsAttrs = dosattrs;
}

static int
cifs_open_file(const unsigned int xid, struct cifs_open_parms *oparms,
	       __u32 *oplock, FILE_ALL_INFO *buf)
{
	if (!(oparms->tcon->ses->capabilities & CAP_NT_SMBS))
		return SMBLegacyOpen(xid, oparms->tcon, oparms->path,
				     oparms->disposition,
				     oparms->desired_access,
				     oparms->create_options,
				     &oparms->fid->netfid, oplock, buf,
				     oparms->cifs_sb->local_nls,
				     cifs_remap(oparms->cifs_sb));
	return CIFS_open(xid, oparms, oplock, buf);
}

static void
cifs_set_fid(struct cifsFileInfo *cfile, struct cifs_fid *fid, __u32 oplock)
{
	struct cifsInodeInfo *cinode = CIFS_I(d_inode(cfile->dentry));
	cfile->fid.netfid = fid->netfid;
	cifs_set_oplock_level(cinode, oplock);
	cinode->can_cache_brlcks = CIFS_CACHE_WRITE(cinode);
}

static void
cifs_close_file(const unsigned int xid, struct cifs_tcon *tcon,
		struct cifs_fid *fid)
{
	CIFSSMBClose(xid, tcon, fid->netfid);
}

static int
cifs_flush_file(const unsigned int xid, struct cifs_tcon *tcon,
		struct cifs_fid *fid)
{
	return CIFSSMBFlush(xid, tcon, fid->netfid);
}

static int
cifs_sync_read(const unsigned int xid, struct cifs_fid *pfid,
	       struct cifs_io_parms *parms, unsigned int *bytes_read,
	       char **buf, int *buf_type)
{
	parms->netfid = pfid->netfid;
	return CIFSSMBRead(xid, parms, bytes_read, buf, buf_type);
}

static int
cifs_sync_write(const unsigned int xid, struct cifs_fid *pfid,
		struct cifs_io_parms *parms, unsigned int *written,
		struct kvec *iov, unsigned long nr_segs)
{

	parms->netfid = pfid->netfid;
	return CIFSSMBWrite2(xid, parms, written, iov, nr_segs);
}

static int
smb_set_file_info(struct inode *inode, const char *full_path,
		  FILE_BASIC_INFO *buf, const unsigned int xid)
{
	int oplock = 0;
	int rc;
	__u32 netpid;
	struct cifs_fid fid;
	struct cifs_open_parms oparms;
	struct cifsFileInfo *open_file;
	struct cifsInodeInfo *cinode = CIFS_I(inode);
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct tcon_link *tlink = NULL;
	struct cifs_tcon *tcon;

	/* if the file is already open for write, just use that fileid */
	open_file = find_writable_file(cinode, FIND_WR_FSUID_ONLY);
	if (open_file) {
		fid.netfid = open_file->fid.netfid;
		netpid = open_file->pid;
		tcon = tlink_tcon(open_file->tlink);
		goto set_via_filehandle;
	}

	tlink = cifs_sb_tlink(cifs_sb);
	if (IS_ERR(tlink)) {
		rc = PTR_ERR(tlink);
		tlink = NULL;
		goto out;
	}
	tcon = tlink_tcon(tlink);

	rc = CIFSSMBSetPathInfo(xid, tcon, full_path, buf, cifs_sb->local_nls,
				cifs_sb);
	if (rc == 0) {
		cinode->cifsAttrs = le32_to_cpu(buf->Attributes);
		goto out;
	} else if (rc != -EOPNOTSUPP && rc != -EINVAL) {
		goto out;
	}

	oparms.tcon = tcon;
	oparms.cifs_sb = cifs_sb;
	oparms.desired_access = SYNCHRONIZE | FILE_WRITE_ATTRIBUTES;
	oparms.create_options = cifs_create_options(cifs_sb, CREATE_NOT_DIR);
	oparms.disposition = FILE_OPEN;
	oparms.path = full_path;
	oparms.fid = &fid;
	oparms.reconnect = false;

	cifs_dbg(FYI, "calling SetFileInfo since SetPathInfo for times not supported by this server\n");
	rc = CIFS_open(xid, &oparms, &oplock, NULL);
	if (rc != 0) {
		if (rc == -EIO)
			rc = -EINVAL;
		goto out;
	}

	netpid = current->tgid;

set_via_filehandle:
	rc = CIFSSMBSetFileInfo(xid, tcon, buf, fid.netfid, netpid);
	if (!rc)
		cinode->cifsAttrs = le32_to_cpu(buf->Attributes);

	if (open_file == NULL)
		CIFSSMBClose(xid, tcon, fid.netfid);
	else
		cifsFileInfo_put(open_file);
out:
	if (tlink != NULL)
		cifs_put_tlink(tlink);
	return rc;
}

static int
cifs_set_compression(const unsigned int xid, struct cifs_tcon *tcon,
		   struct cifsFileInfo *cfile)
{
	return CIFSSMB_set_compression(xid, tcon, cfile->fid.netfid);
}

static int
cifs_query_dir_first(const unsigned int xid, struct cifs_tcon *tcon,
		     const char *path, struct cifs_sb_info *cifs_sb,
		     struct cifs_fid *fid, __u16 search_flags,
		     struct cifs_search_info *srch_inf)
{
	int rc;

	rc = CIFSFindFirst(xid, tcon, path, cifs_sb,
			   &fid->netfid, search_flags, srch_inf, true);
	if (rc)
		cifs_dbg(FYI, "find first failed=%d\n", rc);
	return rc;
}

static int
cifs_query_dir_next(const unsigned int xid, struct cifs_tcon *tcon,
		    struct cifs_fid *fid, __u16 search_flags,
		    struct cifs_search_info *srch_inf)
{
	return CIFSFindNext(xid, tcon, fid->netfid, search_flags, srch_inf);
}

static int
cifs_close_dir(const unsigned int xid, struct cifs_tcon *tcon,
	       struct cifs_fid *fid)
{
	return CIFSFindClose(xid, tcon, fid->netfid);
}

static int
cifs_oplock_response(struct cifs_tcon *tcon, struct cifs_fid *fid,
		     struct cifsInodeInfo *cinode)
{
	return CIFSSMBLock(0, tcon, fid->netfid, current->tgid, 0, 0, 0, 0,
			   LOCKING_ANDX_OPLOCK_RELEASE, false,
			   CIFS_CACHE_READ(cinode) ? 1 : 0);
}

static int
cifs_queryfs(const unsigned int xid, struct cifs_tcon *tcon,
	     struct cifs_sb_info *cifs_sb, struct kstatfs *buf)
{
	int rc = -EOPNOTSUPP;

	buf->f_type = CIFS_SUPER_MAGIC;

	/*
	 * We could add a second check for a QFS Unix capability bit
	 */
	if ((tcon->ses->capabilities & CAP_UNIX) &&
	    (CIFS_POSIX_EXTENSIONS & le64_to_cpu(tcon->fsUnixInfo.Capability)))
		rc = CIFSSMBQFSPosixInfo(xid, tcon, buf);

	/*
	 * Only need to call the old QFSInfo if failed on newer one,
	 * e.g. by OS/2.
	 **/
	if (rc && (tcon->ses->capabilities & CAP_NT_SMBS))
		rc = CIFSSMBQFSInfo(xid, tcon, buf);

	/*
	 * Some old Windows servers also do not support level 103, retry with
	 * older level one if old server failed the previous call or we
	 * bypassed it because we detected that this was an older LANMAN sess
	 */
	if (rc)
		rc = SMBOldQFSInfo(xid, tcon, buf);
	return rc;
}

static int
cifs_mand_lock(const unsigned int xid, struct cifsFileInfo *cfile, __u64 offset,
	       __u64 length, __u32 type, int lock, int unlock, bool wait)
{
	return CIFSSMBLock(xid, tlink_tcon(cfile->tlink), cfile->fid.netfid,
			   current->tgid, length, offset, unlock, lock,
			   (__u8)type, wait, 0);
}

static int
cifs_unix_dfs_readlink(const unsigned int xid, struct cifs_tcon *tcon,
		       const unsigned char *searchName, char **symlinkinfo,
		       const struct nls_table *nls_codepage)
{
#ifdef CONFIG_CIFS_DFS_UPCALL
	int rc;
	struct dfs_info3_param referral = {0};

	rc = get_dfs_path(xid, tcon->ses, searchName, nls_codepage, &referral,
			  0);

	if (!rc) {
		*symlinkinfo = kstrdup(referral.node_name, GFP_KERNEL);
		free_dfs_info_param(&referral);
		if (!*symlinkinfo)
			rc = -ENOMEM;
	}
	return rc;
#else /* No DFS support */
	return -EREMOTE;
#endif
}

static int
cifs_query_symlink(const unsigned int xid, struct cifs_tcon *tcon,
		   struct cifs_sb_info *cifs_sb, const char *full_path,
		   char **target_path, bool is_reparse_point)
{
	int rc;
	int oplock = 0;
	struct cifs_fid fid;
	struct cifs_open_parms oparms;

	cifs_dbg(FYI, "%s: path: %s\n", __func__, full_path);

	if (is_reparse_point) {
		cifs_dbg(VFS, "reparse points not handled for SMB1 symlinks\n");
		return -EOPNOTSUPP;
	}

	/* Check for unix extensions */
	if (cap_unix(tcon->ses)) {
		rc = CIFSSMBUnixQuerySymLink(xid, tcon, full_path, target_path,
					     cifs_sb->local_nls,
					     cifs_remap(cifs_sb));
		if (rc == -EREMOTE)
			rc = cifs_unix_dfs_readlink(xid, tcon, full_path,
						    target_path,
						    cifs_sb->local_nls);

		goto out;
	}

	oparms.tcon = tcon;
	oparms.cifs_sb = cifs_sb;
	oparms.desired_access = FILE_READ_ATTRIBUTES;
	oparms.create_options = cifs_create_options(cifs_sb,
						    OPEN_REPARSE_POINT);
	oparms.disposition = FILE_OPEN;
	oparms.path = full_path;
	oparms.fid = &fid;
	oparms.reconnect = false;

	rc = CIFS_open(xid, &oparms, &oplock, NULL);
	if (rc)
		goto out;

	rc = CIFSSMBQuerySymLink(xid, tcon, fid.netfid, target_path,
				 cifs_sb->local_nls);
	if (rc)
		goto out_close;

	convert_delimiter(*target_path, '/');
out_close:
	CIFSSMBClose(xid, tcon, fid.netfid);
out:
	if (!rc)
		cifs_dbg(FYI, "%s: target path: %s\n", __func__, *target_path);
	return rc;
}

static bool
cifs_is_read_op(__u32 oplock)
{
	return oplock == OPLOCK_READ;
}

static unsigned int
cifs_wp_retry_size(struct inode *inode)
{
	return CIFS_SB(inode->i_sb)->ctx->wsize;
}

static bool
cifs_dir_needs_close(struct cifsFileInfo *cfile)
{
	return !cfile->srch_inf.endOfSearch && !cfile->invalidHandle;
}

static bool
cifs_can_echo(struct TCP_Server_Info *server)
{
	if (server->tcpStatus == CifsGood)
		return true;

	return false;
}

static int
cifs_make_node(unsigned int xid, struct inode *inode,
	       struct dentry *dentry, struct cifs_tcon *tcon,
	       const char *full_path, umode_t mode, dev_t dev)
{
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct inode *newinode = NULL;
	int rc = -EPERM;
	FILE_ALL_INFO *buf = NULL;
	struct cifs_io_parms io_parms;
	__u32 oplock = 0;
	struct cifs_fid fid;
	struct cifs_open_parms oparms;
	unsigned int bytes_written;
	struct win_dev *pdev;
	struct kvec iov[2];

	if (tcon->unix_ext) {
		/*
		 * SMB1 Unix Extensions: requires server support but
		 * works with all special files
		 */
		struct cifs_unix_set_info_args args = {
			.mode	= mode & ~current_umask(),
			.ctime	= NO_CHANGE_64,
			.atime	= NO_CHANGE_64,
			.mtime	= NO_CHANGE_64,
			.device	= dev,
		};
		if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_SET_UID) {
			args.uid = current_fsuid();
			args.gid = current_fsgid();
		} else {
			args.uid = INVALID_UID; /* no change */
			args.gid = INVALID_GID; /* no change */
		}
		rc = CIFSSMBUnixSetPathInfo(xid, tcon, full_path, &args,
					    cifs_sb->local_nls,
					    cifs_remap(cifs_sb));
		if (rc)
			goto out;

		rc = cifs_get_inode_info_unix(&newinode, full_path,
					      inode->i_sb, xid);

		if (rc == 0)
			d_instantiate(dentry, newinode);
		goto out;
	}

	/*
	 * SMB1 SFU emulation: should work with all servers, but only
	 * support block and char device (no socket & fifo)
	 */
	if (!(cifs_sb->mnt_cifs_flags & CIFS_MOUNT_UNX_EMUL))
		goto out;

	if (!S_ISCHR(mode) && !S_ISBLK(mode))
		goto out;

	cifs_dbg(FYI, "sfu compat create special file\n");

	buf = kmalloc(sizeof(FILE_ALL_INFO), GFP_KERNEL);
	if (buf == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	oparms.tcon = tcon;
	oparms.cifs_sb = cifs_sb;
	oparms.desired_access = GENERIC_WRITE;
	oparms.create_options = cifs_create_options(cifs_sb, CREATE_NOT_DIR |
						    CREATE_OPTION_SPECIAL);
	oparms.disposition = FILE_CREATE;
	oparms.path = full_path;
	oparms.fid = &fid;
	oparms.reconnect = false;

	if (tcon->ses->server->oplocks)
		oplock = REQ_OPLOCK;
	else
		oplock = 0;
	rc = tcon->ses->server->ops->open(xid, &oparms, &oplock, buf);
	if (rc)
		goto out;

	/*
	 * BB Do not bother to decode buf since no local inode yet to put
	 * timestamps in, but we can reuse it safely.
	 */

	pdev = (struct win_dev *)buf;
	io_parms.pid = current->tgid;
	io_parms.tcon = tcon;
	io_parms.offset = 0;
	io_parms.length = sizeof(struct win_dev);
	iov[1].iov_base = buf;
	iov[1].iov_len = sizeof(struct win_dev);
	if (S_ISCHR(mode)) {
		memcpy(pdev->type, "IntxCHR", 8);
		pdev->major = cpu_to_le64(MAJOR(dev));
		pdev->minor = cpu_to_le64(MINOR(dev));
		rc = tcon->ses->server->ops->sync_write(xid, &fid, &io_parms,
							&bytes_written, iov, 1);
	} else if (S_ISBLK(mode)) {
		memcpy(pdev->type, "IntxBLK", 8);
		pdev->major = cpu_to_le64(MAJOR(dev));
		pdev->minor = cpu_to_le64(MINOR(dev));
		rc = tcon->ses->server->ops->sync_write(xid, &fid, &io_parms,
							&bytes_written, iov, 1);
	}
	tcon->ses->server->ops->close(xid, tcon, &fid);
	d_drop(dentry);

	/* FIXME: add code here to set EAs */
out:
	kfree(buf);
	return rc;
}

static loff_t cifs_remap_file_range(struct file *src_file, loff_t off,
		struct file *dst_file, loff_t destoff, loff_t len,
		unsigned int remap_flags)
{
	struct inode *src_inode = file_inode(src_file);
	struct inode *target_inode = file_inode(dst_file);
	struct cifsFileInfo *smb_file_src = src_file->private_data;
	struct cifsFileInfo *smb_file_target;
	struct cifs_tcon *target_tcon;
	unsigned int xid;
	int rc;

	if (remap_flags & ~(REMAP_FILE_DEDUP | REMAP_FILE_ADVISORY))
		return -EINVAL;

	cifs_dbg(FYI, "clone range\n");

	xid = get_xid();

	if (!src_file->private_data || !dst_file->private_data) {
		rc = -EBADF;
		cifs_dbg(VFS, "missing cifsFileInfo on copy range src file\n");
		goto out;
	}

	smb_file_target = dst_file->private_data;
	target_tcon = tlink_tcon(smb_file_target->tlink);

	/*
	 * Note: cifs case is easier than btrfs since server responsible for
	 * checks for proper open modes and file type and if it wants
	 * server could even support copy of range where source = target
	 */
	lock_two_nondirectories(target_inode, src_inode);

	if (len == 0)
		len = src_inode->i_size - off;

	cifs_dbg(FYI, "about to flush pages\n");
	/* should we flush first and last page first */
	truncate_inode_pages_range(&target_inode->i_data, destoff,
				   PAGE_ALIGN(destoff + len)-1);

	if (target_tcon->ses->server->ops->duplicate_extents)
		rc = target_tcon->ses->server->ops->duplicate_extents(xid,
			smb_file_src, smb_file_target, off, len, destoff);
	else
		rc = -EOPNOTSUPP;

	/* force revalidate of size and timestamps of target file now
	   that target is updated on the server */
	CIFS_I(target_inode)->time = 0;
	/* although unlocking in the reverse order from locking is not
	   strictly necessary here it is a little cleaner to be consistent */
	unlock_two_nondirectories(src_inode, target_inode);
out:
	free_xid(xid);
	return rc < 0 ? rc : len;
}

ssize_t cifs_file_copychunk_range(unsigned int xid,
				struct file *src_file, loff_t off,
				struct file *dst_file, loff_t destoff,
				size_t len, unsigned int flags)
{
	struct inode *src_inode = file_inode(src_file);
	struct inode *target_inode = file_inode(dst_file);
	struct cifsFileInfo *smb_file_src;
	struct cifsFileInfo *smb_file_target;
	struct cifs_tcon *src_tcon;
	struct cifs_tcon *target_tcon;
	ssize_t rc;

	cifs_dbg(FYI, "copychunk range\n");

	if (!src_file->private_data || !dst_file->private_data) {
		rc = -EBADF;
		cifs_dbg(VFS, "missing cifsFileInfo on copy range src file\n");
		goto out;
	}

	rc = -EXDEV;
	smb_file_target = dst_file->private_data;
	smb_file_src = src_file->private_data;
	src_tcon = tlink_tcon(smb_file_src->tlink);
	target_tcon = tlink_tcon(smb_file_target->tlink);

	if (src_tcon->ses != target_tcon->ses) {
		cifs_dbg(VFS, "source and target of copy not on same server\n");
		goto out;
	}

	rc = -EOPNOTSUPP;
	if (!target_tcon->ses->server->ops->copychunk_range)
		goto out;

	/*
	 * Note: cifs case is easier than btrfs since server responsible for
	 * checks for proper open modes and file type and if it wants
	 * server could even support copy of range where source = target
	 */
	lock_two_nondirectories(target_inode, src_inode);

	cifs_dbg(FYI, "about to flush pages\n");
	/* should we flush first and last page first */
	truncate_inode_pages(&target_inode->i_data, 0);

	rc = file_modified(dst_file);
	if (!rc)
		rc = target_tcon->ses->server->ops->copychunk_range(xid,
			smb_file_src, smb_file_target, off, len, destoff);

	file_accessed(src_file);

	/* force revalidate of size and timestamps of target file now
	 * that target is updated on the server
	 */
	CIFS_I(target_inode)->time = 0;
	/* although unlocking in the reverse order from locking is not
	 * strictly necessary here it is a little cleaner to be consistent
	 */
	unlock_two_nondirectories(src_inode, target_inode);

out:
	return rc;
}

/*
 * Directory operations under CIFS/SMB2/SMB3 are synchronous, so fsync()
 * is a dummy operation.
 */
static int cifs_dir_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	cifs_dbg(FYI, "Sync directory - name: %pD datasync: 0x%x\n",
		 file, datasync);

	return 0;
}

static ssize_t cifs_copy_file_range(struct file *src_file, loff_t off,
				struct file *dst_file, loff_t destoff,
				size_t len, unsigned int flags)
{
	unsigned int xid = get_xid();
	ssize_t rc;
	struct cifsFileInfo *cfile = dst_file->private_data;

	if (cfile->swapfile)
		return -EOPNOTSUPP;

	rc = cifs_file_copychunk_range(xid, src_file, off, dst_file, destoff,
					len, flags);
	free_xid(xid);

	if (rc == -EOPNOTSUPP || rc == -EXDEV)
		rc = generic_copy_file_range(src_file, off, dst_file,
					     destoff, len, flags);
	return rc;
}

static ssize_t
cifs_loose_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	ssize_t rc;
	struct inode *inode = file_inode(iocb->ki_filp);

	if (iocb->ki_flags & IOCB_DIRECT)
		return cifs_user_readv(iocb, iter);

	rc = cifs_revalidate_mapping(inode);
	if (rc)
		return rc;

	return generic_file_read_iter(iocb, iter);
}

static ssize_t cifs_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct cifsInodeInfo *cinode = CIFS_I(inode);
	ssize_t written;
	int rc;

	if (iocb->ki_filp->f_flags & O_DIRECT) {
		written = cifs_user_writev(iocb, from);
		if (written > 0 && CIFS_CACHE_READ(cinode)) {
			cifs_zap_mapping(inode);
			cifs_dbg(FYI,
				 "Set no oplock for inode=%p after a write operation\n",
				 inode);
			cinode->oplock = 0;
		}
		return written;
	}

	written = cifs_get_writer(cinode);
	if (written)
		return written;

	written = generic_file_write_iter(iocb, from);

	if (CIFS_CACHE_WRITE(CIFS_I(inode)))
		goto out;

	rc = filemap_fdatawrite(inode->i_mapping);
	if (rc)
		cifs_dbg(FYI, "cifs_file_write_iter: %d rc on %p inode\n",
			 rc, inode);

out:
	cifs_put_writer(cinode);
	return written;
}

static loff_t cifs_llseek(struct file *file, loff_t offset, int whence)
{
	struct cifsFileInfo *cfile = file->private_data;
	struct cifs_tcon *tcon;

	/*
	 * whence == SEEK_END || SEEK_DATA || SEEK_HOLE => we must revalidate
	 * the cached file length
	 */
	if (whence != SEEK_SET && whence != SEEK_CUR) {
		int rc;
		struct inode *inode = file_inode(file);

		/*
		 * We need to be sure that all dirty pages are written and the
		 * server has the newest file length.
		 */
		if (!CIFS_CACHE_READ(CIFS_I(inode)) && inode->i_mapping &&
		    inode->i_mapping->nrpages != 0) {
			rc = filemap_fdatawait(inode->i_mapping);
			if (rc) {
				mapping_set_error(inode->i_mapping, rc);
				return rc;
			}
		}
		/*
		 * Some applications poll for the file length in this strange
		 * way so we must seek to end on non-oplocked files by
		 * setting the revalidate time to zero.
		 */
		CIFS_I(inode)->time = 0;

		rc = cifs_revalidate_file_attr(file);
		if (rc < 0)
			return (loff_t)rc;
	}
	if (cfile && cfile->tlink) {
		tcon = tlink_tcon(cfile->tlink);
		if (tcon->ses->server->ops->llseek)
			return tcon->ses->server->ops->llseek(file, tcon,
							      offset, whence);
	}
	return generic_file_llseek(file, offset, whence);
}

static int
cifs_setlease(struct file *file, long arg, struct file_lock **lease, void **priv)
{
	/*
	 * Note that this is called by vfs setlease with i_lock held to
	 * protect *lease from going away.
	 */
	struct inode *inode = file_inode(file);
	struct cifsFileInfo *cfile = file->private_data;

	if (!(S_ISREG(inode->i_mode)))
		return -EINVAL;

	/* Check if file is oplocked if this is request for new lease */
	if (arg == F_UNLCK ||
	    ((arg == F_RDLCK) && CIFS_CACHE_READ(CIFS_I(inode))) ||
	    ((arg == F_WRLCK) && CIFS_CACHE_WRITE(CIFS_I(inode))))
		return generic_setlease(file, arg, lease, priv);
	else if (tlink_tcon(cfile->tlink)->local_lease &&
		 !CIFS_CACHE_READ(CIFS_I(inode)))
		/*
		 * If the server claims to support oplock on this file, then we
		 * still need to check oplock even if the local_lease mount
		 * option is set, but there are servers which do not support
		 * oplock for which this mount option may be useful if the user
		 * knows that the file won't be changed on the server by anyone
		 * else.
		 */
		return generic_setlease(file, arg, lease, priv);
	else
		return -EAGAIN;
}

static long cifs_fallocate(struct file *file, int mode, loff_t off, loff_t len)
{
	struct cifs_sb_info *cifs_sb = CIFS_FILE_SB(file);
	struct cifs_tcon *tcon = cifs_sb_master_tcon(cifs_sb);
	struct TCP_Server_Info *server = tcon->ses->server;

	if (server->ops->fallocate)
		return server->ops->fallocate(file, tcon, mode, off, len);

	return -EOPNOTSUPP;
}

static int cifs_permission(struct user_namespace *mnt_userns,
			   struct inode *inode, int mask)
{
	struct cifs_sb_info *cifs_sb;

	cifs_sb = CIFS_SB(inode->i_sb);

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NO_PERM) {
		if ((mask & MAY_EXEC) && !execute_ok(inode))
			return -EACCES;
		else
			return 0;
	} else /* file mode might have been restricted at mount time
		on the client (above and beyond ACL on servers) for
		servers which do not support setting and viewing mode bits,
		so allowing client to check permissions is useful */
		return generic_permission(&init_user_ns, inode, mask);
}

static int
check_smb_hdr(struct smb_hdr *smb)
{
	/* does it have the right SMB "signature" ? */
	if (*(__le32 *) smb->Protocol != cpu_to_le32(0x424d53ff)) {
		cifs_dbg(VFS, "Bad protocol string signature header 0x%x\n",
			 *(unsigned int *)smb->Protocol);
		return 1;
	}

	/* if it's a response then accept */
	if (smb->Flags & SMBFLG_RESPONSE)
		return 0;

	/* only one valid case where server sends us request */
	if (smb->Command == SMB_COM_LOCKING_ANDX)
		return 0;

	cifs_dbg(VFS, "Server sent request, not response. mid=%u\n",
		 get_mid(smb));
	return 1;
}

int
checkSMB(char *buf, unsigned int total_read, struct TCP_Server_Info *server)
{
	struct smb_hdr *smb = (struct smb_hdr *)buf;
	__u32 rfclen = be32_to_cpu(smb->smb_buf_length);
	__u32 clc_len;  /* calculated length */
	cifs_dbg(FYI, "checkSMB Length: 0x%x, smb_buf_length: 0x%x\n",
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
			cifs_dbg(VFS, "rcvd invalid byte count (bcc)\n");
		} else {
			cifs_dbg(VFS, "Length less than smb header size\n");
		}
		return -EIO;
	}

	/* otherwise, there is enough to get to the BCC */
	if (check_smb_hdr(smb))
		return -EIO;
	clc_len = smbCalcSize(smb, server);

	if (4 + rfclen != total_read) {
		cifs_dbg(VFS, "Length read does not match RFC1001 length %d\n",
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
		cifs_dbg(FYI, "Calculated size %u vs length %u mismatch for mid=%u\n",
			 clc_len, 4 + rfclen, mid);

		if (4 + rfclen < clc_len) {
			cifs_dbg(VFS, "RFC1001 size %u smaller than SMB for mid=%u\n",
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
			cifs_dbg(VFS, "RFC1001 size %u more than 512 bytes larger than SMB for mid=%u\n",
				 rfclen, mid);
			return -EIO;
		}
	}
	return 0;
}

bool
is_valid_oplock_break(char *buffer, struct TCP_Server_Info *srv)
{
	struct smb_hdr *buf = (struct smb_hdr *)buffer;
	struct smb_com_lock_req *pSMB = (struct smb_com_lock_req *)buf;
	struct cifs_ses *ses;
	struct cifs_tcon *tcon;
	struct cifsInodeInfo *pCifsInode;
	struct cifsFileInfo *netfile;

	cifs_dbg(FYI, "Checking for oplock break or dnotify response\n");
	if ((pSMB->hdr.Command == SMB_COM_NT_TRANSACT) &&
	   (pSMB->hdr.Flags & SMBFLG_RESPONSE)) {
		struct smb_com_transaction_change_notify_rsp *pSMBr =
			(struct smb_com_transaction_change_notify_rsp *)buf;
		struct file_notify_information *pnotify;
		__u32 data_offset = 0;
		size_t len = srv->total_read - sizeof(pSMBr->hdr.smb_buf_length);

		if (get_bcc(buf) > sizeof(struct file_notify_information)) {
			data_offset = le32_to_cpu(pSMBr->DataOffset);

			if (data_offset >
			    len - sizeof(struct file_notify_information)) {
				cifs_dbg(FYI, "Invalid data_offset %u\n",
					 data_offset);
				return true;
			}
			pnotify = (struct file_notify_information *)
				((char *)&pSMBr->hdr.Protocol + data_offset);
			cifs_dbg(FYI, "dnotify on %s Action: 0x%x\n",
				 pnotify->FileName, pnotify->Action);
			/*   cifs_dump_mem("Rcvd notify Data: ",buf,
				sizeof(struct smb_hdr)+60); */
			return true;
		}
		if (pSMBr->hdr.Status.CifsError) {
			cifs_dbg(FYI, "notify err 0x%x\n",
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
			cifs_dbg(FYI, "Invalid handle on oplock break\n");
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

	cifs_dbg(FYI, "oplock type 0x%x level 0x%x\n",
		 pSMB->LockType, pSMB->OplockLevel);
	if (!(pSMB->LockType & LOCKING_ANDX_OPLOCK_RELEASE))
		return false;

	/* look up tcon based on tid & uid */
	spin_lock(&cifs_tcp_ses_lock);
	list_for_each_entry(ses, &srv->smb_ses_list, smb_ses_list) {
		list_for_each_entry(tcon, &ses->tcon_list, tcon_list) {
			if (tcon->tid != buf->Tid)
				continue;

			cifs_stats_inc(&tcon->stats.cifs_stats.num_oplock_brks);
			spin_lock(&tcon->open_file_lock);
			list_for_each_entry(netfile, &tcon->openFileList, tlist) {
				if (pSMB->Fid != netfile->fid.netfid)
					continue;

				cifs_dbg(FYI, "file id match, oplock break\n");
				pCifsInode = CIFS_I(d_inode(netfile->dentry));

				set_bit(CIFS_INODE_PENDING_OPLOCK_BREAK,
					&pCifsInode->flags);

				netfile->oplock_epoch = 0;
				netfile->oplock_level = pSMB->OplockLevel;
				netfile->oplock_break_cancelled = false;
				cifs_queue_oplock_break(netfile);

				spin_unlock(&tcon->open_file_lock);
				spin_unlock(&cifs_tcp_ses_lock);
				return true;
			}
			spin_unlock(&tcon->open_file_lock);
			spin_unlock(&cifs_tcp_ses_lock);
			cifs_dbg(FYI, "No matching file for oplock break\n");
			return true;
		}
	}
	spin_unlock(&cifs_tcp_ses_lock);
	cifs_dbg(FYI, "Can not process oplock break for non-existent connection\n");
	return true;
}

struct file_system_type cifs_fs_type = {
	.owner = THIS_MODULE,
	.name = "cifs",
	.init_fs_context = smb3_init_fs_context,
	.parameters = smb3_fs_parameters,
	.kill_sb = cifs_kill_sb,
	.fs_flags = FS_RENAME_DOES_D_MOVE,
};
MODULE_ALIAS_FS("cifs");

const struct inode_operations cifs_dir_inode_ops = {
	.create = cifs_create,
	.atomic_open = cifs_atomic_open,
	.lookup = cifs_lookup,
	.getattr = cifs_getattr,
	.unlink = cifs_unlink,
	.link = cifs_hardlink,
	.mkdir = cifs_mkdir,
	.rmdir = cifs_rmdir,
	.rename = cifs_rename2,
	.permission = cifs_permission,
	.setattr = cifs_setattr,
	.symlink = cifs_symlink,
	.mknod   = cifs_mknod,
	.listxattr = cifs_listxattr,
};

const struct inode_operations cifs_file_inode_ops = {
	.setattr = cifs_setattr,
	.getattr = cifs_getattr,
	.permission = cifs_permission,
	.listxattr = cifs_listxattr,
	.fiemap = cifs_fiemap,
};

const struct inode_operations cifs_symlink_inode_ops = {
	.get_link = cifs_get_link,
	.permission = cifs_permission,
	.listxattr = cifs_listxattr,
};

const struct file_operations cifs_file_ops = {
	.read_iter = cifs_loose_read_iter,
	.write_iter = cifs_file_write_iter,
	.open = cifs_open,
	.release = cifs_close,
	.lock = cifs_lock,
	.flock = cifs_flock,
	.fsync = cifs_fsync,
	.flush = cifs_flush,
	.mmap  = cifs_file_mmap,
	.splice_read = generic_file_splice_read,
	.splice_write = iter_file_splice_write,
	.llseek = cifs_llseek,
	.unlocked_ioctl	= cifs_ioctl,
	.copy_file_range = cifs_copy_file_range,
	.remap_file_range = cifs_remap_file_range,
	.setlease = cifs_setlease,
	.fallocate = cifs_fallocate,
};

const struct file_operations cifs_file_strict_ops = {
	.read_iter = cifs_strict_readv,
	.write_iter = cifs_strict_writev,
	.open = cifs_open,
	.release = cifs_close,
	.lock = cifs_lock,
	.flock = cifs_flock,
	.fsync = cifs_strict_fsync,
	.flush = cifs_flush,
	.mmap = cifs_file_strict_mmap,
	.splice_read = generic_file_splice_read,
	.splice_write = iter_file_splice_write,
	.llseek = cifs_llseek,
	.unlocked_ioctl	= cifs_ioctl,
	.copy_file_range = cifs_copy_file_range,
	.remap_file_range = cifs_remap_file_range,
	.setlease = cifs_setlease,
	.fallocate = cifs_fallocate,
};

const struct file_operations cifs_file_direct_ops = {
	.read_iter = cifs_direct_readv,
	.write_iter = cifs_direct_writev,
	.open = cifs_open,
	.release = cifs_close,
	.lock = cifs_lock,
	.flock = cifs_flock,
	.fsync = cifs_fsync,
	.flush = cifs_flush,
	.mmap = cifs_file_mmap,
	.splice_read = generic_file_splice_read,
	.splice_write = iter_file_splice_write,
	.unlocked_ioctl  = cifs_ioctl,
	.copy_file_range = cifs_copy_file_range,
	.remap_file_range = cifs_remap_file_range,
	.llseek = cifs_llseek,
	.setlease = cifs_setlease,
	.fallocate = cifs_fallocate,
};

const struct file_operations cifs_file_nobrl_ops = {
	.read_iter = cifs_loose_read_iter,
	.write_iter = cifs_file_write_iter,
	.open = cifs_open,
	.release = cifs_close,
	.fsync = cifs_fsync,
	.flush = cifs_flush,
	.mmap  = cifs_file_mmap,
	.splice_read = generic_file_splice_read,
	.splice_write = iter_file_splice_write,
	.llseek = cifs_llseek,
	.unlocked_ioctl	= cifs_ioctl,
	.copy_file_range = cifs_copy_file_range,
	.remap_file_range = cifs_remap_file_range,
	.setlease = cifs_setlease,
	.fallocate = cifs_fallocate,
};

const struct file_operations cifs_file_strict_nobrl_ops = {
	.read_iter = cifs_strict_readv,
	.write_iter = cifs_strict_writev,
	.open = cifs_open,
	.release = cifs_close,
	.fsync = cifs_strict_fsync,
	.flush = cifs_flush,
	.mmap = cifs_file_strict_mmap,
	.splice_read = generic_file_splice_read,
	.splice_write = iter_file_splice_write,
	.llseek = cifs_llseek,
	.unlocked_ioctl	= cifs_ioctl,
	.copy_file_range = cifs_copy_file_range,
	.remap_file_range = cifs_remap_file_range,
	.setlease = cifs_setlease,
	.fallocate = cifs_fallocate,
};

const struct file_operations cifs_file_direct_nobrl_ops = {
	.read_iter = cifs_direct_readv,
	.write_iter = cifs_direct_writev,
	.open = cifs_open,
	.release = cifs_close,
	.fsync = cifs_fsync,
	.flush = cifs_flush,
	.mmap = cifs_file_mmap,
	.splice_read = generic_file_splice_read,
	.splice_write = iter_file_splice_write,
	.unlocked_ioctl  = cifs_ioctl,
	.copy_file_range = cifs_copy_file_range,
	.remap_file_range = cifs_remap_file_range,
	.llseek = cifs_llseek,
	.setlease = cifs_setlease,
	.fallocate = cifs_fallocate,
};

const struct file_operations cifs_dir_ops = {
	.iterate_shared = cifs_readdir,
	.release = cifs_closedir,
	.read    = generic_read_dir,
	.unlocked_ioctl  = cifs_ioctl,
	.copy_file_range = cifs_copy_file_range,
	.remap_file_range = cifs_remap_file_range,
	.llseek = generic_file_llseek,
	.fsync = cifs_dir_fsync,
};


struct smb_version_operations smb1_operations = {
	.send_cancel = send_nt_cancel,
	.compare_fids = cifs_compare_fids,
	.setup_request = cifs_setup_request,
	.setup_async_request = cifs_setup_async_request,
	.check_receive = cifs_check_receive,
	.add_credits = cifs_add_credits,
	.set_credits = cifs_set_credits,
	.get_credits_field = cifs_get_credits_field,
	.get_credits = cifs_get_credits,
	.wait_mtu_credits = cifs_wait_mtu_credits,
	.get_next_mid = cifs_get_next_mid,
	.read_data_offset = cifs_read_data_offset,
	.read_data_length = cifs_read_data_length,
	.map_error = map_smb_to_linux_error,
	.find_mid = cifs_find_mid,
	.check_message = checkSMB,
	.dump_detail = cifs_dump_detail,
	.clear_stats = cifs_clear_stats,
	.print_stats = cifs_print_stats,
	.is_oplock_break = is_valid_oplock_break,
	.downgrade_oplock = cifs_downgrade_oplock,
	.check_trans2 = cifs_check_trans2,
	.need_neg = cifs_need_neg,
	.negotiate = cifs_negotiate,
	.negotiate_wsize = cifs_negotiate_wsize,
	.negotiate_rsize = cifs_negotiate_rsize,
	.sess_setup = CIFS_SessSetup,
	.logoff = CIFSSMBLogoff,
	.tree_connect = CIFSTCon,
	.tree_disconnect = CIFSSMBTDis,
	.get_dfs_refer = CIFSGetDFSRefer,
	.qfs_tcon = cifs_qfs_tcon,
	.is_path_accessible = cifs_is_path_accessible,
	.can_echo = cifs_can_echo,
	.query_path_info = cifs_query_path_info,
	.query_file_info = cifs_query_file_info,
	.get_srv_inum = cifs_get_srv_inum,
	.set_path_size = CIFSSMBSetEOF,
	.set_file_size = CIFSSMBSetFileSize,
	.set_file_info = smb_set_file_info,
	.set_compression = cifs_set_compression,
	.echo = CIFSSMBEcho,
	.mkdir = CIFSSMBMkDir,
	.mkdir_setinfo = cifs_mkdir_setinfo,
	.rmdir = CIFSSMBRmDir,
	.unlink = CIFSSMBDelFile,
	.rename_pending_delete = cifs_rename_pending_delete,
	.rename = CIFSSMBRename,
	.create_hardlink = CIFSCreateHardLink,
	.query_symlink = cifs_query_symlink,
	.open = cifs_open_file,
	.set_fid = cifs_set_fid,
	.close = cifs_close_file,
	.flush = cifs_flush_file,
	.async_readv = cifs_async_readv,
	.async_writev = cifs_async_writev,
	.sync_read = cifs_sync_read,
	.sync_write = cifs_sync_write,
	.query_dir_first = cifs_query_dir_first,
	.query_dir_next = cifs_query_dir_next,
	.close_dir = cifs_close_dir,
	.calc_smb_size = smbCalcSize,
	.oplock_response = cifs_oplock_response,
	.queryfs = cifs_queryfs,
	.mand_lock = cifs_mand_lock,
	.mand_unlock_range = cifs_unlock_range,
	.push_mand_locks = cifs_push_mandatory_locks,
	.query_mf_symlink = cifs_query_mf_symlink,
	.create_mf_symlink = cifs_create_mf_symlink,
	.is_read_op = cifs_is_read_op,
	.wp_retry_size = cifs_wp_retry_size,
	.dir_needs_close = cifs_dir_needs_close,
	.select_sectype = cifs_select_sectype,
#ifdef CONFIG_CIFS_XATTR
	.query_all_EAs = CIFSSMBQAllEAs,
	.set_EA = CIFSSMBSetEA,
#endif /* CIFS_XATTR */
	.get_acl = get_cifs_acl,
	.get_acl_by_fid = get_cifs_acl_by_fid,
	.set_acl = set_cifs_acl,
	.make_node = cifs_make_node,
};

struct smb_version_values smb1_values = {
	.version_string = SMB1_VERSION_STRING,
	.protocol_id = SMB10_PROT_ID,
	.large_lock_type = LOCKING_ANDX_LARGE_FILES,
	.exclusive_lock_type = 0,
	.shared_lock_type = LOCKING_ANDX_SHARED_LOCK,
	.unlock_lock_type = 0,
	.header_preamble_size = 4,
	.header_size = sizeof(struct smb_hdr),
	.max_header_size = MAX_CIFS_HDR_SIZE,
	.read_rsp_size = sizeof(READ_RSP),
	.lock_cmd = cpu_to_le16(SMB_COM_LOCKING_ANDX),
	.cap_unix = CAP_UNIX,
	.cap_nt_find = CAP_NT_SMBS | CAP_NT_FIND,
	.cap_large_files = CAP_LARGE_FILES,
	.signing_enabled = SECMODE_SIGN_ENABLED,
	.signing_required = SECMODE_SIGN_REQUIRED,
};
