// SPDX-License-Identifier: LGPL-2.1
/*
 *
 *   Copyright (C) International Business Machines  Corp., 2002,2008
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *   Jeremy Allison (jra@samba.org) 2006.
 *
 */

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/gfp.h>
#include <linux/wait.h>
#include <linux/net.h>
#include <linux/delay.h>
#include <linux/bvec.h>
#include <linux/highmem.h>
#include <linux/uaccess.h>
#include <asm/processor.h>
#include <linux/mempool.h>
#include <linux/sched/signal.h>
#include "pdu.h"
#include "../globals.h"
#include "prototypes.h"
#include "../debug.h"
#include "smb2proto.h"
#include "smbdirect.h"

/* Max number of iovectors we can use off the stack when sending requests. */
#define CIFS_MAX_IOV_SIZE 8

extern inline int wait_for_free_request(struct TCP_Server_Info *, const int,
					unsigned int *);
extern inline int send_cancel(struct TCP_Server_Info *, struct smb_rqst *,
			      struct mid_q_entry *);
extern int __smb_send_rqst(struct TCP_Server_Info *, int,struct smb_rqst *);
extern int wait_for_response(struct TCP_Server_Info *, struct mid_q_entry *);
extern int cifs_sync_mid_result(struct mid_q_entry *, struct TCP_Server_Info *);

void
cifs_wake_up_task(struct mid_q_entry *mid)
{
	wake_up_process(mid->callback_data);
}

struct mid_q_entry *
AllocMidQEntry(const struct smb_hdr *smb_buffer, struct TCP_Server_Info *server)
{
	struct mid_q_entry *temp;

	if (server == NULL) {
		cifs_dbg(VFS, "Null TCP session in AllocMidQEntry\n");
		return NULL;
	}

	temp = mempool_alloc(cifs_mid_poolp, GFP_NOFS);
	memset(temp, 0, sizeof(struct mid_q_entry));
	kref_init(&temp->refcount);
	temp->mid = get_mid(smb_buffer);
	temp->pid = current->pid;
	temp->command = cpu_to_le16(smb_buffer->Command);
	cifs_dbg(FYI, "For smb_command %d\n", smb_buffer->Command);
	/*	do_gettimeofday(&temp->when_sent);*/ /* easier to use jiffies */
	/* when mid allocated can be before when sent */
	temp->when_alloc = jiffies;
	temp->server = server;

	/*
	 * The default is for the mid to be synchronous, so the
	 * default callback just wakes up the current task.
	 */
	get_task_struct(current);
	temp->creator = current;
	temp->callback = cifs_wake_up_task;
	temp->callback_data = current;

	atomic_inc(&mid_count);
	temp->mid_state = MID_REQUEST_ALLOCATED;
	return temp;
}

static void _cifs_mid_q_entry_release(struct kref *refcount)
{
	struct mid_q_entry *midEntry =
			container_of(refcount, struct mid_q_entry, refcount);
#ifdef CONFIG_CIFS_STATS2
	__le16 command = midEntry->server->vals->lock_cmd;
	__u16 smb_cmd = le16_to_cpu(midEntry->command);
	unsigned long now;
	unsigned long roundtrip_time;
#endif
	struct TCP_Server_Info *server = midEntry->server;

	if (midEntry->resp_buf && (midEntry->mid_flags & MID_WAIT_CANCELLED) &&
	    midEntry->mid_state == MID_RESPONSE_RECEIVED &&
	    server->ops->handle_cancelled_mid)
		server->ops->handle_cancelled_mid(midEntry, server);

	midEntry->mid_state = MID_FREE;
	atomic_dec(&mid_count);
	if (midEntry->large_buf)
		cifs_buf_release(midEntry->resp_buf);
	else
		cifs_small_buf_release(midEntry->resp_buf);
#ifdef CONFIG_CIFS_STATS2
	now = jiffies;
	if (now < midEntry->when_alloc)
		cifs_server_dbg(VFS, "Invalid mid allocation time\n");
	roundtrip_time = now - midEntry->when_alloc;

	if (smb_cmd < NUMBER_OF_SMB2_COMMANDS) {
		if (atomic_read(&server->num_cmds[smb_cmd]) == 0) {
			server->slowest_cmd[smb_cmd] = roundtrip_time;
			server->fastest_cmd[smb_cmd] = roundtrip_time;
		} else {
			if (server->slowest_cmd[smb_cmd] < roundtrip_time)
				server->slowest_cmd[smb_cmd] = roundtrip_time;
			else if (server->fastest_cmd[smb_cmd] > roundtrip_time)
				server->fastest_cmd[smb_cmd] = roundtrip_time;
		}
		cifs_stats_inc(&server->num_cmds[smb_cmd]);
		server->time_per_cmd[smb_cmd] += roundtrip_time;
	}
	/*
	 * commands taking longer than one second (default) can be indications
	 * that something is wrong, unless it is quite a slow link or a very
	 * busy server. Note that this calc is unlikely or impossible to wrap
	 * as long as slow_rsp_threshold is not set way above recommended max
	 * value (32767 ie 9 hours) and is generally harmless even if wrong
	 * since only affects debug counters - so leaving the calc as simple
	 * comparison rather than doing multiple conversions and overflow
	 * checks
	 */
	if ((slow_rsp_threshold != 0) &&
	    time_after(now, midEntry->when_alloc + (slow_rsp_threshold * HZ)) &&
	    (midEntry->command != command)) {
		/*
		 * smb2slowcmd[NUMBER_OF_SMB2_COMMANDS] counts by command
		 * NB: le16_to_cpu returns unsigned so can not be negative below
		 */
		if (smb_cmd < NUMBER_OF_SMB2_COMMANDS)
			cifs_stats_inc(&server->smb2slowcmd[smb_cmd]);

		trace_smb3_slow_rsp(smb_cmd, midEntry->mid, midEntry->pid,
			       midEntry->when_sent, midEntry->when_received);
		if (cifsFYI & CIFS_TIMER) {
			pr_debug("slow rsp: cmd %d mid %llu",
				 midEntry->command, midEntry->mid);
			cifs_info("A: 0x%lx S: 0x%lx R: 0x%lx\n",
				  now - midEntry->when_alloc,
				  now - midEntry->when_sent,
				  now - midEntry->when_received);
		}
	}
#endif
	put_task_struct(midEntry->creator);

	mempool_free(midEntry, cifs_mid_poolp);
}

void cifs_mid_q_entry_release(struct mid_q_entry *midEntry)
{
	spin_lock(&GlobalMid_Lock);
	kref_put(&midEntry->refcount, _cifs_mid_q_entry_release);
	spin_unlock(&GlobalMid_Lock);
}

void DeleteMidQEntry(struct mid_q_entry *midEntry)
{
	cifs_mid_q_entry_release(midEntry);
}

void
cifs_delete_mid(struct mid_q_entry *mid)
{
	spin_lock(&GlobalMid_Lock);
	if (!(mid->mid_flags & MID_DELETED)) {
		list_del_init(&mid->qhead);
		mid->mid_flags |= MID_DELETED;
	}
	spin_unlock(&GlobalMid_Lock);

	DeleteMidQEntry(mid);
}

int
smb_send(struct TCP_Server_Info *server, struct smb_hdr *smb_buffer,
	 unsigned int smb_buf_length)
{
	struct kvec iov[2];
	struct smb_rqst rqst = { .rq_iov = iov,
				 .rq_nvec = 2 };

	iov[0].iov_base = smb_buffer;
	iov[0].iov_len = 4;
	iov[1].iov_base = (char *)smb_buffer + 4;
	iov[1].iov_len = smb_buf_length;

	return __smb_send_rqst(server, 1, &rqst);
}

int
cifs_wait_mtu_credits(struct TCP_Server_Info *server, unsigned int size,
		      unsigned int *num, struct cifs_credits *credits)
{
	*num = size;
	credits->value = 0;
	credits->instance = server->reconnect_instance;
	return 0;
}

static int allocate_mid(struct cifs_ses *ses, struct smb_hdr *in_buf,
			struct mid_q_entry **ppmidQ)
{
	spin_lock(&cifs_tcp_ses_lock);
	if (ses->ses_status == SES_NEW) {
		if ((in_buf->Command != SMB_COM_SESSION_SETUP_ANDX) &&
			(in_buf->Command != SMB_COM_NEGOTIATE)) {
			spin_unlock(&cifs_tcp_ses_lock);
			return -EAGAIN;
		}
		/* else ok - we are setting up session */
	}

	if (ses->ses_status == SES_EXITING) {
		/* check if SMB session is bad because we are setting it up */
		if (in_buf->Command != SMB_COM_LOGOFF_ANDX) {
			spin_unlock(&cifs_tcp_ses_lock);
			return -EAGAIN;
		}
		/* else ok - we are shutting down session */
	}
	spin_unlock(&cifs_tcp_ses_lock);

	*ppmidQ = AllocMidQEntry(in_buf, ses->server);
	if (*ppmidQ == NULL)
		return -ENOMEM;
	spin_lock(&GlobalMid_Lock);
	list_add_tail(&(*ppmidQ)->qhead, &ses->server->pending_mid_q);
	spin_unlock(&GlobalMid_Lock);
	return 0;
}

struct mid_q_entry *
cifs_setup_async_request(struct TCP_Server_Info *server, struct smb_rqst *rqst)
{
	int rc;
	struct smb_hdr *hdr = (struct smb_hdr *)rqst->rq_iov[0].iov_base;
	struct mid_q_entry *mid;

	if (rqst->rq_iov[0].iov_len != 4 ||
	    rqst->rq_iov[0].iov_base + 4 != rqst->rq_iov[1].iov_base)
		return ERR_PTR(-EIO);

	/* enable signing if server requires it */
	if (server->sign)
		hdr->Flags2 |= SMBFLG2_SECURITY_SIGNATURE;

	mid = AllocMidQEntry(hdr, server);
	if (mid == NULL)
		return ERR_PTR(-ENOMEM);

	rc = cifs_sign_rqst(rqst, server, &mid->sequence_number);
	if (rc) {
		DeleteMidQEntry(mid);
		return ERR_PTR(rc);
	}

	return mid;
}

/*
 *
 * Send an SMB Request.  No response info (other than return code)
 * needs to be parsed.
 *
 * flags indicate the type of request buffer and how long to wait
 * and whether to log NT STATUS code (error) before mapping it to POSIX error
 *
 */
int
SendReceiveNoRsp(const unsigned int xid, struct cifs_ses *ses,
		 char *in_buf, int flags)
{
	int rc;
	struct kvec iov[1];
	struct kvec rsp_iov;
	int resp_buf_type;

	iov[0].iov_base = in_buf;
	iov[0].iov_len = get_rfc1002_length(in_buf) + 4;
	flags |= CIFS_NO_RSP_BUF;
	rc = SendReceive2(xid, ses, iov, 1, &resp_buf_type, flags, &rsp_iov);
	cifs_dbg(NOISY, "SendRcvNoRsp flags %d rc %d\n", flags, rc);

	return rc;
}

int
cifs_check_receive(struct mid_q_entry *mid, struct TCP_Server_Info *server,
		   bool log_error)
{
	unsigned int len = get_rfc1002_length(mid->resp_buf) + 4;

	dump_smb(mid->resp_buf, min_t(u32, 92, len));

	/* convert the length into a more usable form */
	if (server->sign) {
		struct kvec iov[2];
		int rc = 0;
		struct smb_rqst rqst = { .rq_iov = iov,
					 .rq_nvec = 2 };

		iov[0].iov_base = mid->resp_buf;
		iov[0].iov_len = 4;
		iov[1].iov_base = (char *)mid->resp_buf + 4;
		iov[1].iov_len = len - 4;
		/* FIXME: add code to kill session */
		rc = cifs_verify_signature(&rqst, server,
					   mid->sequence_number);
		if (rc)
			cifs_server_dbg(VFS, "SMB signature verification returned error = %d\n",
				 rc);
	}

	/* BB special case reconnect tid and uid here? */
	return map_and_check_smb_error(mid, log_error);
}

struct mid_q_entry *
cifs_setup_request(struct cifs_ses *ses, struct TCP_Server_Info *ignored,
		   struct smb_rqst *rqst)
{
	int rc;
	struct smb_hdr *hdr = (struct smb_hdr *)rqst->rq_iov[0].iov_base;
	struct mid_q_entry *mid;

	if (rqst->rq_iov[0].iov_len != 4 ||
	    rqst->rq_iov[0].iov_base + 4 != rqst->rq_iov[1].iov_base)
		return ERR_PTR(-EIO);

	rc = allocate_mid(ses, hdr, &mid);
	if (rc)
		return ERR_PTR(rc);
	rc = cifs_sign_rqst(rqst, ses->server, &mid->sequence_number);
	if (rc) {
		cifs_delete_mid(mid);
		return ERR_PTR(rc);
	}
	return mid;
}

/*
 * Return a channel (master if none) of @ses that can be used to send
 * regular requests.
 *
 * If we are currently binding a new channel (negprot/sess.setup),
 * return the new incomplete channel.
 */
struct TCP_Server_Info *cifs_pick_channel(struct cifs_ses *ses)
{
	uint index = 0;

	if (!ses)
		return NULL;

	/* round robin */
	index = (uint)atomic_inc_return(&ses->chan_seq);

	spin_lock(&ses->chan_lock);
	index %= ses->chan_count;
	spin_unlock(&ses->chan_lock);

	return ses->chans[index].server;
}

int
SendReceive2(const unsigned int xid, struct cifs_ses *ses,
	     struct kvec *iov, int n_vec, int *resp_buf_type /* ret */,
	     const int flags, struct kvec *resp_iov)
{
	struct smb_rqst rqst;
	struct kvec s_iov[CIFS_MAX_IOV_SIZE], *new_iov;
	int rc;

	if (n_vec + 1 > CIFS_MAX_IOV_SIZE) {
		new_iov = kmalloc_array(n_vec + 1, sizeof(struct kvec),
					GFP_KERNEL);
		if (!new_iov) {
			/* otherwise cifs_send_recv below sets resp_buf_type */
			*resp_buf_type = CIFS_NO_BUFFER;
			return -ENOMEM;
		}
	} else
		new_iov = s_iov;

	/* 1st iov is a RFC1001 length followed by the rest of the packet */
	memcpy(new_iov + 1, iov, (sizeof(struct kvec) * n_vec));

	new_iov[0].iov_base = new_iov[1].iov_base;
	new_iov[0].iov_len = 4;
	new_iov[1].iov_base += 4;
	new_iov[1].iov_len -= 4;

	memset(&rqst, 0, sizeof(struct smb_rqst));
	rqst.rq_iov = new_iov;
	rqst.rq_nvec = n_vec + 1;

	rc = cifs_send_recv(xid, ses, ses->server,
			    &rqst, resp_buf_type, flags, resp_iov);
	if (n_vec + 1 > CIFS_MAX_IOV_SIZE)
		kfree(new_iov);
	return rc;
}

int
SendReceive(const unsigned int xid, struct cifs_ses *ses,
	    struct smb_hdr *in_buf, struct smb_hdr *out_buf,
	    int *pbytes_returned, const int flags)
{
	int rc = 0;
	struct mid_q_entry *midQ;
	unsigned int len = be32_to_cpu(in_buf->smb_buf_length);
	struct kvec iov = { .iov_base = in_buf, .iov_len = len };
	struct smb_rqst rqst = { .rq_iov = &iov, .rq_nvec = 1 };
	struct cifs_credits credits = { .value = 1, .instance = 0 };
	struct TCP_Server_Info *server;

	if (ses == NULL) {
		cifs_dbg(VFS, "Null smb session\n");
		return -EIO;
	}
	server = ses->server;
	if (server == NULL) {
		cifs_dbg(VFS, "Null tcp session\n");
		return -EIO;
	}

	spin_lock(&cifs_tcp_ses_lock);
	if (server->tcpStatus == CifsExiting) {
		spin_unlock(&cifs_tcp_ses_lock);
		return -ENOENT;
	}
	spin_unlock(&cifs_tcp_ses_lock);

	/* Ensure that we do not send more than 50 overlapping requests
	   to the same server. We may make this configurable later or
	   use ses->maxReq */

	if (len > CIFSMaxBufSize + MAX_CIFS_HDR_SIZE - 4) {
		cifs_server_dbg(VFS, "Invalid length, greater than maximum frame, %d\n",
				len);
		return -EIO;
	}

	rc = wait_for_free_request(server, flags, &credits.instance);
	if (rc)
		return rc;

	/* make sure that we sign in the same order that we send on this socket
	   and avoid races inside tcp sendmsg code that could cause corruption
	   of smb data */

	cifs_server_lock(server);

	rc = allocate_mid(ses, in_buf, &midQ);
	if (rc) {
		cifs_server_unlock(server);
		/* Update # of requests on wire to server */
		add_credits(server, &credits, 0);
		return rc;
	}

	rc = cifs_sign_smb(in_buf, server, &midQ->sequence_number);
	if (rc) {
		cifs_server_unlock(server);
		goto out;
	}

	midQ->mid_state = MID_REQUEST_SUBMITTED;

	cifs_in_send_inc(server);
	rc = smb_send(server, in_buf, len);
	cifs_in_send_dec(server);
	cifs_save_when_sent(midQ);

	if (rc < 0)
		server->sequence_number -= 2;

	cifs_server_unlock(server);

	if (rc < 0)
		goto out;

	rc = wait_for_response(server, midQ);
	if (rc != 0) {
		send_cancel(server, &rqst, midQ);
		spin_lock(&GlobalMid_Lock);
		if (midQ->mid_state == MID_REQUEST_SUBMITTED) {
			/* no longer considered to be "in-flight" */
			midQ->callback = DeleteMidQEntry;
			spin_unlock(&GlobalMid_Lock);
			add_credits(server, &credits, 0);
			return rc;
		}
		spin_unlock(&GlobalMid_Lock);
	}

	rc = cifs_sync_mid_result(midQ, server);
	if (rc != 0) {
		add_credits(server, &credits, 0);
		return rc;
	}

	if (!midQ->resp_buf || !out_buf ||
	    midQ->mid_state != MID_RESPONSE_RECEIVED) {
		rc = -EIO;
		cifs_server_dbg(VFS, "Bad MID state?\n");
		goto out;
	}

	*pbytes_returned = get_rfc1002_length(midQ->resp_buf);
	memcpy(out_buf, midQ->resp_buf, *pbytes_returned + 4);
	rc = cifs_check_receive(midQ, server, 0);
out:
	cifs_delete_mid(midQ);
	add_credits(server, &credits, 0);

	return rc;
}

/* We send a LOCKINGX_CANCEL_LOCK to cause the Windows
   blocking lock to return. */

static int
send_lock_cancel(const unsigned int xid, struct cifs_tcon *tcon,
			struct smb_hdr *in_buf,
			struct smb_hdr *out_buf)
{
	int bytes_returned;
	struct cifs_ses *ses = tcon->ses;
	LOCK_REQ *pSMB = (LOCK_REQ *)in_buf;

	/* We just modify the current in_buf to change
	   the type of lock from LOCKING_ANDX_SHARED_LOCK
	   or LOCKING_ANDX_EXCLUSIVE_LOCK to
	   LOCKING_ANDX_CANCEL_LOCK. */

	pSMB->LockType = LOCKING_ANDX_CANCEL_LOCK|LOCKING_ANDX_LARGE_FILES;
	pSMB->Timeout = 0;
	pSMB->hdr.Mid = get_next_mid(ses->server);

	return SendReceive(xid, ses, in_buf, out_buf,
			&bytes_returned, 0);
}

int
SendReceiveBlockingLock(const unsigned int xid, struct cifs_tcon *tcon,
	    struct smb_hdr *in_buf, struct smb_hdr *out_buf,
	    int *pbytes_returned)
{
	int rc = 0;
	int rstart = 0;
	struct mid_q_entry *midQ;
	struct cifs_ses *ses;
	unsigned int len = be32_to_cpu(in_buf->smb_buf_length);
	struct kvec iov = { .iov_base = in_buf, .iov_len = len };
	struct smb_rqst rqst = { .rq_iov = &iov, .rq_nvec = 1 };
	unsigned int instance;
	struct TCP_Server_Info *server;

	if (tcon == NULL || tcon->ses == NULL) {
		cifs_dbg(VFS, "Null smb session\n");
		return -EIO;
	}
	ses = tcon->ses;
	server = ses->server;

	if (server == NULL) {
		cifs_dbg(VFS, "Null tcp session\n");
		return -EIO;
	}

	spin_lock(&cifs_tcp_ses_lock);
	if (server->tcpStatus == CifsExiting) {
		spin_unlock(&cifs_tcp_ses_lock);
		return -ENOENT;
	}
	spin_unlock(&cifs_tcp_ses_lock);

	/* Ensure that we do not send more than 50 overlapping requests
	   to the same server. We may make this configurable later or
	   use ses->maxReq */

	if (len > CIFSMaxBufSize + MAX_CIFS_HDR_SIZE - 4) {
		cifs_tcon_dbg(VFS, "Invalid length, greater than maximum frame, %d\n",
			      len);
		return -EIO;
	}

	rc = wait_for_free_request(server, CIFS_BLOCKING_OP, &instance);
	if (rc)
		return rc;

	/* make sure that we sign in the same order that we send on this socket
	   and avoid races inside tcp sendmsg code that could cause corruption
	   of smb data */

	cifs_server_lock(server);

	rc = allocate_mid(ses, in_buf, &midQ);
	if (rc) {
		cifs_server_unlock(server);
		return rc;
	}

	rc = cifs_sign_smb(in_buf, server, &midQ->sequence_number);
	if (rc) {
		cifs_delete_mid(midQ);
		cifs_server_unlock(server);
		return rc;
	}

	midQ->mid_state = MID_REQUEST_SUBMITTED;
	cifs_in_send_inc(server);
	rc = smb_send(server, in_buf, len);
	cifs_in_send_dec(server);
	cifs_save_when_sent(midQ);

	if (rc < 0)
		server->sequence_number -= 2;

	cifs_server_unlock(server);

	if (rc < 0) {
		cifs_delete_mid(midQ);
		return rc;
	}

	/* Wait for a reply - allow signals to interrupt. */
	rc = wait_event_interruptible(server->response_q,
		(!(midQ->mid_state == MID_REQUEST_SUBMITTED)) ||
		((server->tcpStatus != CifsGood) &&
		 (server->tcpStatus != CifsNew)));

	/* Were we interrupted by a signal ? */
	spin_lock(&cifs_tcp_ses_lock);
	if ((rc == -ERESTARTSYS) &&
		(midQ->mid_state == MID_REQUEST_SUBMITTED) &&
		((server->tcpStatus == CifsGood) ||
		 (server->tcpStatus == CifsNew))) {
		spin_unlock(&cifs_tcp_ses_lock);

		if (in_buf->Command == SMB_COM_TRANSACTION2) {
			/* POSIX lock. We send a NT_CANCEL SMB to cause the
			   blocking lock to return. */
			rc = send_cancel(server, &rqst, midQ);
			if (rc) {
				cifs_delete_mid(midQ);
				return rc;
			}
		} else {
			/* Windows lock. We send a LOCKINGX_CANCEL_LOCK
			   to cause the blocking lock to return. */

			rc = send_lock_cancel(xid, tcon, in_buf, out_buf);

			/* If we get -ENOLCK back the lock may have
			   already been removed. Don't exit in this case. */
			if (rc && rc != -ENOLCK) {
				cifs_delete_mid(midQ);
				return rc;
			}
		}

		rc = wait_for_response(server, midQ);
		if (rc) {
			send_cancel(server, &rqst, midQ);
			spin_lock(&GlobalMid_Lock);
			if (midQ->mid_state == MID_REQUEST_SUBMITTED) {
				/* no longer considered to be "in-flight" */
				midQ->callback = DeleteMidQEntry;
				spin_unlock(&GlobalMid_Lock);
				return rc;
			}
			spin_unlock(&GlobalMid_Lock);
		}

		/* We got the response - restart system call. */
		rstart = 1;
		spin_lock(&cifs_tcp_ses_lock);
	}
	spin_unlock(&cifs_tcp_ses_lock);

	rc = cifs_sync_mid_result(midQ, server);
	if (rc != 0)
		return rc;

	/* rcvd frame is ok */
	if (out_buf == NULL || midQ->mid_state != MID_RESPONSE_RECEIVED) {
		rc = -EIO;
		cifs_tcon_dbg(VFS, "Bad MID state?\n");
		goto out;
	}

	*pbytes_returned = get_rfc1002_length(midQ->resp_buf);
	memcpy(out_buf, midQ->resp_buf, *pbytes_returned + 4);
	rc = cifs_check_receive(midQ, server, 0);
out:
	cifs_delete_mid(midQ);
	if (rstart && rc == -EACCES)
		return -ERESTARTSYS;
	return rc;
}
