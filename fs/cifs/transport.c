// SPDX-License-Identifier: LGPL-2.1
/*
 *
 *   Copyright (C) International Business Machines  Corp., 2002, 2011
 *                 Etersoft, 2012
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *              Jeremy Allison (jra@samba.org) 2006
 *              Pavel Shilovsky (pshilovsky@samba.org) 2012
 *
 */

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/freezer.h>
#include <asm/processor.h>
#include <linux/mempool.h>
#include <linux/highmem.h>
#include <crypto/aead.h>
#include "globals.h"
#include "prototypes.h"
#include "smb2proto.h"
#include "debug.h"
#include "status.h"
#include "smbdirect.h"
#include "globals.h"

static int
wait_for_free_credits(struct TCP_Server_Info *server, const int num_credits,
		      const int timeout, const int flags,
		      unsigned int *instance)
{
	long rc;
	int *credits;
	int optype;
	long int t;
	int scredits, in_flight;

	if (timeout < 0)
		t = MAX_JIFFY_OFFSET;
	else
		t = msecs_to_jiffies(timeout);

	optype = flags & CIFS_OP_MASK;

	*instance = 0;

	credits = server->ops->get_credits_field(server, optype);
	/* Since an echo is already inflight, no need to wait to send another */
	if (*credits <= 0 && optype == CIFS_ECHO_OP)
		return -EAGAIN;

	spin_lock(&server->req_lock);
	if ((flags & CIFS_TIMEOUT_MASK) == CIFS_NON_BLOCKING) {
		/* oplock breaks must not be held up */
		server->in_flight++;
		if (server->in_flight > server->max_in_flight)
			server->max_in_flight = server->in_flight;
		*credits -= 1;
		*instance = server->reconnect_instance;
		scredits = *credits;
		in_flight = server->in_flight;
		spin_unlock(&server->req_lock);

		trace_smb3_nblk_credits(server->CurrentMid,
				server->conn_id, server->hostname, scredits, -1, in_flight);
		cifs_dbg(FYI, "%s: remove %u credits total=%d\n",
				__func__, 1, scredits);

		return 0;
	}

	while (1) {
		if (*credits < num_credits) {
			scredits = *credits;
			spin_unlock(&server->req_lock);

			cifs_num_waiters_inc(server);
			rc = wait_event_killable_timeout(server->request_q,
				has_credits(server, credits, num_credits), t);
			cifs_num_waiters_dec(server);
			if (!rc) {
				spin_lock(&server->req_lock);
				scredits = *credits;
				in_flight = server->in_flight;
				spin_unlock(&server->req_lock);

				trace_smb3_credit_timeout(server->CurrentMid,
						server->conn_id, server->hostname, scredits,
						num_credits, in_flight);
				cifs_server_dbg(VFS, "wait timed out after %d ms\n",
						timeout);
				return -EBUSY;
			}
			if (rc == -ERESTARTSYS)
				return -ERESTARTSYS;
			spin_lock(&server->req_lock);
		} else {
			spin_unlock(&server->req_lock);

			spin_lock(&cifs_tcp_ses_lock);
			if (server->tcpStatus == CifsExiting) {
				spin_unlock(&cifs_tcp_ses_lock);
				return -ENOENT;
			}
			spin_unlock(&cifs_tcp_ses_lock);

			/*
			 * For normal commands, reserve the last MAX_COMPOUND
			 * credits to compound requests.
			 * Otherwise these compounds could be permanently
			 * starved for credits by single-credit requests.
			 *
			 * To prevent spinning CPU, block this thread until
			 * there are >MAX_COMPOUND credits available.
			 * But only do this is we already have a lot of
			 * credits in flight to avoid triggering this check
			 * for servers that are slow to hand out credits on
			 * new sessions.
			 */
			spin_lock(&server->req_lock);
			if (!optype && num_credits == 1 &&
			    server->in_flight > 2 * MAX_COMPOUND &&
			    *credits <= MAX_COMPOUND) {
				spin_unlock(&server->req_lock);

				cifs_num_waiters_inc(server);
				rc = wait_event_killable_timeout(
					server->request_q,
					has_credits(server, credits,
						    MAX_COMPOUND + 1),
					t);
				cifs_num_waiters_dec(server);
				if (!rc) {
					spin_lock(&server->req_lock);
					scredits = *credits;
					in_flight = server->in_flight;
					spin_unlock(&server->req_lock);

					trace_smb3_credit_timeout(
							server->CurrentMid,
							server->conn_id, server->hostname,
							scredits, num_credits, in_flight);
					cifs_server_dbg(VFS, "wait timed out after %d ms\n",
							timeout);
					return -EBUSY;
				}
				if (rc == -ERESTARTSYS)
					return -ERESTARTSYS;
				spin_lock(&server->req_lock);
				continue;
			}

			/*
			 * Can not count locking commands against total
			 * as they are allowed to block on server.
			 */

			/* update # of requests on the wire to server */
			if ((flags & CIFS_TIMEOUT_MASK) != CIFS_BLOCKING_OP) {
				*credits -= num_credits;
				server->in_flight += num_credits;
				if (server->in_flight > server->max_in_flight)
					server->max_in_flight = server->in_flight;
				*instance = server->reconnect_instance;
			}
			scredits = *credits;
			in_flight = server->in_flight;
			spin_unlock(&server->req_lock);

			trace_smb3_waitff_credits(server->CurrentMid,
					server->conn_id, server->hostname, scredits,
					-(num_credits), in_flight);
			cifs_dbg(FYI, "%s: remove %u credits total=%d\n",
					__func__, num_credits, scredits);
			break;
		}
	}
	return 0;
}

inline int wait_for_free_request(struct TCP_Server_Info *server,
				 const int flags, unsigned int *instance)
{
	return wait_for_free_credits(server, 1, -1, flags, instance);
}

static int
wait_for_compound_request(struct TCP_Server_Info *server, int num,
			  const int flags, unsigned int *instance)
{
	int *credits;
	int scredits, in_flight;

	credits = server->ops->get_credits_field(server, flags & CIFS_OP_MASK);

	spin_lock(&server->req_lock);
	scredits = *credits;
	in_flight = server->in_flight;

	if (*credits < num) {
		/*
		 * If the server is tight on resources or just gives us less
		 * credits for other reasons (e.g. requests are coming out of
		 * order and the server delays granting more credits until it
		 * processes a missing mid) and we exhausted most available
		 * credits there may be situations when we try to send
		 * a compound request but we don't have enough credits. At this
		 * point the client needs to decide if it should wait for
		 * additional credits or fail the request. If at least one
		 * request is in flight there is a high probability that the
		 * server will return enough credits to satisfy this compound
		 * request.
		 *
		 * Return immediately if no requests in flight since we will be
		 * stuck on waiting for credits.
		 */
		if (server->in_flight == 0) {
			spin_unlock(&server->req_lock);
			trace_smb3_insufficient_credits(server->CurrentMid,
					server->conn_id, server->hostname, scredits,
					num, in_flight);
			cifs_dbg(FYI, "%s: %d requests in flight, needed %d total=%d\n",
					__func__, in_flight, num, scredits);
			return -EDEADLK;
		}
	}
	spin_unlock(&server->req_lock);

	return wait_for_free_credits(server, num, 60000, flags,
				     instance);
}

static void
cifs_compound_callback(struct mid_q_entry *mid)
{
	struct TCP_Server_Info *server = mid->server;
	struct cifs_credits credits;

	credits.value = server->ops->get_credits(mid);
	credits.instance = server->reconnect_instance;

	add_credits(server, &credits, mid->optype);
}

static void
cifs_compound_last_callback(struct mid_q_entry *mid)
{
	cifs_compound_callback(mid);
	cifs_wake_up_task(mid);
}

static void
cifs_cancelled_callback(struct mid_q_entry *mid)
{
	cifs_compound_callback(mid);
	DeleteMidQEntry(mid);
}

int cifs_sync_mid_result(struct mid_q_entry *mid, struct TCP_Server_Info *server)
{
	int rc = 0;

	cifs_dbg(FYI, "%s: cmd=%d mid=%llu state=%d\n",
		 __func__, le16_to_cpu(mid->command), mid->mid, mid->mid_state);

	spin_lock(&GlobalMid_Lock);
	switch (mid->mid_state) {
	case MID_RESPONSE_RECEIVED:
		spin_unlock(&GlobalMid_Lock);
		return rc;
	case MID_RETRY_NEEDED:
		rc = -EAGAIN;
		break;
	case MID_RESPONSE_MALFORMED:
		rc = -EIO;
		break;
	case MID_SHUTDOWN:
		rc = -EHOSTDOWN;
		break;
	default:
		if (!(mid->mid_flags & MID_DELETED)) {
			list_del_init(&mid->qhead);
			mid->mid_flags |= MID_DELETED;
		}
		cifs_server_dbg(VFS, "%s: invalid mid state mid=%llu state=%d\n",
			 __func__, mid->mid, mid->mid_state);
		rc = -EIO;
	}
	spin_unlock(&GlobalMid_Lock);

	DeleteMidQEntry(mid);
	return rc;
}

inline int
send_cancel(struct TCP_Server_Info *server, struct smb_rqst *rqst,
	    struct mid_q_entry *mid)
{
	return server->ops->send_cancel ?
		server->ops->send_cancel(server, rqst, mid) : 0;
}

/*
 * smb_send_kvec - send an array of kvecs to the server
 * @server:	Server to send the data to
 * @smb_msg:	Message to send
 * @sent:	amount of data sent on socket is stored here
 *
 * Our basic "send data to server" function. Should be called with srv_mutex
 * held. The caller is responsible for handling the results.
 */
static int
smb_send_kvec(struct TCP_Server_Info *server, struct msghdr *smb_msg,
	      size_t *sent)
{
	int rc = 0;
	int retries = 0;
	struct socket *ssocket = server->ssocket;

	*sent = 0;

	smb_msg->msg_name = (struct sockaddr *) &server->dstaddr;
	smb_msg->msg_namelen = sizeof(struct sockaddr);
	smb_msg->msg_control = NULL;
	smb_msg->msg_controllen = 0;
	if (server->noblocksnd)
		smb_msg->msg_flags = MSG_DONTWAIT + MSG_NOSIGNAL;
	else
		smb_msg->msg_flags = MSG_NOSIGNAL;

	while (msg_data_left(smb_msg)) {
		/*
		 * If blocking send, we try 3 times, since each can block
		 * for 5 seconds. For nonblocking  we have to try more
		 * but wait increasing amounts of time allowing time for
		 * socket to clear.  The overall time we wait in either
		 * case to send on the socket is about 15 seconds.
		 * Similarly we wait for 15 seconds for a response from
		 * the server in SendReceive[2] for the server to send
		 * a response back for most types of requests (except
		 * SMB Write past end of file which can be slow, and
		 * blocking lock operations). NFS waits slightly longer
		 * than CIFS, but this can make it take longer for
		 * nonresponsive servers to be detected and 15 seconds
		 * is more than enough time for modern networks to
		 * send a packet.  In most cases if we fail to send
		 * after the retries we will kill the socket and
		 * reconnect which may clear the network problem.
		 */
		rc = sock_sendmsg(ssocket, smb_msg);
		if (rc == -EAGAIN) {
			retries++;
			if (retries >= 14 ||
			    (!server->noblocksnd && (retries > 2))) {
				cifs_server_dbg(VFS, "sends on sock %p stuck for 15 seconds\n",
					 ssocket);
				return -EAGAIN;
			}
			msleep(1 << retries);
			continue;
		}

		if (rc < 0)
			return rc;

		if (rc == 0) {
			/* should never happen, letting socket clear before
			   retrying is our only obvious option here */
			cifs_server_dbg(VFS, "tcp sent no data\n");
			msleep(500);
			continue;
		}

		/* send was at least partially successful */
		*sent += rc;
		retries = 0; /* in case we get ENOSPC on the next send */
	}
	return 0;
}

unsigned long
smb_rqst_len(struct TCP_Server_Info *server, struct smb_rqst *rqst)
{
	unsigned int i;
	struct kvec *iov;
	int nvec;
	unsigned long buflen = 0;

	if (server->vals->header_preamble_size == 0 &&
	    rqst->rq_nvec >= 2 && rqst->rq_iov[0].iov_len == 4) {
		iov = &rqst->rq_iov[1];
		nvec = rqst->rq_nvec - 1;
	} else {
		iov = rqst->rq_iov;
		nvec = rqst->rq_nvec;
	}

	/* total up iov array first */
	for (i = 0; i < nvec; i++)
		buflen += iov[i].iov_len;

	/*
	 * Add in the page array if there is one. The caller needs to make
	 * sure rq_offset and rq_tailsz are set correctly. If a buffer of
	 * multiple pages ends at page boundary, rq_tailsz needs to be set to
	 * PAGE_SIZE.
	 */
	if (rqst->rq_npages) {
		if (rqst->rq_npages == 1)
			buflen += rqst->rq_tailsz;
		else {
			/*
			 * If there is more than one page, calculate the
			 * buffer length based on rq_offset and rq_tailsz
			 */
			buflen += rqst->rq_pagesz * (rqst->rq_npages - 1) -
					rqst->rq_offset;
			buflen += rqst->rq_tailsz;
		}
	}

	return buflen;
}

int __smb_send_rqst(struct TCP_Server_Info *server, int num_rqst,
		    struct smb_rqst *rqst)
{
	int rc = 0;
	struct kvec *iov;
	int n_vec;
	unsigned int send_length = 0;
	unsigned int i, j;
	sigset_t mask, oldmask;
	size_t total_len = 0, sent, size;
	struct socket *ssocket = server->ssocket;
	struct msghdr smb_msg;
	__be32 rfc1002_marker;

	if (cifs_rdma_enabled(server)) {
		/* return -EAGAIN when connecting or reconnecting */
		rc = -EAGAIN;
		if (server->smbd_conn)
			rc = smbd_send(server, num_rqst, rqst);
		goto smbd_done;
	}

	if (ssocket == NULL)
		return -EAGAIN;

	if (fatal_signal_pending(current)) {
		cifs_dbg(FYI, "signal pending before send request\n");
		return -ERESTARTSYS;
	}

	/* cork the socket */
	tcp_sock_set_cork(ssocket->sk, true);

	for (j = 0; j < num_rqst; j++)
		send_length += smb_rqst_len(server, &rqst[j]);
	rfc1002_marker = cpu_to_be32(send_length);

	/*
	 * We should not allow signals to interrupt the network send because
	 * any partial send will cause session reconnects thus increasing
	 * latency of system calls and overload a server with unnecessary
	 * requests.
	 */

	sigfillset(&mask);
	sigprocmask(SIG_BLOCK, &mask, &oldmask);

	/* Generate a rfc1002 marker for SMB2+ */
	if (server->vals->header_preamble_size == 0) {
		struct kvec hiov = {
			.iov_base = &rfc1002_marker,
			.iov_len  = 4
		};
		iov_iter_kvec(&smb_msg.msg_iter, WRITE, &hiov, 1, 4);
		rc = smb_send_kvec(server, &smb_msg, &sent);
		if (rc < 0)
			goto unmask;

		total_len += sent;
		send_length += 4;
	}

	cifs_dbg(FYI, "Sending smb: smb_len=%u\n", send_length);

	for (j = 0; j < num_rqst; j++) {
		iov = rqst[j].rq_iov;
		n_vec = rqst[j].rq_nvec;

		size = 0;
		for (i = 0; i < n_vec; i++) {
			dump_smb(iov[i].iov_base, iov[i].iov_len);
			size += iov[i].iov_len;
		}

		iov_iter_kvec(&smb_msg.msg_iter, WRITE, iov, n_vec, size);

		rc = smb_send_kvec(server, &smb_msg, &sent);
		if (rc < 0)
			goto unmask;

		total_len += sent;

		/* now walk the page array and send each page in it */
		for (i = 0; i < rqst[j].rq_npages; i++) {
			struct bio_vec bvec;

			bvec.bv_page = rqst[j].rq_pages[i];
			rqst_page_get_length(&rqst[j], i, &bvec.bv_len,
					     &bvec.bv_offset);

			iov_iter_bvec(&smb_msg.msg_iter, WRITE,
				      &bvec, 1, bvec.bv_len);
			rc = smb_send_kvec(server, &smb_msg, &sent);
			if (rc < 0)
				break;

			total_len += sent;
		}
	}

unmask:
	sigprocmask(SIG_SETMASK, &oldmask, NULL);

	/*
	 * If signal is pending but we have already sent the whole packet to
	 * the server we need to return success status to allow a corresponding
	 * mid entry to be kept in the pending requests queue thus allowing
	 * to handle responses from the server by the client.
	 *
	 * If only part of the packet has been sent there is no need to hide
	 * interrupt because the session will be reconnected anyway, so there
	 * won't be any response from the server to handle.
	 */

	if (signal_pending(current) && (total_len != send_length)) {
		cifs_dbg(FYI, "signal is pending after attempt to send\n");
		rc = -ERESTARTSYS;
	}

	/* uncork it */
	tcp_sock_set_cork(ssocket->sk, false);

	if ((total_len > 0) && (total_len != send_length)) {
		cifs_dbg(FYI, "partial send (wanted=%u sent=%zu): terminating session\n",
			 send_length, total_len);
		/*
		 * If we have only sent part of an SMB then the next SMB could
		 * be taken as the remainder of this one. We need to kill the
		 * socket so the server throws away the partial SMB
		 */
		cifs_signal_cifsd_for_reconnect(server, false);
		trace_smb3_partial_send_reconnect(server->CurrentMid,
						  server->conn_id, server->hostname);
	}
smbd_done:
	if (rc < 0 && rc != -EINTR)
		cifs_server_dbg(VFS, "Error %d sending data on socket to server\n",
			 rc);
	else if (rc > 0)
		rc = 0;

	return rc;
}

static int
smb_send_rqst(struct TCP_Server_Info *server, int num_rqst,
	      struct smb_rqst *rqst, int flags)
{
	struct kvec iov;
	struct smb2_transform_hdr *tr_hdr;
	struct smb_rqst cur_rqst[MAX_COMPOUND];
	int rc;

	if (!(flags & CIFS_TRANSFORM_REQ))
		return __smb_send_rqst(server, num_rqst, rqst);

	if (num_rqst > MAX_COMPOUND - 1)
		return -ENOMEM;

	if (!server->ops->init_transform_rq) {
		cifs_server_dbg(VFS, "Encryption requested but transform callback is missing\n");
		return -EIO;
	}

	tr_hdr = kzalloc(sizeof(*tr_hdr), GFP_NOFS);
	if (!tr_hdr)
		return -ENOMEM;

	memset(&cur_rqst[0], 0, sizeof(cur_rqst));
	memset(&iov, 0, sizeof(iov));

	iov.iov_base = tr_hdr;
	iov.iov_len = sizeof(*tr_hdr);
	cur_rqst[0].rq_iov = &iov;
	cur_rqst[0].rq_nvec = 1;

	rc = server->ops->init_transform_rq(server, num_rqst + 1,
					    &cur_rqst[0], rqst);
	if (rc)
		goto out;

	rc = __smb_send_rqst(server, num_rqst + 1, &cur_rqst[0]);
	smb3_free_compound_rqst(num_rqst, &cur_rqst[1]);
out:
	kfree(tr_hdr);
	return rc;
}

int wait_for_response(struct TCP_Server_Info *server, struct mid_q_entry *midQ)
{
	int error;

	error = wait_event_freezekillable_unsafe(server->response_q,
				    midQ->mid_state != MID_REQUEST_SUBMITTED);
	if (error < 0)
		return -ERESTARTSYS;

	return 0;
}

/*
 * Send a SMB request and set the callback function in the mid to handle
 * the result. Caller is responsible for dealing with timeouts.
 */
int
cifs_call_async(struct TCP_Server_Info *server, struct smb_rqst *rqst,
		mid_receive_t *receive, mid_callback_t *callback,
		mid_handle_t *handle, void *cbdata, const int flags,
		const struct cifs_credits *exist_credits)
{
	int rc;
	struct mid_q_entry *mid;
	struct cifs_credits credits = { .value = 0, .instance = 0 };
	unsigned int instance;
	int optype;

	optype = flags & CIFS_OP_MASK;

	if ((flags & CIFS_HAS_CREDITS) == 0) {
		rc = wait_for_free_request(server, flags, &instance);
		if (rc)
			return rc;
		credits.value = 1;
		credits.instance = instance;
	} else
		instance = exist_credits->instance;

	cifs_server_lock(server);

	/*
	 * We can't use credits obtained from the previous session to send this
	 * request. Check if there were reconnects after we obtained credits and
	 * return -EAGAIN in such cases to let callers handle it.
	 */
	if (instance != server->reconnect_instance) {
		cifs_server_unlock(server);
		add_credits_and_wake_if(server, &credits, optype);
		return -EAGAIN;
	}

	mid = server->ops->setup_async_request(server, rqst);
	if (IS_ERR(mid)) {
		cifs_server_unlock(server);
		add_credits_and_wake_if(server, &credits, optype);
		return PTR_ERR(mid);
	}

	mid->receive = receive;
	mid->callback = callback;
	mid->callback_data = cbdata;
	mid->handle = handle;
	mid->mid_state = MID_REQUEST_SUBMITTED;

	/* put it on the pending_mid_q */
	spin_lock(&GlobalMid_Lock);
	list_add_tail(&mid->qhead, &server->pending_mid_q);
	spin_unlock(&GlobalMid_Lock);

	/*
	 * Need to store the time in mid before calling I/O. For call_async,
	 * I/O response may come back and free the mid entry on another thread.
	 */
	cifs_save_when_sent(mid);
	cifs_in_send_inc(server);
	rc = smb_send_rqst(server, 1, rqst, flags);
	cifs_in_send_dec(server);

	if (rc < 0) {
		revert_current_mid(server, mid->credits);
		server->sequence_number -= 2;
		cifs_delete_mid(mid);
	}

	cifs_server_unlock(server);

	if (rc == 0)
		return 0;

	add_credits_and_wake_if(server, &credits, optype);
	return rc;
}

int
compound_send_recv(const unsigned int xid, struct cifs_ses *ses,
		   struct TCP_Server_Info *server,
		   const int flags, const int num_rqst, struct smb_rqst *rqst,
		   int *resp_buf_type, struct kvec *resp_iov)
{
	int i, j, optype, rc = 0;
	struct mid_q_entry *midQ[MAX_COMPOUND];
	bool cancelled_mid[MAX_COMPOUND] = {false};
	struct cifs_credits credits[MAX_COMPOUND] = {
		{ .value = 0, .instance = 0 }
	};
	unsigned int instance;
	char *buf;

	optype = flags & CIFS_OP_MASK;

	for (i = 0; i < num_rqst; i++)
		resp_buf_type[i] = CIFS_NO_BUFFER;  /* no response buf yet */

	if (!ses || !ses->server || !server) {
		cifs_dbg(VFS, "Null session\n");
		return -EIO;
	}

	spin_lock(&cifs_tcp_ses_lock);
	if (server->tcpStatus == CifsExiting) {
		spin_unlock(&cifs_tcp_ses_lock);
		return -ENOENT;
	}
	spin_unlock(&cifs_tcp_ses_lock);

	/*
	 * Wait for all the requests to become available.
	 * This approach still leaves the possibility to be stuck waiting for
	 * credits if the server doesn't grant credits to the outstanding
	 * requests and if the client is completely idle, not generating any
	 * other requests.
	 * This can be handled by the eventual session reconnect.
	 */
	rc = wait_for_compound_request(server, num_rqst, flags,
				       &instance);
	if (rc)
		return rc;

	for (i = 0; i < num_rqst; i++) {
		credits[i].value = 1;
		credits[i].instance = instance;
	}

	/*
	 * Make sure that we sign in the same order that we send on this socket
	 * and avoid races inside tcp sendmsg code that could cause corruption
	 * of smb data.
	 */

	cifs_server_lock(server);

	/*
	 * All the parts of the compound chain belong obtained credits from the
	 * same session. We can not use credits obtained from the previous
	 * session to send this request. Check if there were reconnects after
	 * we obtained credits and return -EAGAIN in such cases to let callers
	 * handle it.
	 */
	if (instance != server->reconnect_instance) {
		cifs_server_unlock(server);
		for (j = 0; j < num_rqst; j++)
			add_credits(server, &credits[j], optype);
		return -EAGAIN;
	}

	for (i = 0; i < num_rqst; i++) {
		midQ[i] = server->ops->setup_request(ses, server, &rqst[i]);
		if (IS_ERR(midQ[i])) {
			revert_current_mid(server, i);
			for (j = 0; j < i; j++)
				cifs_delete_mid(midQ[j]);
			cifs_server_unlock(server);

			/* Update # of requests on wire to server */
			for (j = 0; j < num_rqst; j++)
				add_credits(server, &credits[j], optype);
			return PTR_ERR(midQ[i]);
		}

		midQ[i]->mid_state = MID_REQUEST_SUBMITTED;
		midQ[i]->optype = optype;
		/*
		 * Invoke callback for every part of the compound chain
		 * to calculate credits properly. Wake up this thread only when
		 * the last element is received.
		 */
		if (i < num_rqst - 1)
			midQ[i]->callback = cifs_compound_callback;
		else
			midQ[i]->callback = cifs_compound_last_callback;
	}
	cifs_in_send_inc(server);
	rc = smb_send_rqst(server, num_rqst, rqst, flags);
	cifs_in_send_dec(server);

	for (i = 0; i < num_rqst; i++)
		cifs_save_when_sent(midQ[i]);

	if (rc < 0) {
		revert_current_mid(server, num_rqst);
		server->sequence_number -= 2;
	}

	cifs_server_unlock(server);

	/*
	 * If sending failed for some reason or it is an oplock break that we
	 * will not receive a response to - return credits back
	 */
	if (rc < 0 || (flags & CIFS_NO_SRV_RSP)) {
		for (i = 0; i < num_rqst; i++)
			add_credits(server, &credits[i], optype);
		goto out;
	}

	/*
	 * At this point the request is passed to the network stack - we assume
	 * that any credits taken from the server structure on the client have
	 * been spent and we can't return them back. Once we receive responses
	 * we will collect credits granted by the server in the mid callbacks
	 * and add those credits to the server structure.
	 */

	/*
	 * Compounding is never used during session establish.
	 */
	spin_lock(&cifs_tcp_ses_lock);
	if ((ses->ses_status == SES_NEW) || (optype & CIFS_NEG_OP) || (optype & CIFS_SESS_OP)) {
		spin_unlock(&cifs_tcp_ses_lock);

		cifs_server_lock(server);
		smb311_update_preauth_hash(ses, server, rqst[0].rq_iov, rqst[0].rq_nvec);
		cifs_server_unlock(server);

		spin_lock(&cifs_tcp_ses_lock);
	}
	spin_unlock(&cifs_tcp_ses_lock);

	for (i = 0; i < num_rqst; i++) {
		rc = wait_for_response(server, midQ[i]);
		if (rc != 0)
			break;
	}
	if (rc != 0) {
		for (; i < num_rqst; i++) {
			cifs_server_dbg(FYI, "Cancelling wait for mid %llu cmd: %d\n",
				 midQ[i]->mid, le16_to_cpu(midQ[i]->command));
			send_cancel(server, &rqst[i], midQ[i]);
			spin_lock(&GlobalMid_Lock);
			midQ[i]->mid_flags |= MID_WAIT_CANCELLED;
			if (midQ[i]->mid_state == MID_REQUEST_SUBMITTED) {
				midQ[i]->callback = cifs_cancelled_callback;
				cancelled_mid[i] = true;
				credits[i].value = 0;
			}
			spin_unlock(&GlobalMid_Lock);
		}
	}

	for (i = 0; i < num_rqst; i++) {
		if (rc < 0)
			goto out;

		rc = cifs_sync_mid_result(midQ[i], server);
		if (rc != 0) {
			/* mark this mid as cancelled to not free it below */
			cancelled_mid[i] = true;
			goto out;
		}

		if (!midQ[i]->resp_buf ||
		    midQ[i]->mid_state != MID_RESPONSE_RECEIVED) {
			rc = -EIO;
			cifs_dbg(FYI, "Bad MID state?\n");
			goto out;
		}

		buf = (char *)midQ[i]->resp_buf;
		resp_iov[i].iov_base = buf;
		resp_iov[i].iov_len = midQ[i]->resp_buf_size +
			server->vals->header_preamble_size;

		if (midQ[i]->large_buf)
			resp_buf_type[i] = CIFS_LARGE_BUFFER;
		else
			resp_buf_type[i] = CIFS_SMALL_BUFFER;

		rc = server->ops->check_receive(midQ[i], server,
						     flags & CIFS_LOG_ERROR);

		/* mark it so buf will not be freed by cifs_delete_mid */
		if ((flags & CIFS_NO_RSP_BUF) == 0)
			midQ[i]->resp_buf = NULL;

	}

	/*
	 * Compounding is never used during session establish.
	 */
	spin_lock(&cifs_tcp_ses_lock);
	if ((ses->ses_status == SES_NEW) || (optype & CIFS_NEG_OP) || (optype & CIFS_SESS_OP)) {
		struct kvec iov = {
			.iov_base = resp_iov[0].iov_base,
			.iov_len = resp_iov[0].iov_len
		};
		spin_unlock(&cifs_tcp_ses_lock);
		cifs_server_lock(server);
		smb311_update_preauth_hash(ses, server, &iov, 1);
		cifs_server_unlock(server);
		spin_lock(&cifs_tcp_ses_lock);
	}
	spin_unlock(&cifs_tcp_ses_lock);

out:
	/*
	 * This will dequeue all mids. After this it is important that the
	 * demultiplex_thread will not process any of these mids any futher.
	 * This is prevented above by using a noop callback that will not
	 * wake this thread except for the very last PDU.
	 */
	for (i = 0; i < num_rqst; i++) {
		if (!cancelled_mid[i])
			cifs_delete_mid(midQ[i]);
	}

	return rc;
}

int
cifs_send_recv(const unsigned int xid, struct cifs_ses *ses,
	       struct TCP_Server_Info *server,
	       struct smb_rqst *rqst, int *resp_buf_type, const int flags,
	       struct kvec *resp_iov)
{
	return compound_send_recv(xid, ses, server, flags, 1,
				  rqst, resp_buf_type, resp_iov);
}

static int
smb3_crypto_shash_allocate(struct TCP_Server_Info *server)
{
	struct cifs_secmech *p = &server->secmech;
	int rc;

	rc = cifs_alloc_hash("hmac(sha256)",
			     &p->hmacsha256,
			     &p->sdeschmacsha256);
	if (rc)
		goto err;

	rc = cifs_alloc_hash("cmac(aes)", &p->cmacaes, &p->sdesccmacaes);
	if (rc)
		goto err;

	return 0;
err:
	cifs_free_hash(&p->hmacsha256, &p->sdeschmacsha256);
	return rc;
}

int
smb311_crypto_shash_allocate(struct TCP_Server_Info *server)
{
	struct cifs_secmech *p = &server->secmech;
	int rc = 0;

	rc = cifs_alloc_hash("hmac(sha256)",
			     &p->hmacsha256,
			     &p->sdeschmacsha256);
	if (rc)
		return rc;

	rc = cifs_alloc_hash("cmac(aes)", &p->cmacaes, &p->sdesccmacaes);
	if (rc)
		goto err;

	rc = cifs_alloc_hash("sha512", &p->sha512, &p->sdescsha512);
	if (rc)
		goto err;

	return 0;

err:
	cifs_free_hash(&p->cmacaes, &p->sdesccmacaes);
	cifs_free_hash(&p->hmacsha256, &p->sdeschmacsha256);
	return rc;
}


static
int smb2_get_sign_key(__u64 ses_id, struct TCP_Server_Info *server, u8 *key)
{
	struct cifs_chan *chan;
	struct cifs_ses *ses = NULL;
	struct TCP_Server_Info *it = NULL;
	int i;
	int rc = 0;

	spin_lock(&cifs_tcp_ses_lock);

	list_for_each_entry(it, &cifs_tcp_ses_list, tcp_ses_list) {
		list_for_each_entry(ses, &it->smb_ses_list, smb_ses_list) {
			if (ses->Suid == ses_id)
				goto found;
		}
	}
	cifs_server_dbg(VFS, "%s: Could not find session 0x%llx\n",
			__func__, ses_id);
	rc = -ENOENT;
	goto out;

found:
	spin_lock(&ses->chan_lock);
	if (cifs_chan_needs_reconnect(ses, server) &&
	    !CIFS_ALL_CHANS_NEED_RECONNECT(ses)) {
		/*
		 * If we are in the process of binding a new channel
		 * to an existing session, use the master connection
		 * session key
		 */
		memcpy(key, ses->smb3signingkey, SMB3_SIGN_KEY_SIZE);
		spin_unlock(&ses->chan_lock);
		goto out;
	}

	/*
	 * Otherwise, use the channel key.
	 */

	for (i = 0; i < ses->chan_count; i++) {
		chan = ses->chans + i;
		if (chan->server == server) {
			memcpy(key, chan->signkey, SMB3_SIGN_KEY_SIZE);
			spin_unlock(&ses->chan_lock);
			goto out;
		}
	}
	spin_unlock(&ses->chan_lock);

	cifs_dbg(VFS,
		 "%s: Could not find channel signing key for session 0x%llx\n",
		 __func__, ses_id);
	rc = -ENOENT;

out:
	spin_unlock(&cifs_tcp_ses_lock);
	return rc;
}

static struct cifs_ses *
smb2_find_smb_ses_unlocked(struct TCP_Server_Info *server, __u64 ses_id)
{
	struct cifs_ses *ses;

	list_for_each_entry(ses, &server->smb_ses_list, smb_ses_list) {
		if (ses->Suid != ses_id)
			continue;
		++ses->ses_count;
		return ses;
	}

	return NULL;
}

struct cifs_ses *
smb2_find_smb_ses(struct TCP_Server_Info *server, __u64 ses_id)
{
	struct cifs_ses *ses;

	spin_lock(&cifs_tcp_ses_lock);
	ses = smb2_find_smb_ses_unlocked(server, ses_id);
	spin_unlock(&cifs_tcp_ses_lock);

	return ses;
}

static struct cifs_tcon *
smb2_find_smb_sess_tcon_unlocked(struct cifs_ses *ses, __u32  tid)
{
	struct cifs_tcon *tcon;

	list_for_each_entry(tcon, &ses->tcon_list, tcon_list) {
		if (tcon->tid != tid)
			continue;
		++tcon->tc_count;
		return tcon;
	}

	return NULL;
}

/*
 * Obtain tcon corresponding to the tid in the given
 * cifs_ses
 */

struct cifs_tcon *
smb2_find_smb_tcon(struct TCP_Server_Info *server, __u64 ses_id, __u32  tid)
{
	struct cifs_ses *ses;
	struct cifs_tcon *tcon;

	spin_lock(&cifs_tcp_ses_lock);
	ses = smb2_find_smb_ses_unlocked(server, ses_id);
	if (!ses) {
		spin_unlock(&cifs_tcp_ses_lock);
		return NULL;
	}
	tcon = smb2_find_smb_sess_tcon_unlocked(ses, tid);
	if (!tcon) {
		cifs_put_smb_ses(ses);
		spin_unlock(&cifs_tcp_ses_lock);
		return NULL;
	}
	spin_unlock(&cifs_tcp_ses_lock);
	/* tcon already has a ref to ses, so we don't need ses anymore */
	cifs_put_smb_ses(ses);

	return tcon;
}

int
smb2_calc_signature(struct smb_rqst *rqst, struct TCP_Server_Info *server,
			bool allocate_crypto)
{
	int rc;
	unsigned char smb2_signature[SMB2_HMACSHA256_SIZE];
	unsigned char *sigptr = smb2_signature;
	struct kvec *iov = rqst->rq_iov;
	struct smb2_hdr *shdr = (struct smb2_hdr *)iov[0].iov_base;
	struct cifs_ses *ses;
	struct shash_desc *shash;
	struct crypto_shash *hash;
	struct sdesc *sdesc = NULL;
	struct smb_rqst drqst;

	ses = smb2_find_smb_ses(server, le64_to_cpu(shdr->SessionId));
	if (!ses) {
		cifs_server_dbg(VFS, "%s: Could not find session\n", __func__);
		return 0;
	}

	memset(smb2_signature, 0x0, SMB2_HMACSHA256_SIZE);
	memset(shdr->Signature, 0x0, SMB2_SIGNATURE_SIZE);

	if (allocate_crypto) {
		rc = cifs_alloc_hash("hmac(sha256)", &hash, &sdesc);
		if (rc) {
			cifs_server_dbg(VFS,
					"%s: sha256 alloc failed\n", __func__);
			goto out;
		}
		shash = &sdesc->shash;
	} else {
		hash = server->secmech.hmacsha256;
		shash = &server->secmech.sdeschmacsha256->shash;
	}

	rc = crypto_shash_setkey(hash, ses->auth_key.response,
			SMB2_NTLMV2_SESSKEY_SIZE);
	if (rc) {
		cifs_server_dbg(VFS,
				"%s: Could not update with response\n",
				__func__);
		goto out;
	}

	rc = crypto_shash_init(shash);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not init sha256", __func__);
		goto out;
	}

	/*
	 * For SMB2+, __cifs_calc_signature() expects to sign only the actual
	 * data, that is, iov[0] should not contain a rfc1002 length.
	 *
	 * Sign the rfc1002 length prior to passing the data (iov[1-N]) down to
	 * __cifs_calc_signature().
	 */
	drqst = *rqst;
	if (drqst.rq_nvec >= 2 && iov[0].iov_len == 4) {
		rc = crypto_shash_update(shash, iov[0].iov_base,
					 iov[0].iov_len);
		if (rc) {
			cifs_server_dbg(VFS,
					"%s: Could not update with payload\n",
					__func__);
			goto out;
		}
		drqst.rq_iov++;
		drqst.rq_nvec--;
	}

	rc = __cifs_calc_signature(&drqst, server, sigptr, shash);
	if (!rc)
		memcpy(shdr->Signature, sigptr, SMB2_SIGNATURE_SIZE);

out:
	if (allocate_crypto)
		cifs_free_hash(&hash, &sdesc);
	if (ses)
		cifs_put_smb_ses(ses);
	return rc;
}

static int generate_key(struct cifs_ses *ses, struct kvec label,
			struct kvec context, __u8 *key, unsigned int key_size)
{
	unsigned char zero = 0x0;
	__u8 i[4] = {0, 0, 0, 1};
	__u8 L128[4] = {0, 0, 0, 128};
	__u8 L256[4] = {0, 0, 1, 0};
	int rc = 0;
	unsigned char prfhash[SMB2_HMACSHA256_SIZE];
	unsigned char *hashptr = prfhash;
	struct TCP_Server_Info *server = ses->server;

	memset(prfhash, 0x0, SMB2_HMACSHA256_SIZE);
	memset(key, 0x0, key_size);

	rc = smb3_crypto_shash_allocate(server);
	if (rc) {
		cifs_server_dbg(VFS, "%s: crypto alloc failed\n", __func__);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_setkey(server->secmech.hmacsha256,
		ses->auth_key.response, SMB2_NTLMV2_SESSKEY_SIZE);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not set with session key\n", __func__);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_init(&server->secmech.sdeschmacsha256->shash);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not init sign hmac\n", __func__);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_update(&server->secmech.sdeschmacsha256->shash,
				i, 4);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not update with n\n", __func__);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_update(&server->secmech.sdeschmacsha256->shash,
				label.iov_base, label.iov_len);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not update with label\n", __func__);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_update(&server->secmech.sdeschmacsha256->shash,
				&zero, 1);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not update with zero\n", __func__);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_update(&server->secmech.sdeschmacsha256->shash,
				context.iov_base, context.iov_len);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not update with context\n", __func__);
		goto smb3signkey_ret;
	}

	if ((server->cipher_type == SMB2_ENCRYPTION_AES256_CCM) ||
		(server->cipher_type == SMB2_ENCRYPTION_AES256_GCM)) {
		rc = crypto_shash_update(&server->secmech.sdeschmacsha256->shash,
				L256, 4);
	} else {
		rc = crypto_shash_update(&server->secmech.sdeschmacsha256->shash,
				L128, 4);
	}
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not update with L\n", __func__);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_final(&server->secmech.sdeschmacsha256->shash,
				hashptr);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not generate sha256 hash\n", __func__);
		goto smb3signkey_ret;
	}

	memcpy(key, hashptr, key_size);

smb3signkey_ret:
	return rc;
}

struct derivation {
	struct kvec label;
	struct kvec context;
};

struct derivation_triplet {
	struct derivation signing;
	struct derivation encryption;
	struct derivation decryption;
};

static int
generate_smb3signingkey(struct cifs_ses *ses,
			struct TCP_Server_Info *server,
			const struct derivation_triplet *ptriplet)
{
	int rc;
	bool is_binding = false;
	int chan_index = 0;

	spin_lock(&ses->chan_lock);
	is_binding = !CIFS_ALL_CHANS_NEED_RECONNECT(ses);
	chan_index = cifs_ses_get_chan_index(ses, server);
	/* TODO: introduce ref counting for channels when the can be freed */
	spin_unlock(&ses->chan_lock);

	/*
	 * All channels use the same encryption/decryption keys but
	 * they have their own signing key.
	 *
	 * When we generate the keys, check if it is for a new channel
	 * (binding) in which case we only need to generate a signing
	 * key and store it in the channel as to not overwrite the
	 * master connection signing key stored in the session
	 */

	if (is_binding) {
		rc = generate_key(ses, ptriplet->signing.label,
				  ptriplet->signing.context,
				  ses->chans[chan_index].signkey,
				  SMB3_SIGN_KEY_SIZE);
		if (rc)
			return rc;
	} else {
		rc = generate_key(ses, ptriplet->signing.label,
				  ptriplet->signing.context,
				  ses->smb3signingkey,
				  SMB3_SIGN_KEY_SIZE);
		if (rc)
			return rc;

		/* safe to access primary channel, since it will never go away */
		spin_lock(&ses->chan_lock);
		memcpy(ses->chans[0].signkey, ses->smb3signingkey,
		       SMB3_SIGN_KEY_SIZE);
		spin_unlock(&ses->chan_lock);

		rc = generate_key(ses, ptriplet->encryption.label,
				  ptriplet->encryption.context,
				  ses->smb3encryptionkey,
				  SMB3_ENC_DEC_KEY_SIZE);
		rc = generate_key(ses, ptriplet->decryption.label,
				  ptriplet->decryption.context,
				  ses->smb3decryptionkey,
				  SMB3_ENC_DEC_KEY_SIZE);
		if (rc)
			return rc;
	}

	if (rc)
		return rc;

#ifdef CONFIG_CIFS_DEBUG_DUMP_KEYS
	cifs_dbg(VFS, "%s: dumping generated AES session keys\n", __func__);
	/*
	 * The session id is opaque in terms of endianness, so we can't
	 * print it as a long long. we dump it as we got it on the wire
	 */
	cifs_dbg(VFS, "Session Id    %*ph\n", (int)sizeof(ses->Suid),
			&ses->Suid);
	cifs_dbg(VFS, "Cipher type   %d\n", server->cipher_type);
	cifs_dbg(VFS, "Session Key   %*ph\n",
		 SMB2_NTLMV2_SESSKEY_SIZE, ses->auth_key.response);
	cifs_dbg(VFS, "Signing Key   %*ph\n",
		 SMB3_SIGN_KEY_SIZE, ses->smb3signingkey);
	if ((server->cipher_type == SMB2_ENCRYPTION_AES256_CCM) ||
		(server->cipher_type == SMB2_ENCRYPTION_AES256_GCM)) {
		cifs_dbg(VFS, "ServerIn Key  %*ph\n",
				SMB3_GCM256_CRYPTKEY_SIZE, ses->smb3encryptionkey);
		cifs_dbg(VFS, "ServerOut Key %*ph\n",
				SMB3_GCM256_CRYPTKEY_SIZE, ses->smb3decryptionkey);
	} else {
		cifs_dbg(VFS, "ServerIn Key  %*ph\n",
				SMB3_GCM128_CRYPTKEY_SIZE, ses->smb3encryptionkey);
		cifs_dbg(VFS, "ServerOut Key %*ph\n",
				SMB3_GCM128_CRYPTKEY_SIZE, ses->smb3decryptionkey);
	}
#endif
	return rc;
}

int
generate_smb30signingkey(struct cifs_ses *ses,
			 struct TCP_Server_Info *server)

{
	struct derivation_triplet triplet;
	struct derivation *d;

	d = &triplet.signing;
	d->label.iov_base = "SMB2AESCMAC";
	d->label.iov_len = 12;
	d->context.iov_base = "SmbSign";
	d->context.iov_len = 8;

	d = &triplet.encryption;
	d->label.iov_base = "SMB2AESCCM";
	d->label.iov_len = 11;
	d->context.iov_base = "ServerIn ";
	d->context.iov_len = 10;

	d = &triplet.decryption;
	d->label.iov_base = "SMB2AESCCM";
	d->label.iov_len = 11;
	d->context.iov_base = "ServerOut";
	d->context.iov_len = 10;

	return generate_smb3signingkey(ses, server, &triplet);
}

int
generate_smb311signingkey(struct cifs_ses *ses,
			  struct TCP_Server_Info *server)

{
	struct derivation_triplet triplet;
	struct derivation *d;

	d = &triplet.signing;
	d->label.iov_base = "SMBSigningKey";
	d->label.iov_len = 14;
	d->context.iov_base = ses->preauth_sha_hash;
	d->context.iov_len = 64;

	d = &triplet.encryption;
	d->label.iov_base = "SMBC2SCipherKey";
	d->label.iov_len = 16;
	d->context.iov_base = ses->preauth_sha_hash;
	d->context.iov_len = 64;

	d = &triplet.decryption;
	d->label.iov_base = "SMBS2CCipherKey";
	d->label.iov_len = 16;
	d->context.iov_base = ses->preauth_sha_hash;
	d->context.iov_len = 64;

	return generate_smb3signingkey(ses, server, &triplet);
}

int
smb3_calc_signature(struct smb_rqst *rqst, struct TCP_Server_Info *server,
			bool allocate_crypto)
{
	int rc;
	unsigned char smb3_signature[SMB2_CMACAES_SIZE];
	unsigned char *sigptr = smb3_signature;
	struct kvec *iov = rqst->rq_iov;
	struct smb2_hdr *shdr = (struct smb2_hdr *)iov[0].iov_base;
	struct shash_desc *shash;
	struct crypto_shash *hash;
	struct sdesc *sdesc = NULL;
	struct smb_rqst drqst;
	u8 key[SMB3_SIGN_KEY_SIZE];

	rc = smb2_get_sign_key(le64_to_cpu(shdr->SessionId), server, key);
	if (rc)
		return 0;

	if (allocate_crypto) {
		rc = cifs_alloc_hash("cmac(aes)", &hash, &sdesc);
		if (rc)
			return rc;

		shash = &sdesc->shash;
	} else {
		hash = server->secmech.cmacaes;
		shash = &server->secmech.sdesccmacaes->shash;
	}

	memset(smb3_signature, 0x0, SMB2_CMACAES_SIZE);
	memset(shdr->Signature, 0x0, SMB2_SIGNATURE_SIZE);

	rc = crypto_shash_setkey(hash, key, SMB2_CMACAES_SIZE);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not set key for cmac aes\n", __func__);
		goto out;
	}

	/*
	 * we already allocate sdesccmacaes when we init smb3 signing key,
	 * so unlike smb2 case we do not have to check here if secmech are
	 * initialized
	 */
	rc = crypto_shash_init(shash);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not init cmac aes\n", __func__);
		goto out;
	}

	/*
	 * For SMB2+, __cifs_calc_signature() expects to sign only the actual
	 * data, that is, iov[0] should not contain a rfc1002 length.
	 *
	 * Sign the rfc1002 length prior to passing the data (iov[1-N]) down to
	 * __cifs_calc_signature().
	 */
	drqst = *rqst;
	if (drqst.rq_nvec >= 2 && iov[0].iov_len == 4) {
		rc = crypto_shash_update(shash, iov[0].iov_base,
					 iov[0].iov_len);
		if (rc) {
			cifs_server_dbg(VFS, "%s: Could not update with payload\n",
				 __func__);
			goto out;
		}
		drqst.rq_iov++;
		drqst.rq_nvec--;
	}

	rc = __cifs_calc_signature(&drqst, server, sigptr, shash);
	if (!rc)
		memcpy(shdr->Signature, sigptr, SMB2_SIGNATURE_SIZE);

out:
	if (allocate_crypto)
		cifs_free_hash(&hash, &sdesc);
	return rc;
}

/* must be called with server->srv_mutex held */
static int
smb2_sign_rqst(struct smb_rqst *rqst, struct TCP_Server_Info *server)
{
	int rc = 0;
	struct smb2_hdr *shdr;
	struct smb2_sess_setup_req *ssr;
	bool is_binding;
	bool is_signed;

	shdr = (struct smb2_hdr *)rqst->rq_iov[0].iov_base;
	ssr = (struct smb2_sess_setup_req *)shdr;

	is_binding = shdr->Command == SMB2_SESSION_SETUP &&
		(ssr->Flags & SMB2_SESSION_REQ_FLAG_BINDING);
	is_signed = shdr->Flags & SMB2_FLAGS_SIGNED;

	if (!is_signed)
		return 0;
	spin_lock(&cifs_tcp_ses_lock);
	if (server->ops->need_neg &&
	    server->ops->need_neg(server)) {
		spin_unlock(&cifs_tcp_ses_lock);
		return 0;
	}
	spin_unlock(&cifs_tcp_ses_lock);
	if (!is_binding && !server->session_estab) {
		strncpy(shdr->Signature, "BSRSPYL", 8);
		return 0;
	}

	rc = server->ops->calc_signature(rqst, server, false);

	return rc;
}

int
smb2_verify_signature(struct smb_rqst *rqst, struct TCP_Server_Info *server)
{
	unsigned int rc;
	char server_response_sig[SMB2_SIGNATURE_SIZE];
	struct smb2_hdr *shdr =
			(struct smb2_hdr *)rqst->rq_iov[0].iov_base;

	if ((shdr->Command == SMB2_NEGOTIATE) ||
	    (shdr->Command == SMB2_SESSION_SETUP) ||
	    (shdr->Command == SMB2_OPLOCK_BREAK) ||
	    server->ignore_signature ||
	    (!server->session_estab))
		return 0;

	/*
	 * BB what if signatures are supposed to be on for session but
	 * server does not send one? BB
	 */

	/* Do not need to verify session setups with signature "BSRSPYL " */
	if (memcmp(shdr->Signature, "BSRSPYL ", 8) == 0)
		cifs_dbg(FYI, "dummy signature received for smb command 0x%x\n",
			 shdr->Command);

	/*
	 * Save off the origiginal signature so we can modify the smb and check
	 * our calculated signature against what the server sent.
	 */
	memcpy(server_response_sig, shdr->Signature, SMB2_SIGNATURE_SIZE);

	memset(shdr->Signature, 0, SMB2_SIGNATURE_SIZE);

	rc = server->ops->calc_signature(rqst, server, true);

	if (rc)
		return rc;

	if (memcmp(server_response_sig, shdr->Signature, SMB2_SIGNATURE_SIZE)) {
		cifs_dbg(VFS, "sign fail cmd 0x%x message id 0x%llx\n",
			shdr->Command, shdr->MessageId);
		return -EACCES;
	} else
		return 0;
}

/*
 * Set message id for the request. Should be called after wait_for_free_request
 * and when srv_mutex is held.
 */
static inline void
smb2_seq_num_into_buf(struct TCP_Server_Info *server,
		      struct smb2_hdr *shdr)
{
	unsigned int i, num = le16_to_cpu(shdr->CreditCharge);

	shdr->MessageId = get_next_mid64(server);
	/* skip message numbers according to CreditCharge field */
	for (i = 1; i < num; i++)
		get_next_mid(server);
}

static struct mid_q_entry *
smb2_mid_entry_alloc(const struct smb2_hdr *shdr,
		     struct TCP_Server_Info *server)
{
	struct mid_q_entry *temp;
	unsigned int credits = le16_to_cpu(shdr->CreditCharge);

	if (server == NULL) {
		cifs_dbg(VFS, "Null TCP session in smb2_mid_entry_alloc\n");
		return NULL;
	}

	temp = mempool_alloc(cifs_mid_poolp, GFP_NOFS);
	memset(temp, 0, sizeof(struct mid_q_entry));
	kref_init(&temp->refcount);
	temp->mid = le64_to_cpu(shdr->MessageId);
	temp->credits = credits > 0 ? credits : 1;
	temp->pid = current->pid;
	temp->command = shdr->Command; /* Always LE */
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
	trace_smb3_cmd_enter(le32_to_cpu(shdr->Id.SyncId.TreeId),
			     le64_to_cpu(shdr->SessionId),
			     le16_to_cpu(shdr->Command), temp->mid);
	return temp;
}

static int
smb2_get_mid_entry(struct cifs_ses *ses, struct TCP_Server_Info *server,
		   struct smb2_hdr *shdr, struct mid_q_entry **mid)
{
	spin_lock(&cifs_tcp_ses_lock);
	if (server->tcpStatus == CifsExiting) {
		spin_unlock(&cifs_tcp_ses_lock);
		return -ENOENT;
	}

	if (server->tcpStatus == CifsNeedReconnect) {
		spin_unlock(&cifs_tcp_ses_lock);
		cifs_dbg(FYI, "tcp session dead - return to caller to retry\n");
		return -EAGAIN;
	}

	if (server->tcpStatus == CifsNeedNegotiate &&
	   shdr->Command != SMB2_NEGOTIATE) {
		spin_unlock(&cifs_tcp_ses_lock);
		return -EAGAIN;
	}

	if (ses->ses_status == SES_NEW) {
		if ((shdr->Command != SMB2_SESSION_SETUP) &&
		    (shdr->Command != SMB2_NEGOTIATE)) {
			spin_unlock(&cifs_tcp_ses_lock);
			return -EAGAIN;
		}
		/* else ok - we are setting up session */
	}

	if (ses->ses_status == SES_EXITING) {
		if (shdr->Command != SMB2_LOGOFF) {
			spin_unlock(&cifs_tcp_ses_lock);
			return -EAGAIN;
		}
		/* else ok - we are shutting down the session */
	}
	spin_unlock(&cifs_tcp_ses_lock);

	*mid = smb2_mid_entry_alloc(shdr, server);
	if (*mid == NULL)
		return -ENOMEM;
	spin_lock(&GlobalMid_Lock);
	list_add_tail(&(*mid)->qhead, &server->pending_mid_q);
	spin_unlock(&GlobalMid_Lock);

	return 0;
}

int
smb2_check_receive(struct mid_q_entry *mid, struct TCP_Server_Info *server,
		   bool log_error)
{
	unsigned int len = mid->resp_buf_size;
	struct kvec iov[1];
	struct smb_rqst rqst = { .rq_iov = iov,
				 .rq_nvec = 1 };

	iov[0].iov_base = (char *)mid->resp_buf;
	iov[0].iov_len = len;

	dump_smb(mid->resp_buf, min_t(u32, 80, len));
	/* convert the length into a more usable form */
	if (len > 24 && server->sign && !mid->decrypted) {
		int rc;

		rc = smb2_verify_signature(&rqst, server);
		if (rc)
			cifs_server_dbg(VFS, "SMB signature verification returned error = %d\n",
				 rc);
	}

	return map_smb2_to_linux_error(mid->resp_buf, log_error);
}

struct mid_q_entry *
smb2_setup_request(struct cifs_ses *ses, struct TCP_Server_Info *server,
		   struct smb_rqst *rqst)
{
	int rc;
	struct smb2_hdr *shdr =
			(struct smb2_hdr *)rqst->rq_iov[0].iov_base;
	struct mid_q_entry *mid;

	smb2_seq_num_into_buf(server, shdr);

	rc = smb2_get_mid_entry(ses, server, shdr, &mid);
	if (rc) {
		revert_current_mid_from_hdr(server, shdr);
		return ERR_PTR(rc);
	}

	rc = smb2_sign_rqst(rqst, server);
	if (rc) {
		revert_current_mid_from_hdr(server, shdr);
		cifs_delete_mid(mid);
		return ERR_PTR(rc);
	}

	return mid;
}

struct mid_q_entry *
smb2_setup_async_request(struct TCP_Server_Info *server, struct smb_rqst *rqst)
{
	int rc;
	struct smb2_hdr *shdr =
			(struct smb2_hdr *)rqst->rq_iov[0].iov_base;
	struct mid_q_entry *mid;

	spin_lock(&cifs_tcp_ses_lock);
	if (server->tcpStatus == CifsNeedNegotiate &&
	   shdr->Command != SMB2_NEGOTIATE) {
		spin_unlock(&cifs_tcp_ses_lock);
		return ERR_PTR(-EAGAIN);
	}
	spin_unlock(&cifs_tcp_ses_lock);

	smb2_seq_num_into_buf(server, shdr);

	mid = smb2_mid_entry_alloc(shdr, server);
	if (mid == NULL) {
		revert_current_mid_from_hdr(server, shdr);
		return ERR_PTR(-ENOMEM);
	}

	rc = smb2_sign_rqst(rqst, server);
	if (rc) {
		revert_current_mid_from_hdr(server, shdr);
		DeleteMidQEntry(mid);
		return ERR_PTR(rc);
	}

	return mid;
}

int
smb3_crypto_aead_allocate(struct TCP_Server_Info *server)
{
	struct crypto_aead *tfm;

	if (!server->secmech.ccmaesencrypt) {
		if ((server->cipher_type == SMB2_ENCRYPTION_AES128_GCM) ||
		    (server->cipher_type == SMB2_ENCRYPTION_AES256_GCM))
			tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
		else
			tfm = crypto_alloc_aead("ccm(aes)", 0, 0);
		if (IS_ERR(tfm)) {
			cifs_server_dbg(VFS, "%s: Failed alloc encrypt aead\n",
				 __func__);
			return PTR_ERR(tfm);
		}
		server->secmech.ccmaesencrypt = tfm;
	}

	if (!server->secmech.ccmaesdecrypt) {
		if ((server->cipher_type == SMB2_ENCRYPTION_AES128_GCM) ||
		    (server->cipher_type == SMB2_ENCRYPTION_AES256_GCM))
			tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
		else
			tfm = crypto_alloc_aead("ccm(aes)", 0, 0);
		if (IS_ERR(tfm)) {
			crypto_free_aead(server->secmech.ccmaesencrypt);
			server->secmech.ccmaesencrypt = NULL;
			cifs_server_dbg(VFS, "%s: Failed to alloc decrypt aead\n",
				 __func__);
			return PTR_ERR(tfm);
		}
		server->secmech.ccmaesdecrypt = tfm;
	}

	return 0;
}
