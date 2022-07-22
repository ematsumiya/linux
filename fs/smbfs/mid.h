// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) SUSE LLC, 2022
 *
 * Author(s): Enzo Matsumiya <ematsumiya@suse.de>
 *
 * SMBFS MID definition, helpers, and related functions.
 */
#ifndef _SMBFS_MID_H
#define _SMBFS_MID_H

#include "server_info.h"

#define MID_FREE		0x00
#define MID_REQUEST_ALLOCATED	0x01
#define MID_REQUEST_SUBMITTED	0x02
#define MID_RESPONSE_RECEIVED	0x04
#define MID_RETRY_NEEDED	0x08 /* session closed while this request out */
#define MID_RESPONSE_MALFORMED	0x10
#define MID_SHUTDOWN		0x20

/* MID flags */
#define MID_WAIT_CANCELLED	1 /* cancelled while waiting for response */
#define MID_DELETED		2 /* mid has been dequeued/deleted */

struct smbfs_mid_entry;
/*
 * mid receive callback
 *
 * This function is for receiving the rest of the SMB frame, starting with
 * the WordCount (which is just after the MID in struct smb_hdr).
 *
 * Notes:
 * - This will be called by smbfsd, with no locks held.
 * - The mid will still be on server->pending_mids.
 * - mid->resp_buf will point to the current buffer.
 *
 * Returns zero on a successful receive, or an error. The receive state in
 * the smbfs_server_info will also be updated.
 */
typedef int (mid_receive_t)(struct smbfs_server_info *server,
			    struct smbfs_mid_entry *mid);

/*
 * mid handle function
 *
 * This is called once the mid has been recognized after decryption of the message.
 */
typedef int (mid_handle_t)(struct smbfs_server_info *server,
			   struct smbfs_mid_entry *mid);

/*
 * mid completion callback
 *
 * This is called once the mid has been received off of the socket. When
 * creating one, take special care to avoid deadlocks.
 *
 * Notes:
 * - it will be called by smbfsd, with no locks held
 * - the mid will be removed from any lists
 */
typedef void (mid_complete_t)(struct smbfs_mid_entry *mid);

/* one of these for every pending CIFS request to the server */
struct smbfs_mid_entry {
	struct list_head head; /* mids waiting on reply from this server */
	struct kref refcount;
	struct smbfs_server_info *server; /* server corresponding to this mid */
	
	u64 mid; /* multiplex id */
	u16 credits; /* number of credits consumed by this mid */
	u16 credits_received; /* number of credits from the response */
	u32 pid; /* process id */
	u32 seqn; /* for signing */
	u32 state; /* wish this were enum but can not pass to wait_event */
	unsigned long flags;

	u64 when_alloc; /* when mid was created */
#ifdef CONFIG_SMBFS_STATS_EXTRA
	u64 when_sent; /* time when SMB send finished */
	u64 when_received; /* when demux complete (taken off wire) */
#endif /* CONFIG_SMBFS_STATS_EXTRA */
	mid_receive_t *receive; /* call receive callback */
	mid_handle_t *handle; /* call handle mid callback */
	mid_complete_t *callback; /* call completion callback */
	void *callback_data; /* general purpose pointer for callback */

	struct task_struct *creator;
	void *resp_buf; /* pointer to received SMB header */
	u32 resp_buf_size;
	__le16 cmd; /* SMB command code */
	u32 optype; /* operation type */
	bool has_large_buf; /* if valid response, is pointer to large buf */
	bool has_multi_rsp; /* multiple trans2 responses for one request  */
	bool has_multi_end; /* both received */
	bool is_decrypted; /* decrypted entry */
};

inline u16 get_mid(const struct smb_hdr *smb)
{
	return le16_to_cpu(smb->Mid);
}

inline bool compare_mid(u16 mid, const struct smb_hdr *smb)
{
	return mid == le16_to_cpu(smb->Mid);
}

#ifdef CONFIG_SMBFS_STATS_EXTRA
inline void set_when_sent(struct smbfs_mid_entry *mid)
{
	mid->when_sent = jiffies;
}
#else
static inline void set_when_sent(struct smbfs_mid_entry *mid) {}
#endif /* CONFIG_SMBFS_STATS_EXTRA */
#endif /* _SMBFS_MID_H */
