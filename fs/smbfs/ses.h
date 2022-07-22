// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) SUSE LLC, 2022
 *
 * Author(s): Enzo Matsumiya <ematsumiya@suse.de>
 *
 * SMBFS session definition, helpers, and related functions.
*/
#ifndef _SMBFS_SES_H
#define _SMBFS_SES_H

#include "security.h"
#include "defs.h"

/* reasonable max for client */
#define SMBFS_MAX_CLIENT_NAME_LEN (__NEW_UTS_LEN + 1)

struct smbfs_server_info;

typedef enum smbfs_ses_status {
	SMBFS_SES_STATUS_NEW = 0,
	SMBFS_SES_STATUS_GOOD,
	SMBFS_SES_STATUS_EXITING,
	SMBFS_SES_STATUS_NEED_RECONNECT,
	SMBFS_SES_STATUS_IN_SETUP,
} smbfs_ses_status_t;

struct smbfs_channel {
	bool in_reconnect; /* if session setup in progress for this channel */
	struct smbfs_server_info *server;
	struct smbfs_server_iface *iface; /* interface in use */
	u8 sign_key[SMB3_SIGN_KEY_SIZE];
};

/* one of these for each uid session with a particular host */
struct smbfs_ses {
	struct mutex lock;

	struct list_head head;
	struct list_head reconnect_head; /* reconnect list */
	struct list_head tcons;

	struct smbfs_tcon *tcon_ipc;
	struct smbfs_server_info *server; /* pointer to server info */
	u32 count; /* reference counter */
	smbfs_ses_status_t status; /* protected by smbfs_server_lock */
	u64 override_secflag; /* if non-zero override global sec flags */
	
	char *serverOS; /* name of operating system underlying server */
	char *serverNOS; /* name of network operating system of server */
	char *server_domain; /* security realm of server */

	u64 id; /* remote SMB uid  */
	kuid_t linux_uid; /* overriding owner of files on the mount */
	kuid_t cred_uid; /* owner of credentials */

	u64 capabilities;
	
	char ip_addr[INET6_ADDRSTRLEN + 1]; /* max IP addr string len (IPv4 and v6)*/
	char *user_name; /* must not be null except during init of sess */
	char *domain_name;
	char *password;
	char client_name[SMBFS_MAX_CLIENT_NAME_LEN];

	struct smbfs_session_key auth_key;
	struct smbfs_ntlmssp_auth *ntlmssp; /* ciphertext, flags, server challenge */
	smbfs_security_t sectype; /* what security flavor was specified? */
	bool signing_required; /* is signing required? */
	bool domain_auto;
	
	unsigned long flags; /* see fs/smbfs_common/smb2pdu.h */
	u8 smb3signingkey[SMB3_SIGN_KEY_SIZE];
	u8 smb3encryptionkey[SMB3_ENC_DEC_KEY_SIZE];
	u8 smb3decryptionkey[SMB3_ENC_DEC_KEY_SIZE];
	u8 preauth_sha_hash[SMB2_PREAUTH_HASH_SIZE];

	/*
	 * Network interfaces available on the server this session is
	 * connected to.
	 *
	 * Other channels can be opened by connecting and binding this
	 * session to interfaces from this list.
	 *
	 * iface_lock should be taken when accessing the below iface_* fields
	 */
	spinlock_t iface_lock;
	struct list_head ifaces;
	u32 iface_count;
	u64 iface_last_update; /* jiffies */

	spinlock_t channel_lock;
#define MAX_CHANNELS		16
#define ALL_CHANNELS_SET(ses)	((1UL << (ses)->channel_count) - 1)
#define ALL_CHANNELS_GOOD(ses)	(!(ses)->channels_need_reconnect)

#define ALL_CHANNELS_NEED_RECONNECT(ses) \
	((ses)->channels_need_reconnect == SMBFS_ALL_CHANNELS_SET(ses))
#define SET_ALL_CHANNELS_NEED_RECONNECT(ses) \
	((ses)->channels_need_reconnect = SMBFS_ALL_CHANNELS_SET(ses))
#define CHANNEL_NEEDS_RECONNECT(ses, index) \
	test_bit((index), &(ses)->channels_need_reconnect)
#define CHANNEL_IN_RECONNECT(ses, index) \
	((ses)->channels[(index)].in_reconnect)

	struct smbfs_channel channels[MAX_CHANNELS];
	u32 channel_count;
	u32 max_channels;
	atomic_t channel_seq; /* round robin state */

	/*
	 * channels_need_reconnect is a bitmap indicating which of the channels
	 * under this SMB session needs to be reconnected.
	 *
	 * If not multichannel session, only one bit will be used.
	 *
	 * We will ask for sess and tcon reconnection only if all the
	 * channels are marked for needing reconnection. This will
	 * enable the sessions on top to continue to live till any
	 * of the channels below are active.
	 */
	unsigned long channels_need_reconnect;
};

/* flag sans "SMB2_SESSION_FLAG_" prefix (see fs/smbfs_common/smb2pdu.h) */
#define set_ses_flag(_s, _flag) set_bit(SMB2_SESSION_FLAG_ ## _flag, &_s->flags)
#define get_ses_flag(_s, _flag) test_bit(SMB2_SESSION_FLAG_ ## _flag, &_s->flags)
#define clear_ses_flag(_s, _flag) clear_bit(SMB2_SESSION_FLAG_ ## _flag, &_s->flags)
#endif /* _SMBFS_SES_H */
