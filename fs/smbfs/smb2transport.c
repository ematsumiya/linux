// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) International Business Machines Corp., 2002, 2011
 *                 Etersoft, 2012
 * Author(s): Steve French <sfrench@us.ibm.com>
 *              Jeremy Allison <jra@samba.org> 2006
 *              Pavel Shilovsky <pshilovsky@samba.org> 2012
*/

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/net.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <asm/processor.h>
#include <linux/mempool.h>
#include <linux/highmem.h>
#include <crypto/aead.h>
#include "defs.h"
#include "defs.h"
#include "smb2proto.h"
#include "debug.h"
#include "proc.h"
#include "smb2status.h"
#include "smb2glob.h"


static int
smb3_crypto_shash_allocate(struct smbfs_server_info *server)
{
	struct cifs_secmech *p = &server->sec.ctx;
	int rc;

	rc = cifs_alloc_hash("hmac(sha256)",
			     &p->hmacsha256,
			     &p->sec_desc_hmacsha256);
	if (rc)
		goto err;

	rc = cifs_alloc_hash("cmac(aes)", &p->cmacaes, &p->sec_desc_cmacaes);
	if (rc)
		goto err;

	return 0;
err:
	cifs_free_hash(&p->hmacsha256, &p->sec_desc_hmacsha256);
	return rc;
}

int
smb311_crypto_shash_allocate(struct smbfs_server_info *server)
{
	struct cifs_secmech *p = &server->sec.ctx;
	int rc = 0;

	rc = cifs_alloc_hash("hmac(sha256)",
			     &p->hmacsha256,
			     &p->sec_desc_hmacsha256);
	if (rc)
		return rc;

	rc = cifs_alloc_hash("cmac(aes)", &p->cmacaes, &p->sec_desc_cmacaes);
	if (rc)
		goto err;

	rc = cifs_alloc_hash("sha512", &p->sha512, &p->sec_desc_sha512);
	if (rc)
		goto err;

	return 0;

err:
	cifs_free_hash(&p->cmacaes, &p->sec_desc_cmacaes);
	cifs_free_hash(&p->hmacsha256, &p->sec_desc_hmacsha256);
	return rc;
}


static
int smb2_get_sign_key(__u64 ses_id, struct smbfs_server_info *server, u8 *key)
{
	struct smbfs_channel *chan;
	struct smbfs_ses *ses = NULL;
	struct smbfs_server_info *server = NULL;
	int i;
	int rc = 0;

	spin_lock(&g_servers_lock);

	list_for_each_entry(server, &g_servers_list, head) {
		list_for_each_entry(ses, &it->sessions, head) {
			if (ses->id == ses_id)
				goto found;
		}
	}
	smbfs_server_log(server, "%s: Could not find session 0x%llx\n", __func__, ses_id);
	rc = -ENOENT;
	goto out;

found:
	spin_lock(&ses->channel_lock);
	if (smbfs_channel_needs_reconnect(ses, server) &&
	    !ALL_CHANNELS_NEED_RECONNECT(ses)) {
		/*
		 * If we are in the process of binding a new channel
		 * to an existing session, use the master connection
		 * session key
		 */
		memcpy(key, ses->smb3signingkey, SMB3_SIGN_KEY_SIZE);
		spin_unlock(&ses->channel_lock);
		goto out;
	}

	/*
	 * Otherwise, use the channel key.
	 */

	for (i = 0; i < ses->channel_count; i++) {
		chan = ses->channels + i;
		if (chan->server == server) {
			memcpy(key, chan->signkey, SMB3_SIGN_KEY_SIZE);
			spin_unlock(&ses->channel_lock);
			goto out;
		}
	}
	spin_unlock(&ses->channel_lock);

	smbfs_log("%s: Could not find channel signing key for session 0x%llx\n",
		 __func__, ses_id);
	rc = -ENOENT;

out:
	spin_unlock(&g_servers_lock);
	return rc;
}

static struct smbfs_ses *
smb2_find_smb_ses_unlocked(struct smbfs_server_info *server, __u64 ses_id)
{
	struct smbfs_ses *ses;

	list_for_each_entry(ses, &server->sessions, head) {
		if (ses->id != ses_id)
			continue;
		++ses->count;
		return ses;
	}

	return NULL;
}

struct smbfs_ses *
smb2_find_smb_ses(struct smbfs_server_info *server, __u64 ses_id)
{
	struct smbfs_ses *ses;

	spin_lock(&g_servers_lock);
	ses = smb2_find_smb_ses_unlocked(server, ses_id);
	spin_unlock(&g_servers_lock);

	return ses;
}

static struct smbfs_tcon *
smb2_find_smb_sess_tcon_unlocked(struct smbfs_ses *ses, __u32 tid)
{
	struct smbfs_tcon *tcon;

	list_for_each_entry(tcon, &ses->tcons, head) {
		if (tcon->tid != tid)
			continue;
		++tcon->count;
		return tcon;
	}

	return NULL;
}

/*
 * Obtain tcon corresponding to the tid in the given
 * smbfs_ses
 */

struct smbfs_tcon *
smb2_find_smb_tcon(struct smbfs_server_info *server, __u64 ses_id, __u32 tid)
{
	struct smbfs_ses *ses;
	struct smbfs_tcon *tcon;

	spin_lock(&g_servers_lock);
	ses = smb2_find_smb_ses_unlocked(server, ses_id);
	if (!ses) {
		spin_unlock(&g_servers_lock);
		return NULL;
	}
	tcon = smb2_find_smb_sess_tcon_unlocked(ses, tid);
	if (!tcon) {
		cifs_put_smb_ses(ses);
		spin_unlock(&g_servers_lock);
		return NULL;
	}
	spin_unlock(&g_servers_lock);
	/* tcon already has a ref to ses, so we don't need ses anymore */
	cifs_put_smb_ses(ses);

	return tcon;
}

int
smb2_calc_signature(struct smb_rqst *rqst, struct smbfs_server_info *server,
			bool allocate_crypto)
{
	int rc;
	unsigned char smb2_signature[SMB2_HMACSHA256_SIZE];
	unsigned char *sigptr = smb2_signature;
	struct kvec *iov = rqst->rq_iov;
	struct smb2_hdr *shdr = (struct smb2_hdr *)iov[0].iov_base;
	struct smbfs_ses *ses;
	struct shash_desc *shash;
	struct crypto_shash *hash;
	struct smbfs_sec_desc *sec_desc = NULL;
	struct smb_rqst drqst;

	ses = smb2_find_smb_ses(server, le64_to_cpu(shdr->SessionId));
	if (!ses) {
		smbfs_server_log(server, "%s: Could not find session\n", __func__);
		return 0;
	}

	memset(smb2_signature, 0x0, SMB2_HMACSHA256_SIZE);
	memset(shdr->Signature, 0x0, SMB2_SIGNATURE_SIZE);

	if (allocate_crypto) {
		rc = cifs_alloc_hash("hmac(sha256)", &hash, &sec_desc_);
		if (rc) {
			smbfs_server_log(server, "%s: sha256 alloc failed, rc=%d\n", __func__, rc);
			goto out;
		}
		shash = &sec_desc_->shash;
	} else {
		hash = server->sec.ctx.hmacsha256;
		shash = &server->sec.ctx.sec_desc_hmacsha256->shash;
	}

	rc = crypto_shash_setkey(hash, ses->auth_key.response,
			SMB2_NTLMV2_SESSKEY_SIZE);
	if (rc) {
		smbfs_server_log(server, "%s: Could not update with response, rc=%d\n", __func__, rc);
		goto out;
	}

	rc = crypto_shash_init(shash);
	if (rc) {
		smbfs_server_log(server, "%s: Could not init sha256, rc=%d\n", __func__, rc);
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
			smbfs_server_log(server, "%s: Could not update with payload, rc=%d\n", __func__, rc);
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
		cifs_free_hash(&hash, &sec_desc_);
	if (ses)
		cifs_put_smb_ses(ses);
	return rc;
}

static int generate_key(struct smbfs_ses *ses, struct kvec label,
			struct kvec context, __u8 *key, unsigned int key_size)
{
	unsigned char zero = 0x0;
	__u8 i[4] = {0, 0, 0, 1};
	__u8 L128[4] = {0, 0, 0, 128};
	__u8 L256[4] = {0, 0, 1, 0};
	int rc = 0;
	unsigned char prfhash[SMB2_HMACSHA256_SIZE];
	unsigned char *hashptr = prfhash;
	struct smbfs_server_info *server = ses->server;

	memset(prfhash, 0x0, SMB2_HMACSHA256_SIZE);
	memset(key, 0x0, key_size);

	rc = smb3_crypto_shash_allocate(server);
	if (rc) {
		smbfs_server_log(server, "%s: crypto alloc failed, rc=%d\n", __func__, rc);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_setkey(server->sec.ctx.hmacsha256,
				 ses->auth_key.response, SMB2_NTLMV2_SESSKEY_SIZE);
	if (rc) {
		smbfs_server_log(server, "%s: Could not set with session key, rc=%d\n", __func__, rc);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_init(&server->sec.ctx.sec_desc_hmacsha256->shash);
	if (rc) {
		smbfs_server_log(server, "%s: Could not init sign hmac, rc=%d\n", __func__, rc);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_update(&server->sec.ctx.sec_desc_hmacsha256->shash, i, 4);
	if (rc) {
		smbfs_server_log(server, "%s: Could not update with n, rc=%d\n", __func__, rc);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_update(&server->sec.ctx.sec_desc_hmacsha256->shash,
				label.iov_base, label.iov_len);
	if (rc) {
		smbfs_server_log(server, "%s: Could not update with label, rc=%d\n", __func__, rc);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_update(&server->sec.ctx.sec_desc_hmacsha256->shash, &zero, 1);
	if (rc) {
		smbfs_server_log(server, "%s: Could not update with zero, rc=%d\n", __func__, rc);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_update(&server->sec.ctx.sec_desc_hmacsha256->shash,
				context.iov_base, context.iov_len);
	if (rc) {
		smbfs_server_log(server, "%s: Could not update with context, rc=%d\n", __func__, rc);
		goto smb3signkey_ret;
	}

	if ((server->cipher_type == SMB2_ENCRYPTION_AES256_CCM) ||
	    (server->cipher_type == SMB2_ENCRYPTION_AES256_GCM))
		rc = crypto_shash_update(&server->sec.ctx.sec_desc_hmacsha256->shash, L256, 4);
	else
		rc = crypto_shash_update(&server->sec.ctx.sec_desc_hmacsha256->shash, L128, 4);
	if (rc) {
		smbfs_server_log(server, "%s: Could not update with L, rc=%d\n", __func__, rc);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_final(&server->sec.ctx.sec_desc_hmacsha256->shash, hashptr);
	if (rc) {
		smbfs_server_log(server, "%s: Could not generate sha256 hash, rc=%d\n", __func__, rc);
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
generate_smb3signingkey(struct smbfs_ses *ses,
			struct smbfs_server_info *server,
			const struct derivation_triplet *ptriplet)
{
	int rc;
	bool is_binding = false;
	int chan_index = 0;

	spin_lock(&ses->channel_lock);
	is_binding = !ALL_CHANNELS_NEED_RECONNECT(ses);
	chan_index = smbfs_ses_get_chan_index(ses, server);
	/* TODO: introduce ref counting for channels when the can be freed */
	spin_unlock(&ses->channel_lock);

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
				  ses->channels[chan_index].signkey,
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
		spin_lock(&ses->channel_lock);
		memcpy(ses->channels[0].signkey, ses->smb3signingkey,
		       SMB3_SIGN_KEY_SIZE);
		spin_unlock(&ses->channel_lock);

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

#ifdef CONFIG_SMBFS_DEBUG_DUMP_KEYS
	smbfs_log("%s: dumping generated AES session keys\n", __func__);
	/*
	 * The session id is opaque in terms of endianness, so we can't
	 * print it as a long long. we dump it as we got it on the wire
	 */
	smbfs_log("Session Id    %*ph\n", (int)sizeof(ses->id),
			&ses->id);
	smbfs_log("Cipher type   %d\n", server->cipher_type);
	smbfs_log("Session Key   %*ph\n",
		 SMB2_NTLMV2_SESSKEY_SIZE, ses->auth_key.response);
	smbfs_log("Signing Key   %*ph\n",
		 SMB3_SIGN_KEY_SIZE, ses->smb3signingkey);
	if ((server->cipher_type == SMB2_ENCRYPTION_AES256_CCM) ||
		(server->cipher_type == SMB2_ENCRYPTION_AES256_GCM)) {
		smbfs_log("ServerIn Key  %*ph\n",
				SMB3_GCM256_CRYPTKEY_SIZE, ses->smb3encryptionkey);
		smbfs_log("ServerOut Key %*ph\n",
				SMB3_GCM256_CRYPTKEY_SIZE, ses->smb3decryptionkey);
	} else {
		smbfs_log("ServerIn Key  %*ph\n",
				SMB3_GCM128_CRYPTKEY_SIZE, ses->smb3encryptionkey);
		smbfs_log("ServerOut Key %*ph\n",
				SMB3_GCM128_CRYPTKEY_SIZE, ses->smb3decryptionkey);
	}
#endif
	return rc;
}

int
generate_smb30signingkey(struct smbfs_ses *ses,
			 struct smbfs_server_info *server)

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
generate_smb311signingkey(struct smbfs_ses *ses,
			  struct smbfs_server_info *server)

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
smb3_calc_signature(struct smb_rqst *rqst, struct smbfs_server_info *server,
			bool allocate_crypto)
{
	int rc;
	unsigned char smb3_signature[SMB2_CMACAES_SIZE];
	unsigned char *sigptr = smb3_signature;
	struct kvec *iov = rqst->rq_iov;
	struct smb2_hdr *shdr = (struct smb2_hdr *)iov[0].iov_base;
	struct shash_desc *shash;
	struct crypto_shash *hash;
	struct smbfs_sec_desc *sec_desc = NULL;
	struct smb_rqst drqst;
	u8 key[SMB3_SIGN_KEY_SIZE];

	rc = smb2_get_sign_key(le64_to_cpu(shdr->SessionId), server, key);
	if (rc)
		return 0;

	if (allocate_crypto) {
		rc = cifs_alloc_hash("cmac(aes)", &hash, &sec_desc_);
		if (rc)
			return rc;

		shash = &sec_desc_->shash;
	} else {
		hash = server->sec.ctx.cmacaes;
		shash = &server->sec.ctx.sec_desc_cmacaes->shash;
	}

	memset(smb3_signature, 0x0, SMB2_CMACAES_SIZE);
	memset(shdr->Signature, 0x0, SMB2_SIGNATURE_SIZE);

	rc = crypto_shash_setkey(hash, key, SMB2_CMACAES_SIZE);
	if (rc) {
		smbfs_server_log(server, "%s: Could not set key for cmac aes, rc=%d\n", __func__, rc);
		goto out;
	}

	/*
	 * we already allocate sec_desc_cmacaes when we init smb3 signing key,
	 * so unlike smb2 case we do not have to check here if secmech are
	 * initialized
	 */
	rc = crypto_shash_init(shash);
	if (rc) {
		smbfs_server_log(server, "%s: Could not init cmac aes, rc=%d\n", __func__, rc);
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
		rc = crypto_shash_update(shash, iov[0].iov_base, iov[0].iov_len);
		if (rc) {
			smbfs_server_log(server, "%s: Could not update with payload, rc=%d\n", __func__, rc);
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
		cifs_free_hash(&hash, &sec_desc_);
	return rc;
}

/* must be called with server->srv_mutex held */
static int
smb2_sign_rqst(struct smb_rqst *rqst, struct smbfs_server_info *server)
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
	spin_lock(&g_servers_lock);
	if (server->ops->need_neg &&
	    server->ops->need_neg(server)) {
		spin_unlock(&g_servers_lock);
		return 0;
	}
	spin_unlock(&g_servers_lock);
	if (!is_binding && !server->session_estab) {
		strncpy(shdr->Signature, "BSRSPYL", 8);
		return 0;
	}

	rc = server->ops->calc_signature(rqst, server, false);

	return rc;
}

int
smb2_verify_signature(struct smb_rqst *rqst, struct smbfs_server_info *server)
{
	unsigned int rc;
	char server_response_sig[SMB2_SIGNATURE_SIZE];
	struct smb2_hdr *shdr =
			(struct smb2_hdr *)rqst->rq_iov[0].iov_base;

	if ((shdr->Command == SMB2_NEGOTIATE) ||
	    (shdr->Command == SMB2_SESSION_SETUP) ||
	    (shdr->Command == SMB2_OPLOCK_BREAK) ||
	    server->sec.ignore_signature ||
	    (!server->session_estab))
		return 0;

	/*
	 * TODO: what if signatures are supposed to be on for session but
	 * server does not send one?
	 */

	/* Do not need to verify session setups with signature "BSRSPYL " */
	if (memcmp(shdr->Signature, "BSRSPYL ", 8) == 0)
		smbfs_dbg("dummy signature received for smb command 0x%x\n",
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
		smbfs_log("sign fail cmd 0x%x message id 0x%llx\n",
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
smb2_seq_num_into_buf(struct smbfs_server_info *server,
		      struct smb2_hdr *shdr)
{
	unsigned int i, num = le16_to_cpu(shdr->CreditCharge);

	shdr->MessageId = get_next_mid64(server);
	/* skip message numbers according to CreditCharge field */
	for (i = 1; i < num; i++)
		get_next_mid(server);
}

static struct smbfs_mid_entry *
smb2_mid_entry_alloc(const struct smb2_hdr *shdr,
		     struct smbfs_server_info *server)
{
	struct smbfs_mid_entry *temp;
	unsigned int credits = le16_to_cpu(shdr->CreditCharge);

	if (server == NULL) {
		smbfs_log("Null TCP session in smb2_mid_entry_alloc\n");
		return NULL;
	}

	temp = mempool_alloc(smbfs_mid_pool, GFP_NOFS);
	memset(temp, 0, sizeof(struct smbfs_mid_entry));
	kref_init(&temp->refcount);
	temp->mid = le64_to_cpu(shdr->MessageId);
	temp->credits = credits > 0 ? credits : 1;
	temp->pid = current->pid;
	temp->cmd = shdr->Command; /* Always LE */
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

	atomic_inc(&g_mid_count);
	temp->state = MID_REQUEST_ALLOCATED;
	trace_smb3_cmd_enter(le32_to_cpu(shdr->Id.SyncId.TreeId),
			     le64_to_cpu(shdr->SessionId),
			     le16_to_cpu(shdr->Command), temp->mid);
	return temp;
}

static int
smb2_get_mid_entry(struct smbfs_ses *ses, struct smbfs_server_info *server,
		   struct smb2_hdr *shdr, struct smbfs_mid_entry **mid)
{
	spin_lock(&g_servers_lock);
	if (server->status == SMBFS_STATUS_EXITING) {
		spin_unlock(&g_servers_lock);
		return -ENOENT;
	}

	if (server->status == SMBFS_STATUS_NEED_RECONNECT) {
		spin_unlock(&g_servers_lock);
		smbfs_dbg("tcp session dead - return to caller to retry\n");
		return -EAGAIN;
	}

	if (server->status == SMBFS_STATUS_NEED_NEGOTIATE &&
	   shdr->Command != SMB2_NEGOTIATE) {
		spin_unlock(&g_servers_lock);
		return -EAGAIN;
	}

	if (ses->status == SMBFS_SES_STATUS_NEW) {
		if ((shdr->Command != SMB2_SESSION_SETUP) &&
		    (shdr->Command != SMB2_NEGOTIATE)) {
			spin_unlock(&g_servers_lock);
			return -EAGAIN;
		}
		/* else ok - we are setting up session */
	}

	if (ses->status == SMBFS_SES_STATUS_EXITING) {
		if (shdr->Command != SMB2_LOGOFF) {
			spin_unlock(&g_servers_lock);
			return -EAGAIN;
		}
		/* else ok - we are shutting down the session */
	}
	spin_unlock(&g_servers_lock);

	*mid = smb2_mid_entry_alloc(shdr, server);
	if (*mid == NULL)
		return -ENOMEM;
	spin_lock(&g_mid_lock);
	list_add_tail(&(*mid)->head, &server->pending_mids);
	spin_unlock(&g_mid_lock);

	return 0;
}

int
smb2_check_receive(struct smbfs_mid_entry *mid, struct smbfs_server_info *server,
		   bool log_error)
{
	unsigned int len = mid->resp_buf_size;
	struct kvec iov[1];
	struct smb_rqst rqst = { .rq_iov = iov,
				 .rq_nvec = 1 };

	iov[0].iov_base = (char *)mid->resp_buf;
	iov[0].iov_len = len;

	smbfs_dump_smb(mid->resp_buf, min_t(u32, 80, len));

	/* convert the length into a more usable form */
	if (len > 24 && server->sec.signing_enabled && !mid->decrypted) {
		int rc;

		rc = smb2_verify_signature(&rqst, server);
		if (rc)
			smbfs_server_log(server, "SMB signature verification, rc=%d\n", rc);
	}

	return map_smb2_to_linux_error(mid->resp_buf, log_error);
}

struct smbfs_mid_entry *
smb2_setup_request(struct smbfs_ses *ses, struct smbfs_server_info *server,
		   struct smb_rqst *rqst)
{
	int rc;
	struct smb2_hdr *shdr =
			(struct smb2_hdr *)rqst->rq_iov[0].iov_base;
	struct smbfs_mid_entry *mid;

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

struct smbfs_mid_entry *
smb2_setup_async_request(struct smbfs_server_info *server, struct smb_rqst *rqst)
{
	int rc;
	struct smb2_hdr *shdr =
			(struct smb2_hdr *)rqst->rq_iov[0].iov_base;
	struct smbfs_mid_entry *mid;

	spin_lock(&g_servers_lock);
	if (server->status == SMBFS_STATUS_NEED_NEGOTIATE &&
	   shdr->Command != SMB2_NEGOTIATE) {
		spin_unlock(&g_servers_lock);
		return ERR_PTR(-EAGAIN);
	}
	spin_unlock(&g_servers_lock);

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
smb3_crypto_aead_allocate(struct smbfs_server_info *server)
{
	struct crypto_aead *tfm;

	if (!server->sec.ctx.ccmaesencrypt) {
		if ((server->cipher_type == SMB2_ENCRYPTION_AES128_GCM) ||
		    (server->cipher_type == SMB2_ENCRYPTION_AES256_GCM))
			tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
		else
			tfm = crypto_alloc_aead("ccm(aes)", 0, 0);
		if (IS_ERR(tfm)) {
			smbfs_server_log(server, "%s: Failed alloc encrypt aead, rc=%ld\n", __func__, PTR_ERR(tfm));
			return PTR_ERR(tfm);
		}
		server->sec.ctx.ccmaesencrypt = tfm;
	}

	if (!server->sec.ctx.ccmaesdecrypt) {
		if ((server->cipher_type == SMB2_ENCRYPTION_AES128_GCM) ||
		    (server->cipher_type == SMB2_ENCRYPTION_AES256_GCM))
			tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
		else
			tfm = crypto_alloc_aead("ccm(aes)", 0, 0);
		if (IS_ERR(tfm)) {
			crypto_free_aead(server->sec.ctx.ccmaesencrypt);
			server->sec.ctx.ccmaesencrypt = NULL;
			smbfs_server_log(server, "%s: Failed to alloc decrypt aead, rc=%ld\n", __func__, PTR_ERR(tfm));
			return PTR_ERR(tfm);
		}
		server->sec.ctx.ccmaesdecrypt = tfm;
	}

	return 0;
}
