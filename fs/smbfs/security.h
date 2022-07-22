// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) SUSE LLC, 2022
 *
 * Author(s): Enzo Matsumiya <ematsumiya@suse.de>
 *
 * SMBFS security, signing, and crypto stuff.
*/
#ifndef _SMBFS_SECURITY_H
#define _SMBFS_SECURITY_H

/* Security flags: indicate type of session setup needed */
#define SMBFS_SEC_MAY_SIGN	0x00001
#define SMBFS_SEC_MAY_NTLMV2	0x00004
#define SMBFS_SEC_MAY_KRB5	0x00008
#define SMBFS_SEC_MAY_SEAL	0x00040 /* not supported yet */
#define SMBFS_SEC_MAY_NTLMSSP	0x00080 /* raw NTLMSSP with NTLMV2 */
#define SMBFS_SEC_MUST_SIGN	0x01001

/*
 * Note that only one of the following can be set so the result of setting
 * MUST flags more than once will be to require use of the stronger protocol.
 */
#define SMBFS_SEC_MUST_NTLMV2	0x04004
#define SMBFS_SEC_MUST_KRB5	0x08008
#ifdef CONFIG_SMBFS_UPCALL
#define SMBFS_SEC_MASK		0x8F08F /* flags supported if no weak allowed */
#else
#define SMBFS_SEC_MASK		0x87087 /* flags supported if no weak allowed */
#endif /* CONFIG_SMBFS_UPCALL */
#define SMBFS_SEC_MUST_SEAL	0x40040 /* not supported yet */
#define SMBFS_SEC_MUST_NTLMSSP	0x80080 /* raw NTLMSSP with NTLMV2 */

#define SMBFS_SEC_DEF \
	(SMBFS_SEC_MAY_SIGN | SMBFS_SEC_MAY_NTLMV2 | SMBFS_SEC_MAY_NTLMSSP)
#define SMBFS_SEC_MAX \
	(SMBFS_SEC_MUST_NTLMV2)
#define SMBFS_SEC_AUTH_MASK \
	(SMBFS_SEC_MAY_NTLMV2 | SMBFS_SEC_MAY_KRB5 | SMBFS_SEC_MAY_NTLMSSP)

extern unsigned int sign_pdus; /* enable SMB packet signing */
extern bool enable_gcm_256; /* allow optional negotiate of strongest signing (aes-gcm-256) */
extern bool require_gcm_256; /* require use of strongest signing (aes-gcm-256) */
extern bool enable_negotiate_signing; /* request use of faster (GMAC) signing if available */

typedef enum smbfs_security {
	SMBFS_SECURITY_UNSPECIFIED,	/* not specified */
	SMBFS_SECURITY_NTLMv2,		/* Legacy NTLM auth with NTLMV2 hash */
	SMBFS_SECURITY_RAW_NTLMSSP,	/* NTLMSSP without SPNEGO, NTLMV2 hash */
	SMBFS_SECURITY_KERBEROS,	/* Kerberos via SPNEGO */
} smbfs_security_t;

struct smbfs_session_key {
	unsigned int len;
	char *response;
};

/* crypto security descriptor definition */
struct smbfs_sec_desc {
	struct shash_desc shash;
	char ctx[];
};

/* crypto hashing related structure/fields, not specific to some algorithm */
struct smbfs_sec_ctx {
	struct crypto_shash *hmacmd5; /* hmac-md5 hash function */
	struct crypto_shash *md5; /* md5 hash function */
	struct crypto_shash *hmacsha256; /* hmac-sha256 hash function */
	struct crypto_shash *cmacaes; /* block-cipher based MAC function */
	struct crypto_shash *sha512; /* sha512 hash function */
	struct smbfs_sec_desc *sec_desc_hmacmd5;  /* ctxt to generate NTLMV2 hash, CR1 */
	struct smbfs_sec_desc *sec_desc_md5; /* ctxt to generate cifs/smb signature */
	struct smbfs_sec_desc *sec_desc_hmacsha256;  /* ctxt to generate smb2 signature */
	struct smbfs_sec_desc *sec_desc_cmacaes;  /* ctxt to generate smb3 signature */
	struct smbfs_sec_desc *sec_desc_sha512; /* ctxt to generate smb3.11 signing key */
	struct crypto_aead *ccmaesencrypt; /* smb3 encryption aead */
	struct crypto_aead *ccmaesdecrypt; /* smb3 decryption aead */
};

/* per SMB session structure/fields */
struct smbfs_ntlmssp_auth {
	bool sesskey_per_smbsess; /* whether session key is per SMB session */
	unsigned long client_flags; /* sent by client in type 1 ntlmsssp exchange */
	unsigned long server_flags; /* sent by server in type 2 NTLMSSP exchange */
	unsigned char cipher_text[CIFS_CPHTXT_SIZE]; /* sent to server */
	char crypto_key[CIFS_CRYPTO_KEY_SIZE]; /* used by NTLMSSP */
};

/* security (encryption/decryption and signing) properties of a server */
struct smbfs_server_sec {
	u16 mode;

	bool signing_enabled; /* is signing enabled on this connection? */
	bool ignore_signature; /* skip validation of signatures in SMB2/3 rsp */

	struct smbfs_sec_ctx ctx; /* crypto/security funcs, descriptors */
	struct smbfs_session_key session_key;
	char crypto_key[CIFS_CRYPTO_KEY_SIZE]; /* used by ntlm, NTLMV2 etc */

	/* extended security flavors that server supports */
	bool has_ntlmssp; /* supports NTLMSSP */
	bool has_krb_u2u; /* supports U2U Kerberos */
	bool has_krb; /* supports plain Kerberos */
	bool has_legacy_krb; /* supports legacy MS Kerberos */

	__le16 compress_algo;
	u16 signing_algo;
	__le16 cipher_type;
	/* save initital negprot hash */
	u8 preauth_sha_hash[SMB2_PREAUTH_HASH_SIZE];
};

static inline char *get_security_type_str(smbfs_security_t sectype)
{
	switch (sectype) {
	case SMBFS_SECURITY_RAW_NTLMSSP:
		return "RawNTLMSSP";
	case SMBFS_SECURITY_KERBEROS:
		return "Kerberos";
	case SMBFS_SECURITY_NTLMv2:
		return "NTLMv2";
	default:
		return "Unknown";
	}
}
#endif /* _SMBFS_SECURITY_H */
