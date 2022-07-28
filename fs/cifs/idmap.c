// SPDX-License-Identifier: LGPL-2.1
/*
 *   Copyright (C) International Business Machines  Corp., 2007,2008
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *
 *   idmap init/exit
 */
#include <linux/slab.h>
#include <linux/cred.h>
#include "globals.h"
#include "debug.h"
#include "idmap.h"

const struct cred *root_cred;

static int
cifs_idmap_key_instantiate(struct key *key, struct key_preparsed_payload *prep)
{
	char *payload;

	/*
	 * If the payload is less than or equal to the size of a pointer, then
	 * an allocation here is wasteful. Just copy the data directly to the
	 * payload.value union member instead.
	 *
	 * With this however, you must check the datalen before trying to
	 * dereference payload.data!
	 */
	if (prep->datalen <= sizeof(key->payload)) {
		key->payload.data[0] = NULL;
		memcpy(&key->payload, prep->data, prep->datalen);
	} else {
		payload = kmemdup(prep->data, prep->datalen, GFP_KERNEL);
		if (!payload)
			return -ENOMEM;
		key->payload.data[0] = payload;
	}

	key->datalen = prep->datalen;
	return 0;
}

static inline void
cifs_idmap_key_destroy(struct key *key)
{
	if (key->datalen > sizeof(key->payload))
		kfree(key->payload.data[0]);
}

struct key_type cifs_idmap_key_type = {
	.name        = "cifs.idmap",
	.instantiate = cifs_idmap_key_instantiate,
	.destroy     = cifs_idmap_key_destroy,
	.describe    = user_describe,
};

int
init_cifs_idmap(void)
{
	struct cred *cred;
	struct key *keyring;
	int ret;

	cifs_dbg(FYI, "Registering the %s key type\n",
		 cifs_idmap_key_type.name);

	/* create an override credential set with a special thread keyring in
	 * which requests are cached
	 *
	 * this is used to prevent malicious redirections from being installed
	 * with add_key().
	 */
	cred = prepare_kernel_cred(NULL);
	if (!cred)
		return -ENOMEM;

	keyring = keyring_alloc(".cifs_idmap",
				GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, cred,
				(KEY_POS_ALL & ~KEY_POS_SETATTR) |
				KEY_USR_VIEW | KEY_USR_READ,
				KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
	if (IS_ERR(keyring)) {
		ret = PTR_ERR(keyring);
		goto failed_put_cred;
	}

	ret = register_key_type(&cifs_idmap_key_type);
	if (ret < 0)
		goto failed_put_key;

	/* instruct request_key() to use this special keyring as a cache for
	 * the results it looks up */
	set_bit(KEY_FLAG_ROOT_CAN_CLEAR, &keyring->flags);
	cred->thread_keyring = keyring;
	cred->jit_keyring = KEY_REQKEY_DEFL_THREAD_KEYRING;
	root_cred = cred;

	cifs_dbg(FYI, "cifs idmap keyring: %d\n", key_serial(keyring));
	return 0;

failed_put_key:
	key_put(keyring);
failed_put_cred:
	put_cred(cred);
	return ret;
}

void
exit_cifs_idmap(void)
{
	key_revoke(root_cred->thread_keyring);
	unregister_key_type(&cifs_idmap_key_type);
	put_cred(root_cred);
	cifs_dbg(FYI, "Unregistered %s key type\n", cifs_idmap_key_type.name);
}

