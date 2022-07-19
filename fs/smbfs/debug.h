// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) International Business Machines  Corp., 2000,2002
 * Copyright (c) SUSE LLC, 2022
 *
 * Modified by Steve French <sfrench@us.ibm.com>
 * Modified by Enzo Matsumiya <ematsumiya@suse.de>
 *
 * SMBFS debugging.
 */

#ifndef _SMBFS_DEBUG_H
#define _SMBFS_DEBUG_H

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

extern bool trace_smb;

/*
 * SMBFS log levels
 *
 * SMBFS_LOG_VFS: used to log messages at VFS layer. Always shown (uses pr_err())
 * SMBFS_LOG_INFO: used to log informational messages
 * SMBFS_LOG_FYI: used for general debug messages. Dictated by log_level.
 * SMBFS_LOG_NOISY: use this to print extra debug messages. Requires log_level > 0.
 *
 * SMBFS_LOG_ONCE: use this to log a message only once
 */
#define SMBFS_LOG_VFS		0x1
#define SMBFS_LOG_INFO		0x2
#define SMBFS_LOG_FYI		0x4
#ifdef CONFIG_SMBFS_DEBUG_EXTRA
#define SMBFS_LOG_NOISY		0x8
#else
#define SMBFS_LOG_NOISY		0x0
#endif /* CONFIG_SMBFS_DEBUG_EXTRA */
#define SMBFS_LOG_ONCE		0x10

/*
 * - smbfs*log(): for things we always want logged and the user to see
 * - smbfs*info(): for informational messages (can be filtered via loglevel > 6)
 * - smbfs*dbg(): for debug messages, off by default
 * - trace_smb3_*():  ftrace functions are preferred for complex debug messages
 * intended for developers or experienced admins, off by default
 *
 * smbfs*log() and smbfs*dbg() has a _once() variation to log messages only once
 */
#define __smbfs_print(ratefunc, level, fmt, ...)			\
do {									\
	if ((level) & SMBFS_LOG_FYI)					\
		/* always show function name on debug */		\
		pr_debug_ ## ratefunc("%s: %s: " fmt, __FILE__,		\
				      __func__, ##__VA_ARGS__);		\
	else if ((level) & SMBFS_LOG_INFO)				\
		pr_info_ratelimited(fmt, ##__VA_ARGS__);		\
	else if ((level) & SMBFS_LOG_VFS)				\
		pr_err_ ## ratefunc("VFS: " fmt, ##__VA_ARGS__);	\
	else if (SMBFS_LOG_NOISY && ((level) & SMBFS_LOG_NOISY))	\
		pr_debug_ ## ratefunc(fmt, ##__VA_ARGS__);		\
} while (0)

/* Messages that should include server hostname */
#define __smbfs_server_print(ratefunc, _serverp, level, fmt, ...)	\
do {									\
	if (_serverp && _serverp->hostname)				\
		__smbfs_print(ratefunc, level, "\\\\%s" fmt,		\
			      _serverp->hostname, ##__VA_ARGS__);	\
} while (0)

/* Messages that should include tree name */
#define __smbfs_tcon_print(ratefunc, _tconp, level, fmt, ...)		\
do {									\
	if (_tconp && _tconp->treeName)					\
		__smbfs_print(ratefunc, level, "%s: " fmt,		\
			      _tconp->treeName, ##__VA_ARGS__);		\
} while (0)

/*
 * Messages that we always wanted logged and the user to see.
 *
 * Please note that the smbfs*log() functions must be outside of the
 * ifdef CONFIG_SMBFS_DEBUG.
 */
#define smbfs_log(fmt, ...) \
	__smbfs_print(ratelimited, SMBFS_LOG_VFS, fmt, ##__VA_ARGS__)
#define smbfs_log_once(fmt, ...) \
	__smbfs_print(once, SMBFS_LOG_VFS, fmt, ##__VA_ARGS__)

/* Server log messages */
#define smbfs_server_log(_serverp, fmt, ...)				\
	__smbfs_server_print(ratelimited, _serverp, SMBFS_LOG_VFS, fmt, \
			     ##__VA_ARGS__)
#define smbfs_server_log_once(_serverp, fmt, ...)			\
	__smbfs_server_print(once, _serverp, SMBFS_LOG_VFS, fmt,	\
			     ##__VA_ARGS__)

/* tcon log messages */
#define smbfs_tcon_log(_tconp, fmt, ...) \
	__smbfs_tcon_print(ratelimited, _tconp, SMBFS_LOG_VFS, fmt, ##__VA_ARGS__)
#define smbfs_tcon_log_once(_tconp, fmt, ...) \
	__smbfs_tcon_print(once, _tconp, SMBFS_LOG_VFS, fmt, ##__VA_ARGS__)

/*
 * Debug enabled
 */
#ifdef CONFIG_SMBFS_DEBUG
/* Debug messages */
#define smbfs_dbg(fmt, ...) \
	__smbfs_print(ratelimited, SMBFS_LOG_FYI, fmt, ##__VA_ARGS__)
#define smbfs_dbg_once(fmt, ...) \
	__smbfs_print(once, SMBFS_LOG_FYI, fmt, ##__VA_ARGS__)
/* noisy is always ratelimited */
#define smbfs_dbg_noisy(fmt, ...) \
	__smbfs_print(ratelimited, SMBFS_LOG_NOISY, fmt, ##__VA_ARGS__)

/* Information level messages, minor events */
#define smbfs_info(fmt, ...) \
	__smbfs_print(ratelimited, SMBFS_LOG_INFO, fmt, ##__VA_ARGS__)
/* no smbfs_info_once() */

/* Server debug messages */
#define smbfs_server_dbg(_serverp, fmt, ...)				\
	__smbfs_server_print(ratelimited, _serverp, SMBFS_LOG_FYI,	\
			     fmt, ##__VA_ARGS__)
#define smbfs_server_dbg_once(_serverp, fmt, ...)			\
	__smbfs_server_print(once, _serverp, SMBFS_LOG_FYI,		\
			     fmt, ##__VA_ARGS__)

/* Server info messages, minor events */
#define smbfs_server_info(_serverp, fmt, ...) \
	__smbfs_server_print(ratelimited, _serverp, SMBFS_LOG_INFO, fmt, ##__VA_ARGS__)

/* tcon debug messages */
#define smbfs_tcon_dbg(_tconp, fmt, ...) \
	__smbfs_tcon_print(ratelimited, _tconp, SMBFS_LOG_FYI, fmt, ##__VA_ARGS__)
#define smbfs_tcon_dbg_once(_tconp, fmt, ...)			\
	__smbfs_tcon_print(once, _tconp, SMBFS_LOG_FYI,	fmt, ##__VA_ARGS__)

/* tcon info messages, minor events */
#define smbfs_tcon_info(_tconp, fmt, ...) \
	__smbfs_tcon_print(ratelimited, _tconp, SMBFS_LOG_INFO, fmt, ##__VA_ARGS__)
#else /* CONFIG_SMBFS_DEBUG */
/*
 * Debug disabled
 */
#define smbfs_dbg(fmt, ...) do {} while (0)
#define smbfs_dbg_once(fmt, ...) do {} while (0)
#define smbfs_info(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#define smbfs_server_dbg(_serverp, fmt, ...) do {} while (0)
#define smbfs_server_dbg_once(_serverp, fmt, ...) do {} while (0)
/* _serverp is ignored here */ \
#define smbfs_server_info(_serverp, fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#define smbfs_tcon_dbg(_tconp, fmt, ...) do {} while (0)
#define smbfs_tcon_dbg_once(_tconp, fmt, ...) do {} while (0)
/* _tconp is ignored here */ \
#define smbfs_tcon_info(_tconp, fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#endif /* CONFIG_SMBFS_DEBUG */

static inline void smbfs_dump_mem(char *prefix, void *buf, size_t len)
{
#ifdef CONFIG_SMBFS_DEBUG
	smbfs_dbg("%s dumping buf at 0x%p, len=%zu:\n", prefix, buf, len);
	print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_OFFSET, 16, 4, buf, len, true);
#endif /* CONFIG_SMBFS_DEBUG */
}

static inline void smbfs_dump_detail_smb1(void *buf, struct TCP_Server_Info *server)
{
	struct smb_hdr *smb = (struct smb_hdr *)buf;

	smbfs_log("cmd: %d, err: 0x%x, flags: 0x%x, flags2: 0x%x, mid: %d, pid: %d\n",
		  smb->Command, smb->Status.CifsError, smb->Flags, smb->Flags2,
		  smb->Mid, smb->Pid);
	smbfs_log("smb buf 0x%p, len=%u\n", smb, server->ops->calc_smb_size(smb, server));
}

static inline void smbfs_dump_detail(void *buf, struct TCP_Server_Info *server)
{
	struct smb2_hdr *shdr = (struct smb2_hdr *)buf;

#ifdef CONFIG_SMBFS_DEBUG_EXTRA
	if (is_smb1_server(server)) {
		smbfs_dump_detail_smb1(buf, server);
		return;
	}

	smbfs_server_log(server, "Cmd: %d Err: 0x%x Flags: 0x%x Mid: %llu Pid: %d\n",
			 shdr->Command, shdr->Status, shdr->Flags, shdr->MessageId,
			 shdr->Id.SyncId.ProcessId);
	smbfs_server_log(server, "smb buf 0x%p, len=%u\n", buf,
			 server->ops->calc_smb_size(buf, server));
#endif /* CONFIG_SMBFS_DEBUG_EXTRA */
}

static inline void smbfs_dump_smb(void *buf, size_t len)
{
#ifdef CONFIG_PROC_FS
	if (unlikely(trace_smb))
		print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_NONE, 8, 2, buf, len, true);
#endif /* CONFIG_PROC_FS */
}

static inline void smbfs_dump_mid(struct mid_q_entry *mid_entry)
{
	smbfs_log("mid: %llu, state: %d, cmd: %d, pid: %d, cbdata: 0x%p\n",
		  mid_entry->mid, mid_entry->mid_state,
		  le16_to_cpu(mid_entry->command),
		  mid_entry->pid, mid_entry->callback_data);
#ifdef CONFIG_SMBFS_STATS_EXTRA
	smbfs_log("large_buf: %d, buf: 0x%p, time rcv: %ld, now: %ld\n",
		  mid_entry->large_buf, mid_entry->resp_buf,
		  mid_entry->when_received, jiffies);
#endif /* CONFIG_SMBFS_STATS_EXTRA */
	smbfs_log("multiRsp: %d multiEnd: %d\n",
		  mid_entry->multiRsp, mid_entry->multiEnd);

	if (mid_entry->resp_buf) {
		smbfs_dump_detail(mid_entry->resp_buf, mid_entry->server);
		/* XXX: give a name to "62" */
		smbfs_dump_mem("existing buf: ", mid_entry->resp_buf, 62);
	}
}

static inline void smbfs_dump_mids(struct TCP_Server_Info *server)
{
#ifdef CONFIG_SMBFS_DEBUG_EXTRA
	struct mid_q_entry *mid_entry;

	if (!server)
		return;

	spin_lock(&GlobalMid_Lock);
	list_for_each_entry(mid_entry, &server->pending_mid_q, qhead)
		smbfs_dump_mid(mid_entry);
	spin_unlock(&GlobalMid_Lock);
#endif /* CONFIG_SMBFS_DEBUG_EXTRA */
}
#endif /* _SMBFS_DEBUG_H */
