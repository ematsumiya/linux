# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Linux SMB (version 2.0 and later) client filesystem.
#
ccflags-y += -I$(src)		# needed for trace events
obj-$(CONFIG_CIFS) += cifs.o

cifs-y := trace.o core.o debug.o connect.o misc.o netmisc.o \
	  smbencrypt.o unicode.o nterr.o encrypt.o sess.o export.o \
	  unc.o winucase.o smb2ops.o smb2maperror.o smb2transport.o \
	  smb2misc.o smb2pdu.o smb2inode.o smb2file.o fs_context.o \
	  dns_resolve.o spnego_negtokeninit.asn1.o asn1.o

$(obj)/asn1.o: $(obj)/spnego_negtokeninit.asn1.h
$(obj)/spnego_negtokeninit.asn1.o: $(obj)/spnego_negtokeninit.asn1.c \
				   $(obj)/spnego_negtokeninit.asn1.h
cifs-$(CONFIG_CIFS_UPCALL) += spnego.o
cifs-$(CONFIG_CIFS_DFS_UPCALL) += dfs.o dfs_cache.o
cifs-$(CONFIG_CIFS_SWN_UPCALL) += netlink.o swn.o
cifs-$(CONFIG_CIFS_FSCACHE) += fscache.o
cifs-$(CONFIG_CIFS_SMB_DIRECT) += smbdirect.o
cifs-$(CONFIG_CIFS_ALLOW_INSECURE_LEGACY) += smb1/acl.o smb1/dir.o smb1/file.o \
					     smb1/inode.o smb1/ioctl.o \
					     smb1/link.o smb1/pdu.o \
					     smb1/readdir.o smb1/transport.o
smb1-$(CONFIG_CIFS_XATTR) += smb1/xattr.o
smb1-$(CONFIG_CIFS_ROOT) += smb1/rootfs.o
