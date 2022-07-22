# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Linux CIFS/SMB2/SMB3 VFS client
#
ccflags-y += -I$(src) # needed for trace events

obj-$(CONFIG_SMBFS) += smbfs.o
smbfs-y := trace.o core.o proc.o ses.o tcon.o cifssmb.o connect.o dir.o file.o \
	  inode.o link.o misc.o netmisc.o smbencrypt.o transport.o \
	  cifs_unicode.o nterr.o cifsencrypt.o \
	  readdir.o ioctl.o sess.o export.o unc.o winucase.o \
	  smb2ops.o smb2maperror.o smb2transport.o \
	  smb2misc.o smb2pdu.o smb2inode.o smb2file.o cifsacl.o fs_context.o \
	  dns_resolve.o cifs_spnego_negtokeninit.asn1.o asn1.o

$(obj)/asn1.o: $(obj)/cifs_spnego_negtokeninit.asn1.h
$(obj)/cifs_spnego_negtokeninit.asn1.o: $(obj)/cifs_spnego_negtokeninit.asn1.c $(obj)/cifs_spnego_negtokeninit.asn1.h

smbfs-$(CONFIG_SMBFS_XATTR) += xattr.o
smbfs-$(CONFIG_SMBFS_UPCALL) += cifs_spnego.o
smbfs-$(CONFIG_SMBFS_DFS_UPCALL) += cifs_dfs_ref.o dfs_cache.o
smbfs-$(CONFIG_SMBFS_SWN_UPCALL) += netlink.o cifs_swn.o
smbfs-$(CONFIG_SMBFS_FSCACHE) += fscache.o
smbfs-$(CONFIG_SMBFS_SMB_DIRECT) += smbdirect.o
smbfs-$(CONFIG_SMBFS_ROOT) += cifsroot.o
smbfs-$(CONFIG_SMBFS_ALLOW_INSECURE_LEGACY) += smb1ops.o
