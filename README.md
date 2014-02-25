XNBD
====

Accelio based network block device.

1. General
==========

Xnbd is a network block device over Accelio framework. Xnbd exploits the
advantages of the multi-queue implementation in the block layer as well as
the accelio acceleration facilities to provide fast IO to a remote device.
Xnbd translates IO operations to libaio submit operations to the remote device.

2. Xnbd Prerequisites
=====================

Prior to installing the xnbd package, the following prerequisites are required:

- Accelio
    1.1 version and above

- Kernel
    3.13.1 and above

3. Building and installation
============================

Install xnbd by following steps:

  - auto-generate (autoconf)
    $ ./autogen.sh
  - configure build
    $ ./configure
  - compile
    $ make
  - install
    $ sudo make install

4. HOWTO
========

The following example creates block device vs. remote raio server using Accelio
transport services.

	1. raio server steps:
		- create a file that would be exposed as a block device to xnbd client
		  at <device_path>
		- run ./raio_server <server_ip> <port>

	2. xnbd client steps:
		$ modprobe xnbd
		$ echo <server_ip:port> > /sys/xnbd/add_portal
		$ echo <device_path> > /sys/xnbd/xnbdhost_0/add_device

In this stage, after the login and initialize stages are finished,
a xnbd type block device (/dev/xnbd0) is available and ready for data transfer.

