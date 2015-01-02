Introduction
============

udpproxy allows to proxy UDP flows using [Netfilter queuing
capabilities][1]. This is not just an UDP relay: the destination does
not need to be known in advance. First, flows to be proxied need to be
selected with the help of iptables:

For example:

    # iptables -A OUTPUT -p udp --dport 161 \
       --destination 172.16.100.0/23 -j NFQUEUE --queue-num 10

Then, udpproxy is launched and will relay the packets sent to queue
10:

    # udpproxy -e "ssh somehost ./udpproxy" -q 10

The remote udpproxy does not have to run as root. It only uses
unpriviledged operations.

udpproxy does not handle fragmentation at all. If you use programs
that sends large packets, you should create a dummy interface with
a large MTU and route packets to this interface. udpproxy will then
receives the packets unfragmented and forward them to the remote proxy
which will relies on operating system to handle fragmentation.

[1]: http://www.netfilter.org/projects/libnetfilter_queue/index.html

Installation
============

You can get udpproxy from the git repository:

    $ git clone git://git.luffy.cx/udpproxy.git

There is also a [cgit interface][2] where you can browse the sources
or use [github][3].

[2]: http://cgit.luffy.cx/udpproxy/
[3]: https://github.com/vincentbernat/udpproxy

udpproxy uses autotools. So, you should get ready with:

    $ autoreconf -i
    $ ./configure
    $ make
    $ sudo make install

You need [libevent][4] and [libnetfilter_queue][5]. If you don't have
the latest one, only client-side operations will be allowed.

[4]: http://monkey.org/~provos/libevent/
[5]: http://www.netfilter.org/projects/libnetfilter_queue/index.html

Usage
=====

You can get help with:

    $ udpproxy -h

A simple invocation will start udpproxy stating the command to invoke
the remote udpproxy with `-e` switch and selecting the right Netfilter
queue with `-q` switch:

    $ udpproxy -e "ssh somehost ./udpproxy" -q 10

On server-side, udpproxy needs root privileges. However, the remote
one does not need to and usually, you want to run ssh command as an
unprivileged user. You can use `-u` and `-g` switches for this:

    # udpproxy -u 1000 -g 100 -e "ssh somehost ./udpproxy" -q 10

Or, with the help of the shell:

    # udpproxy -u $(id -u) -g $(id -g) -e "ssh somehost ./udpproxy" -q 10

By default, udpproxy turns itself in the background after being
launched. If you want to keep it in the foreground, use `-d`:

    # udpproxy -d -u $(id -u) -g $(id -g) -e "ssh somehost ./udpproxy" -q 10
