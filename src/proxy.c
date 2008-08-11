/*
 * Copyright (c) 2008 Vincent Bernat <bernat@luffy.cx>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "proxy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#if !CLIENT_ONLY
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#endif


extern const char	*__progname;

void	 usage(void);
void	 proxy_shutdown(int, short, void *);
void	 loop(void);
void	 expire_states(int, short, void *);
void	 udp_incoming(int, short, void *);
#if !CLIENT_ONLY
void	 nfq_incoming(int, short, void *);
int	 nfq_process(struct nfq_q_handle *, struct nfgenmsg *,
    struct nfq_data *, void *);
int	 nfq_init(int, struct nfq_handle **, struct nfq_q_handle **, int *);
void	 nfq_shut(struct nfq_handle *, struct nfq_q_handle *);
int	 start_remote(const char *, int *, int *, uid_t, uid_t);
#endif

static void	 setup_signals(void);
#if !CLIENT_ONLY
static void	 remote_incoming(int, short, void *);
#endif
static void	 local_incoming(int, short, void *);

int keep_running = 1;

void
usage()
{
	extern const char *__progname;
#if !CLIENT_ONLY
	fprintf(stderr, "usage: %s [-d] [-q queue] [-e cmd]\n", __progname);
#else
	fprintf(stderr, "usage: %s [-d]\n", __progname);
#endif
	exit(1);
}

void
expire_states(int fd, short event, void *arg)
{
	struct states *udpstates = (struct states *)arg;
	state_expire(udpstates, UDP_UNCONFIRMED_TTL, UDP_CONFIRMED_TTL);
}

/* Distant process receives an UDP packet */
void
udp_incoming(int fd, short event, void *arg)
{
	struct state *udpstate = (struct state*)arg;
	struct iphdr *ip_header;
	struct udphdr *udp_header;
	char buffer[NFQ_PACKET_BUFFER_SIZE];
	int rv;

	udpstate->count++;
	udpstate->lastchange = time(NULL);
	if ((rv = read(udpstate->socket, buffer + sizeof(struct iphdr) +
		    sizeof(struct udphdr), NFQ_PACKET_BUFFER_SIZE -
		    sizeof(struct iphdr) - sizeof(struct udphdr))) == -1) {
		LLOG_WARN("problem while reading");
		return;
	}
	if (rv == 0) {
		/* Remote end was closed, just ignore it, we will let the state
		 * expire. Not even sure that this can be possible with UDP */
		return;
	}
	udp_header = (struct udphdr *)(buffer + sizeof(struct iphdr));
	udp_header->source = htons(udpstate->dport);
	udp_header->dest = htons(udpstate->sport);
	udp_header->len = htons(sizeof(struct udphdr) + rv);
	udp_header->check = 0;	/* No checksum, as allowed by RFC 768 */

	ip_header = (struct iphdr *)buffer;
	memset(ip_header, 0, sizeof(struct iphdr));
	ip_header->version = IPVERSION;
	ip_header->ihl = sizeof(struct iphdr)/4;
	ip_header->tot_len = htons(rv + sizeof(struct udphdr) +
	    sizeof(struct iphdr));
	ip_header->ttl = IPDEFTTL;
	ip_header->protocol = IPPROTO_UDP;
	memcpy(&ip_header->saddr, &udpstate->destination,
	    sizeof(struct in_addr));
	memcpy(&ip_header->daddr, &udpstate->source,
	    sizeof(struct in_addr));
	ip_header->check = cksum((unsigned char *)ip_header,
	    sizeof(struct iphdr));

	if (send(STDOUT_FILENO, buffer, rv +
		sizeof(struct udphdr) + sizeof(struct iphdr), MSG_DONTWAIT) == -1)
		LLOG_WARN("unable to send back UDP packet");
}

#if !CLIENT_ONLY
/* Proxy process receives a packet from the remote end */
static void
remote_incoming(int fd, short event, void *arg)
{
	static char buf[NFQ_PACKET_BUFFER_SIZE];
	static char *n = buf;	/* Current pointer */
	static int l = 0;	/* Current length */
	static int s = -1;
	int rv;
	struct iphdr* ip_header;
	struct sockaddr_in sin;

	if ((rv = read(fd, n, sizeof(buf) - l)) == -1) {
		LLOG_WARN("problem while reading");
		return;
	}
	if (rv == 0) {
		LLOG_WARN("remote pipe was closed");
		close(fd);
		keep_running = 0;
		return;
	}
	l += rv; n += rv;

	if ((l < sizeof(struct iphdr)) ||
	    (l < ntohs(((struct iphdr*)buf)->tot_len))) {
		/* Too small to analyse, let's continue */
		return;
	}
	ip_header = (struct iphdr*)buf;
	if (l > ip_header->tot_len) {
		LLOG_WARNX("packet too large, hope we can restart");
		goto end;
	}
	if ((s == -1) && ((s = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)) {
		LLOG_WARN("unable to open raw socket");
		fatalx("cannot continue");
	}
	sin.sin_port = 0;
	sin.sin_family = AF_INET;
	memcpy(&sin.sin_addr, &ip_header->daddr, sizeof(struct in_addr));
	if (sendto(s, buf, l, MSG_DONTWAIT, (struct sockaddr *)&sin,
		sizeof(struct sockaddr_in)) == -1) {
		LLOG_WARN("unable to send packet");
		goto end;
	}

end:
	n = buf;
	l = 0;
}
#endif

/* Distant process receives a packet to transmit from the proxy */
static void
local_incoming(int fd, short event, void *arg)
{
	static char buf[NFQ_PACKET_BUFFER_SIZE];
	static char *n = buf;		/* Current pointer */
	static int l = 0;		/* Current length */
	int rv;
	struct iphdr* ip_header;
	struct udphdr* udp_header;
	struct state *udpstate, find;
	struct states *udpstates = (struct states *)arg;

	if ((rv = read(fd, n, sizeof(buf) - l)) == -1) {
		LLOG_WARN("problem while reading");
		return;
	}
	if (rv == 0) {
		LLOG_WARN("remote pipe was closed");
		close(fd);
		keep_running = 0;
		return;
	}
	l += rv; n += rv;
	
	if ((l < sizeof(struct iphdr)) ||
	    (l < ntohs(((struct iphdr*)buf)->tot_len))) {
		/* Too small to analyse, let's continue */
		return;
	}
	ip_header = (struct iphdr*)buf;
	if (l > ip_header->tot_len) {
		LLOG_WARNX("packet too large, hope we can restart");
		goto end;
	}
	if ((IPVERSION != ip_header->version) ||
	    (IPPROTO_UDP != ip_header->protocol)) {
		LLOG_WARNX("non UDPv4 packet received");
		goto end;
	}
	if (l < ip_header->ihl * 4 + sizeof(struct udphdr)) {
		LLOG_WARNX("received too small UDP packet");
		goto end;
	}
	udp_header = (struct udphdr*)(buf + ip_header->ihl * 4);

	LLOG_DEBUG("received packet from %s:%d",
	    inet_ntoa(*(struct in_addr*)&ip_header->saddr),
	    ntohs(udp_header->source));
	LLOG_DEBUG("packet for %s:%d",
	    inet_ntoa(*(struct in_addr*)&ip_header->daddr),
	    ntohs(udp_header->dest));

	/* Get or create and update the current state */
	memcpy(&find.source, &ip_header->saddr, sizeof(struct in_addr));
	memcpy(&find.destination, &ip_header->daddr, sizeof(struct in_addr));
	find.sport = ntohs(udp_header->source);
	find.dport = ntohs(udp_header->dest);
	if ((udpstate = state_get_or_create(udpstates, &find,
		    udp_incoming)) == NULL) {
		LLOG_WARNX("unable to get UDP state");
		goto end;
	}
	udpstate->lastchange = time(NULL);
	udpstate->count++;
	if (send(udpstate->socket, buf + ip_header->ihl * 4 + sizeof(struct udphdr),
		l - ip_header->ihl * 4 - sizeof(struct udphdr), MSG_DONTWAIT) == -1) {
		LLOG_WARN("unable to send packet from proxy");
		goto end;
	}

end:
	n = buf;
	l = 0;
}

#if !CLIENT_ONLY
void
nfq_incoming(int fd, short event, void *arg)
{
	char buf[NFQ_PACKET_BUFFER_SIZE];
	int rv;
	if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
		nfq_handle_packet((struct nfq_handle *)arg,
		    buf, rv);
	else
		LLOG_WARN("unable to handle incoming packet");
}

int
nfq_process(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
    struct nfq_data *nfdata, void *data)
{
	struct nfqnl_msg_packet_hdr *header;
	char *payload = NULL;
	int payload_length;
	int remoteout;

	if (!(header = nfq_get_msg_packet_hdr(nfdata))) {
		LLOG_WARNX("unable to get header");
		return -1;
	}
	if ((payload_length = nfq_get_payload(nfdata,
		    (char**)&payload)) == -1) {
		LLOG_WARNX("unable to get payload");
		return -1;
	}

	/* We now send the packet to the remote end */
	remoteout = *(int*)data;
	if (send(remoteout, payload, payload_length, MSG_DONTWAIT) == -1)
		LLOG_WARN("unable to send packet to remote end");

	/* Drop the package, we will pass it through our proxy */
	return nfq_set_verdict(qh, ntohl(header->packet_id), NF_DROP, 0, NULL);
}


int
nfq_init(int queue, struct nfq_handle **nfq, struct nfq_q_handle **qh, int *remoteout)
{
	LLOG_INFO("Initialize net queue %d", queue);

	if ((*nfq = nfq_open()) == NULL) {
		LLOG_WARNX("unable to open nfqueue");
		return -1;
	}

	nfq_unbind_pf(*nfq, AF_INET);
	if (nfq_bind_pf(*nfq, AF_INET) != 0) {
		nfq_close(*nfq);
		LLOG_WARNX("unable to bind nfqueue to AF_INET");
		return -1;
	}

	if ((*qh = nfq_create_queue(*nfq, queue, &nfq_process,
		    remoteout)) == NULL) {
		nfq_unbind_pf(*nfq, AF_INET);
		nfq_close(*nfq);
		LLOG_WARNX("unable to create queue %d", queue);
		return -1;
	}

	if (nfq_set_mode(*qh, NFQNL_COPY_PACKET,
		NFQ_PACKET_BUFFER_SIZE) == -1) {
		nfq_unbind_pf(*nfq, AF_INET);
		nfq_close(*nfq);
		LLOG_WARNX("unable to set mode");
		return -1;
	}

	return 0;
}

void
nfq_shut(struct nfq_handle *nfq, struct nfq_q_handle *qh)
{
	nfq_destroy_queue(qh);
	nfq_unbind_pf(nfq, AF_INET);
	nfq_close(nfq);
}
#endif

void
proxy_shutdown(int fd, short event, void *arg)
{
	keep_running = 0;
	if (EVENT_SIGNAL(((struct event *)arg)) == SIGCHLD)
		LLOG_WARNX("remote process died");
}

#if !CLIENT_ONLY
int
start_remote(const char *cmd, int *read, int *write, uid_t uid, uid_t gid)
{
	int pipeout[2], pipein[2];
	if ((pipe(pipeout) == -1) || (pipe(pipein) == -1)) {
		LLOG_WARN("unable to create pipes");
		return -1;
	}
	switch (fork()) {
	case -1:
		LLOG_WARN("unable to fork");
		close(pipeout[0]);
		close(pipein[0]);
		close(pipeout[1]);
		close(pipein[1]);
		return -1;
	case 0:
		/* Child */
		close(pipeout[1]);
		close(pipein[0]);
		/* Change uid/gid */
		if ((gid > 0) && (setgid(gid) == -1))
			fatal("unable to change uid");
		if ((uid > 0) && (setuid(uid) == -1))
			fatal("unable to change uid");
		/* Plug to stdin/stdout */
		dup2(pipeout[0], STDIN_FILENO);
		dup2(pipein[1], STDOUT_FILENO);
		execl("/bin/sh", "/bin/sh", "-c", cmd, NULL);
		break;
	default:
		close(pipeout[0]);
		close(pipein[1]);
		*read = pipein[0];
		*write = pipeout[1];
		return 0;
	}
	
	/* Make the compiler happy */
	return -1;
}
#endif

static void
setup_signals()
{
	static struct event evsigint, evsigterm, evsigchld, evsigpipe;
	event_set(&evsigint, SIGINT, EV_SIGNAL | EV_PERSIST, proxy_shutdown,
	    &evsigint);
	if (event_add(&evsigint, NULL) == -1)
		fatal("unable to setup sigint signal");
	event_set(&evsigterm, SIGTERM, EV_SIGNAL | EV_PERSIST, proxy_shutdown,
	    &evsigterm);
	if (event_add(&evsigterm, NULL) == -1)
		fatal("unable to setup sigterm signal");
	event_set(&evsigchld, SIGCHLD, EV_SIGNAL | EV_PERSIST, proxy_shutdown,
	    &evsigchld);
	if (event_add(&evsigchld, NULL) == -1)
		fatal("unable to setup sigchld signal");
	event_set(&evsigpipe, SIGPIPE, EV_SIGNAL | EV_PERSIST, proxy_shutdown,
	    &evsigpipe);
	if (event_add(&evsigpipe, NULL) == -1)
		fatal("unable to setup sigpipe signal");
}

void
loop()
{
	struct timeval tv;

	while (keep_running) {
		tv.tv_usec = 0;
		tv.tv_sec = 1;
		event_loopexit(&tv);
		event_dispatch();
	}
}

int
main(int argc, char **argv)
{
	int ch, queue = -1, debug = 0;
	char *cmd = NULL;
	struct nfq_handle *nfq;
	struct nfq_q_handle *qh;
	int remotein, remoteout;
	uid_t uid = -1, gid = -1;

	struct event evqueue, evrin, evexpire;
        struct timeval tv;
        struct states *udpstates;

	while ((ch = getopt(argc, argv, "dq:e:u:g:")) != -1) {
		switch (ch) {
		case 'd':
			debug++;
			break;
#if !CLIENT_ONLY
		case 'q':
			queue = atoi(optarg);
			break;
		case 'e':
			cmd = optarg;
			break;
		case 'u':
			uid = atoi(optarg);
			break;
		case 'g':
			gid = atoi(optarg);
			break;
#endif
		default:
			usage();
		}
	}

	log_init(debug);

	if ((cmd == NULL) && (queue != -1)) {
		LLOG_INFO("no command given, will call myself");
		cmd = argv[0];
	}

	event_init();

#if !CLIENT_ONLY
        if (queue != -1) {
		/* Packets from remote */
		if (start_remote(cmd, &remotein, &remoteout,
			uid, gid) == -1)
			fatalx("unable to start remote");
		event_set(&evrin, remotein, EV_READ | EV_PERSIST,
		    remote_incoming, &evrin);
		if (event_add(&evrin, NULL) == -1)
			fatal("unable to set event for incoming pipe");

		/* Packets to be forwarded */
		if (nfq_init(queue, &nfq, &qh, &remoteout) == -1)
			fatalx("unable to initialize net queue");
		event_set(&evqueue, nfnl_fd(nfq_nfnlh(nfq)),
		    EV_READ | EV_PERSIST, nfq_incoming, nfq);
		if (event_add(&evqueue, NULL) == -1)
			fatal("unable to set event for netfilter queue");
	} else {
#endif
		/* States expiration */
		udpstates = state_initialize();
		tv.tv_usec = 0;
		tv.tv_sec = 2;
		event_set(&evexpire, -1, EV_TIMEOUT | EV_PERSIST,
		    expire_states, udpstates);
		if (event_add(&evexpire, &tv) == -1)
			fatal("unable to set timer for state expiration");

		/* Packets from proxy */
		event_set(&evrin, STDIN_FILENO, EV_READ | EV_PERSIST,
		    local_incoming, udpstates);
		if (event_add(&evrin, NULL) == -1)
			fatal("unable to set event for incoming pipe");
#if !CLIENT_ONLY
	}
#endif

	setup_signals();
	loop();

#if !CLIENT_ONLY
	if (queue != -1) {
		nfq_shut(nfq, qh);
	}
#endif

	LLOG_INFO("shutdown");

	return 0;
}
