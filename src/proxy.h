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

#ifndef _PROXY_H
#define _PROXY_H 1

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/time.h>
#include <sys/types.h>
#include <event.h>
#include <netinet/in.h>

#define UDP_UNCONFIRMED_TTL 2
#define UDP_CONFIRMED_TTL 30

/* log.c */
void	 log_init(int);
void	 log_warn(const char *, ...);
#define LLOG_WARN(x,...) log_warn("%s: " x, __FUNCTION__, ##__VA_ARGS__)
void	 log_warnx(const char *, ...);
#define LLOG_WARNX(x,...) log_warnx("%s: " x,  __FUNCTION__, ##__VA_ARGS__)
void	 log_info(const char *, ...);
#define LLOG_INFO(x,...) log_info("%s: " x, __FUNCTION__, ##__VA_ARGS__)
void	 log_debug(const char *, ...);
#define LLOG_DEBUG(x,...) log_debug("%s: " x, __FUNCTION__, ##__VA_ARGS__)
void	 fatal(const char *);
void	 fatalx(const char *);

/* cksum.c */
u_int16_t cksum(unsigned char *, int);

/* state.c */
struct state {
	struct in_addr source;
	struct in_addr destination;
	u_int16_t sport;
	u_int16_t dport;
	int socket;
	struct event ev;
	time_t lastchange;
	long int count;
};
struct states;			/* Opaque type */

struct states*	 state_initialize(void);
void		 state_destroy(struct states *);
struct state*	 state_get_or_create(struct states *, struct state *,
		    void (*)(int, short, void *));
struct state*	 state_get(struct states *, struct state *);
void		 state_expire(struct states *, int, int);

#endif
