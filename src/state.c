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

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#if HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include "splay.h"
#endif

struct statenode {
	SPLAY_ENTRY(statenode) entry;
	struct state state;
};

int state_compare(struct statenode *, struct statenode *);
SPLAY_HEAD(states, statenode);	/* Define struct states */
SPLAY_PROTOTYPE(states, statenode, entry, state_compare);

SPLAY_GENERATE(states, statenode, entry, state_compare);

int
state_compare(struct statenode *s1, struct statenode *s2)
{
        int rc;
	if ((rc = s1->state.sport - s2->state.sport) == 0)
		if ((rc = s1->state.destination.s_addr -
			s2->state.destination.s_addr) == 0)
			if ((rc = s1->state.dport - s2->state.dport) == 0)
				rc = s1->state.source.s_addr - s2->state.source.s_addr;
        return rc;
}

struct states*
state_initialize()
{
	struct states *new, empty = SPLAY_INITIALIZER(statenode);
	if ((new = (struct states *)malloc(sizeof(struct states))) == NULL) {
		LLOG_WARN("unable to allocate states tree");
		return NULL;
	}
	memcpy(new, &empty, sizeof(struct states));
	return new;
}

void
state_destroy(struct states *s)
{
	struct statenode *var, *nxt;
	for (var = SPLAY_MIN(states, s); var != NULL; var = nxt) {
		nxt = SPLAY_NEXT(states, s, var);
		SPLAY_REMOVE(states, s, var);
		close(var->state.socket);
		free(var);
	}
}

struct state*
state_get_or_create(struct states *ss, struct state *s,
    void (*callback)(int, short, void *))
{
	struct statenode find, *res;
        struct sockaddr_in dest;
	int opt;

	memcpy(&find.state, s, sizeof(struct state));
	if ((res = SPLAY_FIND(states, ss, &find)) != NULL)
		return &res->state;

        LLOG_DEBUG("create new state");
	if ((res = (struct statenode *)
		calloc(1, sizeof(struct statenode))) == NULL) {
		LLOG_WARN("not enough memory");
		return NULL;
	}

	memcpy(&res->state, s, sizeof(struct state));
	if ((res->state.socket = socket(AF_INET,
		    SOCK_DGRAM, 0)) == -1) {
		LLOG_WARN("unable to allocate socket");
		free(res);
		return NULL;
	}

	opt = IP_PMTUDISC_DONT;
	setsockopt(res->state.socket, IPPROTO_IP, IP_MTU_DISCOVER, &opt, sizeof(opt));

	memset(&dest, 0, sizeof(struct sockaddr_in));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(res->state.dport);
	memcpy(&dest.sin_addr, &res->state.destination,
	    sizeof(struct in_addr));
        if (connect(res->state.socket, (struct sockaddr *)&dest,
		sizeof(struct sockaddr_in)) == -1) {
                LLOG_WARN("unable to connect to remote host");
		close(res->state.socket);
		free(res);
		return NULL;
        }
        event_set(&res->state.ev, res->state.socket,
	    EV_READ | EV_PERSIST, callback, &res->state);
	if (event_add(&res->state.ev, NULL) == -1)
		fatal("unable to set event for UDP socket");

        SPLAY_INSERT(states, ss, res);

	return &res->state;
}

struct state*
state_get(struct states *ss, struct state *s)
{
	struct statenode *res, find;
	memcpy(&find.state, s, sizeof(struct state));
	if ((res = SPLAY_FIND(states, ss, &find)) != NULL)
		return &res->state;
        return NULL;
}

void
state_expire(struct states *ss, int delay1, int delay2)
{
	struct statenode *var, *nxt;
	int i = 0;
	time_t cur = time(NULL);
	for (var = SPLAY_MIN(states, ss); var != NULL; var = nxt) {
		nxt = SPLAY_NEXT(states, ss, var);
		if (((var->state.count < 2) &&
			((cur - var->state.lastchange) > delay1)) ||
		    ((var->state.count > 1) &&
			((cur - var->state.lastchange) > delay2))) {
                        event_del(&var->state.ev);
			close(var->state.socket);
			SPLAY_REMOVE(states, ss, var);
			free(var);
			i++;
		}
	}
	if (i > 0)
		LLOG_DEBUG("%d states have been expired", i);
}
