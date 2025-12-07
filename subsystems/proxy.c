/*
 * Copyright (c) 2005 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <sys/param.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/queue.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <netinet/in.h>

#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <getopt.h>
#include <err.h>
#include <syslog.h>

#include <regex.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/dns.h>
#include <dnet.h>

#include "util.h"
#include "proxy.h"
#include "proxy_messages.h"
#include "smtp.h"
#include "honeyd_overload.h"

extern int debug;

#define DFPRINTF(x, y)	do { \
	if (debug >= x) fprintf y; \
} while (0)

/* globals */

FILE *flog_proxy = NULL;	/* log the proxy transactions somewhere */
static regex_t re_connect;	/* regular expression to match connect */
static regex_t re_hostport;	/* extracts host and port */
static regex_t re_get;		/* generic get request */

/* Extract a captured group from a regex match */
static char *
proxy_regex_group(const char *line, int groupnr, regmatch_t *pmatch)
{
	regoff_t start = pmatch[groupnr].rm_so;
	regoff_t end = pmatch[groupnr].rm_eo;
	char *group;

	if (start < 0 || end < 0)
		return (NULL);

	group = malloc(end - start + 1);
	if (group == NULL)
	{
		syslog(LOG_ERR, "%s: malloc", __func__);
		exit(EXIT_FAILURE);
	}
	memcpy(group, line + start, end - start);
	group[end - start] = '\0';

	return (group);
}

/* Generic PROXY related code */

static char *
proxy_logline(struct proxy_ta *ta)
{
	static char line[1024];
	char *srcipaddress = kv_find(&ta->dictionary, "$srcipaddress");
	char *cmd = kv_find(&ta->dictionary, "$command");
	char *host = kv_find(&ta->dictionary, "$host");
	char *port = kv_find(&ta->dictionary, "$port");
	char *uri = kv_find(&ta->dictionary, "$rawuri");

	if (!strcasecmp("connect", cmd)) {
		snprintf(line, sizeof(line),
		    "%ld %s: CONNECT %s:%s",
		    (long)time(NULL), srcipaddress,
		    host, port);
	} else {
		snprintf(line, sizeof(line),
		    "%ld %s: GET %s:%s%s",
		    (long)time(NULL), srcipaddress,
		    host, port, uri);
	}

	return (line);
}

/* Callbacks for PROXY handling */

static char *
proxy_response(struct proxy_ta *ta, struct const_keyvalue data[]) {
	static char line[1024];
	const struct const_keyvalue *msg;
	struct keyvalue *kv;

	for (msg = &data[0]; msg->key != NULL; msg++) {
		if (strcmp(ta->proxy_id, msg->key) == 0)
			break;
	}

	if (msg->key == NULL)
		return (NULL);

	strlcpy(line, msg->value, sizeof(line));

	TAILQ_FOREACH(kv, &ta->dictionary, next) {
		strrpl(line, sizeof(line), kv->key, kv->value);
	}

	return (line);
}

static int
proxy_allowed_network(const char *host)
{
	regex_t re_uri;
	int rc;
	char *unusednets[] = {
		"^127\\.[0-9]+\\.[0-9]+\\.[0-9]+$",		/* local */
		"^10\\.[0-9]+\\.[0-9]+\\.[0-9]+$",		/* rfc-1918 */
		"^172\\.(1[6-9]|2[0-9]|3[01])\\.[0-9]+\\.[0-9]+$",
		"^192\\.168\\.[0-9]+\\.[0-9]+$",		/* rfc-1918 */
		"^2(2[4-9]|3[0-9])\\.[0-9]+\\.[0-9]+\\.[0-9]+$",/* rfc-1112 */
		"^2(4[0-9]|5[0-5])\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
		"^0\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
		"^255\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
		NULL
	};

	char **p;

	for (p = &unusednets[0]; *p; ++p) {
		rc = regcomp(&re_uri, *p, REG_EXTENDED | REG_ICASE | REG_NOSUB);
		if (rc != 0) {
			/* Default to no match */
			fprintf(stderr, "%s: %s: regcomp failed\n",
			    __func__, *p);
			return (0);
		}

		/* Match against the URI */
		rc = regexec(&re_uri, host, 0, NULL, 0);
		regfree(&re_uri);

		if (rc == 0)
			return (0);
	}

	return (1);
}

/*
 * Checks if we are allowed to retrieve a URL from here.
 */

static int
proxy_allowed_get(struct proxy_ta *ta, struct const_keyvalue data[])
{
	char *host, *uri;
	const struct const_keyvalue *cur;
	regex_t re_uri;
	int rc;

	host = kv_find(&ta->dictionary, "$host");
	uri = kv_find(&ta->dictionary, "$rawuri");

	for (cur = &data[0]; cur->key != NULL; cur++) {
		if (strcmp(host, cur->key) == 0)
			break;
	}

	/* Host is not allowed if we do not find it */
	if (cur->key == NULL)
		return (0);

	rc = regcomp(&re_uri, cur->value, REG_EXTENDED | REG_ICASE | REG_NOSUB);
	if (rc != 0) {
		/* Default to no match */
		fprintf(stderr, "%s: %s: regcomp failed\n",
		    __func__, cur->value);
		return (0);
	}

	/* Match against the URI */
	rc = regexec(&re_uri, uri, 0, NULL, 0);

	regfree(&re_uri);

	return (rc == 0);
}

static int
proxy_bad_connection(struct proxy_ta *ta)
{
	char *response = proxy_response(ta, badconnection);
	bufferevent_write(ta->bev, response, strlen(response));
	ta->wantclose = 1;
	return (0);
}

static void
proxy_remote_readcb(struct bufferevent *bev, void *arg)
{
	struct proxy_ta *ta = arg;
	struct evbuffer *buffer = bufferevent_get_input(bev);
	unsigned char *data = evbuffer_pullup(buffer, -1);
	size_t len = evbuffer_get_length(buffer);

	bufferevent_write(ta->bev, data, len);
	evbuffer_drain(buffer, len);
}

static void
proxy_remote_writecb(struct bufferevent *bev, void *arg)
{
	(void)bev;
	(void)arg;
}

static void
proxy_remote_errorcb(struct bufferevent *bev, short what, void *arg)
{
	struct proxy_ta *ta = arg;
	struct evbuffer *buffer = bufferevent_get_output(ta->bev);
	(void)what;
	fprintf(stderr, "%s: called with %p, freeing\n", __func__, arg);

	/* If we still have data to write; we just wait for the flush */
	if (evbuffer_get_length(buffer)) {
		/* Shutdown this site at least - XXX: maybe call shutdown */
		bufferevent_disable(bev, EV_READ|EV_WRITE);

		ta->wantclose = 1;
	} else {
		proxy_ta_free(ta);
	}
}

static char *
proxy_corrupt(char *data, size_t len)
{
	static char buffer[4096];
	int corruptions = len / CORRUPT_SPACE + 1;
	int i;

	if (len > sizeof(buffer) || len <= 1)
		return (data);

	memcpy(buffer, data, len);
	for (i = 0; i < corruptions; i++) {
		int off = rand() % (len - 1);
		buffer[off] = rand();
	}

	return (buffer);
}

static void
proxy_connect_cb(int fd, short what, void *arg)
{
	char line[1024], *data;
	struct proxy_ta *ta = arg;
	int error;
	socklen_t errsz = sizeof(error);
	char *uri;

	/* Check if the connection completed */
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errsz) == -1 ||
	    error) {
		char *response;
		fprintf(stderr, "%s: connection failed: %s\n",
		    __func__, strerror(error));
		close(fd);

		/* Give them a connect error message */
		kv_replace(&ta->dictionary, "$reason", strerror(error));
		response = proxy_response(ta, badconnect);
		bufferevent_write(ta->bev, response, strlen(response));

		ta->wantclose = 1;
		return;
	}

	ta->remote_bev = bufferevent_socket_new(proxy_base, ta->remote_fd,
	    BEV_OPT_CLOSE_ON_FREE);
	if (ta->remote_bev == NULL) {
		close(fd);
		proxy_ta_free(ta);
		return;
	}
	bufferevent_setcb(ta->remote_bev, proxy_remote_readcb,
	    proxy_remote_writecb, proxy_remote_errorcb, ta);

	/* If this get is not allowed, we are going to corrupt the data */
	if (!proxy_allowed_get(ta, allowedhosts))
		ta->corrupt = 1;

	uri = kv_find(&ta->dictionary, "$rawuri");
	snprintf(line, sizeof(line), "GET %s HTTP/1.0\r\n",
	    ta->corrupt ? proxy_corrupt(uri, strlen(uri)) : uri);
	bufferevent_write(ta->remote_bev, line, strlen(line));

	/* Forward all the headers */
	while ((data = kv_find(&ta->dictionary, "data")) != NULL) {
		/* We do not propagate X-Forwarded-For headers */
		if (strncasecmp(X_FORWARDED, data, strlen(X_FORWARDED))) {
			bufferevent_write(ta->remote_bev,
			    ta->corrupt ? proxy_corrupt(data, strlen(data)) :
			    data, strlen(data)); 
			bufferevent_write(ta->remote_bev, "\r\n", 2); 
		}

		/* Do not invalidate this data until we used it */
		kv_remove(&ta->dictionary, "data");
	}
	bufferevent_write(ta->remote_bev, "\r\n", 2); 

	/* Allow the remote site to send us data */
	bufferevent_enable(ta->remote_bev, EV_READ);

	ta->justforward = 1;
}

static void
proxy_connect(struct proxy_ta *ta, char *host, int port)
{
	fprintf(stderr, "Connecting to %s port %d\n", host, port);

	ta->remote_fd = -1;
	if (proxy_allowed_network(host)) {
		char *local_ip = kv_find(&ta->dictionary, "$dstipaddress");

		if (local_ip != NULL) {
			ta->remote_fd = make_bound_connect(
				SOCK_STREAM, host, port, local_ip);
		} else {
			ta->remote_fd = make_socket(
				connect, SOCK_STREAM, host, port);
		}
	}
	if (ta->remote_fd == -1) {
		char *response;
		fprintf(stderr, "%s: failed to connect: %s\n",
		    __func__, strerror(errno));
		kv_replace(&ta->dictionary, "$reason", strerror(errno));
		response = proxy_response(ta, badconnect);
		bufferevent_write(ta->bev, response, strlen(response));
		ta->wantclose = 1;
		return;
	}

	/* One handy event to get called back on this */
	event_base_once(proxy_base, ta->remote_fd, EV_WRITE, proxy_connect_cb, ta, NULL);
}

static void
proxy_handle_get_cb(int result, char type, int count, int ttl,
    void *addresses, void *arg)
{
	struct proxy_ta *ta = arg;
	struct addr addr;
	struct in_addr *in_addrs = addresses;
	int port = atoi(kv_find(&ta->dictionary, "$port"));
	char *response;

	if (ta->dns_canceled) {
		proxy_ta_free(ta);
		return;
	}
	ta->dns_pending = 0;

	if (result != DNS_ERR_NONE || type != DNS_IPv4_A || count == 0) {
		response = proxy_response(ta, baddomain);
		bufferevent_write(ta->bev, response, strlen(response));
		ta->wantclose = 1;
		return;
	}

	/* Need to make a connection here */
	bufferevent_disable(ta->bev, EV_READ);

	addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &in_addrs[0], IP_ADDR_LEN);
	proxy_connect(ta, addr_ntoa(&addr), port);
}

static int
proxy_handle_get(struct proxy_ta *ta)
{
	char *host = kv_find(&ta->dictionary, "$rawhost");
	int rc;
	regmatch_t pmatch[10];

	kv_replace(&ta->dictionary, "$command", "GET");

	rc = regexec(&re_hostport, host, 10, pmatch, 0);
	if (rc == 0) {
		char *strport = proxy_regex_group(host, 2, pmatch);
		char *real_host = proxy_regex_group(host, 1, pmatch);

		kv_add(&ta->dictionary, "$host", real_host);
		kv_add(&ta->dictionary, "$port", strport);

		free(real_host);
		free(strport);
	} else {
		kv_add(&ta->dictionary, "$host", host);
		kv_add(&ta->dictionary, "$port", "80");
	}

	if (flog_proxy != NULL) {
		char *line = proxy_logline(ta);
		fprintf(flog_proxy, "%s\n", line);
		fflush(flog_proxy);
	}

	/* Try to resolve the domain name */
	evdns_base_resolve_ipv4(proxy_dns_base,
	    kv_find(&ta->dictionary, "$host"), 0, proxy_handle_get_cb, ta);
	ta->dns_pending = 1;
	return (0);
}

static void
proxy_handle_connect_cb(int result, char type, int count, int ttl,
    void *addresses, void *arg)
{
	struct proxy_ta *ta = arg;
	char *host = kv_find(&ta->dictionary, "$host");
	int port = atoi(kv_find(&ta->dictionary, "$port"));
	char *response;
	fprintf(stderr, "Connecting to %s port %d\n", host, port);

	if (ta->dns_canceled) {
		proxy_ta_free(ta);
		return;
	}
	ta->dns_pending = 0;

	if (result != DNS_ERR_NONE) {
		response = proxy_response(ta, baddomain);
		bufferevent_write(ta->bev, response, strlen(response));
		ta->wantclose = 1;
		return;
	}

	if (port != 25 || !proxy_allowed_network(host)) {
		response = proxy_response(ta, badport);
		bufferevent_write(ta->bev, response, strlen(response));
		ta->wantclose = 1;
	} else {
		struct smtp_ta *smtp_ta = NULL;
		int fd = dup(ta->fd);

		if (fd != -1)
			smtp_ta = smtp_ta_new(fd,
			    (struct sockaddr *)&ta->sa, ta->salen, 
			    NULL, 0, 0);
		if (smtp_ta != NULL) {
			response = proxy_response(ta, goodport);
			bufferevent_write(smtp_ta->bev,
			    response, strlen(response));
			smtp_greeting(smtp_ta);

			proxy_ta_free(ta);
		} else {
			kv_add(&ta->dictionary, "$host", host);
			response = proxy_response(ta, badport);
			bufferevent_write(ta->bev, response, strlen(response));
			ta->wantclose = 1;
		}
	}
}

static int
proxy_handle_connect(struct proxy_ta *ta)
{
	char *host = kv_find(&ta->dictionary, "$rawhost");
	int rc;
	regmatch_t pmatch[10];

	kv_replace(&ta->dictionary, "$command", "CONNECT");

	rc = regexec(&re_hostport, host, 10, pmatch, 0);
	if (rc == 0) {
		char *strport = proxy_regex_group(host, 2, pmatch);
		char *real_host = proxy_regex_group(host, 1, pmatch);

		kv_add(&ta->dictionary, "$host", real_host);
		kv_add(&ta->dictionary, "$port", strport);

		free(real_host);
		free(strport);
	} else {
		kv_add(&ta->dictionary, "$host", host);
		kv_add(&ta->dictionary, "$port", "80");
	}

	if (flog_proxy != NULL) {
		char *line = proxy_logline(ta);
		fprintf(flog_proxy, "%s\n", line);
		fflush(flog_proxy);
	}

	/* Try to resolve the domain name */
	evdns_base_resolve_ipv4(proxy_dns_base,
	    kv_find(&ta->dictionary, "$host"), 0, proxy_handle_connect_cb, ta);
	ta->dns_pending = 1;
	return (0);
}

static int
proxy_handle(struct proxy_ta *ta, char *line)
{
	int rc;
	regmatch_t pmatch[10];

	/* Execute regular expressions to match the command */

	rc = regexec(&re_connect, line, 10, pmatch, 0);
	if (rc == 0) {
		char *host = proxy_regex_group(line, 1, pmatch);
		kv_replace(&ta->dictionary, "$rawhost", host);
		free(host);

		ta->empty_cb = proxy_handle_connect;
		return (0);
	}

	rc = regexec(&re_get, line, 10, pmatch, 0);
	if (rc == 0) {
		char *host = proxy_regex_group(line, 1, pmatch);
		char *uri = proxy_regex_group(line, 2, pmatch);
		kv_replace(&ta->dictionary, "$rawhost", host);
		kv_replace(&ta->dictionary, "$rawuri", uri);
		free(host);
		free(uri);

		ta->empty_cb = proxy_handle_get;
		return (0);
	}

	return proxy_bad_connection(ta);
}

static char *
proxy_readline(struct bufferevent *bev)
{
	struct evbuffer *buffer = bufferevent_get_input(bev);
	char *data = (char *)evbuffer_pullup(buffer, -1);
	size_t len = evbuffer_get_length(buffer);
	char *line;
	int i;

	for (i = 0; i < len; i++) {
		if (data[i] == '\r' || data[i] == '\n')
			break;
	}
	
	if (i == len)
		return (NULL);

	if ((line = malloc(i + 1)) == NULL) {
		fprintf(stderr, "%s: out of memory\n", __func__);
		evbuffer_drain(buffer, i);
		return (NULL);
	}

	memcpy(line, data, i);
	line[i] = '\0';

	if ( i < len - 1 ) {
		char fch = data[i], sch = data[i+1];

		/* Drain one more character if needed */
		if ( (sch == '\r' || sch == '\n') && sch != fch )
			i += 1;
	}

	evbuffer_drain(buffer, i + 1);

	return (line);
}

static void
proxy_readcb(struct bufferevent *bev, void *arg)
{
	struct proxy_ta *ta = arg;
	char *line;

	if (ta->justforward) {
		struct evbuffer *input = bufferevent_get_input(bev);
		char *data = (char *)evbuffer_pullup(input, -1);
		size_t len = evbuffer_get_length(input);
		if (ta->corrupt) {
			bufferevent_write(ta->remote_bev,
			    proxy_corrupt(data, len), len);
		} else {
			bufferevent_write(ta->remote_bev, data, len);
		}
		evbuffer_drain(input, len);
		return;
	}

	while ((line = proxy_readline(bev)) != NULL) {
		int res = 0;
		/* If we are ready to close on the bugger, just eat it */
		if (ta->wantclose) {
			free(line);
			continue;
		}
		if (ta->empty_cb) {
			/* eat the input until we get a return */
			if (strlen(line)) {
				kv_add(&ta->dictionary, "data", line);
				free(line);
				continue;
			} else {
				res = (*ta->empty_cb)(ta);
				ta->empty_cb = NULL;
			}
		} else {
			res = proxy_handle(ta, line);
		}
		free(line);

		/* Destroy the state machine on error */
		if (res == -1) {
			proxy_ta_free(ta);
			return;
		}
	}
}

static void
proxy_writecb(struct bufferevent *bev, void *arg)
{
	struct proxy_ta *ta = arg;
	(void)bev;

	if (ta->wantclose)
		proxy_ta_free(ta);
}

static void
proxy_errorcb(struct bufferevent *bev, short what, void *arg)
{
	(void)bev;
	(void)what;
	fprintf(stderr, "%s: called with %p, freeing\n", __func__, arg);

	proxy_ta_free(arg);
}

/* Tear down a connection */
void
proxy_ta_free(struct proxy_ta *ta)
{
	struct keyvalue *entry;

	if (ta->dns_pending && !ta->dns_canceled) {
		/* if we have a pending dns lookup, tell it to cancel */
		ta->dns_canceled = 1;
		return;
	}

	while ((entry = TAILQ_FIRST(&ta->dictionary)) != NULL) {
		TAILQ_REMOVE(&ta->dictionary, entry, next);
		free(entry->key);
		free(entry->value);
		free(entry);
	}

	/* BEV_OPT_CLOSE_ON_FREE handles closing the fds */
	bufferevent_free(ta->bev);

	if (ta->remote_bev) {
		bufferevent_free(ta->remote_bev);
	}

	free(ta);
	
}

/* Create a new PROXY transaction */

struct proxy_ta *
proxy_ta_new(int fd, struct sockaddr *sa, socklen_t salen,
    struct sockaddr *lsa, socklen_t lsalen)
{
	struct proxy_ta *ta = calloc(1, sizeof(struct proxy_ta));
	char *srcipname, *srcportname;
	char *dstipname, *dstportname;

	if (ta == NULL)
		goto error;

	ta->proxy_id = "junkbuster";

	TAILQ_INIT(&ta->dictionary);

	memcpy(&ta->sa, sa, salen);
	ta->salen = salen;

	ta->fd = fd;
	ta->bev = bufferevent_socket_new(proxy_base, fd, BEV_OPT_CLOSE_ON_FREE);
	if (ta->bev == NULL)
		goto error;
	bufferevent_setcb(ta->bev, proxy_readcb, proxy_writecb,
	    proxy_errorcb, ta);

	/* Create our tiny dictionary */
	if (lsa != NULL) {
		name_from_addr(lsa, lsalen, &dstipname, &dstportname);
		kv_add(&ta->dictionary, "$dstipaddress", dstipname);
	}

	name_from_addr(sa, salen, &srcipname, &srcportname);
	kv_add(&ta->dictionary, "$srcipaddress", srcipname);

	bufferevent_enable(ta->bev, EV_READ);

	fprintf(stderr, "%s: new proxy instance to %s complete.\n",
	    __func__, srcipname);

	return (ta);

 error:
	if (ta != NULL)
		free(ta);
	fprintf(stderr, "%s: out of memory\n", __func__);
	close(fd);

	return (NULL);
}

static void
accept_socket(int fd, short what, void *arg)
{
	struct sockaddr_storage ss, lss;
	socklen_t addrlen = sizeof(ss), laddrlen = sizeof(lss);
	int nfd, res;

	if ((nfd = accept(fd, (struct sockaddr *)&ss, &addrlen)) == -1) {
		fprintf(stderr, "%s: bad accept\n", __func__);
		return;
	}

	/* Test our special subsystem magic */
	res = fcntl(fd, F_XXX_GETSOCK, &lss, &laddrlen);

	if (res != -1) {
		/*
		 * We are running under honeyd and could figure out
		 * who we are.  That's great.
		 */
		proxy_ta_new(nfd, (struct sockaddr *)&ss, addrlen,
		    (struct sockaddr *)&lss, laddrlen);
	} else {
		proxy_ta_new(nfd, (struct sockaddr *)&ss, addrlen,
		    NULL, 0);
	}
}

struct event *
proxy_bind_socket(u_short port)
{
	struct event *ev;
	int fd;

	if ((fd = make_socket(bind, SOCK_STREAM, "0.0.0.0", port)) == -1)
	{
		syslog(LOG_ERR, "%s: cannot bind socket: %d", __func__, port);
		exit(EXIT_FAILURE);
	}

	if (listen(fd, 10) == -1)
	{
		syslog(LOG_ERR, "%s: listen failed: %d", __func__, port);
		exit(EXIT_FAILURE);
	}

	/* Schedule the socket for accepting */
	ev = event_new(proxy_base, fd, EV_READ | EV_PERSIST, accept_socket, NULL);
	if (ev == NULL)
	{
		syslog(LOG_ERR, "%s: event_new failed", __func__);
		exit(EXIT_FAILURE);
	}
	event_add(ev, NULL);

	fprintf(stderr,
	    "Bound to port %d\n"
	    "Awaiting connections ... \n",
	    port);

	return ev;
}

void
proxy_init(void)
{
	int rc;
	const char *exp_connect = "^connect[[:space:]]+(.*)[ \t]+http";
	const char *exp_hostport = "^(.*):([0-9]+)$";
	const char *exp_get = "^GET[[:space:]]+http://([^/ ]*)(/?[^ ]*)[[:space:]]+HTTP";

	/* Compile regular expressions for command parsing */
	rc = regcomp(&re_connect, exp_connect, REG_EXTENDED | REG_ICASE);
	if (rc != 0)
	{
		syslog(LOG_ERR, "%s: regcomp failed for re_connect", __func__);
		exit(EXIT_FAILURE);
	}

	rc = regcomp(&re_hostport, exp_hostport, REG_EXTENDED | REG_ICASE);
	if (rc != 0)
	{
		syslog(LOG_ERR, "%s: regcomp failed for re_hostport", __func__);
		exit(EXIT_FAILURE);
	}

	rc = regcomp(&re_get, exp_get, REG_EXTENDED | REG_ICASE);
	if (rc != 0)
	{
		syslog(LOG_ERR, "%s: regcomp failed for re_get", __func__);
		exit(EXIT_FAILURE);
	}
}
