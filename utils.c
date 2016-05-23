/* redsocks - transparent TCP-to-proxy redirector
 * Copyright (C) 2007-2011 Leonid Evdokimov <leon@darkk.net.ru>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "log.h"
#include "utils.h"
#include "redsocks.h" // for redsocks_close
#include "libc-compat.h"

#define MPTCP_ENABLED     26
#define MPTCP_AUTH_CLIENT 27
#define MPTCP_AUTH_CLIENT_SET_UUID 30

extern server_config running_info_test[3][SN_CNT];
extern server_config running_info[3];
extern int ins;
int red_recv_udp_pkt(int fd, char *buf, size_t buflen, struct sockaddr_in *inaddr, struct sockaddr_in *toaddr)
{
	socklen_t addrlen = sizeof(*inaddr);
	ssize_t pktlen;
	struct msghdr msg;
	struct iovec io;
	char control[1024];

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = inaddr;
	msg.msg_namelen = sizeof(*inaddr);
	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	io.iov_base = buf;
	io.iov_len = buflen;

	pktlen = recvmsg(fd, &msg, 0);
	if (pktlen == -1) {
		log_errno(LOG_WARNING, "recvfrom");
		return -1;
	}

	if (toaddr) {
		memset(toaddr, 0, sizeof(*toaddr));
		for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (
				cmsg->cmsg_level == SOL_IP &&
				cmsg->cmsg_type == IP_ORIGDSTADDR &&
				cmsg->cmsg_len >= CMSG_LEN(sizeof(*toaddr))
			) {
				struct sockaddr_in* cmsgaddr = (struct sockaddr_in*)CMSG_DATA(cmsg);
				char buf[RED_INET_ADDRSTRLEN];
				log_error(LOG_DEBUG, "IP_ORIGDSTADDR: %s", red_inet_ntop(cmsgaddr, buf, sizeof(buf)));
				memcpy(toaddr, cmsgaddr, sizeof(*toaddr));
			}
			else {
				log_error(LOG_WARNING, "unexepcted cmsg (level,type) = (%d,%d)",
					cmsg->cmsg_level, cmsg->cmsg_type);
			}
		}
		if (toaddr->sin_family != AF_INET) {
			log_error(LOG_WARNING, "(SOL_IP, IP_ORIGDSTADDR) not found");
			return -1;
		}
	}

	if (addrlen != sizeof(*inaddr)) {
		log_error(LOG_WARNING, "unexpected address length %u instead of %zu", addrlen, sizeof(*inaddr));
		return -1;
	}

	if (pktlen >= buflen) {
		char buf[RED_INET_ADDRSTRLEN];
		log_error(LOG_WARNING, "wow! Truncated udp packet of size %zd from %s! impossible! dropping it...",
		          pktlen, red_inet_ntop(inaddr, buf, sizeof(buf)));
		return -1;
	}

	return pktlen;
}

time_t redsocks_time(time_t *t)
{
	time_t retval;
	retval = time(t);
	if (retval == ((time_t) -1))
		log_errno(LOG_WARNING, "time");
	return retval;
}

char *redsocks_evbuffer_readline(struct evbuffer *buf)
{
#if _EVENT_NUMERIC_VERSION >= 0x02000000
	return evbuffer_readln(buf, NULL, EVBUFFER_EOL_CRLF);
#else
	return evbuffer_readline(buf);
#endif
}

extern void redsocks_relay_connected(struct bufferevent *buffev, void *_arg);
struct bufferevent* red_connect_relay(struct sockaddr_in *addr, evbuffercb writecb, everrorcb errorcb, void *cbarg)
{
	struct bufferevent *retval = NULL;
	int on = 1;
	int relay_fd = -1;
	int error;
	int rc;

	relay_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (relay_fd == -1) {
		log_errno(LOG_ERR, "socket");
		goto fail;
	}

	error = fcntl_nonblock(relay_fd);
	if (error) {
		log_errno(LOG_ERR, "fcntl");
		goto fail;
	}

	error = setsockopt(relay_fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
	if (error) {
		log_errno(LOG_WARNING, "setsockopt");
		goto fail;
	}

	if (writecb == redsocks_relay_connected) {
		int enable = 1;
		redsocks_client * cl = (redsocks_client *)cbarg;
		if (cl != NULL && cl->instance->config.mptcp_enable) {
			char uid[4];
			int len;
			int uuid;
			struct in_addr addr_tmp;
			server_config *tmp, *sc;
			if (setsockopt(relay_fd, IPPROTO_TCP, MPTCP_ENABLED, &enable, sizeof(enable))) {
				log_errno(LOG_WARNING, "setsockopt enable MPTCP failed");
			}

			if (setsockopt(relay_fd, IPPROTO_TCP, MPTCP_AUTH_CLIENT, &enable, sizeof(enable))) {
				log_errno(LOG_WARNING, "setsockopt enable MPTCP Auth failed");
			}

			if (cl->instance->config.mptcp_test_mode) {
				tmp = (server_config *)running_info_test;
				sc = &tmp[ins++ % (SN_CNT * 3)];

			} else {
				tmp = (server_config *)running_info;
				sc = &tmp[ins++ % 3];
			}

			len = Base64decode(uid, sc->key.uid);
			memcpy(&uuid, uid, len);
			log_errno(LOG_WARNING, "setsockopt client_uuid= %x, len=%d , addr = %s\n", uuid, len, inet_ntoa(addr->sin_addr));
			rc = setsockopt(relay_fd, IPPROTO_TCP, MPTCP_AUTH_CLIENT_SET_UUID, &uuid, len);
			if (rc) {
				log_errno(LOG_WARNING, "setsockopt enable MPTCP client_uuid setting failed");
			}

			inet_aton(sc->dst[0].dip, &addr_tmp);
			addr->sin_family = AF_INET;
			addr->sin_port = htons(atoi(sc->proxy_port));
			addr->sin_addr = addr_tmp;
			log_errno(LOG_WARNING, "after setsockopt client_uuid= %x, len=%d , addr = %s\n", uuid, len, inet_ntoa(addr->sin_addr));
		}
	}

	error = connect(relay_fd, (struct sockaddr*)addr, sizeof(*addr));
	if (error && errno != EINPROGRESS) {
		log_errno(LOG_NOTICE, "connect");
		goto fail;
	}

	retval = bufferevent_new(relay_fd, NULL, writecb, errorcb, cbarg);
	if (!retval) {
		log_errno(LOG_ERR, "bufferevent_new");
		goto fail;
	}

	error = bufferevent_enable(retval, EV_WRITE); // we wait for connection...
	if (error) {
		log_errno(LOG_ERR, "bufferevent_enable");
		goto fail;
	}

	return retval;

fail:
	if (relay_fd != -1)
		redsocks_close(relay_fd);
	if (retval)
		bufferevent_free(retval);
	return NULL;
}

int red_socket_geterrno(struct bufferevent *buffev)
{
	int error;
	int pseudo_errno;
	socklen_t optlen = sizeof(pseudo_errno);

	assert(EVENT_FD(&buffev->ev_read) == EVENT_FD(&buffev->ev_write));

	error = getsockopt(EVENT_FD(&buffev->ev_read), SOL_SOCKET, SO_ERROR, &pseudo_errno, &optlen);
	if (error) {
		log_errno(LOG_ERR, "getsockopt");
		return -1;
	}
	return pseudo_errno;
}

/** simple fcntl(2) wrapper, provides errno and all logging to caller
 * I have to use it in event-driven code because of accept(2) (see NOTES)
 * and connect(2) (see ERRORS about EINPROGRESS)
 */
int fcntl_nonblock(int fd)
{
	int error;
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		return -1;

	error = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (error)
		return -1;

	return 0;
}

int red_is_socket_connected_ok(struct bufferevent *buffev)
{
	int pseudo_errno = red_socket_geterrno(buffev);

	if (pseudo_errno == -1) {
		return 0;
	}
	else if (pseudo_errno) {
		errno = pseudo_errno;
		log_errno(LOG_NOTICE, "connect");
		return 0;
	}
	else {
		return 1;
	}
}

char *red_inet_ntop(const struct sockaddr_in* sa, char* buffer, size_t buffer_size)
{
	const char *retval = 0;
	size_t len = 0;
	uint16_t port;
	const char placeholder[] = "???:???";

	assert(buffer_size >= sizeof(placeholder));

	memset(buffer, 0, buffer_size);
	if (sa->sin_family == AF_INET) {
		retval = inet_ntop(AF_INET, &sa->sin_addr, buffer, buffer_size);
		port = ((struct sockaddr_in*)sa)->sin_port;
	}
	else if (sa->sin_family == AF_INET6) {
		retval = inet_ntop(AF_INET6, &((const struct sockaddr_in6*)sa)->sin6_addr, buffer, buffer_size);
		port = ((struct sockaddr_in6*)sa)->sin6_port;
	}
	if (retval) {
		assert(retval == buffer);
		len = strlen(retval);
		snprintf(buffer + len, buffer_size - len, ":%d", ntohs(port));
	}
	else {
		strcpy(buffer, placeholder);
	}
	return buffer;
}

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
