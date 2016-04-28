#include "dnsmasq.h"

#ifdef HAVE_IPSET
#undef MIN
#undef MAX

#include <assert.h>			/* assert */
#include <ctype.h>			/* isspace */
#include <errno.h>			/* errno */
#include <stdarg.h>			/* va_* */
#include <stdbool.h>			/* bool */
#include <stdio.h>			/* fprintf, fgets */
#include <stdlib.h>			/* exit */
#include <string.h>			/* str* */

#include <libipset/debug.h>		/* D() */
#include <libipset/data.h>		/* enum ipset_data */
#include <libipset/parse.h>		/* ipset_parse_* */
#include <libipset/session.h>		/* ipset_session_* */
#include <libipset/types.h>		/* struct ipset_type */
#include <libipset/ui.h>		/* core options, commands */
#include <libipset/utils.h>		/* STREQ */



static struct ipset_session *session;
static uint32_t restore_line = 0;
static char ipaddr_buff[ADDRSTRLEN];

static int
handle_error(void)
{
    /*if (ipset_session_warning(session))
        my_syslog(LOG_ERR, _("%s"), ipset_session_warning(session));
    if (ipset_session_error(session))
        my_syslog(LOG_ERR, _("%s"), ipset_session_error(session));*/
    ipset_session_report_reset(session);
    return -1;
}

void ipset_init(void)
{
    /* Load set types */
    ipset_load_types();

    /* Initialize session */
    session = ipset_session_init(printf);
    if (session == NULL)
        die (_("Cannot initialize ipset session, aborting."), NULL, EC_MISC);
    ipset_session_lineno(session, restore_line);
}

int create_ipset(const char *setname)
{
    int ret = 0;
    enum ipset_cmd cmd = IPSET_CMD_CREATE;
    const struct ipset_type *type;

    ret = ipset_parse_setname(session, IPSET_SETNAME, setname);
    if (ret < 0) return ret;
    ret = ipset_parse_typename(session, IPSET_OPT_TYPENAME, "hash:ip");
    if (ret < 0) return ret;
    type = ipset_type_get(session, cmd);
    if (type == NULL) return -1;
    ret = ipset_cmd(session, cmd, restore_line);
    return ret;
}

int add_to_ipset(const char *setname, const struct all_addr *ipaddr, int flags, int remove)
{
    int ret = 0;
    enum ipset_cmd cmd = remove ? IPSET_CMD_DEL: IPSET_CMD_ADD;
    const struct ipset_type *type;

retry:
    ret = ipset_parse_setname(session, IPSET_SETNAME, setname);
    if (ret < 0) goto err;
    type = ipset_type_get(session, cmd);
    if (type == NULL) 
    {
        handle_error();
        if (create_ipset(setname) < 0) goto err;
        goto retry;
    }
#ifdef HAVE_IPV6
    if (flags & F_IPV4)
        inet_ntop(AF_INET, ipaddr->addr.addr4, ipaddr_buff, ADDRSTRLEN);
    else if (flags & F_IPV6)
        inet_ntop(AF_INET6, ipaddr->addr.addr6, ipaddr_buff, ADDRSTRLEN);
#else
    strcpy(ipaddr_buff, inet_ntoa(ipaddr->addr.addr4));
#endif
    ret = ipset_parse_elem(session, type->last_elem_optional, ipaddr_buff);
    if (ret < 0) goto err;
    ret = ipset_cmd(session, cmd, restore_line);
    if (ret < 0)
    {
err:
        handle_error();
    }
    return ret;
}

#endif
