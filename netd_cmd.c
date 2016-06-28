#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <cutils/sockets.h>
#include <cutils/properties.h>

#define LETV_RESOURCE "letv letv.com lecloud.com lemall.com hdletv.com leauto.com letv.cn letvcdn.com letvcloud.com letvimg.com letvstore.com le.com"

typedef int (*netd_result_handle)(int code, char* res_line, void *arg);

static int netd_csock = -1;

//netd command
static int netd_result(int sock, int cmdid, netd_result_handle handle, void *arg)
{
    char buffer[512];
    fd_set read_fds;
    int rc = 0;

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);

        if ((rc = select(sock +1, &read_fds, NULL, NULL, NULL)) < 0) {
            int res = errno;
            fprintf(stderr, "Error in select (%s)\n", strerror(errno));
            return res;
        } else if (!rc) {
            return ETIMEDOUT;
        } else if (FD_ISSET(sock, &read_fds)) {
            memset(buffer, 0, sizeof(buffer));
            if ((rc = read(sock, buffer, sizeof(buffer))) <= 0) {
                int res = errno;
                if (rc == 0)
                    fprintf(stderr, "Lost connection to Netd - did it crash?\n");
                else
                    fprintf(stderr, "Error reading data (%s)\n", strerror(errno));
                if (rc == 0)
                    return ECONNRESET;
                return res;
            }

            int offset = 0;
            int i = 0;

            for (i = 0; i < rc; i++) {
                if (buffer[i] == '\0') {
                    int code;
                    int id;
                    char tmp[8];
                    char *ptr;

                    strncpy(tmp, buffer + offset, 3);
                    tmp[3] = '\0';
                    code = atoi(tmp);

                    ptr = buffer + offset + 4;
                    while (*ptr != ' ') ptr++;
                    *ptr++ = '\0';
                    id = atoi(buffer + offset + 4);

                    if (id == cmdid) {
                        if (code >= 200 && code < 600) {
                            return 0;
                        } else if (handle != NULL) {
                            handle(code, ptr, arg);
                        }
                    }
                    offset = i + 1;
                }
            }
        }
    }
    return 0;
}

static int netd_cmdx(int sock, char *cmd, netd_result_handle handle, void *arg)
{
    char final_cmd[512];
    static int cmdid = 1000;

    snprintf(final_cmd, sizeof(final_cmd), "%d %s", ++cmdid, cmd);

    if (write(sock, final_cmd, strlen(final_cmd) + 1) < 0) {
        int res = errno;
        perror("write");
        return res;
    }

    return netd_result(sock, cmdid, handle, arg);
}

int init_netd_cmd(void)
{
    int count = 200;
    char status[PROPERTY_VALUE_MAX] = {'\0'};

    while (count-- > 0) {
        if (property_get("init.svc.netd", status, NULL)) {
            if (strcmp(status, "running") == 0) {
                sleep(10);
                break;
            }
        }
        usleep(100000);
    }

    if ((netd_csock = socket_local_client("netd", ANDROID_SOCKET_NAMESPACE_RESERVED,
                                     SOCK_STREAM)) < 0) {
        perror("Failed to connect to netd");
        return -1;
    }
    return 0;
}

int send_netd_cmd(char *cmd)
{
    if (netd_csock < 0 || !cmd)
        return -1;
    return netd_cmdx(netd_csock, cmd, NULL, NULL);
}

int set_proxy_dns_server(char *serverip, int isdel)
{
    char cmd[512];
    char default_ifc[PROPERTY_VALUE_MAX];
    char default_netid[PROPERTY_VALUE_MAX];
    char la_cfg[PROPERTY_VALUE_MAX];
    int ret = 0;

    if (!serverip) return -1;
    if (property_get("net.default.interface", default_ifc, NULL) <= 0) return -1;
    if (property_get("net.default.netid", default_netid, NULL) <= 0) return -1;
    property_get("net.default.la", la_cfg, "0");

    ret = atoi(la_cfg);
    if (ret > 1) {
        if (!isdel) {
            snprintf(cmd, sizeof(cmd), "tether dns add %s %s no "LETV_RESOURCE, default_ifc, serverip);
        } else {
            snprintf(cmd, sizeof(cmd), "tether dns del %s %s no "LETV_RESOURCE, default_ifc, serverip);
        }
        ret = send_netd_cmd(cmd);
    } else if (!isdel && ret == 1) {
        snprintf(cmd, sizeof(cmd), "tether dns set %s %s", default_netid, serverip);
        ret = send_netd_cmd(cmd);
    }
    property_set("net.default.ladns", isdel ? "" : serverip);
    return ret;
}
