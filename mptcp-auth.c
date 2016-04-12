#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/ssl.h>
#include "base64.h"
#include "log.h"
#include "list.h"
#include "redsocks.h"
//#include "OpenSSLInterface.h"

#define UID_FILE "/proc/net/mptcp_net/client_uuid"
#define KEY_FILE "/proc/net/mptcp_net/client_key"
#define MPTCP_AUTH "/proc/net/mptcp_net/mptcp_auth"

struct mptcp_auth_content {
    int cmd;
    int uuid;
    int key[16];
};

enum auth_type {
	AUTH_LOGIN,
	AUTH_LOGOUT,
	AUTH_HEARTBEAT,
};

/* aaaack but it's fast and const should make it shared text page. */
static const unsigned char pr2six[256] =
{
    /* ASCII table */
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

int Base64decode_len(const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);

    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    return nbytesdecoded + 1;
}

int Base64decode(char *bufplain, const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register unsigned char *bufout;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 4) {
    *(bufout++) =
        (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    *(bufout++) =
        (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    *(bufout++) =
        (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    bufin += 4;
    nprbytes -= 4;
    }

    /* Note: (nprbytes == 1) would be an error, so just ingore that case */
    if (nprbytes > 1) {
    *(bufout++) =
        (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    }
    if (nprbytes > 2) {
    *(bufout++) =
        (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    }
    if (nprbytes > 3) {
    *(bufout++) =
        (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    }

    *(bufout++) = '\0';
    nbytesdecoded -= (4 - nprbytes) & 3;
    return nbytesdecoded;
}

server_config running_info[3];
server_config running_info_test[3][SN_CNT];
extern list_head instances;
extern void redsocks_fini_instance(redsocks_instance *instance);
/*
int ssl_sdk(char* buf)
{
	int i = 0;
	int status = 0;
	char buffer[1024] = {0};

	NetSession *session = Create();
	if (!session) {
		log_error("Create session failed!\n");
		return -1;
	}

	if (enumReturnErrorOK != Init(session))
	{
		log_error("Init session failed failed!\n");
		return -1;
	}

//    	char *js =  "action?parameter=%7B%20%22modulename%22%3A%20%22route%22%2C%20%22operation%22%3A%20%22auth%22%2C%20%22data%22%3A%20%7B%20%22targetId%22%3A%20%229ebe2d0e-7c6d-11e5-bb15-fa163e6f7961%22%20%7D%20%7D";
    	setProxyHostAndPort(session, "115.182.92.109", 443);
	i = sendPacketHttp(session, enumRequestTypePost, "", buf, 0, "", &status, buffer, 1024, 2000);
	if (200 != status && enumReturnErrorSocketTimeout != i)
        printf("status = %d\n", status);

	DestroySession(session);
	return 0;
}
*/

size_t process_data(void *buffer, size_t size, size_t nmemb, void *user_p)
{
	json_object *json_result;
	json_object *data, *status;
	json_object *uid, *key;
	json_object *msg, *machine_id, *proxy_port, *proxy,
		    *client_ip;
    redsocks_instance *instance;
    char buf[3][20]= {{0}};
    int action = 0;
	int i;
	int j;

    instance = (redsocks_instance *)user_p;
    server_config *sc = &running_info[instance->if_index];

	fprintf(stdout, "%s \n if_index=%d", (char*) buffer, instance->if_index);

	json_result = json_tokener_parse(buffer);
	if (json_result == NULL) {
		fprintf(stderr, "Failed to get json result\n");
		return 0;
	}

	if (!json_object_object_get_ex(json_result, "status", &status)
			|| json_object_get_type(status) != json_type_int) {

		fprintf(stderr, "Failed to get status\n");
		goto exit;
	}

	json_object_object_get_ex(json_result, "msg", &msg);
    log_error(LOG_DEBUG, "status: (%d), msg = %s \n", json_object_get_int(status),
           json_object_get_string(msg));

    if (json_object_get_int(status) != 200)
        return -1;

	if (json_object_object_get_ex(json_result, "client_ip", &client_ip)) {
        printf("logout success ip: = %s \n", json_object_get_string(client_ip));
		return 0;
	}

    if (strstr(json_object_get_string(msg), "heart")) {
        action = 1;
		goto update_key;
    }

	json_object_object_get_ex(json_result, "machine_id", &machine_id);
    printf("machine_id = %s \n", json_object_get_string(machine_id));
    sc->machine_id = strdup(json_object_get_string(machine_id));

	json_object_object_get_ex(json_result, "proxy_port", &proxy_port);
    printf("proxy_port = %s \n", json_object_get_string(proxy_port));
    sc->proxy_port = strdup(json_object_get_string(proxy_port));

	json_object_object_get_ex(json_result, "proxy", &proxy);

	for (i = 0; i < json_object_array_length(proxy); i++) {
		json_object *ip, *o_type;

		json_object *jproxy = json_object_array_get_idx(proxy, i);
		json_object_object_get_ex(jproxy, "ip", &ip);
		json_object_object_get_ex(jproxy, "operator_type", &o_type);
		printf("\t[%d], ip=%s, operator_type=%s\n",
		       i, json_object_to_json_string(ip), json_object_to_json_string(o_type));

        snprintf(buf[i], 20, "%s", json_object_to_json_string(ip));
        snprintf(buf[i], 20, "%s", (char *)buf[i] + 1);
        j = strlen(buf[i]);
        buf[i][j-1]  = '\0';
        sc->dst[i].dip = strdup(buf[i]);
        sc->dst[i].operator_type = strdup(json_object_to_json_string(o_type));
	}

update_key:
	if (!json_object_object_get_ex(json_result, "data", &data)
			|| json_object_get_type(data) != json_type_object) {
		fprintf(stderr, "Failed to get data\n");
		goto exit;
	}

	if (json_object_object_get_ex(data, "uid", &uid)
			&& json_object_get_type(uid) == json_type_string
			&& json_object_object_get_ex(data, "key", &key)
			&& json_object_get_type(key) == json_type_string) {
		    log_error(LOG_DEBUG, "got : uid(%s), key(%s)\n", json_object_get_string(uid), json_object_get_string(key));
            char buf[92] = {0};
            int j;

            snprintf(buf, sizeof(buf), "%s", json_object_to_json_string(uid));
            snprintf(buf, sizeof(buf), "%s", buf + 1);
            j = strlen(buf);
            buf[j-1] = '\0';
            snprintf(sc->key.uid, 9, "%s", buf);

            memset(buf, 0x0, 92);
            snprintf(buf, sizeof(buf), "%s", json_object_to_json_string(key));
            snprintf(buf, sizeof(buf), "%s", buf + 1);
            j = strlen(buf);
            buf[j-1]  = '\0';
            snprintf(sc->key.key, 89, "%s", buf);
    }

		char client_uid[7], client_key[67];
		int client_uid_len, client_key_len;
		const char *json_uid = json_object_get_string(uid);
		const char *json_key = json_object_get_string(key);
        /*
		if (json_uid == NULL || strlen(json_uid) != 8 || json_key == NULL || strlen(json_key) != 88) {
			fprintf(stderr, "wrong json uid or key len1 = %d, len2= %d\n", strlen(json_uid), strlen(json_key));
					goto exit;
		}
        */

		client_uid_len = Base64decode(client_uid, json_uid);
		client_key_len = Base64decode(client_key, json_key);
		fprintf(stderr, "uid_len(%d), key_len(%d)\n", client_uid_len, client_key_len);

		if (client_uid_len != 4 ||client_key_len != 64) {
			log_error(LOG_ERR, "wrong uid or key\n");
					goto exit;
		}

        int client_uid_int = 0x12345678;
        memset(client_key, 0x01, 64);

#if 0
		//int i;
		fprintf(stderr, "uid: ");
		for (i = 0; i < 3; i++) {
			fprintf(stderr, "%02x:", (unsigned char) client_uid[i]);
		}
		fprintf(stderr, "%02x\n", (unsigned char) client_uid[3]);
		fprintf(stderr, "key: ");
		for (i = 0; i < 63; i++) {
			fprintf(stderr, "%02x:", (unsigned char) client_key[i]);
		}
		fprintf(stderr, "%02x\n", (unsigned char) client_key[63]);

#endif

		FILE * file;
		file = fopen(MPTCP_AUTH, "wb");
		if (file == NULL) {
			fprintf(stderr, "Failed to open %s\n", MPTCP_AUTH);
			goto exit;
		}
//		if (fwrite(client_uid, 1, 4, file) != 4) {
        int rc;
        rc = fwrite(&client_uid_int, sizeof(client_uid_int), 1, file);
		if (rc != 1) {
			fprintf(stderr, "Failed to wirte %s\n", MPTCP_AUTH);
			fclose(file);
			goto exit;
		}
		fclose(file);
		file = fopen(KEY_FILE, "w");
		if (file == NULL) {
			fprintf(stderr, "Failed to open %s\n", MPTCP_AUTH);
			goto exit;
		}
		if (fwrite(client_key, 1, 64, file) != 64) {
			fprintf(stderr, "Failed to wirte %s\n", MPTCP_AUTH);
			fclose(file);
			goto exit;
		}
		fclose(file);
	//} else {
	//	fprintf(stderr, "Failed to get uid or key\n");
	//}

    if (action) {
        goto exit;
    }

exit:

    json_object_put(json_result);

	return 0;
}

int  write_keyfile(char *fname, struct mptcp_auth_content *key)
{
    int rc;
	FILE * file;
	file = fopen(fname, "wb");
	if (file == NULL) {
		fprintf(stderr, "Failed to open %s\n", MPTCP_AUTH);
        return -1;
	}

    rc = fwrite(key, sizeof(struct mptcp_auth_content), 1, file);
	if (rc != 1) {
		fprintf(stderr, "Failed to wirte %s\n", MPTCP_AUTH);
		fclose(file);
        return -1;
	}

	fclose(file);
    return 0;
}

int update_key(json_object *json_result, server_config *sc)
{
    json_object *data;
    struct mptcp_auth_content key_test;
    char client_uid[7], client_key[67];
	int client_uid_len, client_key_len;
	json_object *uid, *key;

	if (!json_object_object_get_ex(json_result, "data", &data)
	    || json_object_get_type(data) != json_type_object) {
		log_error(LOG_ERR, "Failed to get data\n");
		goto exit;
	}

	if (json_object_object_get_ex(data, "uid", &uid)
	    && json_object_get_type(uid) == json_type_string
	    && json_object_object_get_ex(data, "key", &key)
	    && json_object_get_type(key) == json_type_string) {
            char buf[92] = {0};
            int j;

            snprintf(buf, sizeof(buf), "%s", json_object_to_json_string(uid));
            snprintf(buf, sizeof(buf), "%s", buf + 1);
            j = strlen(buf);
            buf[j-1] = '\0';
            snprintf(sc->key.uid, 9, "%s", buf);

            memset(buf, 0x0, 92);
            snprintf(buf, sizeof(buf), "%s", json_object_to_json_string(key));
            snprintf(buf, sizeof(buf), "%s", buf + 1);
            j = strlen(buf);
            buf[j-1]  = '\0';
            snprintf(sc->key.key, 89, "%s", buf);
    }

	client_uid_len = Base64decode(client_uid, sc->key.uid);
	client_key_len = Base64decode(client_key, sc->key.key);
	log_error(LOG_DEBUG, "uid_len(%d), key_len(%d)\n", client_uid_len, client_key_len);

	if (client_uid_len != 4 ||client_key_len != 64) {
		log_error(LOG_ERR, "wrong uid or key\n");
				goto exit;
	}

    key_test.cmd = 0x01;
    memcpy(&key_test.uuid, client_uid, client_uid_len);
    memcpy(&key_test.key, client_key, client_key_len);

    write_keyfile(MPTCP_AUTH, &key_test);

#if 0
		//int i;
		fprintf(stderr, "uid: ");
		for (i = 0; i < 3; i++) {
			fprintf(stderr, "%02x:", (unsigned char) client_uid[i]);
		}
		fprintf(stderr, "%02x\n", (unsigned char) client_uid[3]);
		fprintf(stderr, "key: ");
		for (i = 0; i < 63; i++) {
			fprintf(stderr, "%02x:", (unsigned char) client_key[i]);
		}
		fprintf(stderr, "%02x\n", (unsigned char) client_key[63]);

#endif

exit:
        return 0;
}

size_t process_data_test(void *buffer, size_t size, size_t nmemb, void *user_p)
{
	json_object *json_result, *status;
	json_object *msg, *machine_id, *proxy_port, *proxy, *client_ip;
    redsocks_instance *instance;
    char buf[3][20] = {{0}};
	int i, j;

    instance = (redsocks_instance *)user_p;
    server_config *sc = &running_info_test[instance->if_index][instance->sn_number];

	log_error(LOG_WARNING, "%s\n if_index=%d\n", (char*) buffer, instance->if_index);
	json_result = json_tokener_parse(buffer);
	if (json_result == NULL) {
		fprintf(stderr, "Failed to get json result\n");
		return 0;
	}

	if (!json_object_object_get_ex(json_result, "status", &status)
		|| json_object_get_type(status) != json_type_int) {
		fprintf(stderr, "Failed to get status\n");
		goto exit;
	}

	json_object_object_get_ex(json_result, "msg", &msg);
    log_error(LOG_DEBUG, "status: (%d), msg = %s \n",
            json_object_get_int(status), json_object_get_string(msg));

    if (json_object_get_int(status) != 200)
        return -1;

	if (json_object_object_get_ex(json_result, "client_ip", &client_ip)) {
        fprintf(stdout, "logout success ip: = %s \n", json_object_get_string(client_ip));
		return 0;
	}

    if (strstr(json_object_get_string(msg), "heart")) {
        update_key(json_result, sc);
		goto exit;
    }

	json_object_object_get_ex(json_result, "machine_id", &machine_id);
    sc->machine_id = strdup(json_object_get_string(machine_id));

	json_object_object_get_ex(json_result, "proxy_port", &proxy_port);
    sc->proxy_port = strdup(json_object_get_string(proxy_port));

	json_object_object_get_ex(json_result, "proxy", &proxy);

	for (i = 0; i < json_object_array_length(proxy); i++) {
		json_object *ip, *o_type;

		json_object *jproxy = json_object_array_get_idx(proxy, i);
		json_object_object_get_ex(jproxy, "ip", &ip);
		json_object_object_get_ex(jproxy, "operator_type", &o_type);
		//log_error(LOG_WARNING, "\t[%d], ip=%s, operator_type=%s\n",
		 //      i, json_object_to_json_string(ip), json_object_to_json_string(o_type));

        snprintf(buf[i], sizeof(buf[i]), "%s", json_object_to_json_string(ip));
        snprintf(buf[i], sizeof(buf[i]), "%s", (char *)buf[i] + 1);
        j = strlen(buf[i]);
        buf[i][j-1] = '\0';
        sc->dst[i].dip = strdup(buf[i]);
        sc->dst[i].operator_type = strdup(json_object_to_json_string(o_type));
	}

    update_key(json_result, sc);

exit:
    json_object_put(json_result);

	return 0;
}

struct MemoryStruct {
      char *memory;
      size_t size;
};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  //fprintf(stdout, "########## size = %d, %s\n", (int)realsize, (char*)contents);
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

struct MemoryStruct chunk;
int g_ip_ver = 0;
int doreporter(CURL *handle, int type)
{
    int ret = -1;
    const char *post_str;

    json_object *ip_update = json_object_new_object();
    json_object_object_add(ip_update, "ver", json_object_new_int(g_ip_ver));

    post_str = json_object_to_json_string(ip_update);

    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, post_str);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, &WriteMemoryCallback);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(handle, CURLOPT_VERBOSE, 1L);
    ret = curl_easy_perform(handle);
    if(ret != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(ret));
    } else {
        log_errno(LOG_WARNING, "########%lu bytes retrieved\n", (long)chunk.size);
		FILE * file;

		file = fopen("/tmp/iplist", "w");
		if (file == NULL) {
			log_error(LOG_ERR, "Failed to open /tmp/iplist");
            return -1;
		}

		if (fwrite(chunk.memory, 1, chunk.size, file) != chunk.size) {
			log_error(LOG_ERR, "Failed to wirte /tmp/iplist");
			fclose(file);
            return -1;
		}
		fclose(file);

        json_object *json_result = json_tokener_parse(chunk.memory);
        json_object *status, *ver, *msg;
	    if (json_result == NULL) {
	    	fprintf(stderr, "Failed to get json result\n");
	    	return 0;
	    }

	    if (!json_object_object_get_ex(json_result, "status", &status)
			|| json_object_get_type(status) != json_type_int) {
		    fprintf(stderr, "Failed to get status\n");
            return 0;
	    }

	    json_object_object_get_ex(json_result, "msg", &msg);
	    json_object_object_get_ex(json_result, "ver", &ver);
        printf("status: (%d),ip_version=%d, msg = %s \n",
                json_object_get_int(status),
                json_object_get_int(ver),
                json_object_get_string(msg));

        if (json_object_get_int(status) != 200)
            return -1;

        g_ip_ver = json_object_get_int(ver);

        }


    return ret;
}

char *l_ifname[3] = {
    "eth0",
    "eth0",
    "eth0",
};

#define NO_SN_TEST  0xffffffff
char const* build_json(redsocks_instance *instance, int type, int index, int sn_number)
{
    char const *post_str;
    server_config *sc;
    if (sn_number == NO_SN_TEST) {
        sc = &running_info[index];
        sn_number = 0;
    } else {
        sc = &running_info_test[index][sn_number];
    }

	switch (type) {
    case AUTH_LOGIN: {
       	json_object *jlogin = json_object_new_object();
	    json_object *jarray = json_object_new_array();
        json_object *jID;
        if (sc->lastID[0] != NULL) {
            int i = 0;
            for (i = 0; sc->lastID[i] != NULL; i++) {
                jID = json_object_new_string(sc->lastID[i]);
                json_object_array_add(jarray, jID);
            }
        } else {
                json_object_array_add(jarray, json_object_new_string(""));
        }

        if (instance->config.mptcp_auth_sn[sn_number]) {
       	    json_object_object_add(jlogin, "sn", json_object_new_string(instance->config.mptcp_auth_sn[sn_number]));
       	    json_object_object_add(jlogin, "key", json_object_new_string(instance->config.mptcp_auth_key[sn_number]));
        }

       	json_object_object_add(jlogin, "last_id", jarray);

       	post_str = json_object_to_json_string(jlogin);
		log_error(LOG_DEBUG, "login post_str=%s.", post_str);
	}
	break;

	case AUTH_LOGOUT: {
       		json_object *jlogout = json_object_new_object();
   	    	json_object_object_add(jlogout, "uid", json_object_new_string(sc->key.uid));
   	    	post_str = json_object_to_json_string(jlogout);
		    log_error(LOG_DEBUG, "logout post_str=%s.", post_str);
    }
	break;

	case AUTH_HEARTBEAT: {
	        json_object *heart = json_object_new_object();
	        json_object_object_add(heart, "uid", json_object_new_string(sc->key.uid));
	        json_object_object_add(heart, "update_key", json_object_new_string("1"));
    	    post_str = json_object_to_json_string(heart);
		    log_error(LOG_DEBUG, "heartbeat post_str=%s.", post_str);
	}
	break;

	default:
	    log_error(LOG_ERR, "unknown auth type : %d\n", type);
	    return NULL;
	}

	return post_str;
}

int mptcp_login_test(redsocks_instance *ins, char *url, int if_index, int sn_number)
{
	CURLcode return_code;
	CURL *easy_handle;
	const char *post_str;

	return_code = curl_global_init(CURL_GLOBAL_ALL);
	if (CURLE_OK != return_code) {
		log_error(LOG_ERR, "init libcurl failed.");
		return -1;
	}

	easy_handle = curl_easy_init();
	if (NULL == easy_handle) {
		log_error(LOG_ERR, "get a easy handle failed.");
		curl_global_cleanup();
		return -1;
	}

	curl_easy_setopt(easy_handle, CURLOPT_URL, url);
	curl_easy_setopt(easy_handle, CURLOPT_INTERFACE, l_ifname[if_index]);
    ins->if_index = if_index;
    ins->sn_number = sn_number;

	if (strstr(url, "login"))
	    post_str = build_json(ins, AUTH_LOGIN, if_index, sn_number);
	else if (strstr(url, "logout"))
		post_str = build_json(ins, AUTH_LOGOUT, if_index, sn_number);
	else if (strstr(url, "heart"))
		post_str = build_json(ins, AUTH_HEARTBEAT, if_index, sn_number);
	else if (strstr(url, "iplist"))
		doreporter(easy_handle, 0);
	else
		log_error(LOG_ERR, "Unsupport operation!\n");

    if (!post_str) {
		log_error(LOG_ERR, "Failed to build json string.");
        goto exit;
    }

	curl_easy_setopt(easy_handle, CURLOPT_POSTFIELDS, post_str);
	curl_easy_setopt(easy_handle, CURLOPT_WRITEFUNCTION, &process_data_test);
	curl_easy_setopt(easy_handle, CURLOPT_WRITEDATA, ins);
	curl_easy_setopt(easy_handle, CURLOPT_VERBOSE, 1L);
	curl_easy_perform(easy_handle);

exit:
	curl_easy_cleanup(easy_handle);
	curl_global_cleanup();

	return 0;
}
