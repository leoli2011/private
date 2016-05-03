LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	base.c dnstc.c http-connect.c \
	log.c md5.c socks5.c \
	base64.c http-auth.c http-relay.c main.c \
	parser.c redsocks.c socks4.c utils.c \
	mptcp-auth.c ipset.c netd_cmd.c
LOCAL_C_INCLUDES += $(LOCAL_PATH)
LOCAL_C_INCLUDES += external/curl/include/
LOCAL_C_INCLUDES += external/dnsmasq/src/
LOCAL_C_INCLUDES += external/la_module/ipset/include/
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../openssl/include/

LOCAL_CFLAGS += -O2 -std=gnu99
LOCAL_CFLAGS += -DHAVE_CONFIG_H
LOCAL_STATIC_LIBRARIES := libevent libipset libmnl
LOCAL_SHARED_LIBRARIES := libc libm libcurl libjson-c libssl libcutils liblog
LOCAL_LDFLAGS += -lcurl -ljson-c -lssl
LOCAL_MODULE := redsocks
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := redsocks_iptables
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_MODULE_PATH := $(TARGET_OUT)/bin
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_POST_INSTALL_CMD := chmod 775 $(LOCAL_MODULE_PATH)/$(LOCAL_MODULE)
include $(BUILD_PREBUILT)
