

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#ifdef DEBUG_CONNTRACK
#define inline
#endif

#if !defined(__BIONIC__) && (!defined(__GLIBC__) || (__GLIBC__ < 2))
              typedef unsigned int socklen_t;
#endif

//#include "libiptc/libiptc.h"

#define IP_VERSION 4
#define IP_OFFSET 0x1FFF

#define HOOK_PRE_ROUTING NF_IP_PRE_ROUTING
#define HOOK_LOCAL_IN NF_IP_LOCAL_IN
#define HOOK_FORWARD NF_IP_FORWARD
#define HOOK_LOCAL_OUT NF_IP_LOCAL_OUT
#define HOOK_POST_ROUTING NF_IP_POST_ROUTING

#define STRUCT_ENTRY_TARGET struct xt_entry_target
#define STRUCT_ENTRY struct ipt_entry
#define STRUCT_ENTRY_MATCH struct xt_entry_match
#define STRUCT_GETINFO struct ipt_getinfo
#define STRUCT_GET_ENTRIES struct ipt_get_entries
#define STRUCT_COUNTERS struct xt_counters
#define STRUCT_COUNTERS_INFO struct xt_counters_info
#define STRUCT_STANDARD_TARGET struct xt_standard_target
#define STRUCT_REPLACE struct ipt_replace

#define ENTRY_ITERATE IPT_ENTRY_ITERATE
#define TABLE_MAXNAMELEN XT_TABLE_MAXNAMELEN
#define FUNCTION_MAXNAMELEN XT_FUNCTION_MAXNAMELEN

#define GET_TARGET ipt_get_target

#define ERROR_TARGET XT_ERROR_TARGET
#define NUMHOOKS NF_IP_NUMHOOKS

#define IPT_CHAINLABEL xt_chainlabel

#define TC_DUMP_ENTRIES dump_entries
#define TC_IS_CHAIN iptc_is_chain
#define TC_FIRST_CHAIN iptc_first_chain
#define TC_NEXT_CHAIN iptc_next_chain
#define TC_FIRST_RULE iptc_first_rule
#define TC_NEXT_RULE iptc_next_rule
#define TC_GET_TARGET iptc_get_target
#define TC_BUILTIN iptc_builtin
#define TC_GET_POLICY iptc_get_policy
#define TC_INSERT_ENTRY iptc_insert_entry
#define TC_REPLACE_ENTRY iptc_replace_entry
#define TC_APPEND_ENTRY iptc_append_entry
#define TC_CHECK_ENTRY iptc_check_entry
#define TC_DELETE_ENTRY iptc_delete_entry
#define TC_DELETE_NUM_ENTRY iptc_delete_num_entry
#define TC_FLUSH_ENTRIES iptc_flush_entries
#define TC_ZERO_ENTRIES iptc_zero_entries
#define TC_READ_COUNTER iptc_read_counter
#define TC_ZERO_COUNTER iptc_zero_counter
#define TC_SET_COUNTER iptc_set_counter
#define TC_CREATE_CHAIN iptc_create_chain
#define TC_GET_REFERENCES iptc_get_references
#define TC_DELETE_CHAIN iptc_delete_chain
#define TC_RENAME_CHAIN iptc_rename_chain
#define TC_SET_POLICY iptc_set_policy
#define TC_GET_RAW_SOCKET iptc_get_raw_socket
#define TC_INIT iptc_init
#define TC_FREE iptc_free
#define TC_COMMIT iptc_commit
#define TC_STRERROR iptc_strerror
#define TC_NUM_RULES iptc_num_rules
#define TC_GET_RULE iptc_get_rule
#define TC_OPS iptc_ops

#define TC_AF AF_INET
#define TC_IPPROTO IPPROTO_IP

#define SO_SET_REPLACE IPT_SO_SET_REPLACE
#define SO_SET_ADD_COUNTERS IPT_SO_SET_ADD_COUNTERS
#define SO_GET_INFO IPT_SO_GET_INFO
#define SO_GET_ENTRIES IPT_SO_GET_ENTRIES
#define SO_GET_VERSION IPT_SO_GET_VERSION

#define STANDARD_TARGET XT_STANDARD_TARGET
#define LABEL_RETURN IPTC_LABEL_RETURN
#define LABEL_ACCEPT IPTC_LABEL_ACCEPT
#define LABEL_DROP IPTC_LABEL_DROP
#define LABEL_QUEUE IPTC_LABEL_QUEUE

#define ALIGN XT_ALIGN
#define RETURN XT_RETURN

//#include "libiptc.c"

#define IP_PARTS_NATIVE(n)                \
    (unsigned int)((n) >> 24) & 0xFF,     \
        (unsigned int)((n) >> 16) & 0xFF, \
        (unsigned int)((n) >> 8) & 0xFF,  \
        (unsigned int)((n) & 0xFF)

#define IP_PARTS(n) IP_PARTS_NATIVE(ntohl(n))

