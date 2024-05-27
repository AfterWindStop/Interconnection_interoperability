/*
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#ifndef _LINUX_IF_BRIDGE_H
#define _LINUX_IF_BRIDGE_H

#include <linux/types.h>
#include <linux/if_ether.h>
//#include <linux/in6.h>
#include <netinet/in.h> 

#define SYSFS_BRIDGE_ATTR	"bridge"
#define SYSFS_BRIDGE_FDB	"brforward"
#define SYSFS_BRIDGE_PORT_SUBDIR "brif"
#define SYSFS_BRIDGE_PORT_ATTR	"brport"
#define SYSFS_BRIDGE_PORT_LINK	"bridge"

#define BRCTL_VERSION 1

#define BRCTL_GET_VERSION 0
#define BRCTL_GET_BRIDGES 1
#define BRCTL_ADD_BRIDGE 2
#define BRCTL_DEL_BRIDGE 3
#define BRCTL_ADD_IF 4
#define BRCTL_DEL_IF 5
#define BRCTL_GET_BRIDGE_INFO 6
#define BRCTL_GET_PORT_LIST 7
#define BRCTL_SET_BRIDGE_FORWARD_DELAY 8
#define BRCTL_SET_BRIDGE_HELLO_TIME 9
#define BRCTL_SET_BRIDGE_MAX_AGE 10
#define BRCTL_SET_AGEING_TIME 11
#define BRCTL_SET_GC_INTERVAL 12
#define BRCTL_GET_PORT_INFO 13
#define BRCTL_SET_BRIDGE_STP_STATE 14
#define BRCTL_SET_BRIDGE_PRIORITY 15
#define BRCTL_SET_PORT_PRIORITY 16
#define BRCTL_SET_PATH_COST 17
#define BRCTL_GET_FDB_ENTRIES 18
#define BRCTL_SNOOPING_ENABLE 19
#define BRCTL_SNOOPING_TIMELEN  20
#define BRCTL_SNOOPING_UNREGIST_MODE 21
#define BRCTL_SNOOPING_IFSEND_WAN 22
#define BRCTL_SEND_IGMPREPORT 23
#define BRCTL_SEND_IGMPLEAVE 24
#define BRCTL_SEND_IGMPQUERY 25
#define BRCTL_SNOOPING_MTOU 26
#define BRCTL_SNOOPING_QRYSEND 27
#define BRCTL_SNOOPING_LVMODE  28
#define BRCTL_SET_LAN_MCSOURCE 29
#define BRCTL_SNOOPING_QUERYVER  33
#define BRCTL_SIMULATION_CONF    92
#define BRCTL_USERBEHAVIOR_CONF  35
#define BRCTL_GET_BRPORT        100
#define BRCTL_SET_BRPORT        99
#define BRCTL_MULTICAST_CONF  98
#define BRCTL_VLAN_CONF       97
#define BRCTL_PORTLOCATE_CONF 96
#define BRCTL_LOOPBACK_CONF  95
#define BRCTL_APPWEBPOP_CONF 91
#define BRCTL_GET_FFEINFO        101
#define BRCTL_SET_FILTERS       94
#define BRCTL_GET_FILTERS       93
#define BRCTL_SET_PERMITS       89
#define BRCTL_GET_PERMITS       88
#define BRCTL_SET_BRIDGEPERMIT  105
#define BRCTL_SET_FILTERS_VLAN  130
#define BRCTL_GET_FILTERS_VLAN  131

#define BR_STATE_DISABLED 0
#define BR_STATE_LISTENING 1
#define BR_STATE_LEARNING 2
#define BR_STATE_FORWARDING 3
#define BR_STATE_BLOCKING 4
#define BRCTL_SIMULATION_CONF    92
#ifdef CONFIG_NET_BRIDGE_PD_TABLE
#define BRCTL_ADD_MAC_ITEM 30
#define BRCTL_DEL_MAC_ITEM 31
#define BRCTL_ENABLE_PROJ 32
#define BRCTL_SET_MAX_CLIENT_NUMBER 34
#endif
#ifdef CONFIG_BR_HOLD_DHCP_DISCOVER
#define BRCTL_SET_PORTSDHCPRELAY 36
#endif
#define BRCTL_MLD_SNOOPING 51 
#define BRCTL_MLD_UNREGIST_MODE 52 
#define BRCTL_MLD_SNOOPING_MTOU 53 
#define BRCTL_MLD_SNOOPING_TIMELEN 54 /**/
#define BRCTL_MLD_SNOOPING_IFSEND_WAN 55 /**/
#define BRCTL_MLD_SNOOPING_LVMODE 56 /**/
#define BRCTL_MLD_SNOOPING_TBLSIZE 57 /**/
#define BRCTL_MLD_SNOOPING_SENDQRY 58 /**/
#define BRCTL_SET_VLANBIND    37
#define BRCTL_GET_VLANBIND    38
#define BRCTL_SET_DATABIND 39
#define BRCTL_CLR_DATABIND 40
#define BRCTL_SET_MACDATABIND 41
#define BRCTL_SET_UNUSEDBINDEN 42
#define BRCTL_SET_LEARNBINDEN 43
#define BRCTL_GET_DATABIND    44
#define BRCTL_SET_SSID        45
#define BRCTL_SET_FDB_LIMIT   46
#define BRCTL_GET_FDB_LIMIT   47
#define BRCTL_SET_BR_FILTER   48
#define BRCTL_GET_BR_FILTER   49
#define BRCTL_COMMON_CFG      50
#define BRCTL_SET_WLSSID      60
#define BRCTL_GET_WLSSID      61
#define BRCTL_CFM_CMD         62
#define BRCTL_GET_VLANLEARN    63
#define BRCTL_SET_IGMP_MVLAN  64
#define BRCTL_GET_IGMP_MVLAN  65
#define BRCTL_SHOWIGMP_FDBNODE  66
#define BRCTL_SET_MVLAN_MODE  67
#define BRCTL_SET_MLD_MVLAN         68        
#define BRCTL_GET_MLD_MVLAN          69
#define BRCTL_SHOWMLD_FDBNODE          70
#define BRCTL_SET_INET_ROUTE_BIND       71
#define BRCTL_DEL_MTOUCH_MAC            72
#define BRCTL_DEL_MTOUCH_PORT           73
#define BRCTL_SET_SERVERLIST_MODE       74
#define BRCTL_GET_SERVERLIST_MODE       75
#define BRCTL_SET_BR_GREGISTERTAG     76
#define BRCTL_SET_DEFAULT_CFG                77
#define BRCTL_SET_FW_ENABLE      78
#define BRCTL_SET_FRAME_DETECT  79
#define BRCTL_GET_FRAME_DETECT  80
#define BRCTL_PDT_START       200
#define BRCTL_CLEANALL_L3FAST_ENTRY   81
#define BRCTL_IPRT_SETIPRROUTE_ENTRY  82
#define BRCTL_IPRT_SETIPRROUTE_ENABLE 121
#define BRCTL_PACKET_IFFORBID_WAN    90
#define BRCTL_IPRT_GET_HITCNT         123
#define BRCTL_GET_WAN_STAT            124
#define BRCTL_IPRT_GET_HITIP          125
#ifdef CONFIG_NET_BRIDGE_PD_TABLE
#define DROP_LAN_WAN        (0x01) //0000 0001
#define DROP_LAN_LAN        (0x02) //0000 0010
#define DROP_LAN_LOCAL      (0x04) //0000 0100
#define PKT_PERMIT          (0x00) //0000 0000
enum item_states{DYN_ITEM = 0,STATIC_ITEM};
extern unsigned char net_bridge_pd_table_enable;
#endif //CONFIG_NET_BRIDGE_PD_TABLE
#define __DEV_ETH0          (0x01) //0000 0001
#define __DEV_ETH1          (0x02) //0000 0010
#define __DEV_ETH2          (0x04) //0000 0100
#define __DEV_ETH3          (0x08) //0000 1000
#define __DEV_WLAN0         (0x10) //0001 0000
#define __DEV_WLAN1         (0x20) //0010 0000
#define __DEV_WLAN2         (0x40) //0100 0000
#define __DEV_WLAN3         (0x80) //1000 0000
#ifdef CONFIG_BR_HOLD_DHCP_DISCOVER 
extern unsigned long uldhcp_relay;
#endif

#define BR_STATE_DISABLED 0
#define BR_STATE_LISTENING 1
#define BR_STATE_LEARNING 2
#define BR_STATE_FORWARDING 3
#define BR_STATE_BLOCKING 4

struct __bridge_info {
	__u64 designated_root;
	__u64 bridge_id;
	__u32 root_path_cost;
	__u32 max_age;
	__u32 hello_time;
	__u32 forward_delay;
	__u32 bridge_max_age;
	__u32 bridge_hello_time;
	__u32 bridge_forward_delay;
	__u8 topology_change;
	__u8 topology_change_detected;
	__u8 root_port;
	__u8 stp_enabled;
	__u32 ageing_time;
	__u32 gc_interval;
	__u32 hello_timer_value;
	__u32 tcn_timer_value;
	__u32 topology_change_timer_value;
	__u32 gc_timer_value;
};

struct __port_info {
	__u64 designated_root;
	__u64 designated_bridge;
	__u16 port_id;
	__u16 designated_port;
	__u32 path_cost;
	__u32 designated_cost;
	__u8 state;
	__u8 top_change_ack;
	__u8 config_pending;
	__u8 unused0;
	__u32 message_age_timer_value;
	__u32 forward_delay_timer_value;
	__u32 hold_timer_value;
};

struct __fdb_entry {
	__u8 mac_addr[6];
	__u8 port_no;
	__u8 is_local;
	__u32 ageing_timer_value;
	__u8 port_hi;
	__u16 l2_wanvlanid; /* l2 lan wan */
	__u16 l2_lanvlanid; /* l2 lan  lan */
 	__u16 l3_vlanid;    /* l3 */
	__u8 pad0;
	__u16 unused;
};

/* Bridge Flags */
#define BRIDGE_FLAGS_MASTER	1	/* Bridge command to/from master */
#define BRIDGE_FLAGS_SELF	2	/* Bridge command to/from lowerdev */

#define BRIDGE_MODE_VEB		0	/* Default loopback mode */
#define BRIDGE_MODE_VEPA	1	/* 802.1Qbg defined VEPA mode */
#define BRIDGE_MODE_UNDEF	0xFFFF  /* mode undefined */

/* Bridge management nested attributes
 * [IFLA_AF_SPEC] = {
 *     [IFLA_BRIDGE_FLAGS]
 *     [IFLA_BRIDGE_MODE]
 *     [IFLA_BRIDGE_VLAN_INFO]
 * }
 */
enum {
	IFLA_BRIDGE_FLAGS,
	IFLA_BRIDGE_MODE,
	IFLA_BRIDGE_VLAN_INFO,
	__IFLA_BRIDGE_MAX,
};
#define IFLA_BRIDGE_MAX (__IFLA_BRIDGE_MAX - 1)

#define BRIDGE_VLAN_INFO_MASTER	(1<<0)	/* Operate on Bridge device as well */
#define BRIDGE_VLAN_INFO_PVID	(1<<1)	/* VLAN is PVID, ingress untagged */
#define BRIDGE_VLAN_INFO_UNTAGGED	(1<<2)	/* VLAN egresses untagged */
#define BRIDGE_VLAN_INFO_RANGE_BEGIN	(1<<3) /* VLAN is start of vlan range */
#define BRIDGE_VLAN_INFO_RANGE_END	(1<<4) /* VLAN is end of vlan range */

struct bridge_vlan_info {
	__u16 flags;
	__u16 vid;
};

/* Bridge multicast database attributes
 * [MDBA_MDB] = {
 *     [MDBA_MDB_ENTRY] = {
 *         [MDBA_MDB_ENTRY_INFO]
 *     }
 * }
 * [MDBA_ROUTER] = {
 *    [MDBA_ROUTER_PORT]
 * }
 */
enum {
	MDBA_UNSPEC,
	MDBA_MDB,
	MDBA_ROUTER,
	__MDBA_MAX,
};
#define MDBA_MAX (__MDBA_MAX - 1)

enum {
	MDBA_MDB_UNSPEC,
	MDBA_MDB_ENTRY,
	__MDBA_MDB_MAX,
};
#define MDBA_MDB_MAX (__MDBA_MDB_MAX - 1)

enum {
	MDBA_MDB_ENTRY_UNSPEC,
	MDBA_MDB_ENTRY_INFO,
	__MDBA_MDB_ENTRY_MAX,
};
#define MDBA_MDB_ENTRY_MAX (__MDBA_MDB_ENTRY_MAX - 1)

enum {
	MDBA_ROUTER_UNSPEC,
	MDBA_ROUTER_PORT,
	__MDBA_ROUTER_MAX,
};
#define MDBA_ROUTER_MAX (__MDBA_ROUTER_MAX - 1)

struct br_port_msg {
	__u8  family;
	__u32 ifindex;
};

struct br_mdb_entry {
	__u32 ifindex;
#define MDB_TEMPORARY 0
#define MDB_PERMANENT 1
	__u8 state;
	struct {
		union {
			__be32	ip4;
			struct in6_addr ip6;
		} u;
		__be16		proto;
	} addr;
};

enum {
	MDBA_SET_ENTRY_UNSPEC,
	MDBA_SET_ENTRY,
	__MDBA_SET_ENTRY_MAX,
};
#define MDBA_SET_ENTRY_MAX (__MDBA_SET_ENTRY_MAX - 1)

#endif /* _LINUX_IF_BRIDGE_H */
