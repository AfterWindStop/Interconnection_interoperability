#ifndef __CONNECT_MANAGE_H_
#define __CONNECT_MANAGE_H_

#include <pthread.h>
//#include <mosquitto.h>
#include "../mqtt/include/mosquitto.h"
#include "../cjson/include/cjson/cJSON.h"
#include "util.h"
#include "bus_announce.h"
#include "common_log.h"

#define IP_LEN 16
#define ID_LEN 128
#define TP_LEN 256

#define ARRAY_SIZE(x)  (sizeof(x)/sizeof(x[0])) 
#define BUS_NAME_LEN 		   32
#define HEART_BEAT_INTERVAL    30
#define HEART_BEAT_TIMES 	   4		
#define DEV_DEAD_TIMES 	       2884   // 24h * 60min * 60snd/HEART_BEAT_INTERVAL + HEART_BEAT_TIMES 
//#define PRI_CONFIG_FILE        "/etc/priority_config"

#define dbg_print(FMT, ...)  do { if (g_bus_obj.debug) log_info("[%s][%d]"FMT"\n", __FUNCTION__, __LINE__, ## __VA_ARGS__); } while (0)

enum {
    EV_CLOCK,
    EV_RCV_MSG,
    EV_EXPIRED,
    EV_LOST_HEARTBEAT,
    EV_CONN_ERROR,
    EV_MAX
};

enum BUS_STATE {
    LOCAL_BUS_INIT = 0,
    LOCAL_BUS_CONNECTED = 1,
    LOCAL_BUS_CREATED = 1<<1,
    LOCAL_BUS_DISCONNECTED = 1<<2,
    LOCAL_BUS_DATACENTER_CREATED = 1<<3,
    LOCAL_BUS_DATACENTER_DESTROY = 1<<4,
    LOCAL_BUS_CONNECTING = 1<<5
};

enum DEVICE_TYPE {
    DEV_TYPE_GATEWAY = 0,
    DEV_TYPE_ROUTER,
    DEV_TYPE_SPEAKER,
    DEV_TYPE_OTT,
    DEV_TYPE_CAMERA,
    DEV_TYPE_TERMINAL,
    DEV_TYPE_MAX 
};


struct dev_info {
	struct list_head list;
	int	online;
	int	pending;
	int count;
    cJSON *topology;
	char terminal_id[ID_LEN];
	char type[12];   // 'g':gateway  'r':router  's':speaker  'o':ott  'c':camera  't':terminal
};

struct bus_info {
    cJSON               *bus;
	struct mosquitto    *mosq;
    timer_t             timer_id;
    char                *id;   // points to @bus->id->valuestring.
};

struct bus_object {
    int hb_cnt;               // record the continuously times we lost heart-beat response.
    int need_online    :1;    // if we send an "connected", and got response, set @connected to 1.
    int connected      :1;
    int elect_started  :1;
    int debug          :1;
    int is_dc          :1;
    char br_dev[8];                // local LAN BRIDGE dev, eg: "br0"
    char priority[DEV_TYPE_MAX];   // priority table
	struct bus_info local;         // the "local bus" we created on our own.
	struct bus_info remote;        // the "local bus" on remote.
	struct list_head dev_head;     // device list 
	pthread_mutex_t dev_mutex;
    timer_t elect_timer;
	char *dev_description;
    struct dev_info *cur_dc;
	cJSON *online_dev;

	callback1 bus_event;
	callback2 bus_recv;
	callback3 platform_info;
};

extern struct bus_object g_bus_obj;
int start_local_client(void);
int start_remote_client(void);
void stop_local_client(void);
void stop_remote_client(void);
int convert_type(const char *type_name);
#endif
