#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "connect_manage.h"

#define SELF_TYPE cJSON_GetObjectItem(g_bus_obj.local.bus, "type")->valuestring

int err_flag = 0;
struct bus_object	g_bus_obj;
extern void run_machine(int event);
extern inline int __get_current_state();
extern char *get_state_string(int state);

char g_busId[48] = {0};

int convert_type(const char *type_name)
{
    if (!type_name)
        return DEV_TYPE_TERMINAL;

    switch (*type_name) {
        case 'g':
            return DEV_TYPE_GATEWAY;
        case 'r':
            return DEV_TYPE_ROUTER;
        case 's':
            return DEV_TYPE_SPEAKER;
        case 'o':
            return DEV_TYPE_OTT;
        case 'c':
            return DEV_TYPE_CAMERA;
        default:
            return DEV_TYPE_TERMINAL;
    }
}

/*
 * use 'mosquitto_pub'(provided by 'mosquitto', the open source code) to do some debugging jobs.
 * examples:
 *          mosquitto_pub -h 192.168.1.1 -t debug/ -m on    # turn 'dbg_print' function ON.
 *          mosquitto_pub -h 192.168.1.1 -t debug/ -m off   # turn 'dbg_print' function OFF.
 *          mosquitto_pub -h 192.168.1.1 -t debug/ -m dev   # show device list.
 * note:
 *      if with '-t debug/', all the client connected to the broker will get this message.
 *      using '-t debug/TERMINAL_ID' to send to a specific client.
 *                                                                                      -- shine
 */

static void local_show_devnode(void)
{
	struct dev_info	*dev_entry = NULL;
    
	printf("========show dev info========\n");
    pthread_mutex_lock(&g_bus_obj.dev_mutex);

    list_for_each_entry(dev_entry, &g_bus_obj.dev_head, list) 
        printf("terminal_id[%s]  online[%d]  count[%d]\n", dev_entry->terminal_id, dev_entry->online, dev_entry->count);

    pthread_mutex_unlock(&g_bus_obj.dev_mutex);
	
	return;
}

static void debug_handle(char *topic, char *msg, int len)
{
    char *slash = strrchr(topic, '/');

    // a 'terminal id' may be given just after the slash('/').
    if (slash[1] && strcmp(slash + 1, g_bus_obj.local.id))
        return;

    if (len > ID_LEN)
        return;

    if (!strncmp(msg, "dev", 3))
        local_show_devnode();
    else if (!strncmp(msg, "stat", 4)) {
        printf("current state:[%s]\n", get_state_string(__get_current_state()));
        if (g_bus_obj.is_dc)
            printf("current DC: myself\n");
        else 
            printf("current DC: %s\n", g_bus_obj.cur_dc ? g_bus_obj.cur_dc->terminal_id : "NULL");
    }
    else if (!strcasecmp(msg, "on"))
        g_bus_obj.debug = 1;
    else if (!strcasecmp(msg, "off"))
        g_bus_obj.debug = 0;
    else
        printf("debug info [%s] not support", msg);

    return;
}

cJSON *device_topologic_info(void)
{
    cJSON *info, *j_array, *dev_itm;
	struct dev_info *dev_entry = NULL;

    info = cJSON_CreateObject();
    j_array = cJSON_CreateArray();
    dev_itm = cJSON_CreateObject();

    cJSON_AddStringToObject(dev_itm, "id", g_bus_obj.local.id);
    cJSON_AddStringToObject(dev_itm, "status", "online");
    cJSON_AddItemToArray(j_array, dev_itm);

    pthread_mutex_lock(&g_bus_obj.dev_mutex);
    list_for_each_entry(dev_entry, &g_bus_obj.dev_head, list) {
        dev_itm = cJSON_CreateObject();
        cJSON_AddStringToObject(dev_itm, "id", dev_entry->terminal_id);
        cJSON_AddStringToObject(dev_itm, "status", dev_entry->online ? "online" : "offline");
        cJSON_AddItemToArray(j_array, dev_itm);
    }
    pthread_mutex_unlock(&g_bus_obj.dev_mutex);

    cJSON_AddItemToObject(info, "status", j_array);
    return info;
}

cJSON *online_device_info(void)
{
    cJSON *info, *j_array, *dev_itm;
	struct dev_info *dev_entry = NULL;

    info = cJSON_CreateObject();
    j_array = cJSON_CreateArray();
    dev_itm = cJSON_CreateObject();

    cJSON_AddStringToObject(dev_itm, "id", g_bus_obj.local.id);
    cJSON_AddStringToObject(dev_itm, "status", "online");
    cJSON_AddStringToObject(dev_itm, "type", cJSON_GetObjectItem(g_bus_obj.local.bus, "type")->valuestring);
    cJSON_AddItemToObject(dev_itm, "topology", cJSON_Duplicate(cJSON_GetObjectItem(g_bus_obj.local.bus, "hops"), 1));
    cJSON_AddItemToArray(j_array, dev_itm);

    pthread_mutex_lock(&g_bus_obj.dev_mutex);
    list_for_each_entry(dev_entry, &g_bus_obj.dev_head, list) {
        dev_itm = cJSON_CreateObject();
        cJSON_AddStringToObject(dev_itm, "id", dev_entry->terminal_id);
        cJSON_AddStringToObject(dev_itm, "status", dev_entry->online ? "online" : "offline");
        cJSON_AddStringToObject(dev_itm, "type", dev_entry->type);
        cJSON_AddItemToObject(dev_itm, "topology", cJSON_Duplicate(dev_entry->topology, 1));
        cJSON_AddItemToArray(j_array, dev_itm);
    }
    pthread_mutex_unlock(&g_bus_obj.dev_mutex);

    cJSON_AddItemToObject(info, "status", j_array);
    return info;
}

void send_live_devices(struct mosquitto *mosq, const char *bus_id, const char *dev_id)
{
    char topic[TP_LEN];
    char tid_str[16];
    char *json_str;
    cJSON *j_root, *j_info;

    snprintf(topic, TP_LEN, "%s/%s/setInfo", bus_id, dev_id);
    snprintf(tid_str, 16, "%u", (unsigned int)time(NULL));

    j_root = cJSON_CreateObject();
    cJSON_AddStringToObject(j_root, "transactionId", tid_str);
    cJSON_AddStringToObject(j_root, "originBus", "local");
    cJSON_AddStringToObject(j_root, "busId", bus_id);
    cJSON_AddStringToObject(j_root, "infoId", "device status info");
    j_info = online_device_info();
    cJSON_AddItemToObject(j_root, "info", j_info);
    json_str = cJSON_Print(j_root);

    mosquitto_publish(mosq, NULL, topic, strlen(json_str), json_str, 0, false);
    dbg_print("<PUB>: %s", topic);
    free(json_str);
    cJSON_Delete(j_root);
}

static inline void send_dc_notification(struct mosquitto *mosq)
{
    char topic[TP_LEN];
    snprintf(topic, TP_LEN, "%s/ccToDevice/DcUpNotify", g_bus_obj.local.id);
    mosquitto_publish(mosq, NULL, topic, 2, "{}", 0, false);
}

static int create_bus_object(struct bus_info *bus_obj, 
        void (*connect_callback)(struct mosquitto *, void *, int),
        void (*disconnect_callback)(struct mosquitto *, void *, int),
        void (*topic_callback)(struct mosquitto *, void *, const struct mosquitto_message *))
{
	int ret = 0;
    cJSON *ip_itm;
    cJSON *port_itm;

    if (!bus_obj || !bus_obj->bus)
        return -1;

    ip_itm = cJSON_GetObjectItem(bus_obj->bus, "ip");
    port_itm = cJSON_GetObjectItem(bus_obj->bus, "port");
    if (!ip_itm || !port_itm) {
        dbg_print("<ERR>: bus has no 'ip' or 'port' item\n");
        return -1;
    }
	
	// [1]create a mosquitto client
	bus_obj->mosq = mosquitto_new(NULL, true, NULL);
	if (!bus_obj->mosq){
		switch(errno){
			case ENOMEM:
				dbg_print("<ERR>: Out of memory.");
				break;
			case EINVAL:
				dbg_print("<ERR>: Invalid id and/or clean_session.");
				break;
		}
		goto cleanup;
	}
	
	// [2]set callbacks
	if (connect_callback)
		mosquitto_connect_callback_set(bus_obj->mosq, connect_callback);
	if (disconnect_callback)
		mosquitto_disconnect_callback_set(bus_obj->mosq, disconnect_callback);
	if (topic_callback)
		mosquitto_message_callback_set(bus_obj->mosq, topic_callback);
	
	// [3]connect to broker
	ret = mosquitto_connect_bind(bus_obj->mosq, ip_itm->valuestring, port_itm->valueint, 60, NULL);
	if (ret) {
        dbg_print("<ERR>: connet failed errno=%d, peer_addr=%s, port=%d", errno, ip_itm->valuestring, port_itm->valueint);
		goto cleanup;
	}
	
	// [4]create a listen thread.
	mosquitto_loop_start(bus_obj->mosq);

	return 0;
	
cleanup:
	mosquitto_destroy(bus_obj->mosq);
    bus_obj->mosq = NULL;
	return -1;	
}

static inline void dc_do_unsubscribe(struct mosquitto *mosq)
{
    mosquitto_unsubscribe(mosq, NULL, "+/+/property/setResp");
    mosquitto_unsubscribe(mosq, NULL, "+/+/property/getResp");
    mosquitto_unsubscribe(mosq, NULL, "+/+/method/callResp");
    mosquitto_unsubscribe(mosq, NULL, "+/+/event/subResp");
    mosquitto_unsubscribe(mosq, NULL, "+/+/event/cancelSubResp");
    mosquitto_unsubscribe(mosq, NULL, "+/+/event/notify");
    mosquitto_unsubscribe(mosq, NULL, "+/+/online");	
    dbg_print("<INFO>: DC unsub -Resp topics");
}

static inline void dc_do_subscribe(struct mosquitto *mosq)
{
    mosquitto_subscribe(mosq, NULL, "+/+/property/setResp", 0);	
    mosquitto_subscribe(mosq, NULL, "+/+/property/getResp", 0);	
    mosquitto_subscribe(mosq, NULL, "+/+/method/callResp", 0);	
    mosquitto_subscribe(mosq, NULL, "+/+/event/subResp", 0);	
    mosquitto_subscribe(mosq, NULL, "+/+/event/cancelSubResp", 0);	
    mosquitto_subscribe(mosq, NULL, "+/+/event/notify", 0);	
    mosquitto_subscribe(mosq, NULL, "+/+/online", 0);	
    dbg_print("<INFO>: DC sub -Resp topics");
}

static void terminal_do_unsubscribe(struct mosquitto *mosq, char *bus_id, char *terminal_id)
{
    char topic[TP_LEN];

    snprintf(topic, TP_LEN, "%s/%s/property/set", bus_id, terminal_id);
    mosquitto_unsubscribe(mosq, NULL, topic);

    snprintf(topic, TP_LEN, "%s/%s/property/get", bus_id, terminal_id);
    mosquitto_unsubscribe(mosq, NULL, topic);

    snprintf(topic, TP_LEN, "%s/%s/method/call", bus_id, terminal_id);
    mosquitto_unsubscribe(mosq, NULL, topic);

    snprintf(topic, TP_LEN, "%s/%s/event/sub", bus_id, terminal_id);
    mosquitto_unsubscribe(mosq, NULL, topic);

    snprintf(topic, TP_LEN, "%s/%s/event/cancelSub", bus_id, terminal_id);
    mosquitto_unsubscribe(mosq, NULL, topic);

    snprintf(topic, TP_LEN, "%s/%s/onlineResp", bus_id, terminal_id);
    mosquitto_unsubscribe(mosq, NULL, topic);

    snprintf(topic, TP_LEN, "%s/%s/event/notifyResp", bus_id, terminal_id);
    mosquitto_unsubscribe(mosq, NULL, topic);

    snprintf(topic, TP_LEN, "%s/ccToDevice/DcUpNotify", bus_id);
    mosquitto_unsubscribe(mosq, NULL, topic);

    if (convert_type(SELF_TYPE) != DEV_TYPE_GATEWAY) {
        snprintf(topic, TP_LEN, "%s/%s/setDcUp", bus_id, terminal_id);
        mosquitto_unsubscribe(mosq, NULL, topic);
    }

    // terminal <--> terminal interaction.
    snprintf(topic, TP_LEN, "%s/+/property/setResp", bus_id);
    mosquitto_unsubscribe(mosq, NULL, topic);

    snprintf(topic, TP_LEN, "%s/+/property/getResp", bus_id);
    mosquitto_unsubscribe(mosq, NULL, topic);

    snprintf(topic, TP_LEN, "%s/+/method/callResp", bus_id);
    mosquitto_unsubscribe(mosq, NULL, topic);

    snprintf(topic, TP_LEN, "%s/+/event/subResp", bus_id);
    mosquitto_unsubscribe(mosq, NULL, topic);

    snprintf(topic, TP_LEN, "%s/+/event/cancelSubResp", bus_id);
    mosquitto_unsubscribe(mosq, NULL, topic);

    snprintf(topic, TP_LEN, "%s/+/event/notify", bus_id);
    mosquitto_unsubscribe(mosq, NULL, topic);
    // terminal <--> terminal interaction --end.

    dbg_print("<INFO>: unsub device topics");
	return;
}

static void terminal_do_subscribe(struct mosquitto *mosq, char *bus_id, char *terminal_id)
{
    char topic[TP_LEN];

    snprintf(topic, TP_LEN, "%s/%s/property/set", bus_id, terminal_id);
    mosquitto_subscribe(mosq, NULL, topic, 0);

    snprintf(topic, TP_LEN, "%s/%s/property/get", bus_id, terminal_id);
    mosquitto_subscribe(mosq, NULL, topic, 0);

    snprintf(topic, TP_LEN, "%s/%s/method/call", bus_id, terminal_id);
    mosquitto_subscribe(mosq, NULL, topic, 0);

    snprintf(topic, TP_LEN, "%s/%s/event/sub", bus_id, terminal_id);
    mosquitto_subscribe(mosq, NULL, topic, 0);

    snprintf(topic, TP_LEN, "%s/%s/event/cancelSub", bus_id, terminal_id);
    mosquitto_subscribe(mosq, NULL, topic, 0);

    snprintf(topic, TP_LEN, "%s/%s/onlineResp", bus_id, terminal_id);
    mosquitto_subscribe(mosq, NULL, topic, 0);

    snprintf(topic, TP_LEN, "%s/%s/event/notifyResp", bus_id, terminal_id);
    mosquitto_subscribe(mosq, NULL, topic, 0);

    snprintf(topic, TP_LEN, "%s/ccToDevice/DcUpNotify", bus_id);
    mosquitto_subscribe(mosq, NULL, topic, 0);

    if (convert_type(SELF_TYPE) != DEV_TYPE_GATEWAY) {
        snprintf(topic, TP_LEN, "%s/%s/setDcUp", bus_id, terminal_id);
        mosquitto_subscribe(mosq, NULL, topic, 0);
    }

    // terminal <--> terminal interaction.
    snprintf(topic, TP_LEN, "%s/+/property/setResp", bus_id);
    mosquitto_subscribe(mosq, NULL, topic, 0);	

    snprintf(topic, TP_LEN, "%s/+/property/getResp", bus_id);
    mosquitto_subscribe(mosq, NULL, topic, 0);	

    snprintf(topic, TP_LEN, "%s/+/method/callResp", bus_id);
    mosquitto_subscribe(mosq, NULL, topic, 0);	

    snprintf(topic, TP_LEN, "%s/+/event/subResp", bus_id);
    mosquitto_subscribe(mosq, NULL, topic, 0);	

    snprintf(topic, TP_LEN, "%s/+/event/cancelSubResp", bus_id);
    mosquitto_subscribe(mosq, NULL, topic, 0);	

    snprintf(topic, TP_LEN, "%s/+/event/notify", bus_id);
    mosquitto_subscribe(mosq, NULL, topic, 0);	
    // terminal <--> terminal interaction --end.

    dbg_print("<INFO>: sub terminal topics");
	return;
}

void deal_setinfo_msg(cJSON *root)
{
    int fd, type, ind = 0;
    char *pri_file_path, *str;
    cJSON *j_info_id, *j_info, *element;

    j_info_id = cJSON_GetObjectItem(root, "infoId");
    if (!j_info_id) {
        dbg_print("<WARN>: setInfo msg has no 'infoId' or item");
        return;
    }

    if (!strcmp(j_info_id->valuestring, "priority config")) {
        j_info = cJSON_GetObjectItem(root, "info");
        if (!j_info) {
            dbg_print("<WARN>: setInfo msg has no 'info' item");
            return;
        }

        printf("<INFO>: setInfo priority config\n");
        pri_file_path = getenv("PRIORITY_CONFIG_PATH");
        if (pri_file_path) {
            printf("<INFO>: setInfo priority config env:%s\n", pri_file_path);
            fd = open(pri_file_path, O_WRONLY);
            if (fd) {
                str = cJSON_Print(j_info);
                write(fd, str, strlen(str)); // should deal with the return value of 'write'!
                free(str);
                close(fd);
            }
        }

        cJSON_ArrayForEach(element, j_info) {
            if (cJSON_IsString(element)) {
                type = convert_type(element->valuestring);
                g_bus_obj.priority[type] = ind++;
            }
        }

    } else if (!strcmp(j_info_id->valuestring, "device status info")) {

        if (g_bus_obj.online_dev) 
            cJSON_Delete(g_bus_obj.online_dev);

        g_bus_obj.online_dev = cJSON_DetachItemFromObject(root, "info");
        str = cJSON_Print(g_bus_obj.online_dev);
        dbg_print("<INFO>: receive setInfo with 'device status info':\n%s", str);
        free(str);
    }
}

void deal_offline_pending(struct mosquitto *mosq )
{
    cJSON *msg = NULL;
    unsigned int itime;
    char topic[TP_LEN] = {};
    char tid[16] = {};
    char *msg_str = NULL;
	struct dev_info *dev_entry = NULL;

    //if (!g_bus_obj.is_dc && !g_bus_obj.cur_dc)
        //return;

    itime = (unsigned int)time(NULL);

    pthread_mutex_lock(&g_bus_obj.dev_mutex);
    list_for_each_entry(dev_entry, &g_bus_obj.dev_head, list) {
        // use time++ as transactionId
        snprintf(tid, sizeof(tid), "%u", itime++);
        snprintf(topic, sizeof(topic), "%s/%s/offline", g_bus_obj.local.id, dev_entry->terminal_id);

        msg = cJSON_CreateObject();
        cJSON_AddStringToObject(msg, "transactionId", tid);
        cJSON_AddStringToObject(msg, "originBus", "local");
        msg_str = cJSON_PrintUnformatted(msg);

        if (mosq) {
            mosquitto_publish(g_bus_obj.local.mosq, NULL, topic, strlen(msg_str), msg_str, 0, false);
            dbg_print("<PUB>: %s", topic);
        }
        else 
            g_bus_obj.bus_recv(topic, msg_str, strlen(msg_str));

        free(msg_str);
    }
    pthread_mutex_unlock(&g_bus_obj.dev_mutex);
}

/* ----------------------------local fucntions------------------------------*/

static void send_online_msg(struct mosquitto *mosq, char *bus_id)
{
    char topic[TP_LEN];
    char tid_str[16];
    char *file_str, *json_str;
    cJSON *dev_desc, *device_obj, *message, *hops_itm;

    // read config from file /etc/device_description
    file_str = g_bus_obj.platform_info(INFO_DEV_DESCRIPTION);
    if (!file_str) {
        printf("<ERR>: call hook platform_info failed!\n");
        return;
    }

    if (!(dev_desc = cJSON_Parse(file_str))) {
        free(file_str);
        return;
    }

    snprintf(topic, TP_LEN, "%s/device/online", bus_id);
    snprintf(tid_str, 16, "%u", (unsigned int)time(NULL));

    device_obj = cJSON_DetachItemFromObject(dev_desc, "device");
    message = cJSON_CreateObject();
    cJSON_AddStringToObject(message, "transactionId", tid_str);
    cJSON_AddStringToObject(message, "originBus", "local");
    cJSON_AddStringToObject(message, "busId", bus_id);
    hops_itm = cJSON_GetObjectItem(g_bus_obj.remote.bus, "hops");
    cJSON_AddItemToObject(message, "topology", cJSON_Duplicate(hops_itm, 1));
    cJSON_AddItemToObject(message, "deviceDescription", device_obj);
    json_str = cJSON_Print(message);

    mosquitto_publish(mosq, NULL, topic, strlen(json_str), json_str, 0, false);
    dbg_print("<PUB>: %s", topic);
    free(json_str);
    free(file_str);
    cJSON_Delete(dev_desc);
    cJSON_Delete(message);
}

static void do_dc_election(void)
{
    int tmp, pri = DEV_TYPE_MAX;
    char topic[TP_LEN];
	struct dev_info *dev_entry;
	struct dev_info *candidate = NULL;

    // if I'm a router, I may become a Data Center.
    if (convert_type(SELF_TYPE) == DEV_TYPE_ROUTER)
        pri = g_bus_obj.priority[DEV_TYPE_ROUTER];

    pthread_mutex_lock(&g_bus_obj.dev_mutex);
	list_for_each_entry(dev_entry, &g_bus_obj.dev_head, list) {
        if (!dev_entry->online)
            continue;

        tmp = g_bus_obj.priority[convert_type(dev_entry->type)];
        if (tmp < pri) {
            pri = tmp;
            candidate = dev_entry;
        }
	}
    pthread_mutex_unlock(&g_bus_obj.dev_mutex);

    if (pri != DEV_TYPE_MAX) {
        if (candidate) {
            g_bus_obj.cur_dc = candidate;
            snprintf(topic, TP_LEN, "%s/%s/setDcUp", g_bus_obj.local.id, candidate->terminal_id);
            mosquitto_publish(g_bus_obj.local.mosq, NULL, topic, 2, "{}", 0, false);
            dbg_print("<PUB>: %s", topic);
        } else {
            dbg_print("<INFO>: set is_dc=1, event: LOCAL_BUS_DATACENTER_CREATED\n");
            g_bus_obj.is_dc = 1;
            g_bus_obj.need_online = 0;
            dc_do_subscribe(g_bus_obj.local.mosq);
            send_dc_notification(g_bus_obj.local.mosq);
            g_bus_obj.bus_event(LOCAL_BUS_DATACENTER_CREATED);
        }
    } else
        g_bus_obj.need_online = 0;
}

static void local_timer_thread(union sigval v)
{
	int need_elect = 0, offline_event = 0;
	char topic[TP_LEN] = {};
	struct dev_info *dev_entry, *next;

    // 1. whether need to send a 'online-topic' messge (if there's a DC, and we haven't get onlineResp yet).
    if (g_bus_obj.need_online)
        send_online_msg(g_bus_obj.local.mosq, g_bus_obj.local.id);
	
    // 2. check all the devices' heartbeat.
    pthread_mutex_lock(&g_bus_obj.dev_mutex);
	list_for_each_entry_safe(dev_entry, next, &g_bus_obj.dev_head, list) {
		dev_entry->count++;
		
		// set @online = 0 when there is no 'hearbeatResp' within 120 seconds.
		if (dev_entry->online && dev_entry->count >= HEART_BEAT_TIMES) {
            dev_entry->online = 0;
            dev_entry->pending = 1;
            if (g_bus_obj.elect_started && g_bus_obj.cur_dc == dev_entry) {
                dbg_print("<INFO>: DC down, need to re-elect!");
                
                // we used to have a DC, that means we had subscribed 'device topics', now do unsubscribe.
                terminal_do_unsubscribe(g_bus_obj.local.mosq, g_bus_obj.local.id, g_bus_obj.local.id);
                g_bus_obj.cur_dc = NULL;
                need_elect = 1;
            }
            offline_event = 1;
        }

        // delete this device after 24 hours.
        if (dev_entry->count >= DEV_DEAD_TIMES) {
			if (g_bus_obj.local.mosq) {
				snprintf(topic, TP_LEN, "%s/%s/#", g_bus_obj.local.id, dev_entry->terminal_id);
				mosquitto_unsubscribe(g_bus_obj.local.mosq, NULL, topic);
			}

            list_del(&dev_entry->list);

            if (dev_entry->topology)
                cJSON_Delete(dev_entry->topology);

            free(dev_entry);
        }
	}
    pthread_mutex_unlock(&g_bus_obj.dev_mutex);

    // 3. do these out of the mutex-lock. 
    if (need_elect)
        do_dc_election();

    if (offline_event) {
        // 4. deal with "offline-pending" devices.
        if (g_bus_obj.is_dc)
            deal_offline_pending(NULL);

        // Send live-devices information to DC (only when re-elect does not happened).
        // If DC have changed during election, new DC will get live-devices information after sending 'setDcUpResp' to us.
        if (!need_elect && g_bus_obj.cur_dc)
            send_live_devices(g_bus_obj.local.mosq, g_bus_obj.local.id, g_bus_obj.cur_dc->terminal_id);        
    }

	return;
}

static void local_cleanup_devnode(void)
{
	struct dev_info	*dev_entry, *next;
    
    pthread_mutex_lock(&g_bus_obj.dev_mutex);

	list_for_each_entry_safe(dev_entry, next, &g_bus_obj.dev_head, list) {
        list_del(&dev_entry->list);

        if (dev_entry->topology)
            cJSON_Delete(dev_entry->topology);

        free(dev_entry);
    }

    pthread_mutex_unlock(&g_bus_obj.dev_mutex);
    //dbg_print("<INFO>: cleanup dev list done");
}

static struct dev_info *local_find_devnode(char *terminal_id)
{
	struct dev_info	*dev_entry = NULL;
    
	if (!terminal_id) {
		dbg_print("<WARN>: terminal_id is null");
		return NULL;
	}
	
    pthread_mutex_lock(&g_bus_obj.dev_mutex);
	list_for_each_entry(dev_entry, &g_bus_obj.dev_head, list) {
		if (!strcmp(dev_entry->terminal_id, terminal_id)) {		
            pthread_mutex_unlock(&g_bus_obj.dev_mutex);
			return dev_entry;
		}
	}
    pthread_mutex_unlock(&g_bus_obj.dev_mutex);
	return NULL;
}

static void local_connect_fn(struct mosquitto *mosq, void *obj, int rc)
{
	char 	topic[TP_LEN] = {};

    if (rc) {
        printf("[%s][%d]local_connect_fn error: rc = %d, %s\n", __FUNCTION__, __LINE__, rc, mosquitto_connack_string(rc));
        err_flag = 1;
        return;
    }

    err_flag = 0;

	// pre-subscribe 
	mosquitto_subscribe(mosq, NULL, "debug/+", 0);	
    mosquitto_subscribe(mosq, NULL,  "+/+/setDcDownResp", 0);	
    mosquitto_subscribe(mosq, NULL,  "+/+/setDcUpResp", 0);	

	snprintf(topic, TP_LEN, "%s/+/heartbeat", g_bus_obj.local.id);
	mosquitto_subscribe(mosq, NULL, topic, 0);	
    snprintf(topic, TP_LEN, "%s/%s/setInfo", g_bus_obj.local.id, g_bus_obj.local.id);
    mosquitto_subscribe(mosq, NULL, topic, 0);	

	return;
}

static void local_disconnect_fn(struct mosquitto *mosq, void *obj, int result)
{
	dbg_print("enter");
	return;
}

static void local_message_fn(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg)
{
	int pri; 
	char topic[TP_LEN] = {};
	char *json_str = NULL;
    char *fst_slash, *snd_slash, *last_slash;
    char dev_id[ID_LEN] = {};
	struct dev_info	*dev_entry = NULL;
	cJSON *root, *trans_id, *j_type, *j_conn, *j_hops, *message;

	if (!strncmp(msg->topic, "debug/", 6)) {
        debug_handle(msg->topic, msg->payload, msg->payloadlen);
        return;
    }
	
    fst_slash = strchr(msg->topic, '/');
    if (!fst_slash)
        return;

    last_slash = strrchr(msg->topic, '/');
    snd_slash = strchr(fst_slash + 1, '/');
    if (!snd_slash || snd_slash - fst_slash > ID_LEN) {
		dbg_print("<WARN>: bad topic[%s]!", msg->topic);
        return;
    }

    dbg_print("<RCV>: %s", msg->topic);
    strncpy(dev_id, fst_slash + 1, snd_slash - fst_slash - 1);

	if (!strcmp(last_slash + 1, "heartbeat")) {
        root = cJSON_Parse(msg->payload);
        if (!root) {
            dbg_print("<ERR>: cjson parse: bad payload!");
            return;
        }

        dev_entry = local_find_devnode(dev_id);
        if (!dev_entry) {
            dbg_print("<INFO>: new device %s", dev_id);

            dev_entry = (struct dev_info *)malloc(sizeof(struct dev_info));
            if (!dev_entry) {
                perror("malloc dev_entry fail ");
                goto out_delete;
            }

            j_type = cJSON_GetObjectItem(root, "type");
            if (!j_type) {
                dbg_print("<ERR>: heartbeat with no 'type' item");
                goto out_delete;
            }

            memset(dev_entry, 0, sizeof(struct dev_info));
            strncpy(dev_entry->terminal_id, dev_id, sizeof(dev_entry->terminal_id) - 1);
            strncpy(dev_entry->type, j_type->valuestring, sizeof(dev_entry->type) - 1);

            j_hops = cJSON_GetObjectItem(root, "topology");
            if (!j_hops)
                dbg_print("new device has no 'topology' information");
            else 
                dev_entry->topology = cJSON_Duplicate(j_hops, 1);

            pthread_mutex_lock(&g_bus_obj.dev_mutex);
            list_add(&dev_entry->list, &g_bus_obj.dev_head);
            pthread_mutex_unlock(&g_bus_obj.dev_mutex);
        }

        trans_id = cJSON_GetObjectItem(root, "transactionId");
        if (!trans_id) {
            dbg_print("<ERR>: online message has no 'transactionId' item");
            goto out_delete;
        }

        // if a 'heartbeat' with 'connect' item, it's a connecting-request.
        j_conn = cJSON_GetObjectItem(root, "connect");
        if (cJSON_IsTrue(j_conn)) {
            dbg_print("<INFO>: first heartbeat, set online=0");
            dev_entry->online = 0;

            // this happens when a DC temporarily leave and come back again.
            if (g_bus_obj.cur_dc == dev_entry)
                g_bus_obj.cur_dc = NULL;
        }

		// send 'heartbeatResp'
        snprintf(topic, TP_LEN, "%sResp", msg->topic);
        message = cJSON_CreateObject();
        cJSON_AddStringToObject(message,"transactionId", trans_id->valuestring); 
        cJSON_AddNumberToObject(message,"returnCode", 0); 
        json_str = cJSON_PrintUnformatted(message);
        mosquitto_publish(mosq, NULL, topic, strlen(json_str), json_str, 0, false);
        dbg_print("<PUB>: %s", topic);
        free(json_str);
        cJSON_Delete(message);
        cJSON_Delete(root);

        // check if this -new- device could become a 'data center'
        if (!dev_entry->online && g_bus_obj.elect_started) {
            pri = g_bus_obj.priority[convert_type(dev_entry->type)];  

            if (g_bus_obj.cur_dc) 
            {
                if (pri < g_bus_obj.priority[convert_type(g_bus_obj.cur_dc->type)]) {
                    snprintf(topic, TP_LEN, "%s/%s/setDcDownResp", g_bus_obj.local.id, g_bus_obj.cur_dc->terminal_id);
                    mosquitto_subscribe(mosq, NULL, topic, 0);
                    topic[strlen(topic) - 4] = 0;
                    mosquitto_publish(mosq, NULL, topic, 2, "{}", 0, false);
                    dbg_print("<PUB>: [%s]\n", topic);
                    g_bus_obj.cur_dc = dev_entry;
                }
                else 
                {
                    // new device coming in and we have  DC, tell DC to updata all the online devices.
                    send_live_devices(mosq, g_bus_obj.local.id, g_bus_obj.cur_dc->terminal_id);        
                }

            } 
            else if (pri < DEV_TYPE_MAX && (!g_bus_obj.is_dc || pri < g_bus_obj.priority[DEV_TYPE_ROUTER])) 
            {
                if (g_bus_obj.is_dc) { 
                    g_bus_obj.is_dc = 0;
                    dc_do_unsubscribe(mosq);
                    g_bus_obj.bus_event(LOCAL_BUS_DATACENTER_DESTROY);
                    dbg_print("<INFO> is_dc=0, local event: LOCAL_BUS_DATACENTER_DESTROY");
                }
                snprintf(topic, TP_LEN, "%s/%s/setDcUp", g_bus_obj.local.id, dev_entry->terminal_id);
                mosquitto_publish(mosq, NULL, topic, 2, "{}", 0, false);
                dbg_print("<PUB>: %s", topic);

                g_bus_obj.cur_dc = dev_entry;
            } 
        }

        dev_entry->online = 1;
        dev_entry->count = 0;
	} else if (!strcmp(last_slash + 1, "setDcDownResp")) {
        if (g_bus_obj.cur_dc) {
            snprintf(topic, TP_LEN, "%s/%s/setDcUpResp", g_bus_obj.local.id, g_bus_obj.cur_dc->terminal_id);
            mosquitto_subscribe(mosq, NULL, topic, 0);

            topic[strlen(topic) - 4] = 0;
            mosquitto_publish(mosq, NULL, topic, 2, "{}", 0, false);
            dbg_print("<PUB>: %s", topic);
        } else if (g_bus_obj.is_dc) {
            dbg_print("<INFO>: DC now changes to myself, event:LOCAL_BUS_DATACENTER_CREATED");
            send_dc_notification(mosq);
            g_bus_obj.bus_event(LOCAL_BUS_DATACENTER_CREATED);
        }
    } else if (!strcmp(last_slash + 1, "setDcUpResp")) {
        // first of all, send an announcement
        send_dc_notification(mosq);

        deal_offline_pending(mosq);

        // tell DC all the alive devices.
        send_live_devices(mosq, g_bus_obj.local.id, dev_id);        

        // CC should also act like a --plain-- device too. Try to send an 'online'.
        terminal_do_subscribe(mosq, g_bus_obj.local.id, g_bus_obj.local.id);
        g_bus_obj.need_online = 1;
        send_online_msg(mosq, g_bus_obj.local.id);
    } else if (!strcmp(last_slash + 1, "setInfo")) {
        root = cJSON_Parse(msg->payload);
        if (root) {
            dbg_print("<RCV>: %s (%s)", msg->topic, msg->payload);
            deal_setinfo_msg(root);
            goto out_delete;
        }
    } else {
        if (!strncmp(dev_id, g_bus_obj.local.id, strlen(g_bus_obj.local.id)) && strstr(last_slash + 1, "Resp"))
            return;

        dbg_print("<INFO>: local rcv [%s]", msg->topic);
        g_bus_obj.bus_recv(msg->topic, msg->payload, msg->payloadlen);
    }
    
	return;

out_delete:
    cJSON_Delete(root);
}

static void start_dc_election(union sigval v)
{
    printf("<INFO>: start_dc_election\n");
    do_dc_election();
    g_bus_obj.elect_started = 1;
}

int start_local_client(void)
{
	printf("start_local_client start\n");
	int ret = 0;
	memset(g_busId, 0, sizeof(g_busId));
	memcpy(g_busId, cJSON_GetObjectItem(g_bus_obj.local.bus, "id")->valuestring, strlen(cJSON_GetObjectItem(g_bus_obj.local.bus, "id")->valuestring));		
	printf("start_local_client g_busId = %s\n", g_busId);
	ret = create_bus_object(&g_bus_obj.local, local_connect_fn, local_disconnect_fn, local_message_fn);
	if (ret) {
		dbg_print("<ERR>: create local client fail ");
		return ret;
	}
	
	g_bus_obj.local.timer_id = create_timer(HEART_BEAT_INTERVAL, HEART_BEAT_INTERVAL, local_timer_thread);

    // wait 1 min to elect DATA CENTER
	g_bus_obj.elect_timer = create_timer(20, 0, start_dc_election);
	return 0;
}

void stop_local_client(void)
{
    if (g_bus_obj.local.mosq) {
        mosquitto_destroy(g_bus_obj.local.mosq);
        g_bus_obj.local.mosq = NULL;
    }

    // cleaup dev_list
    local_cleanup_devnode();

    if (g_bus_obj.local.timer_id) {
        timer_delete(g_bus_obj.local.timer_id);
        g_bus_obj.local.timer_id = 0;
    }

    if (g_bus_obj.elect_timer) {
        timer_delete(g_bus_obj.elect_timer);
        g_bus_obj.elect_timer = 0;
    }

    g_bus_obj.elect_started = 0;
    g_bus_obj.is_dc = 0;
    g_bus_obj.connected = 0;
    g_bus_obj.cur_dc = NULL;
}

/* ----------------------------remote fucntions------------------------------*/
static void remote_timer_thread(union sigval v)
{
    char    topic[TP_LEN] = {};
    cJSON   *message    = NULL;
    cJSON   *hops_itm   = NULL;
    char    *json_str   = NULL;
    char    tid_str[16] = {};

    if (!g_bus_obj.remote.bus)
        return;

    // use current time as transactionId.
    sprintf(tid_str, "%u", (unsigned int)time(NULL));

    if (g_bus_obj.need_online)
        send_online_msg(g_bus_obj.remote.mosq, g_bus_obj.remote.id);

    snprintf(topic, TP_LEN, "%s/%s/heartbeat", g_bus_obj.remote.id, g_bus_obj.local.id);
    message = cJSON_CreateObject();
    cJSON_AddStringToObject(message,"transactionId", tid_str);
    cJSON_AddStringToObject(message, "type", SELF_TYPE);        

    // send heartbeat with extra 'connect' item to indicate that this is a first heartbeat, and it's also a 'connecting-request'.
    if (!g_bus_obj.connected) 
    {
        cJSON_AddTrueToObject(message, "connect");
        hops_itm = cJSON_GetObjectItem(g_bus_obj.remote.bus, "hops");
        cJSON_AddItemToObject(message, "topology", cJSON_Duplicate(hops_itm, 1));
    }

    json_str = cJSON_PrintUnformatted(message);
    mosquitto_publish(g_bus_obj.remote.mosq, NULL, topic, strlen(json_str), json_str, 0, false);
    dbg_print("<PUB>: %s", topic);
    free(json_str);
    cJSON_Delete(message);

    if (++g_bus_obj.hb_cnt >= 3) {
        dbg_print("<WARN>: no heartbeat response for 3 times");
        run_machine(EV_LOST_HEARTBEAT);
    }

    return;
}

static void remote_connect_fn(struct mosquitto *mosq, void *obj, int rc)
{
    char topic[TP_LEN] = {};

    if (rc) {
        printf("[%s][%d]remote_connect_fn error: rc = %d, %s\n", __FUNCTION__, __LINE__, rc, mosquitto_connack_string(rc));
        err_flag = 1;
        return;
    }

    err_flag = 0;
	mosquitto_subscribe(mosq, NULL, "debug/+", 0);	

    snprintf(topic, TP_LEN, "%s/%s/heartbeatResp", g_bus_obj.remote.id, g_bus_obj.local.id);
    mosquitto_subscribe(mosq, NULL, topic, 0);

	terminal_do_subscribe(mosq, g_bus_obj.remote.id, g_bus_obj.local.id);
	
	// pub 'heartbeat' periodically.
    g_bus_obj.hb_cnt = 0;
    if (g_bus_obj.remote.timer_id)
        timer_delete(g_bus_obj.remote.timer_id);

    g_bus_obj.remote.timer_id = create_timer(1, HEART_BEAT_INTERVAL, remote_timer_thread);
	return;
}

static void remote_disconnect_fn(struct mosquitto *mosq, void *obj, int result)
{
	dbg_print("enter");
	return;
}

static void remote_message_fn(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg)
{
    char *first_slash;
    char *last_slash;
    char topic[TP_LEN];
    cJSON *root;
	
	if (!strncmp(msg->topic, "debug/", 6)) {
        debug_handle(msg->topic, msg->payload, msg->payloadlen);
        return;
    }

    first_slash = strchr(msg->topic, '/');
    last_slash = strrchr(msg->topic, '/');
    if (!first_slash || !last_slash) {
        dbg_print("<WARN>: invalid topic[%s]", msg->topic);
        return;
    }
	
    dbg_print("<RCV>: %s", msg->topic);

    if (!strcmp(last_slash + 1, "heartbeatResp")) {
        g_bus_obj.hb_cnt = 0;

        if (!g_bus_obj.connected)
            g_bus_obj.connected = 1;

        return;
    }
    else if (!strcmp(last_slash + 1, "onlineResp")) {
        g_bus_obj.need_online = 0;
        return;
    }
    else if (!strcmp(last_slash + 1, "setDcUp")) {

        // first, remove previous topics
        terminal_do_unsubscribe(mosq, g_bus_obj.remote.id, g_bus_obj.local.id);

        // then, subscribe 'online' and a bunch of '-Resp' topics.
        dc_do_subscribe(mosq);

        // and the 'setDcDown' 'setInfo' 'offline' topic
        snprintf(topic, TP_LEN, "%s/%s/setDcDown", g_bus_obj.remote.id, g_bus_obj.local.id);
        mosquitto_subscribe(mosq, NULL, topic, 0);
        dbg_print("<SUB>: %s", topic);
        snprintf(topic, TP_LEN, "%s/%s/setInfo", g_bus_obj.remote.id, g_bus_obj.local.id);
        mosquitto_subscribe(mosq, NULL, topic, 0);
        snprintf(topic, TP_LEN, "%s/+/offline", g_bus_obj.remote.id);
        mosquitto_subscribe(mosq, NULL, topic, 0);
        g_bus_obj.is_dc = 1;
        g_bus_obj.bus_event(LOCAL_BUS_DATACENTER_CREATED);

        // last, send back 'setDcUpResp'
        snprintf(topic, TP_LEN, "%sResp", msg->topic);
        mosquitto_publish(mosq, NULL, topic, 2, "{}", 0, false) ;
        dbg_print("<PUB>: %s, event: LOCAL_BUS_DATACENTER_CREATED", topic);
        return;
    }
    else if (!strcmp(last_slash + 1, "setDcDown")) {

        if (!g_bus_obj.is_dc) {
            dbg_print("<BUG>: receive setDcDown, but I'm not a DC!");
            return;
        }

        dc_do_unsubscribe(mosq);
        mosquitto_unsubscribe(mosq, NULL, msg->topic);
        snprintf(topic, TP_LEN, "%s/%s/setInfo", g_bus_obj.remote.id, g_bus_obj.local.id);
        if (g_bus_obj.online_dev) {
            cJSON_Delete(g_bus_obj.online_dev);
            g_bus_obj.online_dev = NULL;
        }

        mosquitto_unsubscribe(mosq, NULL, topic);
        snprintf(topic, TP_LEN, "%s/+/offline", g_bus_obj.remote.id);
        mosquitto_unsubscribe(mosq, NULL, topic);

        terminal_do_subscribe(mosq, g_bus_obj.remote.id, g_bus_obj.local.id);
        g_bus_obj.is_dc = 0;
        g_bus_obj.bus_event(LOCAL_BUS_DATACENTER_DESTROY);
        dbg_print("<INFO>: event: LOCAL_BUS_DATACENTER_DESTROY\n");
        snprintf(topic, TP_LEN, "%sResp", msg->topic);
        mosquitto_publish(mosq, NULL, topic, 2, "{}", 0, false); 
        return;
    }
    else if (!strcmp(last_slash + 1, "DcUpNotify")) {
        if (!g_bus_obj.is_dc) {
            g_bus_obj.need_online = 1;
            send_online_msg(mosq, g_bus_obj.remote.id);
        }
        return;
    }
    else if (!strcmp(last_slash + 1, "setInfo")) {
        root = cJSON_Parse(msg->payload);
        if (root) {
            deal_setinfo_msg(root);
            cJSON_Delete(root);
        }
        return;
    }

    // drop "-Resp" messages send by myself.
    if (!strncmp(first_slash + 1, g_bus_obj.local.id, strlen(g_bus_obj.local.id)) && strstr(last_slash + 1, "Resp"))
        return;

    dbg_print("<INFO>: remote rcv: %s", msg->topic);
    g_bus_obj.bus_recv(msg->topic, msg->payload, msg->payloadlen);
	
    return;
}

int start_remote_client(void)
{
	printf("start_remote_client\n");
	int ret = 0;

	memset(g_busId, 0, sizeof(g_busId));
	memcpy(g_busId, cJSON_GetObjectItem(g_bus_obj.remote.bus, "id")->valuestring, strlen(cJSON_GetObjectItem(g_bus_obj.remote.bus, "id")->valuestring));		
	printf("start_remote_client g_busId = %s\n", g_busId);
	
	ret = create_bus_object(&g_bus_obj.remote, remote_connect_fn, remote_disconnect_fn, remote_message_fn);
    if (ret) 
        dbg_print("<WARN>: create remote client fail");	

    return ret;
}

void stop_remote_client(void)
{
    if (g_bus_obj.remote.timer_id) {
        timer_delete(g_bus_obj.remote.timer_id);
        g_bus_obj.remote.timer_id = 0;
    }

    if (g_bus_obj.online_dev) {
        cJSON_Delete(g_bus_obj.online_dev);
        g_bus_obj.online_dev = NULL;
    }

    if (g_bus_obj.remote.mosq) {
        mosquitto_destroy(g_bus_obj.remote.mosq);
        g_bus_obj.remote.mosq = NULL;
    }

    g_bus_obj.elect_started = 0;
    g_bus_obj.is_dc = 0;
    g_bus_obj.cur_dc = NULL;
    g_bus_obj.connected = 0;
}
