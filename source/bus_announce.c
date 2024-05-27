#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>

#include "connect_manage.h"

#define BUS_ANN_PORT 32545
#define BUFF_SIZE 1024
#define INIT_WAIT_TIME 10  // should be 35
#define SEND_INTERVAL 10
#define RCV_TIMEOUT 30  //should be 120

#define MOS_PID_FILE  "./mosquitto_local.pid" 
#define MOS_CONFIG_FILE  "./mosquitto_local.conf" 
                     
struct ann_inst {
    int bc_sockfd;                  // socket fd used to broadcast announcement packet.
    int bc_ip;                      // broadcast ip, bitwise network.
    int state;
    int type;
    timer_t timer;
    pthread_mutex_t lock;
};

extern int err_flag;
struct ann_inst g_inst;

char *get_state_string(int state)
{
    switch (state) {
        case LOCAL_BUS_CONNECTED:
            return "conneted";
        case LOCAL_BUS_CREATED:
            return "created";
        case LOCAL_BUS_DISCONNECTED:
            return "disconnected";
        case LOCAL_BUS_INIT:
            return "init";
        case LOCAL_BUS_CONNECTING:
            return "connecting";
    }
    return NULL;
}

inline int __get_current_state()
{
    return g_inst.state;
}

inline void __set_next_state(int state)
{
    g_inst.state = state;
}

void set_next_state(int next_state)
{
    printf("[%d]bus state change: [%s] --> [%s]\n", time(NULL), get_state_string(g_inst.state), get_state_string(next_state));
    __set_next_state(next_state);
    g_bus_obj.bus_event(g_inst.state);
}

static void sig_handle(int sig)
{
    if (sig == SIGUSR1) {
        printf("current state: [%s]\n", get_state_string(g_inst.state));
        if (g_bus_obj.is_dc)
            printf("current DC: myself\n");
        else 
            printf("current DC: %s\n", g_bus_obj.cur_dc ? g_bus_obj.cur_dc->terminal_id : "NULL");

        g_bus_obj.debug = !g_bus_obj.debug;
    }
    else 
        exit(0); // let the atexit function do cleanup things.
}

static inline void send_announcement(char *msg, int len)
{
    struct sockaddr_in dest_addr;

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(BUS_ANN_PORT);
    dest_addr.sin_addr.s_addr = g_inst.bc_ip;

    if (sendto(g_inst.bc_sockfd, msg, len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0)
        perror("send_announcement error");

	return;
}

static void ann_broadcast_local_bus(union sigval sig)
{
	char *msg;

	msg = cJSON_PrintUnformatted(g_bus_obj.local.bus);
	send_announcement(msg, strlen(msg));
	free(msg);
}

void ann_remove_local()
{
    int fd;
    pid_t pid;
    char buf[16] = {};

    // 1. stop timer
    if (g_inst.timer) {
        timer_delete(g_inst.timer);
        g_inst.timer = 0;
    }
        
    // 2. stop client
    stop_local_client();

    // 3. stop broker
    if ((fd = open(MOS_PID_FILE, O_RDONLY)) >= 0)
    {
        read(fd, buf, sizeof(buf) - 1);
        pid = atoi(buf);
        close(fd);

        if (pid > 1)
            kill(pid, SIGTERM);
    }
}

static int ann_connect_local(void)
{
	printf("ann_connect_local\n");
    FILE *fp = NULL;

    // in case it still exists.
    ann_remove_local();

    fp = fopen(MOS_CONFIG_FILE, "w");
    if (!fp) {
        perror("ANN: create config file failed");
        return -1;
    }

    fprintf(fp, "pid_file %s\n", MOS_PID_FILE);
    fprintf(fp, "user root\n");
    fprintf(fp, "listener 1883 %s\n", cJSON_GetObjectItem(g_bus_obj.local.bus, "ip")->valuestring);
    fclose(fp);

    system("mosquitto -d -c "MOS_CONFIG_FILE);
    sleep(1);

    // warn: zero might be a valid timer id.
    g_inst.timer = create_timer(1, SEND_INTERVAL, ann_broadcast_local_bus);

    if (access(MOS_PID_FILE, F_OK) < 0) {
        printf("ANN: local broker does not run!\n");
        return -1;
    } 
    
    if (!start_local_client()) {
        set_next_state(LOCAL_BUS_CREATED);
        return 0;
    } else 
        return -1;
}

int ann_recv_remote_msg(char *rec_buf, int *changed)
{
	printf("ann_recv_remote_msg rec_buf = %s\n", rec_buf);
    int hops_size, ret = -1;
    cJSON *bus_des = NULL;
    cJSON *j_hops;
    cJSON *j_id;
    char *json_str = NULL;

    *changed = 0;
    bus_des = cJSON_Parse(rec_buf);
    if (!bus_des) {
        printf("receive invalid packet\n");
        return -1;
    } 
#if 0
    else {
        json_str = cJSON_PrintUnformatted(bus_des);
        dbg_print("<INFO>: rcv bus: %s", json_str);
        free(json_str);
    }
#endif

    j_id = cJSON_GetObjectItem(bus_des, "id");
    if (!j_id) {
        printf("remote bus has no 'id' item\n");
        goto out;
    }

    if (strlen(j_id->valuestring) > ID_LEN) {
        printf("remote bus 'id' too long\n");
        goto out;
    }

	j_hops = cJSON_GetObjectItem(bus_des, "hops");
    if (!j_hops) {
        printf("remote bus has no 'hops' itme");
        goto out;
    }

	hops_size = cJSON_GetArraySize(j_hops);
    if (hops_size > 20) {
        dbg_print("<WARN>: hops out of range [%d]", hops_size);
        goto out;
    }

    cJSON_AddItemToArray(j_hops, cJSON_CreateString(g_bus_obj.local.id));

    ret = 0;
    if (!g_bus_obj.remote.bus || !cJSON_Compare(bus_des, g_bus_obj.remote.bus, 1)) {
        if (g_bus_obj.remote.bus)
            cJSON_Delete(g_bus_obj.remote.bus);

        g_bus_obj.remote.bus = bus_des;
        g_bus_obj.remote.id = j_id->valuestring;
        *changed = 1;
        dbg_print("<INFO>: bus changed to %s", g_bus_obj.remote.id);
    }

    if (g_inst.type == DEV_TYPE_GATEWAY || g_inst.type == DEV_TYPE_ROUTER) {
		json_str = cJSON_Print(g_bus_obj.remote.bus);
        send_announcement(json_str, strlen(json_str));
        free(json_str);
    }

out:
    if (ret || *changed == 0)
        cJSON_Delete(bus_des);
    return ret;
}

int ann_get_if_addr(char *if_name, int *ip, int type)
{
    int fd;
    struct ifreq ifr = {};
    struct sockaddr_in *sin;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    strcpy(ifr.ifr_name, if_name);

    if (ioctl(fd, type, &ifr) < 0) {
        dbg_print("ioctl get SIOCGIFADDR failed!!");
        close(fd);
        return -1;
    }

    close(fd);
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    *ip = sin->sin_addr.s_addr;
    return 0;
}

int ann_firewall_rules(void)
{
    char cmd[TP_LEN] = {};

    snprintf(cmd, TP_LEN, "iptables -D INPUT -i %s -p udp -m udp --dport %d -j DROP 2>/dev/null", g_bus_obj.br_dev, BUS_ANN_PORT);
	system(cmd);

	snprintf(cmd, TP_LEN, "ebtables -D FORWARD -p 0x800 --ip-proto udp --ip-dport %d -j DROP 2>/dev/null", BUS_ANN_PORT);
	system(cmd);

    // do not receive the packet we send on our own.
    snprintf(cmd, TP_LEN, "iptables -I INPUT -i %s -p udp -m udp --dport %d -j DROP", g_bus_obj.br_dev, BUS_ANN_PORT);
	system(cmd);

	// in case the announcement packet pass through a BRIDGE insterface.
	snprintf(cmd, TP_LEN, "ebtables -I FORWARD -p 0x800 --ip-proto udp --ip-dport %d -j DROP", BUS_ANN_PORT);
	system(cmd);
	return 0;
}	

static void gw_action_on_init(int event)
{
    switch (event) {
        case EV_RCV_MSG:
            // new remote mosq client
            if (!start_remote_client()) {
                set_next_state(LOCAL_BUS_CONNECTED);
                break;
            }
            // else pass through
        case EV_CLOCK:
            // create local broker and send announce
            ann_connect_local();
            break;
        default:
            printf("Warning: recv event=%d on init state\n", event);
            break;
    }
    return;
}

static void gw_action_on_created(int event)
{
    switch (event) {
        case EV_RCV_MSG:
            // try connecting to the remote
            if (!start_remote_client()) {
                // if success, destroy the local
                ann_remove_local();
                set_next_state(LOCAL_BUS_CONNECTED);
            }
            break;
        case EV_EXPIRED:
            break;
        case EV_CONN_ERROR:
            ann_remove_local();
            set_next_state(LOCAL_BUS_INIT);
            break;
        default:
            printf("Warning: recv event=%d on created state\n", event);
            break;
    }
    return;
}

static void gw_action_on_connected(int event)
{
    switch (event) {
        case EV_RCV_MSG:
            // stop the remote, and try connecting to the new one.
            stop_remote_client();
            if (start_remote_client()) {
                // if failed, create a local
                ann_connect_local();
            }
            break;
        case EV_CONN_ERROR:
        case EV_EXPIRED:
        case EV_LOST_HEARTBEAT:
            // stop remote and create a local
            stop_remote_client();
            ann_connect_local();
            break;
        default:
            printf("Warning: recv event=%d on connected state\n", event);
            break;
    }
    return;
}

static void dev_action_on_init(int event)
{
    switch (event) {
        case EV_CLOCK:
            set_next_state(LOCAL_BUS_DISCONNECTED);
            break;
        case EV_RCV_MSG:
            if (!start_remote_client())
                set_next_state(LOCAL_BUS_CONNECTED);
            else
                set_next_state(LOCAL_BUS_DISCONNECTED);
            break;
        default:
            printf("Warning: recv event=%d on init state\n", event);
            break;
    }
    return;
}

static void dev_action_on_connected(int event)
{
    switch (event) {
        case EV_RCV_MSG:
        case EV_LOST_HEARTBEAT:
            // stop the remote, and try connecting to the new one.
            stop_remote_client();
            if (start_remote_client())
                set_next_state(LOCAL_BUS_DISCONNECTED);

            break;
        case EV_EXPIRED:
        case EV_CONN_ERROR:
            stop_remote_client();
            set_next_state(LOCAL_BUS_DISCONNECTED);
            break;
        default:
            printf("Warning: recv event=%d on connected state\n", event);
            break;
    }
    return;
}

static void dev_action_on_disconnected(int event)
{
    switch (event) {
        case EV_EXPIRED:
            break;
        case EV_RCV_MSG:
            // take a try
            if (!start_remote_client())
                set_next_state(LOCAL_BUS_CONNECTED);

            break;
        default:
            printf("Warning: recv event=%d on disconnected state\n", event);
            break;
    }
    return;
}

void run_machine(int event)
{
	printf("run_machine event = %d\n", event);
    pthread_mutex_lock(&g_inst.lock);
	printf("run_machine g_inst.type = %d\n", g_inst.type);
	printf("run_machine g_inst.state = %d\n", g_inst.state);

    if (g_inst.type == DEV_TYPE_GATEWAY || g_inst.type == DEV_TYPE_ROUTER) {
        switch (g_inst.state) {
            case LOCAL_BUS_INIT:
                gw_action_on_init(event);
                break;
            case LOCAL_BUS_CREATED:
                gw_action_on_created(event);
                break;
            case LOCAL_BUS_CONNECTED:
                gw_action_on_connected(event);
                break;
            default:
                printf("gateway/router state wrong\n");
        }
    }
    else
    {
        switch (g_inst.state) {
            case LOCAL_BUS_INIT:
                dev_action_on_init(event);
                break;
            case LOCAL_BUS_CONNECTED:
                dev_action_on_connected(event);
                break;
            case LOCAL_BUS_DISCONNECTED:
                dev_action_on_disconnected(event);
                break;
            default:
                printf("terminal device state wrong\n");
        }
    }
    pthread_mutex_unlock(&g_inst.lock);
    return;
}

static void *bus_ann_start(void *arg)
{
	printf("bus_ann_start\n");
    int sockfd;
    int rcvsize, bus_changed = 0;
    fd_set read_set;
    struct timespec timeout  = {};
    struct sockaddr_in bind_addr;
    char rcvbuf[BUFF_SIZE] = {};

    mosquitto_lib_init();

    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("bus_ann_start socket error");
        return (void*)-1;
    }

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(BUS_ANN_PORT);
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bus_ann_start bind error");
        close(sockfd);
        return (void*)-1;
    }

    __set_next_state(LOCAL_BUS_INIT);
    timeout.tv_sec = INIT_WAIT_TIME; // set init timeout to 20 seconds

    for (;;) {
        FD_ZERO(&read_set);
        FD_SET(sockfd, &read_set);

        switch (pselect(sockfd + 1, &read_set, NULL, NULL , &timeout, NULL)) {
            case -1:
                if (errno != EINTR)
                    perror("bus_ann_start select error");
                break;
            case 0:
                if (__get_current_state() == LOCAL_BUS_INIT)
                    run_machine(EV_CLOCK);
                else if (timeout.tv_sec == RCV_TIMEOUT)
                    run_machine(EV_EXPIRED);

                break;
            default:
                rcvsize = recv(sockfd, rcvbuf, BUFF_SIZE, 0);
                if (rcvsize < 0  || rcvsize == BUFF_SIZE || ann_recv_remote_msg(rcvbuf, &bus_changed)) {
                    dbg_print("rcvsize = %d, errno = %d\n", rcvsize, errno);
                    break;
                }

                timeout.tv_sec = RCV_TIMEOUT;

                if (bus_changed || __get_current_state() != LOCAL_BUS_CONNECTED)
                    run_machine(EV_RCV_MSG);
        }

        if (err_flag) {
            err_flag = 0;
            run_machine(EV_CONN_ERROR);
        }
    }

    mosquitto_lib_cleanup();
    close(sockfd);
    return NULL;
}

static void bus_ann_finish(void)
{
    char cmd[TP_LEN] = {};

    snprintf(cmd, TP_LEN, "iptables -D INPUT -i %s -p udp -m udp --dport %d -j DROP 2>/dev/null", g_bus_obj.br_dev,  BUS_ANN_PORT);
    system(cmd);

	snprintf(cmd, TP_LEN, "ebtables -D FORWARD -p 0x800 --ip-proto udp --ip-dport %d -j DROP 2>/dev/null", BUS_ANN_PORT);
    system(cmd);

    if (g_bus_obj.local.bus)
        cJSON_Delete(g_bus_obj.local.bus);

    if (g_bus_obj.remote.bus)
        cJSON_Delete(g_bus_obj.remote.bus);

    if (g_inst.state == LOCAL_BUS_CREATED) 
        ann_remove_local();
    else if (g_inst.state == LOCAL_BUS_CONNECTED) 
        stop_remote_client();

}

static int get_pri_config(void)
{
    int fd, ind, type, ret = -1;
    char file_buf[BUFF_SIZE] = {};
    cJSON *j_pri, *j_item, *element, *j_conf;
    const char *priconf_path = getenv("PRIORITY_CONFIG_PATH");

    for (ind = 0; ind < DEV_TYPE_MAX; ind++)
        g_bus_obj.priority[ind] = DEV_TYPE_MAX;

    // default priority: speaker > router > ott
    g_bus_obj.priority[DEV_TYPE_SPEAKER] = 0;
    g_bus_obj.priority[DEV_TYPE_ROUTER] = 1;
    g_bus_obj.priority[DEV_TYPE_OTT] = 2;

    if (!priconf_path) {
        dbg_print("no PRIORITY_CONFIG_PATH env\n");
        return 0;
    }

    fd = open(priconf_path, O_RDONLY);
    if (fd < 0) {
        printf("open config file %s failed, errno=%d\n", priconf_path, errno);
        return -1;
    }
    read(fd, file_buf, sizeof(file_buf));
    close(fd);

    j_pri = cJSON_Parse(file_buf);
    if (!j_pri) {
        printf("config file is not in json format\n");
        return -1;
    }

    j_conf = cJSON_GetObjectItem(j_pri, "priority_config");
    if (!j_conf) {
        printf("config file has no item  named 'priority_config'\n");
        goto out;
    }

    j_item = cJSON_GetObjectItem(j_conf, "items");
    if (!cJSON_IsArray(j_item)) {
        printf("priority has no Array named 'items'\n");
        goto out;
    }

    ret = ind = 0;
    printf("priority from PRIORITY_CONFIG_PATH:\n");
    cJSON_ArrayForEach(element, j_item) {
        if (cJSON_IsString(element)) {
            printf("%s > ", element->valuestring);
            type = convert_type(element->valuestring);
            g_bus_obj.priority[type] = ind++;
        }
    }
    printf("\n");
out:
    cJSON_Delete(j_pri);
    return ret;
}

static int bus_obj_init(void)
{
    int ret = -1, ip = 0;
    char *file_str;
    cJSON *id_itm;
    cJSON *type_itm;
    cJSON *dev_itm;
    cJSON *root;
    cJSON *json_hops;
    cJSON *terminal_device;
    struct in_addr local_ip;

	INIT_LIST_HEAD(&g_bus_obj.dev_head);
    pthread_mutex_init(&g_bus_obj.dev_mutex, NULL);
    pthread_mutex_init(&g_inst.lock, NULL);

    // read device descrition
    file_str = g_bus_obj.platform_info(INFO_DEV_DESCRIPTION);
    if (!file_str) {
        printf("read dev config failed!\n");
        return -1;
    }

    root = cJSON_Parse(file_str);
    if (!root) {
        printf("cjson parse: bad config file\n");
        free(file_str);
        return -1;
    }

    terminal_device = cJSON_GetObjectItem(root, "device"); 
    if (!terminal_device) {
        printf("cjson parse: config file has no 'device' item\n");
        goto fail_out;
    }

    id_itm = cJSON_GetObjectItem(terminal_device, "terminalId");
    if (!id_itm) {
        printf("cjson parse: device has no 'terminalId' item\n");
        goto fail_out;
    }

    type_itm = cJSON_GetObjectItem(terminal_device, "type");
    if (!type_itm) {
        printf("cjson parse: device has no 'type' item\n");
        goto fail_out;
    }

    printf("bus init: type [%s]\n", type_itm->valuestring);

    g_inst.type = convert_type(type_itm->valuestring); 
    if (g_inst.type == DEV_TYPE_GATEWAY || g_inst.type == DEV_TYPE_ROUTER) {
        dev_itm = cJSON_GetObjectItem(terminal_device, "dev");
        if (!dev_itm) {
            printf("warning: device has no 'dev' item, using 'br0' as default LAN-BRIDGE device\n");
            strncpy(g_bus_obj.br_dev, "br0", sizeof(g_bus_obj.br_dev) - 1);
        }
        else 
            strncpy(g_bus_obj.br_dev, dev_itm->valuestring, sizeof(g_bus_obj.br_dev) - 1);

        if (ann_get_if_addr(g_bus_obj.br_dev, &ip, SIOCGIFADDR) || 
            ann_get_if_addr(g_bus_obj.br_dev, &g_inst.bc_ip, SIOCGIFBRDADDR)) {
            printf("get interface[%s] address failed\n", g_bus_obj.br_dev);
            goto fail_out;
        }

        get_pri_config();
    }

    ret = 0;
    local_ip.s_addr = ip;
    g_bus_obj.local.bus = cJSON_CreateObject();
    cJSON_AddStringToObject(g_bus_obj.local.bus, "id", id_itm->valuestring); 
    cJSON_AddStringToObject(g_bus_obj.local.bus, "type", type_itm->valuestring); 
    cJSON_AddStringToObject(g_bus_obj.local.bus, "ip", inet_ntoa(local_ip)); 
    cJSON_AddNumberToObject(g_bus_obj.local.bus, "port", 1883); 
    json_hops = cJSON_CreateArray();
    cJSON_AddItemToArray(json_hops, cJSON_CreateString(id_itm->valuestring));
    cJSON_AddItemToObject(g_bus_obj.local.bus, "hops", json_hops);

    // we use id-string very often, so here store it in @g_bus_obj.local.id.
    g_bus_obj.local.id = cJSON_GetObjectItem(g_bus_obj.local.bus, "id")->valuestring;

fail_out:
    free(file_str);
    cJSON_Delete(root);
    return ret;
}

/*
* 描述：获取info_id 对应的相关信息
* 用来从家庭控制中心获取信息
* 返回信息存放的内存地址，json字符串格式，调用者需要释放此内存。 
*/
void *local_bus_get_info(int info_id)
{
    char *ret_buf = NULL;
    cJSON *info, *j_array;
    
    switch (info_id) {
        case LOCAL_BUS_TERMINAL_STATUS:
            return g_bus_obj.is_dc ? online_device_info() : cJSON_PrintUnformatted(g_bus_obj.online_dev);
        case LOCAL_BUS_STATUS:
            info = cJSON_CreateObject();
            j_array = cJSON_CreateArray();
            cJSON_AddItemToObject(info, "status", j_array);

            if (!g_bus_obj.local.mosq && !g_bus_obj.is_dc) {
                cJSON_AddItemToArray(j_array, cJSON_CreateString("terminal"));
            } else {
                if (g_bus_obj.local.mosq)
                    cJSON_AddItemToArray(j_array, cJSON_CreateString("cc"));

                if (g_bus_obj.is_dc)
                    cJSON_AddItemToArray(j_array, cJSON_CreateString("dc"));
            }
            break;
    }

    return ret_buf;
}

/*
* callback
* CAL_BUS_CONNECTED
* 用来向家庭local bus总线发送消息
* !NOTE：发往远端local bus时，会为@topic自动添加bus_id和device_id，例如：
* 想要发送 localbus/localid/method/call，则topic赋值"method/call"即可。
* 而发往本地的local bus则需要填写完整的topic（此点有待确认）
*/
int local_bus_send(char *topic, void *msg, int len)
{
    int ret = 0;
    char new_topic[TP_LEN];

    if (!topic || !msg) {
        dbg_print("<ERR>: illegal parameter\n");
        return -1;
    }

    dbg_print("<INFO>: send topic[%s] state[%s]", topic, get_state_string(__get_current_state()));

    if (g_bus_obj.local.mosq) {
        return mosquitto_publish(g_bus_obj.local.mosq, NULL, topic, len, msg, 0, false);
    }
    else if (g_bus_obj.remote.mosq) {
        if (!g_bus_obj.remote.id) {
            printf("error: remote 'id' is NULL!\n");
            return -1;
        }

        sprintf(new_topic, "%s/%s/%s", g_bus_obj.remote.id, g_bus_obj.local.id, topic);
        ret = mosquitto_publish(g_bus_obj.remote.mosq, NULL, new_topic, len, msg, 0, false);
        return ret;
    } else {
        dbg_print("<WARN>: send failed, bus not created.");
        return -1;
    }
}

/*
* 描述：启动家庭互通
* @local_bus_event 通告local bus状态信息的回调函数
* @local_bus_recv  转发local bus上来的主题消息的回调函数
*/
int local_bus_start(callback1 local_bus_event, callback2 local_bus_recv, callback3 platform_get_info)
{
	printf("local_bus_start\n");
    pthread_t pid;

    if (!local_bus_event || !local_bus_recv) {
        printf("[%s][%d]: illegal parameter!\n", __FUNCTION__, __LINE__);
        return -1;
    }

    g_bus_obj.bus_event = local_bus_event;
    g_bus_obj.bus_recv = local_bus_recv;
    g_bus_obj.platform_info = platform_get_info;

    if (bus_obj_init()) 
        return -1;

    atexit(bus_ann_finish);
    signal(SIGINT, sig_handle);
    signal(SIGTERM, sig_handle);
    signal(SIGUSR1, sig_handle);

    if (g_inst.type == DEV_TYPE_GATEWAY || g_inst.type == DEV_TYPE_ROUTER) {

        // gateway/router. A broadcast socket is need for sending or forwarding bus announcement packet.
        g_inst.bc_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (g_inst.bc_sockfd < 0) {
            perror("local_bus_start create socket error");
            return -1;
        }

        if (setsockopt(g_inst.bc_sockfd, SOL_SOCKET, SO_BROADCAST, (int[]){1}, sizeof(int)) < 0) {
            perror("local_bus_start setsockopt error");
            close(g_inst.bc_sockfd);
            return -1;
        }

        ann_firewall_rules();
    }

    pthread_create(&pid, NULL, bus_ann_start, NULL);

    return 0;
}

