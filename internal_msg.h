#ifndef _MSG_H
#define _MSG_H

#include "./mqtt/include/mosquitto.h"

enum {
    RET_OK = 0,             //成功
    RET_SOCK = -1,          //socket错误
    RET_BIND_ERR = -2,      //端口绑定失败
    RET_EACK = -3,          //未收到ACK或者发送的数据解析错误
    RET_INVALD_PARA = -4,   //传入参数无效
    RET_ERR = -5            //通用错误
};

enum msg_source{
	SOURCE_INTERNAL = 1,
	SOURCE_LOCALBUS,
	SOURCE_CLOUDBUS
};

enum device_Function{
	DEVICE_ONLINE,		//上线
	DEVICE_OFFLINE,		//下线
	DEVICE_HEARTBEAT	//心跳
};

enum connect_status{
	CLOUD_BUS_DISCONNECTED,
	CLOUD_BUS_CONNECTED
};

struct busRouteInfo{
	int event_id;
	char *topic;
	char *msg;
	int len;
	bool is_true;
};

typedef void(*onMsgCallback)(char *topic, void *msg, int len);//总线路由回调
typedef void(*recv_callback)(char *topic, void *msg, int len);
typedef void(*cloudcallback1)(int event_id);
typedef void(*cloudcallback2)(char *topic, void *msg, int len);
typedef void(*on_messageCallback)(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg);

struct  cloudBusInfo{
	cloudcallback1 bus_event;
	cloudcallback2 bus_recv;
};

int internal_start(recv_callback internal_recv, int port);
int internal_stop(int port);
int internal_send(char *topic, void *msg, int len);


void local_bus_event(int event_id, void *data, int len);
void local_bus_recv(char *topic, void *msg, int len);
void cloud_bus_event(int event_id);

//启动平台互通
int startCloud(onMsgCallback callback);
void stopCloud();

//启动家庭互通
int startlocal(onMsgCallback callback);

//启动内部通信
int startInternal(onMsgCallback callback, int port);


//启动总线路由
int busRoute();

int cloud_bus_start(cloudcallback1 cloud_bus_event, cloudcallback2 cloud_bus_recv);
int cloud_bus_stop();
int cloud_bus_send(char *topic, void *msg, int len);

char *generatePwd(const char *key, const char *res);

void getDevInfo();


void internal_callback(char *topic, void *msg, int len);
void cloudBus_callback(char *topic, void *msg, int len);
void localBus_callback(char *topic, void *msg, int len);

/****/
int mqtt_init(const char *name, const char *pwd);
int mqtt_pub(const char *topic, void *msg, int len);
int mqtt_sub(const char *topic);
int mqtt_unsub(const char *topic);
int mqtt_uninit();
/*****/
#endif
