#ifndef __BUS_ANNOUNCE_H_
#define __BUS_ANNOUNCE_H_

#define INFO_DEV_DESCRIPTION  0 
#define LOCAL_BUS_TERMINAL_STATUS 0
#define LOCAL_BUS_STATUS 1

typedef void  (*callback1)(int);
typedef void  (*callback2)(char *, void *, int);
typedef void *(*callback3)(int);

int local_bus_send(char *topic, void *msg, int len);
int local_bus_start(callback1 local_bus_event, callback2 local_bus_recv, callback3 platform_get_info);
void *local_bus_get_info(int info_id);
#endif


