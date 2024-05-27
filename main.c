#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/hmac.h>
#include "internal_msg.h"
#include "./cjson/include/cjson/cJSON.h"
#include "./uuid/include/uuid/uuid.h"
#include "./source/connect_manage.h"

#include "./base64/base64.h"
#include "internal_msg.h"
#include "./source/common_log.h"

extern void localBus_callback(char *topic, void *msg, int len);

extern char g_terminalId[33];
extern bool g_deviceConfigFin;

int main(int argc, char *argv[]) 
{
	int ret = 0;
	
	start_log_parm();

	system("killall mosquitto");
	ret = startInternal(internal_callback, 39023);
	if(ret != 0)
	{
		sleep(5);
		startInternal(internal_callback, 39023);
	}

	getDevInfo();

	busRoute();

	while(1)
	{
		if(g_deviceConfigFin)
		{
			g_deviceConfigFin = false;
			break;
		}
	}
	
	startlocal(localBus_callback);

	while(1)
	{
		sleep(10);
		if(strlen(g_terminalId) == 0)
		{
			printf("g_terminalId is NULL, need getDevInfo!!!\n");
			log_info("g_terminalId is NULL, need getDevInfo!!!\n");
			getDevInfo();
		}
	}

	return 0;
}

