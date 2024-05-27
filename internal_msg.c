#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/hmac.h>
#include "curl/include/curl.h"

#include "internal_msg.h"
#include "./base64/base64.h"

#include "./source/connect_manage.h"
#include "./source/common_log.h"

static int ports[] = {39023, 39123};
static int ser_port = 0;
static int ser_fd = -1;

static int g_localBus = 0;
static int g_cloudBus = 0;

static int g_msgResource = 0;

static int g_isHeartBeat = 0;
static int g_isOnLine = 0;
static int g_local_connect_status = 0;

char g_terminalId[33] = {0};
static char g_type[33] = {0};
static char g_deviceName[33] = {0};

static char g_filePath[128] = {0};
static int g_fileSize = 0;
bool g_deviceConfigFin = false;
static int reTrying = 0;

const char *control_topic_list[] = {
        "method/call",
        "property/get",
        "property/set",
        "event/sub",
        "event/cancelSub",
        "setInfo"
};

struct mosquitto *mosq;
struct cloudBusInfo g_cloudBusInfo;
struct busRouteInfo g_busRouteinfo;

pthread_t heartBeat_tid;
//pthread_mutex_t g_mutex;

/*******/
//#define HOST "127.0.0.1"
#define HOST "link-br.tstar-tech.com" //#define HOST "139.217.130.202"/
//此处修改为域名
#define PORT  1883
#define PORT_SSL 8883
#define KEEP_ALIVE 60
#define MSG_MAX_SIZE  512

#define OSSADDRESS	"http://link-br.tstar-tech.com/base/api/v2/upload/log"

static char topic_msg[][20] = {
	"onlineResp",
	"event/notifyResp", 
	"heartbeatResp", 
	"property/set",
	"property/get",
	"method/call",
	"event/sub",
	"event/cancelSub",
	"internal/call",
	"internal/callResp"
};

#define BUSID "cloudBus"

extern char g_busId[48];

//#define SSL_ENABLE 
/******/

static void sig_handle(int sig)
{
	printf("sig_handle sig = %d\n", sig);
	log_info("sig_handle sig = %d\n", sig);
    exit(1);  // let the atexit function do cleanup things.
}

/**device pwd**/
void replace_special_char(const char *src, char *dest)
{
	//printf("src = %s\n", src);
	int i = 0, j = 0;
	for(i = 0, j = 0; i < strlen(src); i++, j++)
	{
		//printf("src = %c\n", src[i]);
		if(src[i] == '+')
		{
			strncpy(dest+j, "%2B", 3);
			j+=2;
		}
		else if(src[i] == ' ')
		{
			strncpy(dest+j, "%20", 3);
			j+=2;
		}
		else if(src[i] == '/')
		{
			strncpy(dest+j, "%2F", 3);
			j+=2;
		}
		else if(src[i] == '?')
		{
			strncpy(dest+j, "%3F", 3);
			j+=2;
		}
		else if(src[i] == '%')
		{
			strncpy(dest+j, "%25", 3);
			j+=2;
		}
		else if(src[i] == '#')
		{
			strncpy(dest+j, "%23", 3);
			j+=2;
		}
		else if(src[i] == '&')
		{
			strncpy(dest+j, "%26", 3);
			j+=2;
		}
		else if(src[i] == '=')
		{
			strncpy(dest+j, "%3D", 3);
			j+=2;
		}
		else
		{
			dest[j] = src[i];
		}
	}
}
//
char *generatePwd(const char *key, const char *res)
{
	if(key == NULL)
		return NULL;
	
	static uint8_t buf[256] = {0};
	memset(buf, 0, sizeof(buf));
	uint16_t len = 0;
	int ret = 0;
	ret = base64_decode(key, buf, &len);
	
	char stringForSignature[128] = {0};
	struct timeval tv;
	gettimeofday(&tv, NULL);
	sprintf(stringForSignature, "%ld\\n%s\\n%s\\n%s", tv.tv_sec+86400, "sha1", res, "2018-10-31");
	stringForSignature[strlen(stringForSignature)] = '\0';

	convert_to_utf8(stringForSignature, strlen(stringForSignature));
	
	char result[256] = {0};
	unsigned int digest_len = 0;
	HMAC(EVP_sha1(), buf, len, stringForSignature, strlen(stringForSignature), result, &digest_len);
	memset(buf, 0, sizeof(buf));
	ret = base64_encode(result, strlen(result), buf);
	
	char res_str[50] = {0};
	replace_special_char(res, res_str);
	
	char t1[120] = {0};
	replace_special_char(buf, t1);
	memset(buf, 0, sizeof(buf));
	sprintf(buf, "%s&%s%s&%s%ld&%s&%s%s", "version=2018-10-31", "res=", res_str, "et=", tv.tv_sec+86400, "method=hmacsha1", "sign=", t1);
	
	return buf;
	
}


void getDevInfo()
{
	cJSON *param = cJSON_CreateObject();
	char random[31] = {0};
	srand((unsigned)time(NULL));
	int i = 0;
	for(i = 0; i < 30; i++)
		random[i] = rand()%10 + '0';
	cJSON_AddStringToObject(param, "transactionId", random);
	cJSON_AddStringToObject(param, "infoId", "INFO_DEV_DESCRIPTION");
	
	char *out = cJSON_Print(param);
	printf("param out = %s\n", out);
	log_info("param out = %s\n", out);
	internal_send("dev/getInfo", (void *)out, strlen(out));
	cJSON_Delete(param);
	free(out);
}

#if 1

/* 回调函数，用于接收 CURL 库接收到的 HTTP 数据 */
size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t realsize = size * nmemb;
    char *content = (char *)userdata;
    memcpy(content, ptr, realsize);
	content[realsize] = '\0';
	printf("content = %s", content);
	log_info("content = %s", content);
	if (strlen(ptr) != 0 && realsize != 0)
	{
		cJSON *httpData = cJSON_Parse(content);
	    if(!httpData) 
	    {
	        printf("get httpData faild !\n");
			log_info("get httpData faild !\n");
	        return -1;
	    }

		cJSON *returnData = cJSON_GetObjectItem(httpData, "returnData");
	    if(!returnData) 
	    {
	        printf("no returnData!\n");
			log_info("no returnData!\n");
	        return -1;
	    }
	 
	    cJSON *filePath = cJSON_GetObjectItem(returnData, "filePath");
	    if(!filePath) 
	    {
	        printf("No filePath !\n");
			log_info("No filePath !\n");
	        return -1;
	    }

		cJSON *fileSize = cJSON_GetObjectItem(returnData, "fileSize");
	    if(!fileSize) 
	    {
	        printf("No fileSize !\n");
			log_info("No fileSize !\n");
	        return -1;
	    }
	    printf("filePath is %s\n",filePath->valuestring);
		printf("fileSize is %d\n",fileSize->valueint);
		log_info("filePath is %s\n",filePath->valuestring);
		log_info("fileSize is %d\n",fileSize->valueint);
		memcpy(g_filePath, filePath->valuestring, strlen(filePath->valuestring));
		g_fileSize = fileSize->valueint;
	}
    return realsize;
}

int uploadFile(const char *filePath, const char *user, const char *passwd, const char *clientID)
{
	printf("uploadFile filePath = %s, user = %s\n", filePath, user);
	log_info("uploadFile filePath = %s, user = %s\n", filePath, user);
	if(filePath == NULL || clientID == NULL || strlen(filePath) == 0 || strlen(clientID) == 0)
	{
		return -1;
	}
	
	CURL *curl;  
	int status = 0;  
	CURLM *multi_handle;  
	int still_running;  
	CURLcode res;
	struct curl_httppost *formpost=NULL;  
	struct curl_httppost *lastptr=NULL;  
	struct curl_slist *headerlist=NULL;  
	static const char buf[] = "Expect:";
	char content[4096] = {0};
	memset(content, 0, sizeof(content));
	
	curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "file",CURLFORM_FILE, filePath, CURLFORM_END);

	char clientIdHeader[128] = {0};
	char userHeader[128] = {0};
	char passwdHeader[256] = {0};

	sprintf(clientIdHeader, "clientId: %s", clientID);
	sprintf(userHeader, "userName: %s", user);
	sprintf(passwdHeader, "password: %s", passwd);
  	log_info("clientIdHeader = %s\n", clientIdHeader);
	log_info("userHeader = %s\n", userHeader);
	log_info("passwdHeader = %s\n", passwdHeader);
	curl = curl_easy_init();
  	multi_handle = curl_multi_init();   
  	headerlist = curl_slist_append(headerlist, buf);  
  	headerlist = curl_slist_append(headerlist, clientIdHeader);  
  	headerlist = curl_slist_append(headerlist, userHeader);  
  	headerlist = curl_slist_append(headerlist, passwdHeader);  
	if(curl && multi_handle) 
	{   
	    curl_easy_setopt(curl, CURLOPT_URL, OSSADDRESS);  
	    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);  
	    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);  
	    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);  
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, content);

	    curl_multi_add_handle(multi_handle, curl);
	    res = curl_multi_perform(multi_handle, &still_running);  
	 	do{  
			struct timeval timeout;  
			int rc;

			fd_set fdread;  
			fd_set fdwrite;  
			fd_set fdexcep;  
			int maxfd = -1;  

			long curl_timeo = -1;  

			FD_ZERO(&fdread);  
			FD_ZERO(&fdwrite);  
			FD_ZERO(&fdexcep);

			timeout.tv_sec = 1;  
			timeout.tv_usec = 0;  

			curl_multi_timeout(multi_handle, &curl_timeo);  
			if(curl_timeo >= 0) {  
			timeout.tv_sec = curl_timeo / 1000;  
			if(timeout.tv_sec > 1)  
			  timeout.tv_sec = 1;  
			else  
			  timeout.tv_usec = (curl_timeo % 1000) * 1000;  
			}  

			curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);  
			rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);  
			switch(rc)
			{  
				case -1:   
					break;  
				case 0:  
				default:  
					curl_multi_perform(multi_handle, &still_running);  
					break;  
			}  
	    } while(still_running);
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
		curl_multi_cleanup(multi_handle);  
	    curl_easy_cleanup(curl);   
	    curl_formfree(formpost);   
	    curl_slist_free_all (headerlist);
#if 0
		if(status == 200 && strlen(content) != 0)
		{
			cJSON *httpData = cJSON_Parse(content);
		    if(!httpData) 
		    {
		        printf("get httpData faild !\n");
				log_info("get httpData faild !\n");
		        return -1;
		    }

			cJSON *returnData = cJSON_GetObjectItem(httpData, "returnData");
		    if(!returnData) 
		    {
		        printf("no returnData!\n");
				log_info("no returnData!\n");
		        return -1;
		    }
		 
		    cJSON *filePath = cJSON_GetObjectItem(returnData, "filePath");
		    if(!filePath) 
		    {
		        printf("No filePath !\n");
				log_info("No filePath !\n");
		        return -1;
		    }

			cJSON *fileSize = cJSON_GetObjectItem(returnData, "fileSize");
		    if(!fileSize) 
		    {
		        printf("No fileSize !\n");
				log_info("No fileSize !\n");
		        return -1;
		    }
		    printf("filePath is %s\n",filePath->valuestring);
			printf("fileSize is %d\n",fileSize->valueint);
			log_info("filePath is %s\n",filePath->valuestring);
			log_info("fileSize is %d\n",fileSize->valueint);
			memcpy(g_filePath, filePath->valuestring, strlen(filePath->valuestring));
			g_fileSize = fileSize->valueint;
		}
#endif
  }  
  return status;  
}
#endif
/*************/
//内部通信
static void* msg_recv_thr(void *p)
{	
    recv_callback callback = (recv_callback)p;
    char topic[256];
    char msg[50000];
    char buf[50000];
    int tlen = 0;
    int dlen = 0;
    int rlen = 0;

    struct sockaddr_in cliaddr;
    int clen = sizeof(cliaddr);
 	
	while(1) {
        memset(buf, 0, sizeof(buf));
        memset(msg, 0, sizeof(msg));
		memset(topic, 0, sizeof(topic));
        rlen = recvfrom(ser_fd, buf, sizeof(buf), 0, (struct sockaddr*)&cliaddr, &clen);        //接收数据
		printf("recvfrom rlen = %d, buf = %s\n", rlen, buf);
		log_info("recvfrom rlen = %d, buf = %s\n", rlen, buf);
		if (rlen > 0) {
            memcpy(&tlen, buf, 4);                  //解析topic长度
            memcpy(topic, buf + 4, tlen);           //解析topic
            memcpy(&dlen, buf + 4 + tlen, 4);       //解析数据长度
            memcpy(msg, buf + 8 + tlen, dlen);      //解析数据
            printf("recvfrom tlen = %d, dlen = %d, msg = %s\n", tlen, dlen, msg);
			log_info("recvfrom tlen = %d, dlen = %d, msg = %s\n", tlen, dlen, msg);
            if (rlen == tlen + dlen + 8) 
			{      //接收数据大小等于包真正大小
				callback(topic, msg, dlen);     //回调用户传入接口
                sendto(ser_fd, "ACK", 3, 0, (struct sockaddr*)&cliaddr, sizeof(cliaddr));       //数据正确，回送ACK
            } 
			else 
			{
				printf("msg error\n");
				log_info("msg error\n");
                sendto(ser_fd, "UCK", 3, 0, (struct sockaddr*)&cliaddr, sizeof(cliaddr));       //数据不正确，回送UCK
            }
        }
	}

	pthread_exit(NULL);	
}

int internal_start(recv_callback callback, int port) {
    pthread_t tid;	
	int err;
    int reuse = 0;
    
    ser_port = port;

    ser_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(ser_fd == -1)
    {
        perror("socket"); 
        return RET_SOCK;      
    }

    if (setsockopt(ser_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
            perror("setsockopet error\n");
            return -1;
    }
 
    printf("listen port %d\n", ser_port);
	log_info("listen port %d\n", ser_port);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ser_port);
    addr.sin_addr.s_addr = INADDR_ANY;
    int ret = bind(ser_fd, (struct sockaddr*)&addr, sizeof(addr));      //socket绑定端口
    if(ret == -1)
    {
        perror("bind");
        return RET_BIND_ERR;        //ports have used
    }

	err = pthread_create(&tid, NULL, msg_recv_thr, callback);           //创建数据接收线程
	if (err) {
		fprintf(stderr, "Create pthread fail:%s\n", strerror(err));
		return RET_ERR;
	}

    return 0;
}

int internal_send(char *topic, void *msg, int len) {
    int port;
    int ret = 0;
    int rlen = 0;
    int slen = 0;
    struct timeval tv;
    int tlen = strlen(topic);
    int total = 8 + tlen + len;    //最大发送数据
    char *buf = malloc(total);     //分配发送buffer
	if (len <= 0 || topic == NULL || msg == NULL) 
        return RET_INVALD_PARA;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd == -1)
    {
        perror("socket");
        return RET_SOCK;
    }
    
    tv.tv_sec = 3;      
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {         //设置socket超时
        perror("socket option SO_RCVTIMEO not supportn");   
        return RET_SOCK;
    }

    if (ser_port == ports[0])
        port = ports[1];
    else
        port = ports[0];

    printf("send data port %d\n", port);
	log_info("send data port %d\n", port);

    struct sockaddr_in seraddr;
    seraddr.sin_family = AF_INET;
    seraddr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &seraddr.sin_addr.s_addr);

    slen = sizeof(seraddr);
 
    memset(buf, 0x0, sizeof(buf));

    memcpy(buf, &tlen, 4);              //topic 长度
    memcpy(buf + 4, topic, tlen);       //topic 数据
    memcpy(buf + 4 + tlen, &len, 4);    //消息 长度
    memcpy(buf + 8 + tlen, msg, len);   //消息 数据

    sendto(fd, buf, total, 0, (struct sockaddr*)&seraddr, sizeof(seraddr));         //发送数据

    memset(buf, 0x0, total);
    rlen = recvfrom(fd, buf, total, 0, (struct sockaddr*)&seraddr, &slen);          //等待ACK
    printf("rlen = %d, buf = %s, total = %d\n", rlen, buf, total);
	log_info("rlen = %d, buf = %s, total = %d\n", rlen, buf, total);
    if (rlen > 0 && strcmp(buf, "ACK") == 0) {
        ret = RET_OK;
    } else {
        ret = RET_EACK;             //ACK错误或者超时
    }

    free(buf);
    close(fd);

    return ret;
}

void onMsgCallbackFun(char *topic, void *msg, int len)//总线路由回调测试
{
	printf("onMsgCallbackFun topic = %s, msg = %s, len = %d\n", topic, (char *)msg, len);
	log_info("onMsgCallbackFun topic = %s, msg = %s, len = %d\n", topic, (char *)msg, len);
	char *temp = NULL;
	if(strcmp(topic, "method/callResp") == 0 && strstr(msg, "filePath") != NULL)
	{//上传日志到平台
		/******/
		char *pwd = NULL;
		pwd = generatePwd("rBYeJXTp2q4V3C2", "/products/test/devices/test");
		//初始化平台互通连接
		printf("pwd = %s\n", pwd);
		log_info("pwd = %s\n", pwd);

		cJSON *root = cJSON_Parse((const char *)msg);
	    if(!root) 
	    {
	        printf("cJSON_Parse msg failed!\n");
			log_info("cJSON_Parse msg failed!\n");
			cJSON_Delete(root);
	        return;
	    }

		cJSON *transactionId = cJSON_GetObjectItem(root, "transactionId");
	    if(!transactionId) 
	    {
	        printf("No transactionId !\n");
			log_info("No transactionId !\n");
			cJSON_Delete(root);
	        return;
	    }

		cJSON *out = cJSON_GetObjectItem(root, "out");
	    if(!out) 
	    {
	        printf("no out!\n");
			log_info("no out!\n");
			cJSON_Delete(root);
	        return;
	    }

		cJSON *filePath = cJSON_GetObjectItem(out, "filePath");
	    if(!filePath) 
	    {
	        printf("No filePath !\n");
			log_info("No filePath !\n");
			cJSON_Delete(root);
	        return;
	    }

	    printf("filePath = %s\n",filePath->valuestring);
		printf("transactionId = %s\n",transactionId->valuestring);
		log_info("filePath = %s\n",filePath->valuestring);
		log_info("transactionId = %s\n",transactionId->valuestring);

		int responseCode = uploadFile(filePath->valuestring, "test", pwd, g_terminalId);
		printf("responseCode = %d\n", responseCode);
		log_info("responseCode = %d\n", responseCode);
		cJSON *param = cJSON_CreateObject();
		cJSON_AddStringToObject(param, "transactionId", transactionId->valuestring);
		cJSON_AddStringToObject(param, "originBus", "cloud");
		if(responseCode == 200)
			cJSON_AddNumberToObject(param, "returnCode", 0);
		else
			cJSON_AddNumberToObject(param, "returnCode", -1);

		cJSON *fileInfo = cJSON_CreateObject();
		if(responseCode == 200)
			cJSON_AddStringToObject(fileInfo, "result", "Completed");
		else
			cJSON_AddStringToObject(fileInfo, "result", "Error_other");
		cJSON_AddNumberToObject(fileInfo, "fileSize", g_fileSize);
		cJSON_AddStringToObject(fileInfo, "filePath", g_filePath);
		cJSON_AddItemToObject(param, "out", fileInfo);
		temp = cJSON_Print(param);
		printf("param temp = %s\n", temp);
		log_info("param temp = %s\n", temp);
		len = strlen(temp);
		printf("lhl len = %d\n", len);
		log_info("lhl len = %d\n", len);
		cJSON_Delete(param);
		/******/
	}
	
	if(strcmp(topic, "dev/getInfoResp") == 0)
	{
		cJSON *json;
		json = cJSON_Parse(msg);
		if(!json)
		{
			printf("json parse failed\n");
			log_info("json parse failed\n");
			cJSON_Delete(json);
			return;
		}

		cJSON *devinfo = cJSON_GetObjectItem(json, "INFO_DEV_DESCRIPTION");
		if(!devinfo)
		{
			printf("devinfo parse failed\n");
			log_info("devinfo parse failed\n");
			cJSON_Delete(json);
			return;
		}

		if(cJSON_IsObject(devinfo))
		{
			char *deviceInfo;
			deviceInfo = cJSON_Print(devinfo);
			int fd = -1;
		    struct stat sb;
		    const char *filename = "./device_description";
            fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) 
			{
                log_info("open config file %s failed\n", filename);
                return;
            }
			write(fd, deviceInfo, strlen(deviceInfo));
			close(fd);
			g_deviceConfigFin = true;
			free(deviceInfo);
		}

		cJSON *device = cJSON_GetObjectItem(devinfo, "device");
		if(!device)
		{
			printf("device parse failed\n");
			log_info("device parse failed\n");
			cJSON_Delete(json);
			return;
		}

		cJSON *tid = cJSON_GetObjectItem(device, "terminalId");
		if(!tid)
		{
			printf("terminalId parse failed\n");
			log_info("terminalId parse failed\n");
			cJSON_Delete(json);
			return;
		}
		memset(g_terminalId, 0, sizeof(g_terminalId));
		memcpy(g_terminalId, tid->valuestring, strlen(tid->valuestring));

		cJSON *deviceName = cJSON_GetObjectItem(device, "deviceName");
		if(!deviceName)
		{
			printf("deviceName parse failed\n");
			log_info("deviceName parse failed\n");
			cJSON_Delete(json);
			return;
		}
		memset(g_deviceName, 0, sizeof(g_deviceName));
		memcpy(g_deviceName, deviceName->valuestring, strlen(deviceName->valuestring));
		
		cJSON *type = cJSON_GetObjectItem(device, "type");
		if(!type)
		{
			printf("type parse failed\n");
			log_info("type parse failed\n");
			cJSON_Delete(json);
			return;
		}
		memset(g_type, 0, sizeof(g_type));
		memcpy(g_type, type->valuestring, strlen(type->valuestring));
		printf("g_terminalId = %s\n", g_terminalId);
		log_info("g_terminalId = %s\n", g_terminalId);
		if(json)
			cJSON_Delete(json);
		return;
	}

	if(strstr(topic, "device/online") != NULL && strstr(msg, "topology") != NULL && strstr(msg, "deviceDescription") != NULL)
	{
		printf("parse device/online\n");
		log_info("parse device/online\n");
		int i = 0;
		char buf[128] = {0};
		cJSON *json;
		json = cJSON_Parse(msg);
		if(!json)
		{
			log_info("json parse failed\n");
			cJSON_Delete(json);
			return;
		}
		cJSON *busId = cJSON_GetObjectItem(json, "busId");
		if(!busId)
		{
			log_info("busId parse failed\n");
			cJSON_Delete(json);
			return;
		}
		printf("online busId = %s\n", busId->valuestring);
		log_info("online busId = %s\n", busId->valuestring);
		
		cJSON *deviceDescription = cJSON_GetObjectItem(json, "deviceDescription");
		if(!deviceDescription)
		{
			log_info("deviceDescription parse failed\n");
			cJSON_Delete(json);
			return;
		}
		cJSON *tid = cJSON_GetObjectItem(deviceDescription, "terminalId");
		if(!tid)
		{
			log_info("tid parse failed\n");
			cJSON_Delete(json);
			return;
		}
		
		if(strcmp(g_terminalId, tid->valuestring) != 0)
		{
			for(i = 0; i < sizeof(topic_msg)/sizeof(topic_msg[0]); i++)
			{
				if(strlen(busId->valuestring) != 0 && strlen(tid->valuestring) != 0)
				{
					memset(buf, 0, sizeof(buf));
					sprintf(buf, "%s/%s/%s", busId->valuestring, tid->valuestring, topic_msg[i]);
					int ret = mqtt_sub(buf);
					printf("online mqtt_sub---%s %d\n", buf, ret);
					log_info("online mqtt_sub---%s %d\n", buf, ret);
				}
			}
		}
		/***********************************************/
	}

	if(strstr(topic, "offline") != NULL && strstr(msg, "originBus") != NULL && strstr(msg, "local") != NULL)
	{//[busId]/[terminalId]/offline
		printf("parse offline\n");
		log_info("parse offline\n");
		int i = 0;
		char buf[128] = {0};
		char str[128] = {0};
		int index = strstr(topic, "offline") - topic;
		memcpy(str, topic, index - 1);
		printf("str  = %s\n", str);
		
		for(i = 0; i < sizeof(topic_msg)/sizeof(topic_msg[0]); i++)
		{
			if(strlen(str) != 0)
			{
				memset(buf, 0, sizeof(buf));
				sprintf(buf, "%s/%s", str, topic_msg[i]);
				int ret = mqtt_unsub(buf);
				printf("offline mqtt_sub---%s %d\n", buf, ret);
				log_info("offline mqtt_sub---%s %d\n", buf, ret);
			}
		}
		/***********************************************/
	}

	g_busRouteinfo.topic = (char *)malloc(strlen(topic)+1);
	if(g_busRouteinfo.topic == NULL)
	{
		log_info("topic malloc error\n");
		return;
	}
	g_busRouteinfo.msg = (char *)malloc(len+1);
	if(g_busRouteinfo.msg == NULL)
	{
		log_info("msg malloc error\n");
		free(g_busRouteinfo.topic);
		g_busRouteinfo.topic = NULL;
		return;
	}

	memset(g_busRouteinfo.topic, 0, strlen(topic)+1);
	memset(g_busRouteinfo.msg, 0, len+1);
	memcpy(g_busRouteinfo.topic, topic, strlen(topic));
	if(strcmp(topic, "method/callResp") == 0 && strstr(msg, "filePath") != NULL)
		memcpy(g_busRouteinfo.msg, temp, len);
	else
		memcpy(g_busRouteinfo.msg, (char *)msg, len);
	g_busRouteinfo.len = len;
	g_busRouteinfo.is_true = true;
	if(temp)
		free(temp);
}


void internal_callback(char *topic, void *msg, int len)
{
	g_msgResource = 1;//内部通信
	onMsgCallbackFun(topic, msg, len);
}

void cloudBus_callback(char *topic, void *msg, int len)
{
	g_msgResource = 2;//平台互通
	onMsgCallbackFun(topic, msg, len);
}

void localBus_callback(char *topic, void *msg, int len)
{
	g_msgResource = 3;//家庭互通
	onMsgCallbackFun(topic, msg, len);
}

void cloud_bus_event(int event_id)
{
	log_info("cloud_bus_event event_id = %d\n", event_id);
}

//设备周期上报
void notifyDeviceInfo(enum device_Function dev_fun)
{
	char random[31] = {0};
	srand((unsigned)time(NULL));
	int i = 0;
	for(i = 0; i < 30; i++)
		random[i] = rand()%10 + '0';
	if(dev_fun == DEVICE_ONLINE)//上线
	{
		cJSON *param = cJSON_CreateObject();
		cJSON_AddStringToObject(param, "transactionId", random);
		if(g_local_connect_status != LOCAL_BUS_CONNECTED)
			cJSON_AddStringToObject(param, "originBus", "cloud");
		else
			cJSON_AddStringToObject(param, "originBus", "local");
		cJSON_AddStringToObject(param, "busId", g_busId);

		//cJSON_AddStringToObject(param, "topology", " ");
		cJSON* infoArray = cJSON_CreateArray();
		cJSON_AddItemToArray(infoArray, cJSON_CreateString(g_terminalId));
    	cJSON_AddItemToObject(param, "topology", infoArray);
		
		cJSON *deviceInfo = cJSON_CreateObject();
		cJSON_AddStringToObject(deviceInfo, "deviceName", g_deviceName);
		cJSON_AddStringToObject(deviceInfo, "type", g_type);
		cJSON_AddStringToObject(deviceInfo, "terminalId", g_terminalId);
		cJSON_AddStringToObject(deviceInfo, "service", " ");
		cJSON_AddItemToObject(param, "deviceDescription", deviceInfo);

		char *out = cJSON_Print(param);
		printf("param out = %s\n", out);
		log_info("param out = %s\n", out);

		char topic[128] = {0};
		memset(topic, 0, sizeof(topic));
		sprintf(topic, "%s/device/online", g_busId);
		
		int ret = mqtt_pub(topic, (void *)out, strlen(out));
		printf("mqtt_pub online ret = %d\n", ret);
		log_info("mqtt_pub online ret = %d\n", ret);
		cJSON_Delete(param);
		free(out);
	}
	else if(dev_fun == DEVICE_OFFLINE)//下线
	{
		cJSON *param = cJSON_CreateObject();
		cJSON_AddStringToObject(param, "transactionId", random);
		cJSON_AddStringToObject(param, "originBus", "cloud");

		char *out = cJSON_Print(param);
		printf("param out = %s\n", out);
		log_info("param out = %s\n", out);
		char buf[128] = {0};
		sprintf(buf, "%s/%s/device/offline",  g_busId, g_terminalId);
		printf("buf = %s\n", buf);
		log_info("buf = %s\n", buf);
		int ret = mqtt_pub(buf, (void *)out, strlen(out));
		//printf("mqtt_pub online ret = %d\n", ret);
		cJSON_Delete(param);
		free(out);
	}
	else if(dev_fun == DEVICE_HEARTBEAT)//心跳
	{
		//printf("heartBeat\n");
		cJSON *heartBeat = cJSON_CreateObject();
		cJSON_AddStringToObject(heartBeat, "transactionId", random);
		cJSON_AddStringToObject(heartBeat, "terminalId", g_terminalId);
#if 0
		char *buff, *status;
		buff = local_bus_get_info(0);
		if(strlen(buff) != 0)
		{
			char *first_slash = strchr(buff, '[');
			char *last_slash = strrchr(buff, ']');
			status = (char *)malloc(last_slash - first_slash + 1);
			if(status == NULL)
			{
				printf("status malloc failed\n");
				return;
			}
			strncpy(status, first_slash + 1, last_slash - first_slash - 1);
		}
		
		cJSON* statusArray = cJSON_CreateArray();
        cJSON* statusObj = cJSON_Parse(status);
		cJSON_AddItemToArray(statusArray, statusObj);
		cJSON_AddItemToObject(heartBeat, "info", statusArray);
		free(status);
		free(buff);
#else
		cJSON* infoArray = cJSON_CreateArray();
		cJSON* statusObj1 = cJSON_CreateObject();
		cJSON_AddStringToObject(statusObj1, "id", g_terminalId);
		cJSON_AddStringToObject(statusObj1, "status", "online");
		cJSON_AddItemToArray(infoArray, statusObj1);
		cJSON_AddItemToObject(heartBeat, "info", infoArray);

#endif		
		char *out = cJSON_Print(heartBeat);
		printf("heartBeat = %s\n", out);
		log_info("heartBeat = %s\n", out);
		char buf[128] = {0};
		sprintf(buf, "%s/%s/heartbeat",  g_busId, g_terminalId);
		int ret = mqtt_pub(buf, (void *)out, strlen(out));
		cJSON_Delete(heartBeat);
		free(out);
		
	}
	else
	{
		log_info("param error\n");
	}
}

void on_connect(struct mosquitto *mosq, void *userdata, int rc)
{
	log_info("rc = %d\n", rc);
    if(rc == 0) 
	{
        printf("Connected to broker.\n");
		log_info("Connected to broker.\n");
		//平台互通连接成功后发送上线主题，同时订阅上线应答，应答完成后可以取消订阅
		char buf[128] = {0};
		int i = 0;
		for(i = 0; i < sizeof(topic_msg)/sizeof(topic_msg[0]); i++)
		{
			if(strlen(g_terminalId) != 0)
			{
				memset(buf, 0, sizeof(buf));
				sprintf(buf, "%s/%s/%s", g_busId, g_terminalId, topic_msg[i]);
				int ret = mqtt_sub(buf);
				log_info("mqtt_sub %s = %d\n", buf, ret);
			}
		}
		notifyDeviceInfo(DEVICE_ONLINE);
    }
	/*else
	{
        printf("Connection failed.\n");
		log_info("Connection failed.\n");
    }*/
}


void my_disconnect_callback(struct mosquitto *mosq, void *obj, int result)
{
	//int ret = mosquitto_reconnect_async(mosq);
	printf("disconnect result = %d, result = %d\n", result, result);
	log_info("disconnect result = %d, result = %d\n", result, result);

	sleep(10);//10S后尝试重连
	char *pwd = NULL;
	pwd = generatePwd("rBYeJXTp2q4V3C2", "/products/test/devices/test");
	//初始化平台互通连接
	int ret = mqtt_init("test", pwd);
	log_info("mqtt_init ret = %d\n", ret);
	if(ret < 0)
	{
		log_info("mqtt_init fail\n");
		return;
	}
}

void omMessage_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg)
{
	printf("omMessage_callback obj = %s, topic = %s, msg = %s\n", (char *)obj, msg->topic, (char *)msg->payload);
	log_info("omMessage_callback obj = %s, topic = %s, msg = %s\n", (char *)obj, msg->topic, (char *)msg->payload);
	char buf[128] = {0};
	sprintf(buf, "%s/%s/onlineResp", g_busId, g_terminalId);
	if(strncmp(buf, msg->topic, strlen(buf)) == 0)//上线应答完成后取消订阅
	{
		g_isOnLine = 1;//收到上线回复
		g_isHeartBeat = 1;
		memset(buf, 0, sizeof(buf));
		sprintf(buf, "%s/%s/onlineResp", g_busId, g_terminalId);
		int ret = mqtt_unsub(buf);
		log_info("mqtt_unsub ret = %d\n", ret);
		return;
	}

	char 	topic[TP_LEN]       = {};
    char    *first_slash, *last_slash;

    first_slash = strchr(msg->topic, '/');
    last_slash = strrchr(msg->topic, '/');
	
	if (!strncmp(last_slash + 1, "heartbeatResp", 13)) //收到心跳消息
	{
		return;
	}

	if(g_cloudBusInfo.bus_recv)
    	g_cloudBusInfo.bus_recv(msg->topic, msg->payload, msg->payloadlen);
	else
		log_info("g_cloudBusInfo.bus_recv false\n");
}

static void *cloud_bus_heartBeat(void *p)
{
	printf("cloud_bus_heartBeat\n");
	log_info("cloud_bus_heartBeat\n");
	time_t elapsed_time = 1;
	
	while(g_cloudBus)
	{
		if(g_isHeartBeat)//连续3次没有收到心跳回复消息，按总线异常处理（重连）
		{
			if(elapsed_time % (12 * 60 *60) == 0)
			{
				notifyDeviceInfo(DEVICE_HEARTBEAT);
			}
		}
		
		if(g_isOnLine == 0)
		{//未收到上线回复,每隔30S发送上线主题消息
			if(elapsed_time % 30 == 0)
			{	
				log_info("start notifyDeviceInfo\n");
				notifyDeviceInfo(DEVICE_ONLINE);
			}
		}
	
		usleep(1000000);
		elapsed_time++;
		//printf("elapsed_time = %ld\n", elapsed_time);
	}
	log_info("cloud_bus_heartBeat thread exit\n");
	pthread_exit(NULL);
}

//启动平台互通
int startCloud(onMsgCallback callback)
{
	printf("startCloud\n");
	log_info("startCloud\n");
	int ret = 0;
	signal(SIGINT, sig_handle);
    signal(SIGTERM, sig_handle);

	if(g_local_connect_status != LOCAL_BUS_CONNECTED)
	{//启动平台互通
		memset(g_busId, 0, sizeof(g_busId));
		memcpy(g_busId, BUSID, strlen(BUSID));
	}
	
	log_info("g_busid 1 = %s\n", g_busId);

	if(strlen(g_terminalId) == 0)
	{
		printf("terminalId get failed!!!!!!!!!\n");
		log_info("terminalId get failed!!!!!!!!!\n");
		return -1;
	}

	char *pwd = NULL;
	pwd = generatePwd("rBYeJXTp2q4V3C2", "/products/test/devices/test");
	//初始化平台互通连接
	ret = mqtt_init("test", pwd);
	log_info("mqtt_init ret = %d\n", ret);
	if(ret < 0)
	{
		log_info("mqtt_init fail\n");
		return -1;
	}
	
	g_cloudBus = 1;

	ret = cloud_bus_start(cloud_bus_event, callback);
	log_info("cloud_bus_start ret = %d\n", ret);
	//启动成功后通过事件回调将启动状态通知出去
	if(g_cloudBusInfo.bus_event)
		g_cloudBusInfo.bus_event(CLOUD_BUS_CONNECTED);

	//平台互通上线主题发送完成后，每隔12小时向平台发送心跳信息，携带自身与家庭其他终端在线状态
	pthread_create(&heartBeat_tid, NULL, cloud_bus_heartBeat, NULL);

	atexit(stopCloud);
	return 0;
}

//关闭平台互通
void stopCloud()
{
	printf("stopCloud\n");
	log_info("stopCloud\n");
	int ret = 0;

	char buf[128] = {0};
	int i = 0;
	for(i = 0; i < sizeof(topic_msg)/sizeof(topic_msg[0]); i++)
	{
		if(strlen(g_terminalId) != 0)
		{
			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%s/%s/%s", g_busId, g_terminalId, topic_msg[i]);
			ret = mqtt_unsub(buf);
			log_info("mqtt_unsub %s = %d\n", buf, ret);
		}
	}
	ret = mqtt_uninit();
	log_info("mqtt_uninit ret = %d\n", ret);
	if(ret < 0)
	{
		log_info("mqtt_uninit fail\n");
		return;
	}
	g_cloudBus = 0;
	if(g_cloudBusInfo.bus_event)
		g_cloudBusInfo.bus_event(CLOUD_BUS_DISCONNECTED);
	ret = cloud_bus_stop();
	log_info("cloud_bus_stop ret = %d\n", ret);
	g_isHeartBeat = 0;
	g_isOnLine = 0;
	//g_local_connect_status = 0;
	printf("stop cloud finish\n");
	log_info("stop cloud finish\n");
	return;
}

//监听平台互通
int cloud_bus_start(cloudcallback1 cloud_bus_event, cloudcallback2 cloud_bus_recv)
{
	printf("cloud_bus_start\n");
	log_info("cloud_bus_start\n");
	g_cloudBusInfo.bus_event = cloud_bus_event;
	g_cloudBusInfo.bus_recv = cloud_bus_recv;

	return 0;
}

int cloud_bus_stop()
{
	printf("cloud_bus_stop\n");
	log_info("cloud_bus_stop\n");
	g_cloudBusInfo.bus_event = NULL;
	g_cloudBusInfo.bus_recv = NULL;
	return 0;
}

int cloud_bus_send(char *topic, void *msg, int len)
{
	int ret = mqtt_pub(topic, msg, len);
	return ret;
}

void local_bus_callback1(int event_id)
{
    printf("local_bus_callback1 event: %d\n", event_id);
	log_info("local_bus_callback1 event: %d\n", event_id);
	int ret= 0;
	g_local_connect_status = event_id;

	if(g_local_connect_status != LOCAL_BUS_CONNECTED)
	{	
		if(g_cloudBus == 0)
		{
			ret = startCloud(cloudBus_callback);//启动平台互通
			if(ret == 0)
				log_info("cloud_bus_start succ\n");
			else
				log_info("cloud_bus_start failed\n");
		}
	}
	else
	{
		if(g_cloudBus == 1)
		{
			stopCloud();//关闭平台互通
			log_info("cloud_bus_stop succ\n");;
		}
	}
}

void *local_bus_callback3(int info_id)
{
    int fd = -1, len = 0;
    char *file_buf;
    struct stat sb;
    const char *filename = "./device_description";

    switch (info_id)
    {
        case INFO_DEV_DESCRIPTION:
            if (stat(filename, &sb) == -1) {
                log_info("can not stat config file %s\n", filename);
                return NULL;
            }

            fd = open(filename, O_RDONLY);
            if (fd < 0) {
                log_info("open config file %s failed\n", filename);
                return NULL;
            }

            file_buf = malloc(sb.st_size + 1);
            if (!file_buf) {
                log_info("malloc file buffer failed\n");
                close(fd);
                return NULL;
            }

            file_buf[sb.st_size] = 0;

            do {
                len += read(fd, file_buf + len, sb.st_size - len);
            } while (len < sb.st_size && errno == EINTR);

            close(fd);
			printf("file_buf = %s\n", file_buf);
            return file_buf;
        default:
            break;
    }
    return NULL;
}

static void *local_fun(void *p)
{
#if 0
	log_info("local_fun\n");
	int ret = 0;

	while(1) 
	{
		sleep(5);
		if(g_local_connect_status != LOCAL_BUS_CONNECTED)
		{	
			if(g_cloudBus == 0)
			{
				ret = startCloud(cloudBus_callback);//启动平台互通
				if(ret == 0)
					log_info("cloud_bus_start succ\n");
				else
					log_info("cloud_bus_start failed\n");
			}
		}
		else
		{
			if(g_cloudBus == 1)
			{
				stopCloud();//关闭平台互通
				log_info("cloud_bus_stop succ\n");
			}
		}
	}
	pthread_exit(NULL);
#endif
	return NULL;
}


//启动家庭互通
int startlocal(onMsgCallback callback)
{
	printf("startlocal\n");
	log_info("startlocal\n");
	int ret = 0;
	ret = local_bus_start(local_bus_callback1, callback, local_bus_callback3);
	log_info("local_bus_start ret = %d\n", ret);
	if(ret != 0)
	{
		log_info("local_bus_start failed\n");
		return -1;
	}
	g_localBus = 1;

	//pthread_t pid;
	//pthread_create(&pid, NULL, local_fun, NULL);
	
    return 0;
}


//启动内部通信
int startInternal(onMsgCallback callback, int port)
{
	printf("startInternal\n");
	log_info("startInternal\n");
	int ret = 0;
	ret = internal_start(callback, port);
	log_info("internal_start ret = %d\n", ret);
	if(ret != 0)
	{
		log_info("internal_start failed\n");
		return -1;
	}	
    return 0;
}

int process_send_internal(const char *topic, const void *msg, size_t len) 
{
    char buf[128] = {0};
    if (strstr(topic, "/") != NULL) 
		{
        char *temp = NULL;
        char *str = NULL;
        str = strstr(topic, "/");
        printf("str =  %s\n", str);
        log_info("str =  %s\n", str);
        if (strstr(str + 1, "/") != NULL) {
            temp = strstr(str + 1, "/");
            printf("temp =  %s\n", temp);
            log_info("temp =  %s\n", temp);
            memcpy(buf, temp + 1, strlen(temp) - 1);
            printf("buf = %s\n", buf);
            log_info("buf = %s\n", buf);
        }
    }
    int ret = internal_send(buf, (void *)msg, len);
	return ret;
}

static void *bus_route_fun(void *p)
{
	log_info("bus_route_fun\n");
	int ret = 0;
	int failCount = 0;
	while(1) 
	{	
		usleep(200000);
		//pthread_mutex_lock(&g_mutex);
		if(g_busRouteinfo.is_true)
		{
		    char terminalId[50] = {0};
			char *first_slash = strchr(g_busRouteinfo.topic, '/');
			printf("first_slash = %s\n", first_slash);
			if(first_slash)
			{
				char *temp = strchr(first_slash + 1, '/');
				printf("temp = %s\n", temp);
				if(temp)
				{
					char *second_flag = strstr(temp, "/");
					printf("second_flag = %s\n", second_flag);
					if(second_flag && first_slash)
					{
						memcpy(terminalId, first_slash + 1, second_flag - first_slash - 1);
					}
				}
			}
			printf("terminalId = %s\n", terminalId);  
			printf("g_msgResource = %d\n", g_msgResource);
			log_info("terminalId = %s\n", terminalId);  
			log_info("g_msgResource = %d\n", g_msgResource);
			if(g_msgResource == 1)/*内部通信消息*/
			{
				if(g_cloudBus)//平台互通和家庭互通同时存在，上行数据通过平台互通直接出去
				{
					char buf[256] = {0};
					char tmp[256] = {0};
					memset(buf, 0, sizeof(buf));
					memset(tmp, 0, sizeof(tmp));
					sprintf(buf, "%s/%s/%s", g_busId, g_terminalId, g_busRouteinfo.topic);
					printf("buf = %s\n", buf);
					log_info("buf = %s\n", buf);
					sprintf(tmp, "%s/%s/%s%s", g_busId, g_terminalId, g_busRouteinfo.topic, "Resp");
					printf("tmp = %s\n", tmp);
					log_info("tmp = %s\n", tmp);
					ret = mqtt_sub(tmp);
					ret = mqtt_pub(buf, (void *)g_busRouteinfo.msg, g_busRouteinfo.len);
					printf("send cloudbus 1 ret = %d\n", ret);
					log_info("send cloudbus 1 ret = %d\n", ret);
					if(ret != 0)
					failCount++;
				}
				else if(g_localBus == 1 && g_cloudBus == 0)//家庭互通存在，上行消息通过存在的连接出去
				{
					ret = local_bus_send(g_busRouteinfo.topic, (void *)g_busRouteinfo.msg, g_busRouteinfo.len);
					printf("send localbus 2 ret = %d\n", ret);
					log_info("send localbus 2 ret = %d\n", ret);
				}
				else//同时不存在，总线路由直接回复结果
				{
					//新增修改--同时不存在，总线路由直接回复上行不通
					cJSON *root = cJSON_Parse((const char *)g_busRouteinfo.msg);
				    if (root == NULL) {
				        printf("Error parsing msg JSON\n");
				        return;
				    }

					// 修改returnCode字段的值为-1
					cJSON *returnCode = cJSON_GetObjectItem(root, "returnCode");
					if (returnCode != NULL) 
					{
					    cJSON_DeleteItemFromObject(root, "returnCode");
					    cJSON_AddNumberToObject(root, "returnCode", -1);
					}
					
				    cJSON_AddStringToObject(root, "desc", "operation not working");
				    char *new_msg = cJSON_PrintUnformatted(root);
				    size_t new_len = strlen(new_msg);
				    printf("New JSON message: %s\n", new_msg);
					ret = internal_send(g_busRouteinfo.topic, (void *)new_msg, new_len);
					printf("send internal 3 g_busRouteinfo.topic = %s\n", g_busRouteinfo.topic);
					log_info("send internal 3 g_busRouteinfo.topic = %s\n", g_busRouteinfo.topic);
					cJSON_free(new_msg);
				    cJSON_Delete(root);
				}
			}
			else if(g_msgResource == 2)/*平台互通消息*/
			{//分析消息是自身（terminalID）设备还是下挂子设备，下挂设备则发松消息给家庭互通，自身消息则直接发送消息给内部通信
				if(strcmp(terminalId, g_terminalId) == 0)/*自身设备*///发给内部通信
				{
					ret = process_send_internal(g_busRouteinfo.topic, (void *)g_busRouteinfo.msg, g_busRouteinfo.len);
					printf("send internal 4 ret = %d\n", ret);
					log_info("send internal 4 ret = %d\n", ret);
				}
				else//发给家庭互通
				{					
					local_bus_send(g_busRouteinfo.topic, (void *)g_busRouteinfo.msg, g_busRouteinfo.len);
					printf("send localbus 5 ret = %d\n", ret);
					log_info("send localbus 5 ret = %d\n", ret);
				}
			}
			else if(g_msgResource == 3)/*家庭互通消息*/
			{//分析消息是否自身，如果是自身消息，总线路由直接将消息发送内部通信；非自身则将消息发送平台互通
			/*二期需求:
			1,平台互通不存在，消息丢给内部通信；
			2,平台互通存在：
				1）msg中originBus为cloud将消息发送至平台互通；
				2）msg中originBus为local，需要判断消息类型，为信息上报类消息发送至平台互通，控制类消息抓发至内部通信*/
				if(g_cloudBus)//平台互通存在
				{
					cJSON *root = cJSON_Parse(g_busRouteinfo.msg);
					if(!root) 
					{
						log_info("cJSON_Parse msg failed!\n");
						return;
					}
					
					cJSON *originBus = cJSON_GetObjectItem(root, "originBus");
					if(!originBus)
					{
						printf("originBus parse failed\n");
						log_info("originBus parse failed\n");
						return;
					}

					if (strcmp(originBus->valuestring, "cloud") == 0)//发给平台互通
					{
						char sub_topic[256] = {0};
						memset(sub_topic, 0, sizeof(sub_topic));
						
						if(strstr(g_busRouteinfo.topic, "online") != NULL && strstr(g_busRouteinfo.msg, "deviceDescription") != NULL)
						{
							log_info("get online msg\n");
							
							cJSON *deviceDescription = cJSON_GetObjectItem(root, "deviceDescription");
							if(!deviceDescription) 
							{
								log_info("No deviceDescription !\n");
								return;
							}

							cJSON *terminalIdStr = cJSON_GetObjectItem(deviceDescription, "terminalId");
							if(!terminalIdStr) 
							{
								log_info("no terminalIdStr!\n");
								return;
							}

							printf("terminalIdStr = %s\n", terminalIdStr->valuestring);
							log_info("terminalIdStr = %s\n", terminalIdStr->valuestring);
							char busid[48] = {0};
							int index = 0;
							char *str = NULL;
							str = strstr(g_busRouteinfo.topic, "/");
							if(str != NULL)
								index = str - g_busRouteinfo.topic;
							log_info("index = %d\n", index);
							memset(busid, 0, sizeof(busid));
							strncpy(busid, g_busRouteinfo.topic, index);
							printf("busid = %s\n", busid);
							log_info("busid = %s\n", busid);
							sprintf(sub_topic, "%s/%s/%s", busid, terminalIdStr->valuestring, "onlineResp");
						}
						else
							sprintf(sub_topic, "%s%s", g_busRouteinfo.topic, "Resp");
						printf("sub_topic = %s\n", sub_topic);
						log_info("sub_topic = %s\n", sub_topic);
						ret = mqtt_sub(sub_topic);
						ret = mqtt_pub(g_busRouteinfo.topic, (void *)g_busRouteinfo.msg, g_busRouteinfo.len);
						printf("send cloudbus 6 ret = %d\n", ret);
						log_info("send cloudbus 6 ret = %d\n", ret);
						if(ret != 0)
							failCount++;
					}
					else//需要判断消息类型，为信息上报类消息发送至平台互通，控制类消息抓发至内部通信
					{
						int i, found = 0;
					    for (i = 0; i < sizeof(control_topic_list) / sizeof(control_topic_list[0]); i++) 
						{
					        if (strcmp(g_busRouteinfo.topic, control_topic_list[i]) == 0) 
							{
					            found = 1;
					            break;
					        }
					    }
						if (found) {
							ret = process_send_internal(g_busRouteinfo.topic, (void *)g_busRouteinfo.msg, g_busRouteinfo.len);	
							printf("send internal 7 ret = %d\n", ret);
							log_info("send internal 7 ret = %d\n", ret);
						} 
						else 
						{
							char sub_topic[256] = {0};
							memset(sub_topic, 0, sizeof(sub_topic));
					        sprintf(sub_topic, "%s%s", g_busRouteinfo.topic, "Resp");
							printf("sub_topic = %s\n", sub_topic);
							log_info("sub_topic = %s\n", sub_topic);
							ret = mqtt_sub(sub_topic);
							ret = mqtt_pub(g_busRouteinfo.topic, (void *)g_busRouteinfo.msg, g_busRouteinfo.len);
							printf("send cloudbus 8 ret = %d\n", ret);
							log_info("send cloudbus 8 ret = %d\n", ret);
							if(ret != 0)
								failCount++;
					    }
					}
				}
				else//不存在
				{
					ret = process_send_internal(g_busRouteinfo.topic, (void *)g_busRouteinfo.msg, g_busRouteinfo.len);
					printf("send internal 9 ret = %d\n", ret);
					log_info("send internal 9 ret = %d\n", ret);
				}

			}
			else{}
		
			if (g_busRouteinfo.topic) 
			{
	            free(g_busRouteinfo.topic);
	            g_busRouteinfo.topic = NULL;
	        }
	        if (g_busRouteinfo.msg) 
			{
	            free(g_busRouteinfo.msg);
	            g_busRouteinfo.msg = NULL;
	        }
			g_busRouteinfo.event_id = 0;
			g_busRouteinfo.is_true = false;
			g_busRouteinfo.len = 0;
			
			g_msgResource = 0;
			
			log_info("failCount = %d\n", failCount);
			if(failCount == 10)
			{
				if(reTrying == 0)
				{
					mqtt_uninit();
					char *pwd = NULL;
					pwd = generatePwd("rBYeJXTp2q4V3C2", "/products/test/devices/test");
					//初始化平台互通连接
					int ret = mqtt_init("test", pwd);
					log_info("mqtt_init retry ret = %d\n", ret);
					failCount = 0;
				}
			}
		}
		//pthread_mutex_unlock(&g_mutex);
	}

	pthread_exit(NULL);
	return NULL;
}

//总线路由
int busRoute()
{
	printf("busRoute\n");
	log_info("busRoute\n");
	memset(&g_busRouteinfo, 0, sizeof(g_busRouteinfo));
	pthread_t tid;
	//pthread_mutex_init(&g_mutex, NULL);
	pthread_create(&tid, NULL, bus_route_fun, NULL);

	return 0;
}


/***********mqtt******************/
int mqtt_init(const char *name, const char *pwd)
{
	log_info("mqtt init\n");
	int	ret;
	int port =  0;
	if(name == NULL || pwd == NULL || strlen(name) == 0 || strlen(pwd) == 0)
		return -1;

	/* MQTT 初始化 */
	ret = mosquitto_lib_init();
	if(ret)
	{
		log_info("mqtt_init:Init lib error!\n");
		goto cleanup;
	}

	/* 创建新的客户端 */
	//mosq = mosquitto_new(NULL, true, NULL);
	if(strlen(g_terminalId) != 0)
		mosq = mosquitto_new(g_terminalId, true, NULL);
	else
		mosq = mosquitto_new(NULL, true, NULL);
	log_info("mosquitto_new mosq = %x\n", mosq);
	if(mosq == NULL)
	{
		 log_info("mqtt_init:Create a new client failure\n");
		 goto cleanup;
	}
	
	if(name != NULL && pwd != NULL)
	{
		ret = mosquitto_username_pw_set(mosq,name,pwd);
		if(ret)
		{
			log_info("mqtt_init:mosquitto_username_pw_set error!\n");
			goto cleanup;
		}
	}

#ifdef SSL_ENABLE
	ret = mosquitto_tls_set(mosq, "/etc/sslPub/ca.crt", "/etc/sslPub", "/etc/sslPub/client.crt", "/etc/sslPub/pkcs8_client.key", NULL);
	log_info("mosquitto_tls_set ret = %d\n", ret);
	if(ret)
	{
		log_info("mosquitto_tls_set error!\n");
		goto cleanup;
	}

	ret = mosquitto_tls_insecure_set(mosq, true);
	log_info("mosquitto_tls_insecure_set ret = %d\n", ret);
	if(ret)
	{
		log_info("mosquitto_tls_set error!\n");
		goto cleanup;
	}
#endif

	mosquitto_opts_set(mosq,MQTT_PROTOCOL_V311,NULL);
	/* 回调函数 */
	mosquitto_message_callback_set(mosq, omMessage_callback);
	mosquitto_connect_callback_set(mosq, on_connect);
	//mosquitto_disconnect_callback_set(mosq, my_disconnect_callback);	
	mosquitto_reconnect_delay_set(mosq, 5, 10, true);

	//设置遗嘱消息
	if(strlen(g_terminalId) != 0)
	{
		char buf[128] = {0};
		memset(buf, 0, sizeof(buf));
		sprintf(buf, "%s/%s/%s", g_busId, g_terminalId, "device/offline");
		log_info("buf = %s\n", buf);
		cJSON *param = cJSON_CreateObject();
		char random[31] = {0};
		srand((unsigned)time(NULL));
		int i = 0;
		for(i = 0; i < 30; i++)
			random[i] = rand()%10 + '0';
		cJSON_AddStringToObject(param, "transactionId", random);
		cJSON_AddStringToObject(param, "originBus", "cloud");
		
		char *out = cJSON_Print(param);
		log_info("param out = %s, %d\n", out, strlen(out));
		mosquitto_will_set(mosq, buf, strlen(out), (void *)out, 1, false);
		cJSON_Delete(param);
		free(out);
	}
	
	/* 连接代理 */
RECONNECT:
#ifdef SSL_ENABLE
	ret = mosquitto_connect(mosq, HOST, PORT_SSL, KEEP_ALIVE);
#else
	ret = mosquitto_connect(mosq, HOST, PORT, KEEP_ALIVE);
#endif
	if(ret != MOSQ_ERR_SUCCESS)
	{
		log_info("mosquitto_connect ret = %d\n", ret);
		sleep(10);
		reTrying++;
		log_info("mqtt_init:Connect server error!, this is %d reconnect\n", reTrying);
		goto RECONNECT;
	}
	
#ifdef SSL_ENABLE
		port = PORT_SSL;
#else
		port = PORT;
#endif
	log_info("mqtt_init: %s:%d connection client is OK\n", HOST, port);
	reTrying = 0;
	int loop = mosquitto_loop_start(mosq); 
	if(loop != MOSQ_ERR_SUCCESS)
	{
		log_info("mosquitto loop error\n");
		goto cleanup;
	}
	
	return ret;
/* 释放 清空 */
cleanup:
	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	mosq = NULL;
	return -1;
}

int mqtt_sub(const char *topic)
{
	int ret = mosquitto_subscribe(mosq, NULL, topic, 0);
	log_info("mqtt_sub ret = %d\n", ret);
	return ret;
}

int mqtt_unsub(const char *topic)
{
	int ret = mosquitto_unsubscribe(mosq, NULL, topic);
	log_info("mosquitto_unsubscribe ret = %d\n", ret);
	return ret;
}

int mqtt_pub(const char *topic, void *msg, int len)
{
	int ret = 0;
	if(g_cloudBus)
	{
		ret = mosquitto_publish(mosq, NULL, topic, len, msg, 0, 0);
	}
	else
	{
		log_info("cloud bus not start\n");
	}
	return ret;
}

int mqtt_uninit()
{
	log_info("mqtt_uninit  mosq = %x\n", mosq);
	if(mosq)
	{
		log_info("mqtt_uninit 1\n");
		mosquitto_disconnect(mosq);
		log_info("mqtt_uninit 2\n");
		mosquitto_loop_stop(mosq, true);
		log_info("mqtt_uninit 3\n");
		mosquitto_destroy(mosq);
		log_info("mqtt_uninit 4\n");
		mosquitto_lib_cleanup();
		log_info("mqtt_uninit 5\n");
		mosq = NULL;
	}
	return 0;
}
/*********************************/

