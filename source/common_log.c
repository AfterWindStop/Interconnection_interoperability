#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include "common_log.h"
#include "../internal_msg.h"

#define MAX_BUF_LEN 			8*1024

struct log_cfg
{
    int enable;
    int level;
    int mask;
    char dir[128];
    char log_file[128];
    char del_file[128];
    int max_len;
    int cur_len;
    FILE *fp;
    char buffer[MAX_BUF_LEN];
};

static struct log_cfg g_log_parm = {.enable = 0, .level = COM_LOG_LEVEL_INIT, .mask = LOG_CONS,};

struct log_cfg *employ_log_parm(void)
{
    return &g_log_parm;
}

void vos_localtime(char* buffer, int len, char* formate)
{
    time_t tmp;
    time(&tmp);
	struct tm * time = localtime(&tmp);
    snprintf(buffer,len, formate, time->tm_year + 1900, time->tm_mon + 1, time->tm_mday, time->tm_hour, time->tm_min, time->tm_sec);
}

char *log_parm_desc(void)
{
    struct log_cfg *log_parm = employ_log_parm();
    static char buffer[256] = {0};
    snprintf(buffer, sizeof(buffer), "log_file(%s) len(%d) max_len(%d) level(0x%x) mask(0x%x)\n", log_parm->log_file, log_parm->cur_len, log_parm->max_len, log_parm->level,
             log_parm->mask);
    return buffer;
}


void init_log_parm(struct log_cfg *log_parm)
{
    memset(log_parm, 0, sizeof(struct log_cfg));
	log_parm->level = COM_LOG_LEVEL_INIT;
    log_parm->mask = LOG_MASK_ALL;
    snprintf(log_parm->dir, sizeof(log_parm->dir), "%s", "/tmp/");
    log_parm->max_len = LOG_MAX_LEN;
}

void start_log_parm()
{
    struct log_cfg *log_parm = employ_log_parm();
    cJSON *parm = NULL;
	DIR *log_dir = NULL;
    struct dirent *log_file = NULL;
    long long time_stamp = 0;
    long long otime_stamp = 0;
    long long ntime_stamp = 0;
    struct stat file_stat;
    char current[128];
    init_log_parm(log_parm);

    log_dir = opendir(log_parm->dir);
    if(log_dir)
    {
        log_file = readdir(log_dir);
        while(log_file)
        {
            if(log_file->d_name && strlen(log_file->d_name) && (log_file->d_type & DT_REG) && strcmp(log_file->d_name, ".") && strcmp(log_file->d_name, "..") && (0 == strncmp(log_file->d_name, "xjsdk", strlen("xjsdk"))))
            {
                sscanf(log_file->d_name, "xjsdk%lld.log", &time_stamp);
                if(!otime_stamp || otime_stamp > time_stamp)
                {
                    otime_stamp = time_stamp;
                }
                if(!ntime_stamp || ntime_stamp < time_stamp)
                {
                    ntime_stamp = time_stamp;
                }
            }
            log_file = readdir(log_dir);
        }
		closedir(log_dir);
    }
	if(ntime_stamp)
	{
		snprintf(log_parm->log_file, sizeof(log_parm->log_file), "%sxjsdk_%lld.log", log_parm->dir, ntime_stamp);
	}
	else  
	{
		vos_localtime(current, sizeof(current), "%04d%02d%02d%02d%02d%02d");
		snprintf(log_parm->log_file, sizeof(log_parm->log_file), "%sxjsdk_%s.log", log_parm->dir, current);
	}
	if(otime_stamp)
	{
		snprintf(log_parm->del_file, sizeof(log_parm->del_file), "%sxjsdk_%lld.log", log_parm->dir, otime_stamp);
	}
	log_parm->enable = 1;
	//show_log_parm();
	memset(&file_stat, 0, sizeof(struct stat));
    if(0 == stat(log_parm->log_file, &file_stat))
    {
        log_parm->cur_len = file_stat.st_size;
    }
    log_parm->fp = fopen(log_parm->log_file, "ab");
}


int back_log_file(void)
{
    struct log_cfg *log_parm = employ_log_parm();
    char current[128] = {0};
    if(!log_parm->fp)
    {
        return RET_ERR;
    }
    fclose(log_parm->fp);
	if(strlen(log_parm->del_file))
	{
		unlink(log_parm->del_file);
		memset(log_parm->del_file, 0, sizeof(log_parm->del_file));
	}
	strcpy(log_parm->del_file, log_parm->log_file);
	vos_localtime(current, sizeof(current), "%04d%02d%02d%02d%02d%02d");
	snprintf(log_parm->log_file, sizeof(log_parm->log_file), "%sxjsdk_%s.log", log_parm->dir, current);
    log_parm->fp = fopen(log_parm->log_file, "ab");
    if(NULL == log_parm->fp)
    {
        log_error("%s %d :open %s fail!\n", __FILE__, __LINE__, log_parm->log_file);
        return RET_ERR;
    }
    log_parm->cur_len = 0;
    return RET_OK;
}

int save_log(char *str, int slen)
{
    struct log_cfg *log_parm = employ_log_parm();
    int len = 0;
    len = slen + 1;
    if(log_parm->cur_len + len > log_parm->max_len)
    {
        back_log_file();
    }
    if(!log_parm->fp)
    {
        return RET_ERR;
    }
    fwrite(str, 1, slen, log_parm->fp);
    fflush(log_parm->fp);
    log_parm->cur_len += slen;
    return RET_OK;
}

void do_log(int mask, int level, const char *file, int line, const char *func, char *fmt, ...)
{
    struct log_cfg *log_parm = employ_log_parm();
    int len = 0;
    va_list ap;
    char current[128] = {0};
	memset(log_parm->buffer, 0, sizeof(log_parm->buffer));
	vos_localtime(current, sizeof(current), "%04d/%02d/%02d %02d:%02d:%02d");
    len += snprintf(log_parm->buffer, sizeof(log_parm->buffer), "[%s][%s](%d)[%s]:", current, file, line, func);
	memset(&ap, 0, sizeof(va_list));
    va_start(ap, fmt);
    len += vsnprintf(log_parm->buffer + len, sizeof(log_parm->buffer) - len - 1, fmt, ap);
    va_end(ap);
	if(log_parm->buffer[strlen(log_parm->buffer) - 1] != 10)
    {
        log_parm->buffer[strlen(log_parm->buffer)] = 10;
        len += 1;
    }

    save_log(log_parm->buffer, len > MAX_BUF_LEN ? MAX_BUF_LEN : len);
}

