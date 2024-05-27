#ifndef _COMMON_LOG_H_
#define _COMMON_LOG_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../cjson/include/cjson/cJSON.h"


enum log_level {
    COM_LOG_LEVEL_OFF     = 0,
    COM_LOG_LEVEL_EMERG   = 1,
    COM_LOG_LEVEL_ERROR   = 1 << 1,
    COM_LOG_LEVEL_WARN    = 1 << 2,
    COM_LOG_LEVEL_INFO    = 1 << 3,
    COM_LOG_LEVEL_DEBUG   = 1 << 4,
};

enum log_mask {
    LOG_NONE = 0,
    LOG_LOG = 1,
    LOG_CONS = 1 << 1,
};

#define COM_LOG_LEVEL_ALL  (COM_LOG_LEVEL_EMERG | COM_LOG_LEVEL_ERROR | COM_LOG_LEVEL_WARN | COM_LOG_LEVEL_INFO | COM_LOG_LEVEL_DEBUG)
#define COM_LOG_LEVEL_INIT  (COM_LOG_LEVEL_EMERG | COM_LOG_LEVEL_ERROR| COM_LOG_LEVEL_WARN| COM_LOG_LEVEL_INFO)
#define LOG_MASK_ALL (LOG_LOG|LOG_CONS)

#define LOG_MAX_LEN (2 * 1024 * 1024)
void start_log_parm();
void do_log(int mask, int level, const char *file, int line, const char *func, char *fmt, ...);

#define log_debug(args...)    do_log(LOG_CONS, COM_LOG_LEVEL_DEBUG, __FILE__,__LINE__,__FUNCTION__, ##args)
#define slog_debug(args...)   do_log(LOG_LOG|LOG_CONS, COM_LOG_LEVEL_DEBUG, __FILE__,__LINE__,__FUNCTION__, ##args)

#define log_info(args...)    do_log(LOG_CONS, COM_LOG_LEVEL_INFO, __FILE__,__LINE__,__FUNCTION__, ##args)
#define slog_info(args...)   do_log(LOG_LOG|LOG_CONS, COM_LOG_LEVEL_INFO, __FILE__,__LINE__,__FUNCTION__, ##args)

#define log_warn(args...)    do_log(LOG_CONS, COM_LOG_LEVEL_WARN, __FILE__,__LINE__,__FUNCTION__, ##args)
#define slog_warn(args...)   do_log(LOG_LOG|LOG_CONS, COM_LOG_LEVEL_WARN, __FILE__,__LINE__,__FUNCTION__, ##args)

#define log_error(args...)    do_log(LOG_CONS, COM_LOG_LEVEL_ERROR, __FILE__,__LINE__,__FUNCTION__, ##args)
#define slog_error(args...)   do_log(LOG_LOG|LOG_CONS, COM_LOG_LEVEL_ERROR, __FILE__,__LINE__,__FUNCTION__, ##args)

#define log_emerg(args...)    do_log(LOG_CONS, COM_LOG_LEVEL_EMERG, __FILE__,__LINE__,__FUNCTION__, ##args)
#define slog_emerg(args...)   do_log(LOG_LOG|LOG_CONS, COM_LOG_LEVEL_EMERG, __FILE__,__LINE__,__FUNCTION__, ##args)

#endif
