#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "util.h"

void list_add(struct list_head *new, struct list_head *head)
{
    head->next->prev = new;
    new->next = head->next;
    new->prev = head;
    head->next = new;
}

void list_del(struct list_head *ent)
{
    ent->prev->next = ent->next;
    ent->next->prev = ent->prev;
    ent->next = NULL;
    ent->prev = NULL;
}

timer_t create_timer(int time_val, int time_itr, void (*timer_thread)(union sigval))
{
	timer_t timer_id;
	struct sigevent evp;
	memset(&evp, 0, sizeof(evp));
	evp.sigev_notify = SIGEV_THREAD;
	evp.sigev_notify_function = timer_thread;
	
	if (timer_create(CLOCK_REALTIME, &evp, &timer_id) == -1) {
		printf("[%s][%d] create timer fail \n", __FUNCTION__, __LINE__);
		return 0;
	}
	
	struct itimerspec it;
	it.it_value.tv_sec = time_val;
	it.it_value.tv_nsec = 0;
	it.it_interval.tv_sec = time_itr;
	it.it_interval.tv_nsec = 0;
	
	if (timer_settime(timer_id, 0, &it, NULL) == -1) {
		printf("[%s][%d] set timer fail \n", __FUNCTION__, __LINE__);
		return 0;
	}
	
	return timer_id;
}

