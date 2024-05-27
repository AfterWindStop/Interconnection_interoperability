#ifndef __UTIL_HEAD__
#define __UTIL_HEAD__

#include <time.h>
#include <errno.h>
#include <signal.h>

struct list_head {
    struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) {&(name), &(name)}

//#define offsetof(type, mem) ((size_t)&((type*)0)->mem)

#define list_entry(ptr, type, mem) ({ \
        const typeof(((type *)0)->mem) *__mptr = (ptr); \
        (type *)((char*)__mptr - offsetof(type, mem)); \
      })

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); pos = n, n = pos->next)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     &pos->member != (head); 					\
	     pos = n, n = list_next_entry(n, member))

#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)
	
void list_add(struct list_head *new, struct list_head *head);
void list_del(struct list_head *list);
timer_t create_timer(int time_val, int time_itr, void (*timer_thread)(union sigval));
char *read_config(const char *filename);
int dev_str2type(const char *type_name);
#endif
