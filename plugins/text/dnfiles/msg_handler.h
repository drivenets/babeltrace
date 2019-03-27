#ifndef BABELTRACE_PLUGIN_TEXT_DNFILES_MSG_HANDLER_H
#define BABELTRACE_PLUGIN_TEXT_DNFILES_MSG_HANDLER_H
#include <babeltrace/babeltrace.h>
#include "uthash.h"

#define MAX_HOSTNAME 128
#define MAX_LOG_NAME 128
#define MAX_FILE_PATH MAX_LOG_NAME + 128
#define LOGS_PATH "/var/log/dn/traces/"

struct logger {
	char name[MAX_LOG_NAME];
	FILE *fp;
	bool rotating;
	UT_hash_handle hh;
};

enum bt_component_status handle_notification(
		struct bt_notification *notification);
enum bt_component_status init_handler(void);
void flush_all_loggers(void);
void close_all_loggers(void);
void rotate_loggers(void);

#endif /* BABELTRACE_PLUGIN_TEXT_DNFILES_MSG_HANDLER_H */
