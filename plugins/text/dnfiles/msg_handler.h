#ifndef BABELTRACE_PLUGIN_TEXT_DNFILES_MSG_HANDLER_H
#define BABELTRACE_PLUGIN_TEXT_DNFILES_MSG_HANDLER_H
#include <babeltrace/babeltrace.h>
#include "uthash.h"

#define MAX_LOG_NAME 128

struct logger_config {
	unsigned int file_size;
	unsigned int max_files;
};

struct logger {
	char name[MAX_LOG_NAME];
	FILE *fp;
	struct logger_config *config;
	unsigned int num_of_files;
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
