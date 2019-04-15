#include <babeltrace/ctf-ir/stream-internal.h>
#include <babeltrace/compat/time-internal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <inttypes.h>

#include "msg_handler.h"
#define MAX_FILE_SIZE 10 * 1024 * 1024
#define MAX_CONFIG_NAME MAX_LOG_NAME + 16


static struct logger *loggers = NULL;
static pthread_mutex_t lock;


static inline FILE *open_file(const char *name)
{
	char path[MAX_FILE_PATH];
	char hostname[MAX_HOSTNAME];
	gethostname(hostname, MAX_HOSTNAME);
	snprintf(path, MAX_FILE_PATH, "%s%s/%s", LOGS_PATH, hostname, name);
	printf("%s\n", path);
	return fopen(path, "a+");
}


static struct logger *create_logger(const char *name)
{
	struct logger *logger = (struct logger *)malloc(sizeof(struct logger));
	logger->fp = open_file(name);
	logger->rotating = false;
	strcpy(logger->name, name);
	pthread_mutex_lock(&lock);
	HASH_ADD_STR(loggers, name, logger);
	pthread_mutex_unlock(&lock);
	return logger;
}

static const char *get_event_field_str(
		struct bt_field *payload, const char *name)
{
	struct bt_field *field = NULL;
	const char *res = NULL;
	if (bt_field_get_type_id(payload) != CTF_TYPE_STRUCT)
		goto error;  // TODO deal with this error
	field = bt_field_structure_get_field_by_name(payload, name);
	if (!field)
		goto error; // TODO deal with this error

	if (bt_field_get_type_id(field) != CTF_TYPE_STRING)
		goto error; // TODO deal with this error

	res = bt_field_string_get_value(field);

error:
	bt_put(field);
	return res;
}


static inline enum bt_component_status get_event_field_int(
		struct bt_field *payload,
		const char *name,
		long int *num)
{
	struct bt_field *field;
	enum bt_component_status ret;
	if (bt_field_get_type_id(payload) != CTF_TYPE_STRUCT)
		return BT_COMPONENT_STATUS_ERROR;
	field = bt_field_structure_get_field_by_name(payload, name);
	if (!field)
		return BT_COMPONENT_STATUS_ERROR;

	if (bt_field_get_type_id(field) != CTF_TYPE_INTEGER)
		return BT_COMPONENT_STATUS_ERROR;

	ret = bt_field_signed_integer_get_value(field, num);
	bt_put(field);
	return ret;
}


static void print_info( struct logger *logger, struct bt_field *payload)
{
	const char *procname = get_event_field_str(payload, "procname");
	const char *file = get_event_field_str(payload, "file");
	const char *func = get_event_field_str(payload, "func");
	long int line, pid, tid;
	int ret;

	ret = get_event_field_int(payload, "pid", &pid);
	if (ret)
	{
		fprintf(logger->fp, "No pid for entry\n");
		return;
	}
	ret = get_event_field_int(payload, "tid", &tid);
	if (ret)
	{
		fprintf(logger->fp, "No tid for entry\n");
		return;
	}

	ret = get_event_field_int(payload, "line", &line);
	if (ret || !procname || !file || !func)
	{
		fprintf(logger->fp, "Invalid entry\n");
		return;
	}
	fprintf(logger->fp, "[%s:%ld %s()] [%s:%ld/%ld]: ",
			file, line, func, procname, pid, tid);

}

static void print_integer(
		struct logger *logger,
		struct bt_field *field)
{
	struct bt_field_type *field_type = NULL;
	enum bt_string_encoding encoding;
	int signedness;
	union {
		uint64_t u;
		int64_t s;
	} v;

	field_type = bt_field_get_type(field);
	if (!field_type)
		goto end;

	signedness = bt_ctf_field_type_integer_get_signed(field_type);
	if (signedness < 0)
		goto end;

	if (!signedness) {
		if (bt_field_unsigned_integer_get_value(field, &v.u) < 0)
			goto end;

	} else {
		if (bt_field_signed_integer_get_value(field, &v.s) < 0)
			goto end;
	}

	encoding = bt_field_type_integer_get_encoding(field_type);
	switch (encoding) {
	case BT_STRING_ENCODING_UTF8:
	case BT_STRING_ENCODING_ASCII:
		fprintf(logger->fp, "%c", (int) v.u);
		goto end;
	case BT_STRING_ENCODING_NONE:
	case BT_STRING_ENCODING_UNKNOWN:
		break;
	default:
		goto end;

	}
end:
	bt_put(field_type);
	bt_put(field);
	return;
}

static void print_msg(
		struct logger *logger,
		struct bt_field *payload)
{
	struct bt_field *field = NULL;
	struct bt_field_type *seq_type = NULL, *field_type = NULL;
	struct bt_field *length_field = NULL;
	uint64_t len, i;
	if (bt_field_get_type_id(payload) != CTF_TYPE_STRUCT)
		goto error;

	field = bt_field_structure_get_field_by_name(payload, "msg");
	if (!field)
		goto error;

	if (bt_field_get_type_id(field) != CTF_TYPE_SEQUENCE)
		goto error;

	seq_type = bt_field_get_type(field);
	if (!seq_type)
		goto error;

	length_field = bt_field_sequence_get_length(field);
	if (!length_field)
		goto error;

	if (bt_field_unsigned_integer_get_value(length_field, &len) < 0)
		goto error;

	field_type = bt_field_type_sequence_get_element_type(seq_type);
	if (!field_type)
		goto error;

	if (bt_field_type_get_type_id(field_type) != BT_FIELD_TYPE_ID_INTEGER)
		goto error;

	if (bt_field_type_integer_get_encoding(field_type) !=
			BT_STRING_ENCODING_UTF8)
		goto error;

	if (bt_field_type_integer_get_size(field_type) != CHAR_BIT)
		goto error;

	if (bt_field_type_get_alignment(field_type) != CHAR_BIT)
		goto error;

	for (i = 0; i < len; i++)
		print_integer(logger, bt_field_sequence_get_field(field, i));

	fprintf(logger->fp, "\n");
	goto end;
error:
	fprintf(logger->fp, "Failed to retrieve msg\n");

end:
	bt_put(length_field);
	bt_put(seq_type);
	bt_put(field_type);
	bt_put(field);
	return;
}

static void print_time(
		struct logger *logger,
		struct bt_notification *notif,
		struct bt_event *event)
{

	struct bt_clock_class_priority_map *cc_prio_map =
		bt_notification_event_get_clock_class_priority_map(notif);
	struct bt_clock_class *clock_class =
		bt_clock_class_priority_map_get_highest_priority_clock_class(
			cc_prio_map);
	struct bt_clock_value *clock_value =
		bt_event_get_clock_value(event, clock_class);
	int ret;
	int64_t ts_nsec = 0;	/* add configurable offset */
	int64_t ts_sec = 0;	/* add configurable offset */
	uint64_t ts_sec_abs, ts_nsec_abs;
	bool is_negative;

	if (!clock_value || !cc_prio_map || !clock_class) {
		fprintf(logger->fp, "?????????? ??:??:??.?????????");
		return;
	}

	ret = bt_clock_value_get_value_ns_from_epoch(clock_value, &ts_nsec);
	if (ret) {
		// TODO: log, this is unexpected
		fprintf(logger->fp, "Error");
		return;
	}

	ts_sec += ts_nsec / 1000000000;
	ts_nsec = ts_nsec % 1000000000;

	if (ts_sec >= 0 && ts_nsec >= 0) {
		is_negative = false;
		ts_sec_abs = ts_sec;
		ts_nsec_abs = ts_nsec;
	} else if (ts_sec > 0 && ts_nsec < 0) {
		is_negative = false;
		ts_sec_abs = ts_sec - 1;
		ts_nsec_abs = 1000000000 + ts_nsec;
	} else if (ts_sec == 0 && ts_nsec < 0) {
		is_negative = true;
		ts_sec_abs = ts_sec;
		ts_nsec_abs = -ts_nsec;
	} else if (ts_sec < 0 && ts_nsec > 0) {
		is_negative = true;
		ts_sec_abs = -(ts_sec + 1);
		ts_nsec_abs = 1000000000 - ts_nsec;
	} else if (ts_sec < 0 && ts_nsec == 0) {
		is_negative = true;
		ts_sec_abs = -ts_sec;
		ts_nsec_abs = ts_nsec;
	} else {	/* (ts_sec < 0 && ts_nsec < 0) */
		is_negative = true;
		ts_sec_abs = -ts_sec;
		ts_nsec_abs = -ts_nsec;
	}

	struct tm tm;
	time_t time_s = (time_t) ts_sec_abs;

	if (is_negative) {
		// TODO: log instead
		fprintf(logger->fp, "Failed");
		return;
	}


	if (!bt_gmtime_r(&time_s, &tm)) {
		// TODO: log instead
		fprintf(logger->fp, "FailedGMT");
		return;
	}
	char timestr[26];
	size_t res;

	/* Print date and time */
	res = strftime(timestr, sizeof(timestr),
			"%Y-%m-%d ", &tm);
	if (!res && strnlen(timestr, 12) != 11) {
		// TODO: log instead
		fprintf(logger->fp, "FailedStr");
		return;
	}

	fprintf(logger->fp, "%s%02d:%02d:%02d.%09" PRIu64 " ", timestr,
			tm.tm_hour, tm.tm_min, tm.tm_sec, ts_nsec_abs);
	bt_put(clock_value);
	bt_put(clock_class);
	bt_put(cc_prio_map);
	return;
}

static inline const char *get_level_str(enum bt_event_class_log_level level)
{
	switch (level) {
	case BT_EVENT_CLASS_LOG_LEVEL_UNKNOWN:
		return "UNKNOWN/CATEGORY";
	case BT_EVENT_CLASS_LOG_LEVEL_UNSPECIFIED:
		return "UNSPECIFIED/CATEGORY";
	case BT_EVENT_CLASS_LOG_LEVEL_EMERGENCY:
		return "EMERGENCY/CATEGORY";
	case BT_EVENT_CLASS_LOG_LEVEL_ALERT:
		return "ALERT/CATEGORY";
	case BT_EVENT_CLASS_LOG_LEVEL_CRITICAL:
		return "CRITICAL/CATEGORY";
	case BT_EVENT_CLASS_LOG_LEVEL_ERROR:
		return "ERROR/CATEGORY";
	case BT_EVENT_CLASS_LOG_LEVEL_WARNING:
		return "WARNING/CATEGORY";
	case BT_EVENT_CLASS_LOG_LEVEL_NOTICE:
		return "NOTICE/CATEGORY";
	case BT_EVENT_CLASS_LOG_LEVEL_INFO:
		return "INFO/CATEGORY";
	case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_SYSTEM:
		return "DEBUG_SYSTEM/CATEGORY";
	case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_PROGRAM:
		return "DEBUG_PROGRAM/CATEGORY";
	case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_PROCESS:
		return "DEBUG_PROCESS/CATEGORY";
	case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_MODULE:
		return "DEBUG_MODULE/CATEGORY";
	case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_UNIT:
		return "DEBUG_UNIT/CATEGORY";
	case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_FUNCTION:
		return "DEBUG_FUNCTION/CATEGORY";
	case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_LINE:
		return "DEBUG_LINE/CATEGORY";
	case BT_EVENT_CLASS_LOG_LEVEL_DEBUG:
		return "DEBUG/CATEGORY";
	default:
		return "UNKNOWN";
	}
}

static void print_severity(
		struct logger *logger,
		struct bt_event_class *event_cls)
{
	fprintf(logger->fp, "[%-18s] ",
		get_level_str(bt_event_class_get_log_level(event_cls)));
}

static enum bt_component_status handle_event(
		struct bt_notification *notification)
{
	struct bt_event *event = bt_notification_event_get_event(notification);
	struct bt_field *payload = bt_event_get_event_payload(event);
	struct bt_event_class *event_cls = bt_event_get_class(event);
	const char *procname = get_event_field_str(payload, "procname");
	struct logger *logger;
	if (!event)
		goto end_handle;

	if (!procname || strlen(procname) > MAX_LOG_NAME)
		goto end_handle;


	HASH_FIND_STR(loggers, procname, logger);
	if (!logger)
		logger = create_logger(procname);

	if (!logger || !logger->fp)
		goto end_handle;

	if (logger->rotating)
	{
		fclose(logger->fp);
		logger->fp = open_file(logger->name);
		logger->rotating = false;
	}
	print_time(logger, notification, event);
	print_severity(logger, event_cls);
	print_info(logger, payload);
	print_msg(logger, payload);

end_handle:
	bt_put(event_cls);
	bt_put(payload);
	bt_put(event);
	return BT_COMPONENT_STATUS_OK;
}


enum bt_component_status handle_notification(
		struct bt_notification *notification)
{
	enum bt_component_status ret = BT_COMPONENT_STATUS_OK;

	switch (bt_notification_get_type(notification))
	{
	case BT_NOTIFICATION_TYPE_EVENT:
		ret = handle_event(notification);
		break;
	case BT_NOTIFICATION_TYPE_INACTIVITY:
		fprintf(stderr, "Inactivity notification\n");
		break;
	case BT_NOTIFICATION_TYPE_PACKET_BEGIN:
	case BT_NOTIFICATION_TYPE_PACKET_END:
	case BT_NOTIFICATION_TYPE_STREAM_BEGIN:
	case BT_NOTIFICATION_TYPE_STREAM_END:
		break;
	case BT_NOTIFICATION_TYPE_DISCARDED_PACKETS:
	case BT_NOTIFICATION_TYPE_DISCARDED_EVENTS:
		break;
	default:
		fprintf(stderr, "Unhandled notification type\n");
	}

	return ret;
}

enum bt_component_status init_handler(void)
{
	if (pthread_mutex_init(&lock, NULL) != 0)
		return BT_COMPONENT_STATUS_ERROR;
	return BT_COMPONENT_STATUS_OK;
}

void flush_all_loggers(void)
{
	struct logger *logger, *tmp;
	pthread_mutex_lock(&lock);
	HASH_ITER(hh, loggers, logger, tmp) {
		fflush(logger->fp);
	}
	pthread_mutex_unlock(&lock);
}

void close_all_loggers(void)
{
	struct logger *logger, *tmp;
	pthread_mutex_lock(&lock);
	HASH_ITER(hh, loggers, logger, tmp) {
		if (logger->fp)
		{
			fclose(logger->fp);
		}
		HASH_DEL(loggers, logger);
		free(logger);
	}
	pthread_mutex_unlock(&lock);
}


void rotate_loggers(void)
{
	struct logger *logger, *tmp;
	printf("Rotating\n");
	flush_all_loggers();
	pthread_mutex_lock(&lock);
	HASH_ITER(hh, loggers, logger, tmp) {
		logger->rotating = true;
	}
	pthread_mutex_unlock(&lock);
}
