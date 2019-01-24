#include <babeltrace/ctf-ir/stream-internal.h>
#include <babeltrace/compat/time-internal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h> // for access function
#include <inttypes.h>

#include "msg_handler.h"
#define MAX_FILE_SIZE 10 * 1024 * 1024
#define LOGS_PATH "/var/log/dn/traces/"
#define MAX_FILE_PATH MAX_LOG_NAME + 22


static struct logger *loggers = NULL;
static pthread_mutex_t lock;

static inline FILE *open_file(const char *name)
{
	char path[MAX_FILE_PATH] = LOGS_PATH;
	return fopen(strcat(path, name), "a+");
}

static unsigned int calc_num_of_files(const char *name, unsigned int max_files)
{
	char path[MAX_FILE_PATH];
	char file[MAX_FILE_PATH];
	unsigned int num_of_files = 1;
	strcpy(path, LOGS_PATH);
	strcat(path, name);
	sprintf(file, "%s.%d", path, num_of_files);
	while ((access(file, F_OK) != -1) & (num_of_files < max_files))
	{
		num_of_files++;
		sprintf(file, "%s.%d", path, num_of_files);
	}
	return num_of_files;
}

static struct logger *create_logger(const char *name)
{
	struct logger *logger = (struct logger *)malloc(sizeof(struct logger));
	logger->fp = open_file(name);
	logger->rotating = false;
	logger->max_files = 10;
	logger->max_file_size = MAX_FILE_SIZE;
	logger->num_of_files = calc_num_of_files(name, logger->max_files);
	strcpy(logger->name, name);
	pthread_mutex_lock(&lock);
	HASH_ADD_STR(loggers, name, logger);
	pthread_mutex_unlock(&lock);
	return logger;
}

static const char *get_event_field_str(struct bt_field *payload, const char *name)
{
	struct bt_field *field;
	const char *res;
	if (bt_field_get_type_id(payload) != CTF_TYPE_STRUCT)
		return NULL;  // TODO deal with this error
	field = bt_field_structure_get_field_by_name(payload, name);
	if (!field)
		return NULL; // TODO deal with this error

	if (bt_field_get_type_id(field) != CTF_TYPE_STRING)
		return NULL; // TODO deal with this error

	res = bt_field_string_get_value(field);
	bt_put(field);
	return res;
}


static inline enum bt_component_status get_event_field_int(
		struct bt_event *event,
		const char *name,
		long int *num)
{
	struct bt_field *field = bt_event_get_event_payload(event);
	if (bt_field_get_type_id(field) != CTF_TYPE_STRUCT)
		return BT_COMPONENT_STATUS_ERROR;
	field = bt_field_structure_get_field_by_name(field, name);
	if (!field)
		return BT_COMPONENT_STATUS_ERROR;

	if (bt_field_get_type_id(field) != CTF_TYPE_INTEGER)
		return BT_COMPONENT_STATUS_ERROR;

	return bt_field_signed_integer_get_value(field, num);
}


static void print_info(
		struct logger *logger,
		struct bt_event *event,
		struct bt_field *payload)
{
	const char *procname = get_event_field_str(payload, "procname");
	const char *file = get_event_field_str(payload, "file");
	const char *func = get_event_field_str(payload, "func");
	long int line;
	int ret;
	ret = get_event_field_int(event, "line", &line);
	if (ret || !procname || !file || !func)
	{
		fprintf(logger->fp, "Invalid entry\n");
		return;
	}
	fprintf(logger->fp, "%s, %s(%ld):%s: ",
			procname, file, line, func);
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
	return;
}

static void print_msg(struct logger *logger, struct bt_event *event)
{
	struct bt_field *field = bt_event_get_event_payload(event);
	struct bt_field_type *seq_type = NULL, *field_type = NULL;
	struct bt_field *length_field = NULL;
	uint64_t len, i;
	if (bt_field_get_type_id(field) != CTF_TYPE_STRUCT)
		goto error;

	field = bt_field_structure_get_field_by_name(field, "msg");
	if (!field)
		goto error;

	if (bt_field_get_type_id(field) != CTF_TYPE_SEQUENCE)
		goto error;

	seq_type = bt_field_get_type(field);
	if (!seq_type)
		goto error;

	length_field = bt_field_sequence_get_length(field);
	if (!length_field)
		goto error_seq;

	if (bt_field_unsigned_integer_get_value(length_field, &len) < 0)
		goto error_length;

	field_type = bt_field_type_sequence_get_element_type(seq_type);
	if (!field_type)
		goto error_length;

	if (bt_field_type_get_type_id(field_type) != BT_FIELD_TYPE_ID_INTEGER)
		goto error_field;

	if (bt_field_type_integer_get_encoding(field_type) !=
			BT_STRING_ENCODING_UTF8)
		goto error_field;

	if (bt_field_type_integer_get_size(field_type) != CHAR_BIT)
		goto error_field;

	if (bt_field_type_get_alignment(field_type) != CHAR_BIT)
		goto error_field;

	for (i = 0; i < len; i++)
		print_integer(
			logger, bt_field_sequence_get_field(field, i));

	fprintf(logger->fp, "\n");
	bt_put(length_field);
	bt_put(seq_type);
	bt_put(field_type);
	bt_put(field);
	return;

error_field:
	bt_put(field_type);

error_length:
	bt_put(length_field);

error_seq:
	bt_put(seq_type);

error:
	bt_put(field);
	fprintf(logger->fp, "Failed to retrieve msg\n");

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

enum bt_component_status handle_notification(
		struct bt_notification *notification)
{
	struct bt_event *event = bt_notification_event_get_event(notification);
	struct bt_field *payload = bt_event_get_event_payload(event);
	const char *procname = get_event_field_str(payload, "procname");
	struct logger *logger;
	if (!procname || strlen(procname) > MAX_LOG_NAME)
		return BT_COMPONENT_STATUS_OK;

	HASH_FIND_STR(loggers, procname, logger);
	if (!logger)
		logger = create_logger(procname);

	if (!logger || !logger->fp)
		return BT_COMPONENT_STATUS_OK;

	if (logger->rotating)
	{
		fclose(logger->fp);
		logger->fp = open_file(logger->name);
		logger->rotating = false;
	}
	print_time(logger, notification, event);
	print_info(logger, event, payload);
	print_msg(logger, event);
	bt_put(payload);
	bt_put(event);
	return BT_COMPONENT_STATUS_OK;
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
		fclose(logger->fp);
		HASH_DEL(loggers, logger);
		free(logger);
	}
	pthread_mutex_unlock(&lock);
}

void rotate_log(struct logger *logger)
{
	int i;
	char path[MAX_FILE_PATH];
	strcpy(path, LOGS_PATH);
	strcat(path, logger->name);

	for (i=logger->num_of_files; i>=0; i--)
	{
		char src[MAX_FILE_PATH];
		char dst[MAX_FILE_PATH];

		if (i > 0)
			sprintf(src, "%s.%d", path, i);

		else
			strcpy(src, path);
		sprintf(dst, "%s.%d", path, i + 1);

		if (i >= logger->max_files)
			remove(src);

		else
			rename(src, dst);
	}

	logger->num_of_files++;
	if (logger->num_of_files > logger->max_files)
		logger->num_of_files = logger->max_files;
	logger->rotating = true;
}

void rotate_loggers(void)
{
	struct logger *logger, *tmp;
	pthread_mutex_lock(&lock);
	HASH_ITER(hh, loggers, logger, tmp) {
		struct stat filestats;
		if (logger->rotating == true)
			continue;

		fstat(logger->fp->_fileno, &filestats);
		if (filestats.st_size > logger->max_file_size)
			rotate_log(logger);
	}
	pthread_mutex_unlock(&lock);
}
