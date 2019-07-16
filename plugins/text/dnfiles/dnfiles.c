#include <babeltrace/babeltrace.h>
#include <babeltrace/common-internal.h>
#include <plugins-common.h>
#include <pthread.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "dn_logger.h"
#include "msg_handler.h"
#include "dnfiles.h"

#define FLUSH_TIMER 10000000 //mirco seconds

pthread_t service_thread;
bool running = true;
bool should_rotate = false;

static void *service_func(void *arg)
{
	struct dnfiles_component *data = (struct dnfiles_component *)arg;
	while (running)
	{
		keepalive_timer += 1;
		g_usleep(1000000);
		_dn_tracelog_TRACE_CATEGORY_GENERAL_TRACE_INFO(
				"babeltrace", 0, 0, "none", 0, "none", "ka");
		flush_all_loggers();
		if (should_rotate)
		{
			rotate_loggers();
			should_rotate = false;
		}
		if (data->keepalive_interval && (keepalive_timer > data->keepalive_interval))
		{
			printf("Did not get keepalive for %ld seconds, Exiting...\n", data->keepalive_interval);
			exit(1);
		}
	}
	return NULL;
}

static void handle_rotation(int signo)
{
	should_rotate = true;
}


BT_HIDDEN
enum bt_component_status dnfiles_consume(struct bt_private_component *component)
{
	enum bt_component_status ret;
	struct bt_notification *notification = NULL;
	struct bt_notification_iterator *it;
	struct dnfiles_component *data =
		bt_private_component_get_user_data(component);
	enum bt_notification_iterator_status it_ret;

	if (unlikely(data->error))
	{
		ret = BT_COMPONENT_STATUS_ERROR;
		goto end;
	}

	it = data->input_iterator;
	it_ret = bt_notification_iterator_next(it);

	switch (it_ret) {
	case BT_NOTIFICATION_ITERATOR_STATUS_END:
		BT_PUT(data->input_iterator);
		ret = BT_COMPONENT_STATUS_END;
		goto end;

	case BT_NOTIFICATION_ITERATOR_STATUS_AGAIN:
		ret = BT_COMPONENT_STATUS_AGAIN;
		goto end;

	case BT_NOTIFICATION_ITERATOR_STATUS_OK:
		break;
	default:
		ret = BT_COMPONENT_STATUS_ERROR;
		goto end;
	}

	notification = bt_notification_iterator_get_notification(it);
	assert(notification);
	ret = handle_notification(notification);
end:
	bt_put(notification);
	return ret;
}


BT_HIDDEN
enum bt_component_status dnfiles_init(
		struct bt_private_component *component,
		struct bt_value *params,
		UNUSED_VAR void *init_method_data)
{
	char path[MAX_FILE_PATH] = LOGS_PATH;
	char hostname[MAX_HOSTNAME];
	enum bt_component_status ret = BT_COMPONENT_STATUS_OK;
	struct dnfiles_component *data = g_new0(struct dnfiles_component, 1);
	keepalive_timer = 0;
	if (!data)
	{
		ret = BT_COMPONENT_STATUS_NOMEM;
		goto error;
	}

	gethostname(hostname, MAX_HOSTNAME);
	strcat(path, hostname);
	printf("Creating path %s\n", path);
	mkdir(path, 0700);

	struct bt_value *keepalive_interval = bt_value_map_get(params, "keepalive-interval");
	if (keepalive_interval) {
		if (!bt_value_is_integer(keepalive_interval)) {
			printf("Expecting a integer value for the `keepalive-interval` parameter");
		}

		ret = bt_value_integer_get(keepalive_interval, &data->keepalive_interval);
		assert(ret == 0);
	}
	else
	{
		data->keepalive_interval = 0;
	}
	printf("setting keepalive interval to %ld\n", data->keepalive_interval);
	// TODO init strings if needed
	if (pthread_create(&service_thread, NULL, service_func, (void *)data) != 0)
	{
		ret = BT_COMPONENT_STATUS_ERROR;
		goto error;
	}

	ret = bt_private_component_sink_add_input_private_port(component,
		"in", NULL, NULL);
	if (ret != BT_COMPONENT_STATUS_OK)
		goto error;

	ret = bt_private_component_set_user_data(component, data);
	if (ret != BT_COMPONENT_STATUS_OK)
		goto error;

	if (signal(SIGUSR1, handle_rotation) == SIG_ERR)
	{
		ret = BT_COMPONENT_STATUS_ERROR;
		goto error;
	}
	ret = init_handler();
	if (ret == BT_COMPONENT_STATUS_OK)
		goto end;
	
error:
	g_free(data);
end:
	return ret;
}

BT_HIDDEN
void dnfiles_finalize(struct bt_private_component *component)
{
	void *data = bt_private_component_get_user_data(component);
	running = false;
	pthread_join(service_thread, NULL);
	close_all_loggers();
	g_free(data);
}


BT_HIDDEN
void dnfiles_port_connected(
		struct bt_private_component *component,
		struct bt_private_port *self_port,
		struct bt_port *other_port)
{
	enum bt_connection_status conn_status;
	struct bt_private_connection *connection;
	struct dnfiles_component *data;
	static const enum bt_notification_type notif_types[] = {
		BT_NOTIFICATION_TYPE_EVENT,
		BT_NOTIFICATION_TYPE_DISCARDED_PACKETS,
		BT_NOTIFICATION_TYPE_DISCARDED_EVENTS,
		BT_NOTIFICATION_TYPE_SENTINEL,
	};

	data = bt_private_component_get_user_data(component);
	assert(data);
	assert(!data->input_iterator);
	connection = bt_private_port_get_private_connection(self_port);
	assert(connection);
	conn_status = bt_private_connection_create_notification_iterator(
		connection, notif_types, &data->input_iterator);
	if (conn_status != BT_CONNECTION_STATUS_OK) {
		data->error = true;
	}

	bt_put(connection);
}

