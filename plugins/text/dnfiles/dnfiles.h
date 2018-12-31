#ifndef BABELTRACE_PLUGIN_TEXT_DNFILES_DNFILES_H
#define BABELTRACE_PLUGIN_TEXT_DNFILES_DNFILES_H

#include <babeltrace/babeltrace-internal.h>
#include <babeltrace/babeltrace.h>
#include <stdbool.h>

struct dnfiles_component {
	bool error;
	struct bt_notification_iterator *input_iterator;
};


BT_HIDDEN
enum bt_component_status dnfiles_consume(
		struct bt_private_component *component);

BT_HIDDEN
enum bt_component_status dnfiles_init(
		struct bt_private_component *component,
		struct bt_value *params,
		void *init_method_data);

BT_HIDDEN
void dnfiles_finalize(struct bt_private_component *component);

BT_HIDDEN
void dnfiles_port_connected(
		struct bt_private_component *component,
		struct bt_private_port *self_port,
		struct bt_port *other_port);
#endif /* BABELTRACE_PLUGIN_TEXT_DNFILES_DNFILES_H */
