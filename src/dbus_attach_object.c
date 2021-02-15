#include "dbus_attach_object.h"
#include "debug.h"

static struct generic_data *root;
static GSList *pending = NULL;
static int global_flags = 0;

static gboolean check_experimental(int flags, int flag)
{
	if (!(flags & flag))
		return FALSE;

	return !(global_flags & G_DBUS_FLAG_ENABLE_EXPERIMENTAL);
}

static struct interface_data *find_interface(GSList *interfaces,
						const char *name)
{
	GSList *list;

	g_print("\nIN : find_interface() in\n");
	if(name) g_print("-> name : %s\n", name);

	if (name == NULL)
	{
		g_print("OUT A : find_interface()\n");
		return NULL;
	}

	for (list = interfaces; list; list = list->next) {
		struct interface_data *iface = list->data;
		if (!strcmp(name, iface->name))
		{
			g_print("OUT B : find_interface()\n");
			return iface;
		}
	}

	g_print("OUT : find_interface()\n");
	return NULL;
}

static void remove_pending(struct generic_data *data)
{
	g_print("\nIN : remove_pending() in\n");

	if (data->process_id > 0) {
		g_source_remove(data->process_id);
		data->process_id = 0;
	}

	pending = g_slist_remove(pending, data);

	g_print("OUT A : remove_pending()\n");
}

static void append_property(struct interface_data *iface,
			const GDBusPropertyTable *p, DBusMessageIter *dict)
{
	DBusMessageIter entry, value;

	g_print("\nIN : append_property() in (object.c)\n");

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
								&entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &p->name);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, p->type,
								&value);

	p->get(p, &value, iface->user_data);

	dbus_message_iter_close_container(&entry, &value);
	dbus_message_iter_close_container(dict, &entry);

	g_print("OUT : reset_parent() out\n");
}


static void append_properties(struct interface_data *data,
							DBusMessageIter *iter)
{
	DBusMessageIter dict;
	const GDBusPropertyTable *p;

	g_print("\nIN : append_properties() in (object.c)\n");

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	for (p = data->properties; p && p->name; p++) {
		if (check_experimental(p->flags,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL))
			continue;

		if (p->get == NULL)
			continue;

		if (p->exists != NULL && !p->exists(p, data->user_data))
			continue;

		append_property(data, p, &dict);
	}

	dbus_message_iter_close_container(iter, &dict);

	g_print("OUT : append_properties() out\n");
}

static void append_interface(gpointer data, gpointer user_data)
{
	struct interface_data *iface = data;
	DBusMessageIter *array = user_data;
	DBusMessageIter entry;

	g_print("\nIN : append_interface() in (object.c)\n");

	dbus_message_iter_open_container(array, DBUS_TYPE_DICT_ENTRY, NULL,
								&entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &iface->name);
	append_properties(data, &entry);
	dbus_message_iter_close_container(array, &entry);

	g_print("OUT : append_interface()\n");
}

static void emit_interfaces_added(struct generic_data *data)
{
	DBusMessage *signal;
	DBusMessageIter iter, array;

	g_print("\nIN : emit_interfaces_added() in\n");

	if (root == NULL || data == root)
	{
		g_print("OUT A : emit_interfaces_added()\n");
		return;
	}

	signal = dbus_message_new_signal(root->path,
					DBUS_INTERFACE_OBJECT_MANAGER,
					"InterfacesAdded");
	if (signal == NULL)
	{
		g_print("OUT B : emit_interfaces_added() out\n");
		return;
	}

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
								&data->path);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_ARRAY_AS_STRING
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &array);

	g_slist_foreach(data->added, append_interface, &array);
	g_slist_free(data->added);
	data->added = NULL;

	dbus_message_iter_close_container(&iter, &array);

	g_print("-> DBus Method Call : InterfacesAdded\n");
	/* Use dbus_connection_send to avoid recursive calls to g_dbus_flush */
	dbus_connection_send(data->conn, signal, NULL);
	dbus_message_unref(signal);

	g_print("OUT : emit_interfaces_added()\n");
}

static void process_properties_from_interface(struct generic_data *data,
						struct interface_data *iface)
{
	GSList *l;
	DBusMessage *signal;
	DBusMessageIter iter, dict, array;
	GSList *invalidated;

	g_print("\nIN : process_properties_from_interface() in (object.c)\n");
	if(iface) g_print("-> iface.name : %s\n", iface->name);
	if(data) g_print("-> data->path : %s\n", data->path);

	if (iface->pending_prop == NULL)
	{
		g_print("OUT A : process_properties_from_interface()\n");
		return;
	}

	signal = dbus_message_new_signal(data->path,
			DBUS_INTERFACE_PROPERTIES, "PropertiesChanged");
	if (signal == NULL) {
		error("Unable to allocate new " DBUS_INTERFACE_PROPERTIES
						".PropertiesChanged signal");

		g_print("OUT B : process_properties_from_interface()\n");
		return;
	}

	iface->pending_prop = g_slist_reverse(iface->pending_prop);

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING,	&iface->name);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	invalidated = NULL;

	for (l = iface->pending_prop; l != NULL; l = l->next) {
		GDBusPropertyTable *p = l->data;

		if (p->get == NULL)
			continue;

		if (p->exists != NULL && !p->exists(p, iface->user_data)) {
			invalidated = g_slist_prepend(invalidated, p);
			continue;
		}

		append_property(iface, p, &dict);
	}

	dbus_message_iter_close_container(&iter, &dict);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array);
	for (l = invalidated; l != NULL; l = g_slist_next(l)) {
		GDBusPropertyTable *p = l->data;

		dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING,
								&p->name);
	}
	g_slist_free(invalidated);
	dbus_message_iter_close_container(&iter, &array);

	g_slist_free(iface->pending_prop);
	iface->pending_prop = NULL;

	g_print("-> DBus Method Call : PropertiesChanged()\n");

	/* Use dbus_connection_send to avoid recursive calls to g_dbus_flush */
	dbus_connection_send(data->conn, signal, NULL);
	dbus_message_unref(signal);

	g_print("OUT : process_properties_from_interface()\n");
}

static void process_property_changes(struct generic_data *data)
{
	GSList *l;

	data->pending_prop = FALSE;

	g_print("\nIN : process_property_changes() in (object.c)\n");

	for (l = data->interfaces; l != NULL; l = l->next) {
		struct interface_data *iface = l->data;
		process_properties_from_interface(data, iface);
	}

	g_print("OUT : process_property_changes()\n");
		
}

static void append_name(gpointer data, gpointer user_data)
{
	char *name = data;
	DBusMessageIter *iter = user_data;

	g_print("\nIN : append_name() in (object.c)\n");
	if(name) g_print("-> name : %s\n", name);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &name);

	g_print("OUT : append_name()\n");
}

static void emit_interfaces_removed(struct generic_data *data)
{
	DBusMessage *signal;
	DBusMessageIter iter, array;

	g_print("\nIN : emit_interfaces_removed() in\n");

	if (root == NULL || data == root)
	{
		g_print("OUT A : emit_interfaces_removed()\n");
		return;
	}

	signal = dbus_message_new_signal(root->path,
					DBUS_INTERFACE_OBJECT_MANAGER,
					"InterfacesRemoved");
	if (signal == NULL)
	{
		g_print("OUT B : emit_interfaces_removed()\n");
		return;
	}

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
								&data->path);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_STRING_AS_STRING, &array);


	g_slist_foreach(data->removed, append_name, &array);
	g_slist_free_full(data->removed, g_free);
	data->removed = NULL;

	dbus_message_iter_close_container(&iter, &array);

	g_print("-> DBus Method Call : InterfacesRemoved()\n");
	/* Use dbus_connection_send to avoid recursive calls to g_dbus_flush */
	dbus_connection_send(data->conn, signal, NULL);
	dbus_message_unref(signal);

	g_print("OUT : emit_interfaces_removed()\n");
}

static gboolean process_changes(gpointer user_data)
{
	struct generic_data *data = user_data;

	g_print("\nIN IDLE : process_changes() in\n");

	if(user_data)
	{
		if(data->path) g_print("-> user_data.path : %s\n", data->path);
	}

	remove_pending(data);

	if (data->added != NULL)
	{
		emit_interfaces_added(data);
	}
		
	/* Flush pending properties */
	if (data->pending_prop == TRUE)
	{
		process_property_changes(data);
	}
		
	if (data->removed != NULL)
	{
		emit_interfaces_removed(data);
	}	
		
	data->process_id = 0;

	g_print("OUT : process_changes()\n");

	return FALSE;
}


static void add_pending(struct generic_data *data)
{
	guint old_id = data->process_id;

	g_print("\nIN : add_pending() in\n");

	data->process_id = g_idle_add(process_changes, data);

	if (old_id > 0) {
		/*
		 * If the element already had an old idler, remove the old one,
		 * no need to re-add it to the pending list.
		 */
		g_source_remove(old_id);
		g_print("OUT A : add_pending()\n");
		return;
	}

	pending = g_slist_append(pending, data);
	g_print("OUT : add_pending()\n");
}

static gboolean add_interface(struct generic_data *data,
				const char *name,
				const GDBusMethodTable *methods,
				const GDBusSignalTable *signals,
				const GDBusPropertyTable *properties,
				void *user_data,
				GDBusDestroyFunction destroy)
{
	struct interface_data *iface;
	const GDBusMethodTable *method;
	const GDBusSignalTable *signal;
	const GDBusPropertyTable *property;

	g_print("\nIN : add_interface() in (code : object.c)\n");
	g_print("-> name : %s\n", name);

	g_print("=========== Debug add_interface() arg ============\n");
	print_methods(methods);
	print_signals(signals);
	print_properties(properties);

	for (method = methods; method && method->name; method++) {
		if (!check_experimental(method->flags, G_DBUS_METHOD_FLAG_EXPERIMENTAL))
		{
			g_print("-> method->flag was not G_DBUS_METHOD_FLAG_EXPERIMENTAL\n");
			g_print("-> method name : %s\n", method->name);
			goto done;
		}
	}

	for (signal = signals; signal && signal->name; signal++) {
		if (!check_experimental(signal->flags, G_DBUS_SIGNAL_FLAG_EXPERIMENTAL))
		{
			g_print("-> signal->flag was not G_DBUS_SIGNAL_FLAG_EXPERIMENTAL\n");
			g_print("-> signal name : %s\n", signal->name);
			goto done;
		}
	}

	for (property = properties; property && property->name; property++) {
		if (!check_experimental(property->flags, G_DBUS_PROPERTY_FLAG_EXPERIMENTAL))
		{
			g_print("-> property->flag was not G_DBUS_PROPERTY_FAG_EXPERIMENTAL\n");
			g_print("-> property name : %s\n", property->name);
			goto done;
		}
	}

	/* Nothing to register */
	g_print("-> Nothing to register\n");
	g_print("OUT A : add_interface()\n");
	return FALSE;

done:
	iface = g_new0(struct interface_data, 1);
	iface->name = g_strdup(name);
	iface->methods = methods;
	iface->signals = signals;
	iface->properties = properties;
	iface->user_data = user_data;
	iface->destroy = destroy;

	g_print("-> data->interface append\n");
	data->interfaces = g_slist_append(data->interfaces, iface);
	if (data->parent == NULL)
	{
		g_print("-> data->parent : NULL\n");
		g_print("OUT B : add_interface() \n");
		return TRUE;
	}
	
	data->added = g_slist_append(data->added, iface);

	add_pending(data);

	g_print("OUT : add_interface()\n");
	return TRUE;
}

static void reset_parent(gpointer data, gpointer user_data)
{
	struct generic_data *child = data;
	struct generic_data *parent = user_data;

	g_print("\nIN : reset_parent() in (object.c)\n");

	child->parent = parent;

	g_print("OUT : reset_parent() out\n");
}

static void generic_unregister(DBusConnection *connection, void *user_data)
{
	struct generic_data *data = user_data;
	struct generic_data *parent = data->parent;

	g_print("\nIN HANDLER : generic_unregister() in\n");

	if (parent != NULL)
		parent->objects = g_slist_remove(parent->objects, data);

	if (data->process_id > 0) {
		g_source_remove(data->process_id);
		data->process_id = 0;
		process_changes(data);
	}

	g_slist_foreach(data->objects, reset_parent, data->parent);
	g_slist_free(data->objects);

	dbus_connection_unref(data->conn);
	g_free(data->introspect);
	g_free(data->path);
	g_free(data);

	g_print("OUT : generic_unregister()\n");
}

static gboolean g_dbus_args_have_signature(const GDBusArgInfo *args,
							DBusMessage *message)
{
	const char *sig = dbus_message_get_signature(message);
	const char *p = NULL;

	g_print("\nIN : g_dbus_args_have_signature() in (object.c)\n");

	for (; args && args->signature && *sig; args++) {
		p = args->signature;

		for (; *sig && *p; sig++, p++) {
			if (*p != *sig)
			{
				g_print("OUT A : g_dbus_args_have_signature()\n");
				return FALSE;
			}
		}
	}

	if (*sig || (p && *p) || (args && args->signature))
	{
		g_print("OUT B : g_dbus_args_have_signature()\n");
		return FALSE;
	}
		
	g_print("OUT : g_dbus_args_have_signature()\n");
	return TRUE;
}

static gboolean check_signal(DBusConnection *conn, const char *path,
				const char *interface, const char *name,
				const GDBusArgInfo **args)
{
	struct generic_data *data = NULL;
	struct interface_data *iface;
	const GDBusSignalTable *signal;

	g_print("\nIN : check_signal() in (object.c)\n");
	if(path) g_print("-> path : %s\n", path);
	if(interface) g_print("-> interface : %s\n", interface);
	if(name) g_print("-> name : %s\n", name);

	*args = NULL;
	if (!dbus_connection_get_object_path_data(conn, path,
					(void *) &data) || data == NULL) {
		error("dbus_connection_emit_signal: path %s isn't registered",
				path);
		g_print("OUT A : check_signal()\n");
		return FALSE;
	}

	iface = find_interface(data->interfaces, interface);
	if (iface == NULL) {
		error("dbus_connection_emit_signal: %s does not implement %s",
				path, interface);
		g_print("OUT B : check_signal()\n");
		return FALSE;
	}

	for (signal = iface->signals; signal && signal->name; signal++) {
		if (strcmp(signal->name, name) != 0)
			continue;

		if (signal->flags & G_DBUS_SIGNAL_FLAG_EXPERIMENTAL) {
			const char *env = g_getenv("GDBUS_EXPERIMENTAL");
			if (g_strcmp0(env, "1") != 0)
				break;
		}

		*args = signal->args;

		g_print("OUT C : check_signal()\n");
		return TRUE;
	}

	error("No signal named %s on interface %s", name, interface);
	g_print("OUT : check_signal()\n");
	return FALSE;
}

static void g_dbus_flush(DBusConnection *connection)
{
	GSList *l;

	g_print("\nIN : g_dbus_flush() in (object.c)\n");

	for (l = pending; l;) {
		struct generic_data *data = l->data;

		l = l->next;
		if (data->conn != connection)
			continue;

		process_changes(data);
	}
	g_print("OUT : g_dbus_flush()\n");
}

gboolean g_dbus_send_message(DBusConnection *connection, DBusMessage *message)
{
	dbus_bool_t result = FALSE;

	g_print("\nIN : g_dbus_send_message() in (object.c)\n");

	if (!message)
	{
		g_print("OUT A : g_dbus_send_message()\n");
		return FALSE;
	}

	int type = dbus_message_get_type(message);
	g_print("-> message.type : %d\n", type);

	const char* interface = dbus_message_get_interface(message);
	if(interface)
	{
		g_print("-> message.interface : %s\n", interface);
	} 

	const char* path = dbus_message_get_path(message);
	if(path)
	{
		g_print("-> message.path : %s\n", path);
	} 

	const char* member = dbus_message_get_member(message);
	if(member)
	{
		g_print("-> message.member : %s\n", member);
	} 

	if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_METHOD_CALL)
		dbus_message_set_no_reply(message, TRUE);
	else if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_SIGNAL) {
		const char *path = dbus_message_get_path(message);
		const char *interface = dbus_message_get_interface(message);
		const char *name = dbus_message_get_member(message);
		const GDBusArgInfo *args;

		if (!check_signal(connection, path, interface, name, &args))
			goto out;
	}

	/* Flush pending signal to guarantee message order */
	g_dbus_flush(connection);

	result = dbus_connection_send(connection, message, NULL);
	
	g_print("OUT : g_dbus_send_message()\n");
out:
	dbus_message_unref(message);

	g_print("OUT B : g_dbus_send_message()\n");
	return result;
}

static DBusHandlerResult process_message(DBusConnection *connection,
			DBusMessage *message, const GDBusMethodTable *method,
							void *iface_user_data)
{
	DBusMessage *reply;

	g_print("\nIN : process_message() in (object.c)\n");

	if(message)
	{
		int type = dbus_message_get_type(message);
		g_print("-> message.type : %d\n", type);

		const char* path = dbus_message_get_path(message);
		if(path) g_print("-> message.path : %s\n", path);

		const char* interface = dbus_message_get_interface(message);
		if(interface) g_print("-> message.interface : %s\n", interface);

		const char* member = dbus_message_get_member(message);
		if(member) g_print("-> message.member : %s\n", member);
	}

	if(method)
	{
		g_print("-> method : %s\n", method->name);
	}

	reply = method->function(connection, message, iface_user_data);

	if (method->flags & G_DBUS_METHOD_FLAG_NOREPLY ||
					dbus_message_get_no_reply(message)) {
		if (reply != NULL)
			dbus_message_unref(reply);
		
		g_print("OUT A : process_message()\n");
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (method->flags & G_DBUS_METHOD_FLAG_ASYNC) {
		if (reply == NULL)
		{
			g_print("OUT B : process_message()\n");
			return DBUS_HANDLER_RESULT_HANDLED;
		}
			
	}

	if (reply == NULL)
	{
		g_print("OUT C : process_message()\n");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}
		

	g_print("-> GDBus Method Call : %s\n", method->name);
	g_dbus_send_message(connection, reply);

	g_print("OUT : process_message()\n");
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult generic_message(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct generic_data *data = user_data;
	struct interface_data *iface;
	const GDBusMethodTable *method;
	const char *interface;

	g_print("\nIN HANDLER : generic_message() in\n");

	interface = dbus_message_get_interface(message);
	if(interface) g_print("-> message.interface : %s\n", interface);

	iface = find_interface(data->interfaces, interface);
	if (iface == NULL)
	{
		g_print("OUT A : generic_message()\n");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
		

	for (method = iface->methods; method &&
			method->name && method->function; method++) {

		if (dbus_message_is_method_call(message, iface->name,
							method->name) == FALSE)
			continue;

		if (check_experimental(method->flags,
					G_DBUS_METHOD_FLAG_EXPERIMENTAL))
		{
			g_print("OUT B : generic_message()\n");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
			
		if (g_dbus_args_have_signature(method->in_args,
							message) == FALSE)
			continue;

		/*
		if (check_privilege(connection, message, method,
						iface->user_data) == TRUE)
		{
			g_print("OUT C : generic_message()\n");
			return DBUS_HANDLER_RESULT_HANDLED;
		}
		*/	

		g_print("OUT D : generic_message() \n");
		return process_message(connection, message, method,
							iface->user_data);
	}

	g_print("OUT : generic_message()\n");
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusObjectPathVTable generic_table = {
	.unregister_function	= generic_unregister,
	.message_function	= generic_message,
};

static void print_arguments(GString *gstr, const GDBusArgInfo *args,
						const char *direction)
{
	for (; args && args->name; args++) {
		g_string_append_printf(gstr,
					"<arg name=\"%s\" type=\"%s\"",
					args->name, args->signature);

		if (direction)
			g_string_append_printf(gstr,
					" direction=\"%s\"/>\n", direction);
		else
			g_string_append_printf(gstr, "/>\n");

	}
}

static void generate_interface_xml(GString *gstr, struct interface_data *iface)
{
	const GDBusMethodTable *method;
	const GDBusSignalTable *signal;
	const GDBusPropertyTable *property;

	g_print("\nIN : generate_interface_xml() in (object.c)\n");

	for (method = iface->methods; method && method->name; method++) {
		if (check_experimental(method->flags,
					G_DBUS_METHOD_FLAG_EXPERIMENTAL))
			continue;

		g_string_append_printf(gstr, "<method name=\"%s\">",
								method->name);
		print_arguments(gstr, method->in_args, "in");
		print_arguments(gstr, method->out_args, "out");

		if (method->flags & G_DBUS_METHOD_FLAG_DEPRECATED)
			g_string_append_printf(gstr,
						G_DBUS_ANNOTATE_DEPRECATED);

		if (method->flags & G_DBUS_METHOD_FLAG_NOREPLY)
			g_string_append_printf(gstr, G_DBUS_ANNOTATE_NOREPLY);

		g_string_append_printf(gstr, "</method>");
	}

	for (signal = iface->signals; signal && signal->name; signal++) {
		if (check_experimental(signal->flags,
					G_DBUS_SIGNAL_FLAG_EXPERIMENTAL))
			continue;

		g_string_append_printf(gstr, "<signal name=\"%s\">",
								signal->name);
		print_arguments(gstr, signal->args, NULL);

		if (signal->flags & G_DBUS_SIGNAL_FLAG_DEPRECATED)
			g_string_append_printf(gstr,
						G_DBUS_ANNOTATE_DEPRECATED);

		g_string_append_printf(gstr, "</signal>\n");
	}

	for (property = iface->properties; property && property->name;
								property++) {
		if (check_experimental(property->flags,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL))
			continue;

		g_string_append_printf(gstr, "<property name=\"%s\""
					" type=\"%s\" access=\"%s%s\">",
					property->name,	property->type,
					property->get ? "read" : "",
					property->set ? "write" : "");

		if (property->flags & G_DBUS_PROPERTY_FLAG_DEPRECATED)
			g_string_append_printf(gstr,
						G_DBUS_ANNOTATE_DEPRECATED);

		g_string_append_printf(gstr, "</property>");
	}

	g_print("OUT : generate_interface_xml() out\n");
}

static void generate_introspection_xml(DBusConnection *conn,
				struct generic_data *data, const char *path)
{
	GSList *list;
	GString *gstr;
	char **children;
	int i;

	g_print("\nIN : generate_introspection_xml() in (object.c)\n");
	if(path) g_print("-> path : %s\n", path);

	g_free(data->introspect);

	gstr = g_string_new(DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE);

	g_string_append_printf(gstr, "<node>");

	for (list = data->interfaces; list; list = list->next) {
		struct interface_data *iface = list->data;

		g_string_append_printf(gstr, "<interface name=\"%s\">",
								iface->name);

		generate_interface_xml(gstr, iface);

		g_string_append_printf(gstr, "</interface>");
	}

	if (!dbus_connection_list_registered(conn, path, &children))
		goto done;

	for (i = 0; children[i]; i++)
		g_string_append_printf(gstr, "<node name=\"%s\"/>",
								children[i]);

	dbus_free_string_array(children);

	g_print("OUT : generate_introspection_xml()\n");
done:
	g_string_append_printf(gstr, "</node>");

	data->introspect = g_string_free(gstr, FALSE);

	g_print("OUT A : generate_introspection_xml() out\n");
}

static DBusMessage *introspect(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct generic_data *data = user_data;
	DBusMessage *reply;

	g_print("\nIN HANDLER : introspect() in (object.c)\n");

	if (data->introspect == NULL)
		generate_introspection_xml(connection, data,
						dbus_message_get_path(message));

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
	{
		g_print("OUT A : introspect()\n");
		return NULL;
	}	

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &data->introspect,
					DBUS_TYPE_INVALID);

	g_print("OUT : introspect() out\n");

	return reply;
}

static const GDBusMethodTable introspect_methods[] = {
	{ GDBUS_METHOD("Introspect", NULL,
			GDBUS_ARGS({ "xml", "s" }), introspect) },
	{ }
};

static struct generic_data *invalidate_parent_data(DBusConnection *conn,
						const char *child_path)
{
	struct generic_data *data = NULL, *child = NULL, *parent = NULL;
	char *parent_path, *slash;

	g_print("\nIN : invalidate_parent_data() in\n");
	if(child_path) g_print("-> child_path : %s\n", child_path);

	parent_path = g_strdup(child_path);
	slash = strrchr(parent_path, '/');

	g_print("-> slash : %s\n", slash);

	if (slash == NULL)
		goto done;

	if (slash == parent_path && parent_path[1] != '\0')
		parent_path[1] = '\0';
	else
		*slash = '\0';

	if (!strlen(parent_path))
		goto done;

	if (dbus_connection_get_object_path_data(conn, parent_path,
							(void *) &data) == FALSE) {
		g_print("-> Not enough memory\n");
		goto done;
	}
	else
	{
		if(data == NULL) g_print("-> Path %s have not data\n", parent_path);
		else g_print("-> Path %s have data\n", parent_path);
	}

	parent = invalidate_parent_data(conn, parent_path);

	if (data == NULL) {
		data = parent;
		if (data == NULL)
			goto done;
	}

	g_free(data->introspect);
	data->introspect = NULL;

	if (!dbus_connection_get_object_path_data(conn, child_path,
							(void *) &child))
		goto done;

	if (child == NULL || g_slist_find(data->objects, child) != NULL)
		goto done;

	data->objects = g_slist_prepend(data->objects, child);
	child->parent = data;

	g_print("OUT : invalidate_parent_data()\n");
done:
	g_free(parent_path);

	g_print("OUT A : invalidate_parent_data()\n");
	return data;
}

static void append_interfaces(struct generic_data *data, DBusMessageIter *iter)
{
	DBusMessageIter array;

	g_print("\nIN : append_interfaces() in (object.c)\n");

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_ARRAY_AS_STRING
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &array);

	g_slist_foreach(data->interfaces, append_interface, &array);

	dbus_message_iter_close_container(iter, &array);

	g_print("OUT : append_interfaces()\n");
}

static void append_object(gpointer data, gpointer user_data)
{
	struct generic_data *child = data;
	DBusMessageIter *array = user_data;
	DBusMessageIter entry;

	g_print("\nIN : append_object() in (object.c)\n");

	dbus_message_iter_open_container(array, DBUS_TYPE_DICT_ENTRY, NULL,
								&entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH,
								&child->path);
	
	append_interfaces(child, &entry);
	dbus_message_iter_close_container(array, &entry);

	g_slist_foreach(child->objects, append_object, user_data);

	g_print("OUT : append_object()\n");
}

static DBusMessage *get_objects(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct generic_data *data = user_data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter array;

	g_print("\nIN : get_objects() in (object.c)\n");

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
	{	
		g_print("OUT A : get_objects()\n");
		return NULL;
	}

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_OBJECT_PATH_AS_STRING
					DBUS_TYPE_ARRAY_AS_STRING
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_ARRAY_AS_STRING
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&array);

	g_slist_foreach(data->objects, append_object, &array);

	dbus_message_iter_close_container(&iter, &array);

	g_print("OUT : get_objects()\n");
	return reply;
}

static const GDBusMethodTable manager_methods[] = {
	{ GDBUS_METHOD("GetManagedObjects", NULL,
		GDBUS_ARGS({ "objects", "a{oa{sa{sv}}}" }), get_objects) },
	{ }
};

static const GDBusSignalTable manager_signals[] = {
	{ GDBUS_SIGNAL("InterfacesAdded",
		GDBUS_ARGS({ "object", "o" },
				{ "interfaces", "a{sa{sv}}" })) },
	{ GDBUS_SIGNAL("InterfacesRemoved",
		GDBUS_ARGS({ "object", "o" }, { "interfaces", "as" })) },
	{ }
};

gboolean dbus_attach_object_manager(DBusConnection* in_connection)
{
	struct generic_data *data;
	const char path[] = "/";

	if (dbus_connection_get_object_path_data(in_connection, path,
						(void *) &data) == TRUE) {
		if (data != NULL) {
			//path("/") 상에 Attach된 Object가 존재한다면, 그대로 사용한다.  
			data->refcount++;
		}
		else
		{
			//path("/") 상에 Attach된 Object가 존재하지 않는다면, 새로 생성하여 등록한다. 
			data = g_new0(struct generic_data, 1);
			data->conn = dbus_connection_ref(in_connection);
			data->path = g_strdup(path);
			data->refcount = 1;
			data->introspect = g_strdup(DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE "<node></node>");

			if (!dbus_connection_register_object_path(in_connection, path, &generic_table, data)) {
				//path("/")에 Object 등록을 실패한 경우, 생성한 모든 Object 변수 동적할당 해제
				dbus_connection_unref(data->conn);
				g_free(data->path);
				g_free(data->introspect);
				g_free(data);

				return FALSE;
			}
			
			g_print("-> dbus_connection_register_object_path() success\n");

			invalidate_parent_data(in_connection, path);

			add_interface(data, DBUS_INTERFACE_INTROSPECTABLE, introspect_methods, NULL, NULL, data, NULL);
		}
	}
	else
	{
		g_print("dbus_connection_get_object_path_data() is FALSE\n");
		return FALSE;
	}

	add_interface(data, DBUS_INTERFACE_OBJECT_MANAGER, manager_methods, manager_signals, NULL, data, NULL);

	root = data;

	g_print("OUT : g_dbus_attach_object_manager()\n");

	return TRUE;
}