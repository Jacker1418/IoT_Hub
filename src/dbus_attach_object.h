#ifndef __DBUS_ATTACH_OBJECT_H__
#define __DBUS_ATTACH_OBJECT_H__

#include <stdio.h>
#include <string.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "gdbus.h"

#define DBUS_INTERFACE_OBJECT_MANAGER "org.freedesktop.DBus.ObjectManager"

#define G_DBUS_ANNOTATE(name_, value_)	"<annotation name=\"org.freedesktop.DBus." name_ "\" " "value=\"" value_ "\"/>"

#define G_DBUS_ANNOTATE_DEPRECATED G_DBUS_ANNOTATE("Deprecated", "true")

#define G_DBUS_ANNOTATE_NOREPLY G_DBUS_ANNOTATE("Method.NoReply", "true")

struct generic_data {
	unsigned int refcount;
	DBusConnection *conn;
	char *path;
	GSList *interfaces;
	GSList *objects;
	GSList *added;
	GSList *removed;
	guint process_id;
	gboolean pending_prop;
	char *introspect;
	struct generic_data *parent;
};

struct interface_data {
	char *name;
	const GDBusMethodTable *methods;
	const GDBusSignalTable *signals;
	const GDBusPropertyTable *properties;
	GSList *pending_prop;
	void *user_data;
	GDBusDestroyFunction destroy;
};

gboolean dbus_attach_object_manager(DBusConnection* in_connection);

#endif
