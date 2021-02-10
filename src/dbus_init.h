#ifndef __DBUS_INIT_H__
#define __DBUS_INIT_H__

#include <glib.h>
#include <dbus/dbus.h>

DBusConnection* dbus_init(DBusBusType in_type, const char *in_name, DBusError *out_error);

#endif
