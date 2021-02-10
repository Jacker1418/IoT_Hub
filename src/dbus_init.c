#include "dbus_init.h"

#define DEBUG_TIMOUT_LOG FALSE

struct timeout_handler {
	guint id;
	DBusTimeout *timeout;
};

struct watch_info {
	guint id;
	DBusWatch *watch;
	DBusConnection *conn;
};

DBusConnection* dbus_init(DBusBusType in_type, const char *in_name, DBusError *out_error)
{
    DBusConnection *result = NULL;

    result = dbus_bus_get(in_type, out_error);
    if(out_error != NULL)
    {
        if(dbus_error_is_set(out_error) == TRUE)
        {
            return NULL;
        }
    }

    if(result == NULL)
    {
        return NULL;
    }
}