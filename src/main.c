#include "main.h"

DBusConnection* dbus_connection;

int main(int argc, char* argv[])
{
    GDBusClient *client;

    dbus_connection = dbus_init(DBUS_BUS_SYSTEM, NULL, NULL);

    gboolean result = dbus_attach_object_manager(dbus_connection);
    if(!result)
    {
        g_print("dbus_attach_object_manager() is Fail\n");
        return 0;
    }

    return 0;
}