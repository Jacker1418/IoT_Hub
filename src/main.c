#include "main.h"

DBusConnection* inst_dbus_connection;

int main(int argc, char* argv[])
{
    inst_dbus_connection = dbus_init(DBUS_BUS_SYSTEM, NULL, NULL);

    return 0;
}