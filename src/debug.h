#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdio.h>
#include <string.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "gdbus.h"

void print_methods(const GDBusMethodTable* in_method);
void print_signals(const GDBusSignalTable* in_signal);
void print_properties(const GDBusPropertyTable* in_property);
void print_interfaces(gpointer in_interface, gpointer in_user_data);

#endif
