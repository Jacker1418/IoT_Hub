#include "debug.h"
#include "dbus_attach_object.h"

void print_methods(const GDBusMethodTable* in_method)
{
	const GDBusMethodTable *method = in_method;

	if(in_method == NULL) g_print("-> in_method is NULL\n");

	for (method = in_method; method && method->name; method++) 
	{
		g_print("-> generic_data->method : %s\n", method->name);
	}
	
}

void print_signals(const GDBusSignalTable* in_signal)
{
	const GDBusSignalTable *signal = in_signal;

	if(in_signal == NULL) g_print("-> in_signal is NULL\n");

	for (signal = in_signal; signal && signal->name; signal++) 
	{
		g_print("-> generic_data->signal : %s\n", signal->name);
	}
	
}

void print_properties(const GDBusPropertyTable* in_property)
{
	const GDBusPropertyTable *property = in_property;

	if(in_property == NULL) g_print("-> in_property is NULL\n");

	for (property = in_property; property && property->name; property++) 
	{
		g_print("-> generic_data->property : %s\n", property->name);
	}
}

void print_interfaces(gpointer in_interface, gpointer in_user_data)
{
	struct interface_data *iface = in_interface;
	g_print("-> generic_data->interface : %s\n", iface->name);

	print_methods(iface->methods);
	print_signals(iface->signals);
	print_properties(iface->properties);	
}
