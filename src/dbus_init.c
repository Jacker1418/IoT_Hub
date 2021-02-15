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

static gboolean message_dispatch(void *data)
{
	DBusConnection *conn = data;

	g_print("\nIN IDLE : message_dispatch() in (mainloop.c)\n");

	/* Dispatch messages */
	while (dbus_connection_dispatch(conn) == DBUS_DISPATCH_DATA_REMAINS);

	dbus_connection_unref(conn);

	g_print("OUT : message_dispatch()\n");

	return FALSE;
}

static inline void queue_dispatch(DBusConnection *conn,
						DBusDispatchStatus status)
{
	g_print("\nIN : queue_dispatch() in (mainloop.c)\n");
	if (status == DBUS_DISPATCH_DATA_REMAINS)
	{
		g_print("-> status : DBUS_DISPATCH_DATA_REMAINS\n");
		g_idle_add(message_dispatch, dbus_connection_ref(conn));
	}
	else
	{
		if(status == DBUS_DISPATCH_COMPLETE) g_print("-> status : DBUS_DISPATCH_COMPLETE\n");
		if(status == DBUS_DISPATCH_NEED_MEMORY) g_print("-> status : DBUS_DISPATCH_NEED_MEMORY\n");
	}

	g_print("OUT : queue_dispatch()\n");
}

static gboolean watch_func(GIOChannel *chan, GIOCondition cond, gpointer data)
{

	g_print("\nIN IO_WATCH : watch_func() in  (mainloop.c)\n");

	struct watch_info *info = data;
	unsigned int flags = 0;
	DBusDispatchStatus status;
	DBusConnection *conn;

	if (cond & G_IO_IN)  flags |= DBUS_WATCH_READABLE;
	if (cond & G_IO_OUT) flags |= DBUS_WATCH_WRITABLE;
	if (cond & G_IO_HUP) flags |= DBUS_WATCH_HANGUP;
	if (cond & G_IO_ERR) flags |= DBUS_WATCH_ERROR;

	/* Protect connection from being destroyed by dbus_watch_handle */
	conn = dbus_connection_ref(info->conn);

	dbus_watch_handle(info->watch, flags);

	status = dbus_connection_get_dispatch_status(conn);

	queue_dispatch(conn, status);

	dbus_connection_unref(conn);

	g_print("OUT : watch_func()\n");

	return TRUE;
}

static void watch_info_free(void *data)
{
	struct watch_info *info = data;

	g_print("\nIN Handler : watch_info_free() in  (mainloop.c)\n");

	if (info->id > 0) {
		g_source_remove(info->id);
		info->id = 0;
	}

	dbus_connection_unref(info->conn);

	g_free(info);

	g_print("OUT : watch_info_free()\n");
}

static dbus_bool_t add_watch(DBusWatch *watch, void *data)
{
	DBusConnection *conn = data;
	GIOCondition cond = G_IO_HUP | G_IO_ERR;
	GIOChannel *chan;
	struct watch_info *info;
	unsigned int flags;
	int fd;

	g_print("\nIN HANDLER : add_watch() in  (mainloop.c)\n");

	if (!dbus_watch_get_enabled(watch))
	{
		g_print("OUT A : add_watch()\n");
		return TRUE;
	}

	info = g_new0(struct watch_info, 1);

	fd = dbus_watch_get_unix_fd(watch);
	chan = g_io_channel_unix_new(fd);

	info->watch = watch;
	info->conn = dbus_connection_ref(conn);

	dbus_watch_set_data(watch, info, watch_info_free);

	flags = dbus_watch_get_flags(watch);

	if (flags & DBUS_WATCH_READABLE) cond |= G_IO_IN;
	if (flags & DBUS_WATCH_WRITABLE) cond |= G_IO_OUT;

	info->id = g_io_add_watch(chan, cond, watch_func, info);

	g_io_channel_unref(chan);

	g_print("OUT : add_watch()\n");

	return TRUE;
}

static void remove_watch(DBusWatch *watch, void *data)
{
	g_print("\nIN HANDLER : remove_watch() in (mainloop.c)\n");

	if (dbus_watch_get_enabled(watch))
	{
		g_print("OUT A : remove_watch()\n");
		return;
	}

	/* will trigger watch_info_free() */
	dbus_watch_set_data(watch, NULL, NULL);

	g_print("OUT : remove_watch()\n");
}

static void watch_toggled(DBusWatch *watch, void *data)
{
	g_print("\nIN Handler : watch_toggled() in (mainloop.c)\n");
	/* Because we just exit on OOM, enable/disable is
	 * no different from add/remove */
	if (dbus_watch_get_enabled(watch))
	{
		add_watch(watch, data);
	}
		
	else
	{
		remove_watch(watch, data);
	}
	
	g_print("OUT : watch_toggled()\n");
}

static gboolean timeout_handler_dispatch(gpointer data)
{
	struct timeout_handler *handler = data;

	if(DEBUG_TIMOUT_LOG) g_print("\nIN HANDLER : timeout_handler_dispatch() in (id : %d)\n", handler->id);

	handler->id = 0;

	/* if not enabled should not be polled by the main loop */
	if (!dbus_timeout_get_enabled(handler->timeout))
	{
		g_print("OUT A : timeout_handler_dispatch()\n");
		return FALSE;
	}

	dbus_timeout_handle(handler->timeout);

	if(DEBUG_TIMOUT_LOG) g_print("OUT : timeout_handler_dispatch()\n");

	return FALSE;
}

static void timeout_handler_free(void *data)
{
	struct timeout_handler *handler = data;

	if(DEBUG_TIMOUT_LOG) g_print("\nIN HANDLER : timeout_handler_free() in (id : %d)\n", handler->id);
	if (handler->id > 0) {
		g_source_remove(handler->id);
		handler->id = 0;
	}

	g_free(handler);

	if(DEBUG_TIMOUT_LOG) g_print("OUT : timeout_handler_free()\n");
}

static dbus_bool_t add_timeout(DBusTimeout *timeout, void *data)
{

	int interval = dbus_timeout_get_interval(timeout);

	struct timeout_handler *handler;

	if(DEBUG_TIMOUT_LOG) g_print("\nIN HANDLER : add_timeout() in (id : %d)\n", handler->id);

	if (!dbus_timeout_get_enabled(timeout))
	{
		if(DEBUG_TIMOUT_LOG) g_print("OUT A : add_timeout()\n");
		return TRUE;
	}

	handler = g_new0(struct timeout_handler, 1);

	handler->timeout = timeout;

	dbus_timeout_set_data(timeout, handler, timeout_handler_free);

	handler->id = g_timeout_add(interval, timeout_handler_dispatch,
								handler);

	if(DEBUG_TIMOUT_LOG) g_print("OUT : add_timeout()\n");

	return TRUE;
}

static void remove_timeout(DBusTimeout *timeout, void *data)
{
	if(DEBUG_TIMOUT_LOG) g_print("\nIN HANDLER : remove_timeout() in (mainloop.c)\n");
	/* will trigger timeout_handler_free() */
	dbus_timeout_set_data(timeout, NULL, NULL);

	if(DEBUG_TIMOUT_LOG) g_print("OUT : remove_timeout()\n");
}

static void timeout_toggled(DBusTimeout *timeout, void *data)
{
	if(DEBUG_TIMOUT_LOG) g_print("\nIN HANDLER : timeout_toggled() in (mainloop.c)\n");
	if (dbus_timeout_get_enabled(timeout))
	{
		add_timeout(timeout, data);
	}
	else
	{
		remove_timeout(timeout, data);
	}
		
	if(DEBUG_TIMOUT_LOG) g_print("OUT : timeout_toggled()\n");
}

static void dispatch_status(DBusConnection *conn,
					DBusDispatchStatus status, void *data)
{
	g_print("\nIN HANDLER : dispatch_status() in (mainloop.c)\n");
	
	if (!dbus_connection_get_is_connected(conn))
	{
		g_print("OUT A : dispatch_status()\n");
		return;
	}

	queue_dispatch(conn, status);

	g_print("OUT : dispatch_status()\n");
}

DBusConnection* dbus_init(DBusBusType in_type, const char *in_name, DBusError *out_error)
{
    DBusConnection *result = NULL;
    DBusDispatchStatus status;

	//dbus deamon으로부터 DBusConnection Instance를 얻어온다.
    result = dbus_bus_get(in_type, out_error);
    if(out_error != NULL)
    {
		//dbus_bus_get() 함수의 동작에 Error가 있을 경우, Error 확인
        if(dbus_error_is_set(out_error) == TRUE)
        {
            return NULL;
        }
    }

    if(result == NULL)
    {
        return NULL;
    }

    //setup_bus() 함수를 래퍼런스
    //setup_dbus_with_main_loop() 함수내의 Watch, Timeout, Dispatch Handler 등록
    //1. dbus에서 발생하는 IO Event에 대한 감시용 Handler를 등록한다. 
	dbus_connection_set_watch_functions(result, add_watch, remove_watch, watch_toggled, result, NULL);

    //2. dbus 함수 호출에 대한 Timer에 대해 생성 및 만료 시 호출될 Handler를 등록한다.
	dbus_connection_set_timeout_functions(result, add_timeout, remove_timeout, timeout_toggled, NULL, NULL);

    //3. dbus를 통해 얻은 message에 대해 Dispatch할 수 있도록 Handler를 등록한다. 
	dbus_connection_set_dispatch_status_function(result, dispatch_status, NULL, NULL);

    status = dbus_connection_get_dispatch_status(result);
    
	//dbus message Queue 확인
    queue_dispatch(result, status);

    return result;
}