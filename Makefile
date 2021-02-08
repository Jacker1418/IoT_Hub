CC=gcc
TARGET=bluez

LDLIBS:= `pkg-config --libs glib-2.0 gio-2.0 dbus-1`
CLFAGS:= `pkg-config --cflags glib-2.0 gio-2.0 dbus-1` -Wall -Wextra

INCLUDE:= -I./lib -I./src

all:
	$(CC) $(CLFAGS) $(LDLIBS) $(INCLUDE) -o $(TARGET) ./main.c