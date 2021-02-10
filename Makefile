## Makefile 설계 시 참고사항 https://modoocode.com/311

CC=gcc
TARGET=bluez

LDLIBS = `pkg-config --libs glib-2.0 gio-2.0 dbus-1`
CLFAGS = `pkg-config --cflags glib-2.0 gio-2.0 dbus-1` -Wall -Wextra

SRC_DIR = ./src

OBJ_DIR = ./obj

SOURCES = $(notdir $(wildcard $(SRC_DIR)/*.c))
OBJECTS = $(SOURCES:.c=.o)

OBJECT_LIST = $(patsubst %.o, $(OBJ_DIR)/%.o, $(OBJECTS))
DEPENDENCYS = $(OBJECT_LIST:.o=.d)

all: bluez

$(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) $(CLFAGS) -c $< -o $@ -MD $(LDLIBS)

$(TARGET) : $(OBJECT_LIST)
	$(CC) $(CLFAGS) $(OBJECT_LIST) -o $(TARGET) $(LDLIBS)

clean:
	rm -f $(OBJECT_LIST) $(DEPENDENCYS) $(TARGET)

-include $(DEPENDENCYS)