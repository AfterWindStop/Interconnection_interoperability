export C_INCLUDE_PATH=./openssl/include:$C_INCLUDE_PATH

CC=gcc
CFLAGS=-Werror
EXEC=xjsdk
LIB_NAME=libxjsdk.a
AR=ar rcs

SOURCES = internal_msg.c ./base64/base64.c ./source/bus_announce.c ./source/connect_manage.c ./source/util.c ./source/common_log.c
OBJFILES = $(SOURCES:%.c=%.o)
HEADERS = internal_msg.h ./source/bus_announce.h ./source/connect_manage.h ./source/util.h ./source/common_log.h#./mqtt/include/
#HEADERS+=-I./mqtt/include

CFLAGS+=-I./mqtt/include/
CFLAGS+=-I./cjson/include/
CFLAGS+=-I./uuid/include/
CFLAGS+=-I./base64/

$(EXEC):main.c $(LIB_NAME) $(HEADERS)
	@echo
	@echo linking $@ from $<..
	${CC} -g ${CFLAGS} -o $@ $^ -lpthread -L./mqtt/lib -lmosquitto -lmosquittopp -L./uuid/lib -luuid -L./cjson/lib -lcjson -L./openssl/lib -lssl -lcrypto -lrt -Wl,-rpath=../lib

$(LIB_NAME):  $(OBJFILES)
	@echo 
	@echo linking $@ from $<..
	${AR} -o $@ $^

$(OBJFILES): %.o: %.c $(HEADERS)
	@echo
	@echo Compiling $@ from $<..
	${CC} -g -c -o $@ $<

.PHONY: clean $(LIB_NAME) $(EXEC)

clean:
	@echo
	@echo Removing generated files...
	rm -rf $(EXEC) $(LIB_NAME) *.o ./source/*.o
