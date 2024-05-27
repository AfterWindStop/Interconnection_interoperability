export C_INCLUDE_PATH=./openssl/include:$C_INCLUDE_PATH

CC=/home/lihelong/homeplatform/route/cross_compiler/arm-linux-glibc/usr/bin/arm-linux-gcc
#CC=/home/lihelong/homeplatform/gateway/arm-linux-glibc/usr/bin/arm-linux-gcc
CFLAGS=-Werror
EXEC=xjsdk
LIB_NAME=libxjsdk.a
AR=ar rcs

SOURCES = internal_msg.c ./base64/base64.c ./source/bus_announce.c ./source/connect_manage.c ./source/util.c ./source/common_log.c
OBJFILES = $(SOURCES:%.c=%.o)
HEADERS = internal_msg.h ./source/bus_announce.h ./source/connect_manage.h ./source/util.h ./source/common_log.h#./mqtt/include/

CFLAGS+=-I./mqtt/include/
CFLAGS+=-I./cjson/include/
CFLAGS+=-I./uuid/include/
CFLAGS+=-I./base64/

$(EXEC):main.c $(LIB_NAME) $(HEADERS)
	@echo
	@echo linking $@ from $<..
	${CC} -g ${CFLAGS} -o $@ $^ -lpthread -L./mqtt/lib -lmosquitto -lmosquittopp -L./cjson/lib -lcjson -L./dis/lib/ -L./curl/lib -lcurl -lrt -Wl,-rpath=../lib -L./openssl/lib -lssl -lcrypto

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
