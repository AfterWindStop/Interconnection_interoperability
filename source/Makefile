OBJS := $(patsubst %.S,${OUTPUT_OBJ_DIR}/%.o,$(wildcard *.S)) 
OBJC := $(patsubst %.c,${OUTPUT_OBJ_DIR}/%.o,$(wildcard *.c)) 
DEPS := $(patsubst %.c,${OUTPUT_OBJ_DIR}/%.d,$(wildcard *.c))


OBJ := $(DEPS) ${OBJS} ${OBJC}

all: ${OBJ}

$(OUTPUT_OBJ_DIR)/%.d: %.c
	$(CC) -MM $(CFLAGS) $< | sed  -e s!$(patsubst %.c,%.o,$<):!$(patsubst %.c,$(OUTPUT_OBJ_DIR)/%.o,$<):! > $@
-include ${DEPS}

$(OUTPUT_OBJ_DIR)/%.o : %.c
	$(CC) $(CFLAGS) -c $(PICFLAG) $< -o $@

