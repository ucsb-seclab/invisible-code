include ../flags.mk
include ../config.mk

OUT_DIR := $(OO)/libdrmcode

.PHONY: all libdrmcode clean

all: libdrmcode
################################################################################
# Teec configuration
################################################################################
MAJOR_VERSION	:= 1
MINOR_VERSION	:= 0
LIB_NAME	:= libdrmcode.so
LIB_MAJOR	:= $(LIB_NAME).$(MAJOR_VERSION)
LIB_MAJ_MIN	:= $(LIB_NAME).$(MAJOR_VERSION).$(MINOR_VERSION)

TEEC_SRCS	:= drm_init.c

TEEC_SRC_DIR	:= src
TEEC_OBJ_DIR	:= $(OUT_DIR)
TEEC_OBJS 	:= $(patsubst %.c,$(TEEC_OBJ_DIR)/%.o, $(TEEC_SRCS))
TEEC_INCLUDES 	:= \
		   ${CURDIR}/include \
		   ${CURDIR}/../public \

TEEC_CFLAGS	:= $(addprefix -I, $(TEEC_INCLUDES)) $(CFLAGS) -D_GNU_SOURCE \
		   -DDEBUGLEVEL_$(CFG_TEE_CLIENT_LOG_LEVEL) \
		   -DBINARY_PREFIX=\"DRM\"

TEEC_LFLAGS    :=
TEEC_LIBRARY	:= $(OUT_DIR)/$(LIB_MAJ_MIN)

libdrmcode: $(TEEC_LIBRARY)
	$(VPREFIX)ln -sf $(TEEC_LIBRARY) $(OUT_DIR)/$(LIB_MAJOR)
	$(VPREFIX)ln -sf $(OUT_DIR)/$(LIB_MAJOR) $(OUT_DIR)/$(LIB_NAME)

$(TEEC_LIBRARY): $(TEEC_OBJS)
	@echo "  LINK    $@"
	$(VPREFIX)$(CC) -shared -Wl,-soname,$(LIB_MAJ_MIN) $(TEEC_LFLAGS) -o $@ $+
	@echo ""

$(TEEC_OBJ_DIR)/%.o: ${TEEC_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(TEEC_OBJ_DIR)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(TEEC_CFLAGS) -c $< -o $@

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(TEEC_OBJS) $(TEEC_LIBRARY) $(OUT_DIR)/$(LIB_MAJOR) $(OUT_DIR)/$(LIB_NAME)
	$(call rmdir,$(OUT_DIR))
