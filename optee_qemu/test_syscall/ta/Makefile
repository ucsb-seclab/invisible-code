CFG_TEE_TA_LOG_LEVEL ?= 4
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL) -fomit-frame-pointer

# The UUID for the Trusted Application
BINARY=8aaaf200-2450-11e4-0d0e-0a0d0b0e0e0f

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

.PHONY: all
ifneq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk),)
all: $(BINARY).ta
else
all:
	@echo "$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk does not exist. Is TA_DEV_KIT_DIR correctly defined?" && false
endif

.PHONY: clean
ifneq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk),)
clean: clean_ta_file
else
clean:
	@echo "$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk does not exist. Is TA_DEV_KIT_DIR correctly defined?"
	@echo "You can remove manually $(BINARY).ta"
endif

.PHONY: clean_ta_file
clean_ta_file:
	rm -f $(BINARY).ta
