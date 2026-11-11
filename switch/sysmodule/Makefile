#---------------------------------------------------------------------------------
# zerotier-nx sysmodule (Atmosphère libstratosphere 1.12.0).
# Built by the top-level `make sysmodule` inside the ztnx-build Docker image.
#---------------------------------------------------------------------------------
SYSMODULE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ATMOSPHERE_LIBS := $(SYSMODULE_DIR)/../../third_party/Atmosphere/libraries
include $(ATMOSPHERE_LIBS)/config/templates/stratosphere.mk

TARGET		:=	zerotier-nx
BUILD		:=	build
SOURCES		:=	source ../../native/driver ../../native/runtime ../../native/vsock
DATA		:=	data
INCLUDES	:=	source ../../native/driver ../../native/runtime ../../native/vsock ../../native/ctl ../../native/zt ../../crates/ztnx-ffi/include
TITLE_ID	:=	4200000000005A54

ZTNX_BUILD_UNIX ?= $(shell date +%s)
RUST_LIB_DIR	?=	$(abspath $(SYSMODULE_DIR)/../../target/switch/aarch64-nintendo-switch-freestanding/release)
# ZeroTier's core and its glue (native/zt), built by the top-level Makefile.
ZT_LIB_DIR	?=	$(abspath $(SYSMODULE_DIR)/../../target/zt-switch)
# No newlib stdio/printf: state files go through ams::fs, and the shared C
# code's snprintf is routed to libstratosphere's formatter (see
# ztnx_snprintf in main.cpp and ztnx_driver.h).
# -Os after the template's -O2: this code is small and none of it is hot
# enough for the difference to show (the speed test's per-call figures).
CFLAGS		+=	-DZTNX_BUILD_UNIX=$(ZTNX_BUILD_UNIX) -Wno-error=sign-compare -DZTNX_NO_STDIO -Os
CXXFLAGS	+=	-DZTNX_BUILD_UNIX=$(ZTNX_BUILD_UNIX) -DZTNX_NO_STDIO -Os
LIBS		:=	-lztnx_ffi -lztcore $(LIBS)

# ZeroTier's core uses C++ exceptions. Atmosphère's template links every
# sysmodule with the exception entry points wrapped to abort stubs and with
# .eh_frame discarded (stratosphere.specs); undo both. What is kept: pure
# virtual calls and exit() still abort. Code built without exceptions (all of
# it except libztcore.a and operator_new.cpp) has no unwind tables, so an
# exception that reached it would end in std::terminate; the core catches its
# own at the ZT_Node_* boundary.
CXXWRAPS	:=	-Wl,--wrap,__cxa_pure_virtual -Wl,--wrap,exit
LDFLAGS		=	-specs=$(DEVKITPRO)/libnx/switch.specs $(CXXFLAGS) $(CXXWRAPS) $(CXXREQUIRED) -Wl,-Map,$(notdir $*.map) -Wl,-z,relro,-z,now

ifneq ($(BUILD),$(notdir $(CURDIR)))

export OUTPUT	:=	$(CURDIR)/$(TARGET)
export TOPDIR	:=	$(CURDIR)
export VPATH	:=	$(foreach dir,$(SOURCES),$(CURDIR)/$(dir))
export DEPSDIR	:=	$(CURDIR)/$(BUILD)

CFILES		:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c)))
CPPFILES	:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
export LD	:=	$(CXX)
export OFILES	:=	$(CPPFILES:.cpp=.o) $(CFILES:.c=.o)
export INCLUDE	:=	$(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
			$(foreach dir,$(LIBDIRS),-I$(dir)/include) \
			$(foreach dir,$(AMS_LIBDIRS),-I$(dir)/include) \
			-I$(CURDIR)/$(BUILD)
export LIBPATHS	:=	$(foreach dir,$(LIBDIRS),-L$(dir)/lib) \
			$(foreach dir,$(AMS_LIBDIRS),-L$(dir)/$(ATMOSPHERE_LIBRARY_DIR)) \
			-L$(RUST_LIB_DIR) -L$(ZT_LIB_DIR)
export APP_JSON	:=	$(TOPDIR)/res/app.json
export RUST_LIB_DIR
export ZT_LIB_DIR

.PHONY: $(BUILD) clean all dist

all: $(BUILD)

$(BUILD):
	@[ -d $@ ] || mkdir -p $@
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

# SD card layout: atmosphere/contents/<tid>/{exefs.nsp,toolbox.json,flags/boot2.flag}
dist: all
	@rm -rf dist && mkdir -p dist/atmosphere/contents/$(TITLE_ID)/flags
	@cp $(TARGET).nsp dist/atmosphere/contents/$(TITLE_ID)/exefs.nsp
	@cp res/toolbox.json dist/atmosphere/contents/$(TITLE_ID)/
	@touch dist/atmosphere/contents/$(TITLE_ID)/flags/boot2.flag
	@echo "staged dist/atmosphere/contents/$(TITLE_ID)"

clean:
	@rm -fr $(BUILD) dist $(TARGET).elf $(TARGET).nso $(TARGET).npdm $(TARGET).nsp $(TARGET).map

else

DEPENDS	:=	$(OFILES:.o=.d)

all	:	$(OUTPUT).nsp
$(OUTPUT).nsp	:	$(OUTPUT).nso $(OUTPUT).npdm
$(OUTPUT).nso	:	$(OUTPUT).elf
$(OUTPUT).elf	:	$(OFILES) $(RUST_LIB_DIR)/libztnx_ffi.a $(ZT_LIB_DIR)/libztcore.a

# The one file here that throws (std::bad_alloc from operator new).
operator_new.o	:	CXXFLAGS += -fexceptions
$(OFILES)	:	$(ATMOSPHERE_LIBRARIES_DIR)/libstratosphere/$(ATMOSPHERE_LIBRARY_DIR)/libstratosphere.a

%.npdm	:	$(APP_JSON)
	@npdmtool $< $@
	@echo built ... $(notdir $@)

-include $(DEPENDS)

endif
