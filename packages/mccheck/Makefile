#
# Copyright (C) 2006-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=mccheck
PKG_RELEASE:=7

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/mccheck
  SECTION:=custom
  CATEGORY:=Custom packages
  TITLE:=Utility for monitoring multicast MPEG-TS streams
endef

define Package/mccheck/description
 This package contains an utility useful to checking multicast MPEG-TS
 packets for drops
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

target=$(firstword $(subst -, ,$(BOARD)))

MAKE_FLAGS += TARGET="$(target)"
TARGET_CFLAGS += -Dtarget_$(target)=1 -Wall

MCCHECK_CONFFILE = ./files/mccheck.conf

ifeq ($(findstring ramips,$(CONFIG_TARGET_BOARD)),ramips)
  MCCHECK_CONFFILE = ./files/mccheck.conf
endif

ifeq ($(findstring ar71xx,$(CONFIG_TARGET_BOARD)),ar71xx)
  MCCHECK_CONFFILE = ./files/mccheck.conf.ar71xx
endif

ifeq ($(findstring brcm47xx,$(CONFIG_TARGET_BOARD)),brcm47xx)
  MCCHECK_CONFFILE = ./files/mccheck.conf.brcm47xx
endif

define Package/mccheck/conffiles
/etc/config/mccheck
endef

define Package/mccheck/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) $(MCCHECK_CONFFILE) $(1)/etc/config/mccheck
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/mccheck.init $(1)/etc/init.d/mccheck
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mccheck $(1)/bin/
endef

$(eval $(call BuildPackage,mccheck))
