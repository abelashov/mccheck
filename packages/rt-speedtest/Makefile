#
# Copyright (C) 2006-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=rt-speedtest
PKG_RELEASE:=10

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/rt-speedtest
  SECTION:=custom
  CATEGORY:=Custom packages
  TITLE:=Utility for monitoring Internet access speed
endef

define Package/rt-speedtest/description
 This package contains an utility useful to measurement Internet access
 speed
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

target=$(firstword $(subst -, ,$(BOARD)))

MAKE_FLAGS += TARGET="$(target)"
TARGET_CFLAGS += -Dtarget_$(target)=1 -Wall

define Package/rt-speedtest/conffiles
/etc/config/rt-speedtest
endef

define Package/rt-speedtest/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/rt-speedtest.conf $(1)/etc/config/rt-speedtest
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/rt-speedtest.init $(1)/etc/init.d/rt-speedtest
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/rt-speedtest $(1)/bin/
endef

$(eval $(call BuildPackage,rt-speedtest))
