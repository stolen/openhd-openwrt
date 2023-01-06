include $(TOPDIR)/rules.mk

PKG_NAME:=openhd-wfb
PKG_SOURCE_DATE:=2022-12-31
PKG_VERSION:=22.12
PKG_RELEASE:=1

PKG_MAINTAINER:=Danil Zagoskin <z@gosk.in>
PKG_LICENCE:=GPL-3.0
PKG_LICENSE_FILES:=LICENSE.txt

CMAKE_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/openhd-wfb
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Wireless
  TITLE:=long range RTP over raw WiFI packets
  DEPENDS+= +libstdcpp +libpcap +libsodium
  URL:=https://openhdfpv.org/
endef

PKG_BUILD_DEPENDS:=spdlog

define Package/openhd-wfb/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/* $(1)/usr/bin/
endef

$(eval $(call BuildPackage,openhd-wfb))
