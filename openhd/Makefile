include $(TOPDIR)/rules.mk

PKG_NAME:=openhd
PKG_SOURCE_DATE:=2022-12-31
PKG_VERSION:=22.12
PKG_RELEASE:=1

PKG_MAINTAINER:=Danil Zagoskin <z@gosk.in>
PKG_LICENCE:=GPL-3.0
PKG_LICENSE_FILES:=LICENSE.txt

CMAKE_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/openhd
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Wireless
  TITLE:=Open source digital FPV ecosystem
  DEPENDS+= +libstdcpp +libpcap +libsodium +boost +boost-filesystem \
			+gstreamer1 +libgst1app +libgst1sdp +libgst1video \
			+libusb-1.0
  URL:=https://openhdfpv.org/
endef

PKG_BUILD_DEPENDS:=spdlog

define Package/openhd/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/* $(1)/usr/bin/
endef

$(eval $(call BuildPackage,openhd))
