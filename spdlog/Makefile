include $(TOPDIR)/rules.mk

PKG_NAME:=spdlog
PKG_VERSION:=1.9.2
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/gabime/$(PKG_NAME)/archive/refs/tags/v$(PKG_VERSION).tar.gz?
PKG_HASH=6fff9215f5cb81760be4cc16d033526d1080427d236e86d70bb02994f85e3d38

PKG_MAINTAINER:=Danil Zagoskin <z@gosk.in>
PKG_LICENCE:=MIT
PKG_LICENSE_FILES:=LICENSE

CMAKE_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/$(PKG_NAME)
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=Very fast, header-only/compiled, C++ logging library
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/spdlog
	$(CP) $(PKG_INSTALL_DIR)/usr/include/spdlog/* $(1)/usr/include/spdlog
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libspdlog.a $(1)/usr/lib
	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/spdlog.pc $(1)/usr/lib/pkgconfig/
	$(INSTALL_DIR) $(1)/usr/lib/cmake
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/cmake/spdlog $(1)/usr/lib/cmake/
endef

#define Package/$(PKG_NAME)/install
#	$(INSTALL_DIR) $(1)/usr/lib
#	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libspdlog.* $(1)/usr/lib/
#endef

$(eval $(call BuildPackage,$(PKG_NAME)))
