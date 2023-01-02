include $(TOPDIR)/rules.mk

PKG_NAME:=libspdlog
PKG_VERSION:=1.11.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/gabime/spdlog.git
PKG_SOURCE_DATE:=2022-11-03
PKG_SOURCE_VERSION:=ad0e89cbfb4d0c1ce4d097e134eb7be67baebb36

CMAKE_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/libspdlog
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=Very fast, header-only/compiled, C++ logging library
endef

# define Build/InstallDev
# 	$(INSTALL_DIR) $(1)/usr/include/spdlog
# 	$(CP) $(PKG_INSTALL_DIR)/usr/include/sodium/* $(1)/usr/include/sodium
# 	$(INSTALL_DIR) $(1)/usr/lib
# 	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libspdlog.a $(1)/usr/lib
# 	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig
# 	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/libspdlog.pc $(1)/usr/lib/pkgconfig/
# 	$(INSTALL_DIR) $(1)/usr/lib/cmake
# 	$(CP) $(PKG_INSTALL_DIR)/usr/lib/cmake/spdlog $(1)/usr/lib/cmake/
# endef

define Package/libspdlog/install
endef

$(eval $(call BuildPackage,libspdlog))
