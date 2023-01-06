//
// Created by consti10 on 02.05.22.
//

#ifndef OPENHD_OPENHD_INTERFACE_H
#define OPENHD_OPENHD_INTERFACE_H

#include <memory>
#include <utility>

#include "mavlink_settings/ISettingsComponent.hpp"
#include "openhd-action-handler.hpp"
#include "openhd-external-device.hpp"
#include "openhd-led-codes.hpp"
#include "openhd-platform.hpp"
#include "openhd-profile.hpp"
#include "openhd-spdlog.hpp"
#include "openhd-telemetry-tx-rx.h"
#include "usb_tether_listener.h"
#include "wb_link.h"
#include "wifi_hotspot.h"

/**
 * Takes care of everything networking related, like wifibroadcast, usb / tethering / WiFi-hotspot usw.
 */
class OHDInterface :public openhd::ISettingsComponent{
 public:
  /**
   * @param platform platform we are running on
   * @param profile air or ground
   * @param opt_action_handler r.n used to propagate rate control from wb_link to ohd_video
   */
  explicit OHDInterface(OHDPlatform platform,OHDProfile profile,std::shared_ptr<openhd::ActionHandler> opt_action_handler=nullptr);
  OHDInterface(const OHDInterface&)=delete;
  OHDInterface(const OHDInterface&&)=delete;
  // Verbose string about the current state.
  [[nodiscard]] std::string createDebug() const;
  // For telemetry
  void set_external_device_callback(openhd::EXTERNAL_DEVICE_CALLBACK cb);
  // settings hacky begin
  std::vector<openhd::Setting> get_all_settings()override;
  // settings hacky end
  // easy access without polluting the headers
  static void print_internal_fec_optimization_method();
  // r.n only wb, but his might change
  std::shared_ptr<OHDLink> get_link_handle();
 private:
  /**
    * after calling this method with an external device's ip address
    * (for example an externally connected tablet) data will be forwarded to the device's ip address.
    * It is safe to call this method multiple times with the same IP address, since we internally keep track here.
   */
  void addExternalDeviceIpForwarding(const openhd::ExternalDevice& external_device);
  /**
    * stop forwarding data to the device's ip address.
    * Does nothing if the device's ip address is not registered for forwarding or already has ben removed.
   */
  void removeExternalDeviceIpForwarding(const openhd::ExternalDevice& external_device);
 private:
  const OHDProfile m_profile;
  const OHDPlatform m_platform;
  std::shared_ptr<WBLink> m_wb_link;
  std::unique_ptr<USBTetherListener> m_usb_tether_listener;
  std::unique_ptr<WifiHotspot> m_wifi_hotspot;
  std::unique_ptr<openhd::LEDBlinker> m_error_blinker;
  std::mutex m_external_device_callback_mutex;
  openhd::EXTERNAL_DEVICE_CALLBACK m_external_device_callback = nullptr;
  std::shared_ptr<spdlog::logger> m_console;
};

#endif //OPENHD_OPENHD_INTERFACE_H
