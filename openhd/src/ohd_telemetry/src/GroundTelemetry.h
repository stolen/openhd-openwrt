//
// Created by consti10 on 13.04.22.
//

#ifndef OPENHD_TELEMETRY_GROUNDTELEMETRY_H
#define OPENHD_TELEMETRY_GROUNDTELEMETRY_H

#include "endpoints/UDPEndpoint2.h"
#include "internal/OHDMainComponent.h"
#include "mavlink_settings/ISettingsComponent.hpp"
#include "mavsdk_temporary/XMavlinkParamProvider.h"
#include "GroundTelemetrySettings.h"
#include "openhd-action-handler.hpp"
#include "openhd-spdlog.hpp"
#include "endpoints/WBEndpoint.h"
#include "ohd_link.hpp"

#ifdef OPENHD_TELEMETRY_SDL_FOR_JOYSTICK_FOUND
#include "rc/JoystickReader.h"
#include "rc/RcJoystickSender.h"
#endif

/**
 * OpenHD Ground telemetry. Assumes a air instance running on the air pi.
 */
class GroundTelemetry :public MavlinkSystem{
 public:
  explicit GroundTelemetry(OHDPlatform platform,std::shared_ptr<openhd::ActionHandler> opt_action_handler=nullptr);
  GroundTelemetry(const GroundTelemetry&)=delete;
  GroundTelemetry(const GroundTelemetry&&)=delete;
  ~GroundTelemetry();
  /**
   * Telemetry will run infinite in its own threads until terminate is set to true
   * @param enableExtendedLogging be really verbose on logging.
   */
  void loop_infinite(bool& terminate,bool enableExtendedLogging = false);
  /**
   * @return verbose string about the current state, for debugging
   */
  [[nodiscard]] std::string create_debug()const;
  /**
   * add settings to the generic mavlink parameter server
   * changes are propagated back through the settings instances
   * @param settings the settings to add
   */
  void add_settings_generic(const std::vector<openhd::Setting>& settings);
  /**
   * must be called once all settings have been added, this is needed to avoid an invariant parameter set
   */
  void settings_generic_ready();
  // Add the IP of another Ground station client, to start forwarding telemetry data there
  void add_external_ground_station_ip(const std::string& ip_openhd,const std::string& ip_dest_device);
  void remove_external_ground_station_ip(const std::string& ip_openhd,const std::string& ip_dest_device);
  //
  void set_link_handle(std::shared_ptr<OHDLink> link);
 private:
  const OHDPlatform _platform;
  // called every time one or more messages from the air unit are received
  void on_messages_air_unit(const std::vector<MavlinkMessage>& messages);
  // send messages to the air unit, lossy
  void send_messages_air_unit(const std::vector<MavlinkMessage>& messages);
  // called every time one or more messages are received from any of the clients connected to the Ground Station (For Example QOpenHD)
  void on_messages_ground_station_clients(const std::vector<MavlinkMessage>& messages);
  // send one or more messages to all clients connected to the ground station, for example QOpenHD
  void send_messages_ground_station_clients(const std::vector<MavlinkMessage>& messages);
 private:
  std::unique_ptr<openhd::telemetry::ground::SettingsHolder> m_groundTelemetrySettings;
  std::unique_ptr<UDPEndpoint2> udpGroundClient = nullptr;
  // We rely on another service for starting the rx/tx links
  //std::unique_ptr<UDPEndpoint> udpWifibroadcastEndpoint;
  std::unique_ptr<WBEndpoint> m_wb_endpoint;
  std::shared_ptr<OHDMainComponent> m_ohd_main_component;
  std::mutex components_lock;
  std::vector<std::shared_ptr<MavlinkComponent>> components;
  std::shared_ptr<XMavlinkParamProvider> generic_mavlink_param_provider;
  // telemetry to / from external ground stations (e.g. not the QOpenHD instance running on the device itself (localhost)
  std::mutex other_udp_ground_stations_lock;
  std::map<std::string,std::shared_ptr<UDPEndpoint2>> _other_udp_ground_stations{};
  //
#ifdef OPENHD_TELEMETRY_SDL_FOR_JOYSTICK_FOUND
  //std::unique_ptr<JoystickReader> m_joystick_reader;
  std::unique_ptr<RcJoystickSender> m_rc_joystick_sender;
#endif
  std::shared_ptr<spdlog::logger> m_console;
  std::vector<openhd::Setting> get_all_settings();
};

#endif //OPENHD_TELEMETRY_GROUNDTELEMETRY_H
