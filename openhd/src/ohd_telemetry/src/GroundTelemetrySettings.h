//
// Created by consti10 on 07.11.22.
//

#ifndef OPENHD_OPENHD_OHD_TELEMETRY_SRC_GROUNDTELEMETRYSETTINGS_H_
#define OPENHD_OPENHD_OHD_TELEMETRY_SRC_GROUNDTELEMETRYSETTINGS_H_

#include <map>

#include "openhd-settings-directories.hpp"
#include "openhd-settings-persistent.hpp"

namespace openhd::telemetry::ground{

static const std::string SETTINGS_DIRECTORY =std::string(BASE_PATH)+std::string("telemetry/");

struct Settings{
  bool enable_rc_over_joystick=false;
  int rc_over_joystick_update_rate_hz=30;
  std::string rc_channel_mapping="0,1,2,3,4,5,6,7";
};

static bool valid_joystick_update_rate(int value){
    return value>=1 && value<=150;
}

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Settings,enable_rc_over_joystick,rc_over_joystick_update_rate_hz,rc_channel_mapping);

class SettingsHolder:public openhd::settings::PersistentSettings<Settings>{
 public:
  SettingsHolder():
                     openhd::settings::PersistentSettings<Settings>(
                         SETTINGS_DIRECTORY){
    init();
  }
 private:
  [[nodiscard]] std::string get_unique_filename()const override{
    std::stringstream ss;
    ss<<"ground_settings.json";
    return ss.str();
  }
  [[nodiscard]] Settings create_default()const override{
    return Settings{};
  }
};

}

#endif  // OPENHD_OPENHD_OHD_TELEMETRY_SRC_GROUNDTELEMETRYSETTINGS_H_
