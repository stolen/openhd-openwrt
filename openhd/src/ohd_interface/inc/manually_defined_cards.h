//
// Created by consti10 on 13.12.22.
//

#ifndef OPENHD_OPENHD_OHD_INTERFACE_INC_MANUALLY_DEFINED_CARDS_H_
#define OPENHD_OPENHD_OHD_INTERFACE_INC_MANUALLY_DEFINED_CARDS_H_

#include "wifi_card.hpp"
#include "openhd-spdlog.hpp"

// The helper in this namespace exist if for some reason you want to work on OpenHD and cannot rely on the autodetect of cards and what to use
// them for.

namespace openhd {

struct ManuallyDefinedCard {
  std::string interface_name;
  std::string mac_address;
  WifiUseFor usage;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(ManuallyDefinedCard, interface_name,
                                   mac_address, usage);

struct ManuallyDefinedCards {
  std::vector<ManuallyDefinedCard> cards;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(ManuallyDefinedCards, cards);

static const std::string FILE_PATH_MANUALLY_DEFINED_CARDS=std::string(INTERFACE_SETTINGS_DIRECTORY)+std::string("manual_cards.json");

static std::vector<ManuallyDefinedCard> get_manually_defined_cards_from_file(const std::string& filename) {
  if (!OHDFilesystemUtil::exists(filename.c_str())) {
    throw std::runtime_error(fmt::format("With great power comes great responsibility.File {} does not exist",filename));
  }
  std::ifstream f(filename);
  try {
    nlohmann::json j;
    f >> j;
    auto tmp = j.get<ManuallyDefinedCards>();
    return tmp.cards;
  } catch (nlohmann::json::exception& ex) {
    throw std::runtime_error(fmt::format("With great power comes great responsibility.File {} is invalid",filename));
  }
  return {};
}

static void write_manual_cards_template() {
  const auto file_path = "/tmp/manual_cards.json.template";
  ManuallyDefinedCard example{"wlan0", "ac:9e:17:59:61:03",
                              WifiUseFor::MonitorMode};
  ManuallyDefinedCards content{};
  content.cards.push_back(example);
  const nlohmann::json tmp = content;
  // and write them locally for persistence
  std::ofstream t(file_path);
  t << tmp.dump(4);
  t.close();
}

static bool manually_defined_cards_file_exists(){
  return OHDFilesystemUtil::exists(FILE_PATH_MANUALLY_DEFINED_CARDS.c_str());
}

// For developers
// By using the file(s) specified here you can tell openhd to ignore certain interfaces
// This can be usefully if you want to create some kind of custom networking or similar
namespace ignore{

static constexpr auto filename_ignore_interfaces="/boot/openhd/ignore_interfaces.txt";
static constexpr auto filename_ignore_macs="/boot/openhd/ignore_macs.txt";

static bool should_be_ignored(const char* file_name,const std::string& evaluated){
  if(!OHDFilesystemUtil::exists(file_name)){
    return false;
  }
  const auto content=OHDFilesystemUtil::read_file(file_name);
  if(content.find(evaluated) != std::string::npos){
    return true;
  }
  return false;
}

static bool should_be_ignored_interface(const std::string& interface_name){
  return should_be_ignored(filename_ignore_interfaces,interface_name);
}

static bool should_be_ignored_mac(const std::string& mac){
  return should_be_ignored(filename_ignore_macs,mac);
}
}

}
#endif  // OPENHD_OPENHD_OHD_INTERFACE_INC_MANUALLY_DEFINED_CARDS_H_
