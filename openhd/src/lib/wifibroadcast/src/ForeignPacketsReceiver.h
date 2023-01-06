//
// Created by consti10 on 17.12.22.
//

#ifndef WIFIBROADCAST_SRC_FOREIGNPACKETSRECEIVER_H_
#define WIFIBROADCAST_SRC_FOREIGNPACKETSRECEIVER_H_

#include <cstdint>
#include <vector>
#include <memory>

#include "RawReceiver.hpp"

// Helper - get (most likely all) packets that are not coming from a running openhd instance,
// but rather someone else talking on this channel.
// most likely because of the radio port - we really need to migrate to a single rx instance for all cards
// but for now, it is enough for us.
class ForeignPacketsReceiver {
 public:
  explicit ForeignPacketsReceiver(std::vector<std::string> wlans,std::vector<int> openhd_radio_ports,std::shared_ptr<spdlog::logger> console= nullptr);
  ~ForeignPacketsReceiver();
  struct Stats{
    int curr_received_pps=0;
    int curr_received_bps=0;
    std::string to_string()const{
      return fmt::format("curr pps:{}, curr bps:{}",curr_received_pps,curr_received_bps);
    }
  };
  Stats get_current_stats();
 private:
  void on_foreign_packet(uint8_t wlan_idx, const pcap_pkthdr &hdr, const uint8_t *pkt);
  void m_loop();
  std::shared_ptr<spdlog::logger> m_console;
  std::unique_ptr<MultiRxPcapReceiver> m_receiver;
  std::vector<int> m_openhd_radio_ports;
  std::unique_ptr<std::thread> m_thread;
  int64_t m_n_foreign_packets=0;
  int64_t m_n_foreign_bytes=0;
  //TODO make me atomic
  Stats m_curr_stats;
  BitrateCalculator m_foreign_packets_bps_calc{};
  PacketsPerSecondCalculator m_foreign_packets_pps_calc{};
};

#endif  // WIFIBROADCAST_SRC_FOREIGNPACKETSRECEIVER_H_
