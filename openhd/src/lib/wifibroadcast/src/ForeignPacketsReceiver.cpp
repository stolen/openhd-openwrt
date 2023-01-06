//
// Created by consti10 on 17.12.22.
//

#include "ForeignPacketsReceiver.h"

#include <utility>

ForeignPacketsReceiver::ForeignPacketsReceiver(std::vector<std::string> wlans,std::vector<int> openhd_radio_ports,std::shared_ptr<spdlog::logger> console):
  m_openhd_radio_ports(std::move(openhd_radio_ports)) {
  if(!console){
    m_console=wifibroadcast::log::create_or_get("wb_foreign_rx");
  }else{
    m_console=console;
  }
  auto cb=[this](const uint8_t wlan_idx, const pcap_pkthdr &hdr, const uint8_t *pkt){
    on_foreign_packet(wlan_idx,hdr,pkt);
  };
  auto cb2=[this](){
  };
  MultiRxPcapReceiver::Options options;
  options.rxInterfaces=wlans;
  options.dataCallback=cb;
  options.logCallback=cb2;
  options.log_interval=std::chrono::milliseconds(100);
  options.radio_port=-1;
  options.excluded_radio_ports=m_openhd_radio_ports;
  m_receiver=std::make_unique<MultiRxPcapReceiver>(options);
  m_thread=std::make_unique<std::thread>(&ForeignPacketsReceiver::m_loop, this);
}

ForeignPacketsReceiver::~ForeignPacketsReceiver() {
  m_receiver->stop();
  if(m_thread->joinable())m_thread->join();
  m_thread= nullptr;
}

void ForeignPacketsReceiver::on_foreign_packet(const uint8_t wlan_idx,const pcap_pkthdr &hdr,const uint8_t *pkt) {
  //m_console->debug("X got packet");
  const auto parsedPacket = RawReceiverHelper::processReceivedPcapPacket(hdr, pkt,false);
  if(!parsedPacket.has_value()){
    m_console->warn("Discarding packet due to pcap parsing error!");
    return;
  }
  m_n_foreign_packets++;
  m_n_foreign_bytes+=static_cast<int64_t>(parsedPacket->payloadSize);
  Stats new_stats{};
  new_stats.curr_received_pps=static_cast<int>(m_foreign_packets_pps_calc.get_last_or_recalculate(m_n_foreign_packets,std::chrono::seconds(1)));
  new_stats.curr_received_bps=static_cast<int>(m_foreign_packets_bps_calc.get_last_or_recalculate(m_n_foreign_bytes,std::chrono::seconds(1)));
  m_curr_stats=new_stats;
}

void ForeignPacketsReceiver::m_loop() {
  m_receiver->loop();
}

ForeignPacketsReceiver::Stats ForeignPacketsReceiver::get_current_stats() {
  return m_curr_stats;
}
