//
// Created by consti10 on 23.11.22.
//

#include "WBMultiPacketInjector.h"

WBMultiPacketInjector::WBMultiPacketInjector(const std::string& wlan,Ieee80211Header ieee_80211_header,
                                             RadiotapHeader radiotap_header):
m_pcap_transmitter(wlan),
m_wlan(wlan),
m_ieee_80211_header(ieee_80211_header),
m_radiotap_header(radiotap_header)
{
  m_process_data_thread_run=true;
  m_process_data_thread=std::make_unique<std::thread>(&WBMultiPacketInjector::loop_process_data, this);
}

WBMultiPacketInjector::~WBMultiPacketInjector() {
  m_process_data_thread_run=false;
  m_process_data_thread->join();
}

bool WBMultiPacketInjector::enqueue_packet(
    const AbstractWBPacket& abstractWbPacket) {
  auto packet=std::make_shared<std::vector<uint8_t>>(abstractWbPacket.payload,abstractWbPacket.payload+abstractWbPacket.payloadSize);
  return m_data_queue.try_enqueue(packet);
}

void WBMultiPacketInjector::set_mcs_index(int mcs_index) {
  if(mcs_index<0 || mcs_index>7){
    wifibroadcast::log::get_default()->warn("Invalid mcs index {}",mcs_index);
    return;
  }
}

void WBMultiPacketInjector::loop_process_data() {
  std::shared_ptr<std::vector<uint8_t>> packet;
  static constexpr std::int64_t timeout_usecs=100*1000;
  while (m_process_data_thread_run){
    if(m_data_queue.wait_dequeue_timed(packet,timeout_usecs)){
      inject_packet(packet->data(),packet->size(),0);
    }
  }
}

void WBMultiPacketInjector::inject_packet(const uint8_t* packet,const std::size_t packet_len,uint16_t radio_port) {
  m_ieee_80211_header.writeParams(radio_port, m_ieee80211_seq);
  m_ieee80211_seq += 16;
  AbstractWBPacket abstract_wb_packet{packet,packet_len};
  const auto injectionTime = m_pcap_transmitter.injectPacket(m_radiotap_header, m_ieee_80211_header, abstract_wb_packet);

}
