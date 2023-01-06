//
// Created by consti10 on 23.11.22.
//

#ifndef WIFIBROADCAST_SRC_WBMULTIPACKETINJECTOR_H_
#define WIFIBROADCAST_SRC_WBMULTIPACKETINJECTOR_H_

#include "RawTransmitter.hpp"
#include "readerwriterqueue/readerwritercircularbuffer.h"

// Can be used by multiple WB TX / RX instance(s)
// This has the benefit that all packets go through a single class instance,
// which makes counting total n of packets or reasoning about packets in the tx queue much easier.
// Also, this design makes it easier to add re-transmissions at some point
class WBMultiPacketInjector {
 public:
  WBMultiPacketInjector(const std::string& wlan,Ieee80211Header ieee_80211_header,RadiotapHeader radiotap_header);
  ~WBMultiPacketInjector();
  /**
   * TODO Thread-safe and lock_free
   * @param abstractWbPacket the (raw) data of the packet you want to inject
   * @return true on success (space in extra tx queue available), false otherwise.
   */
  bool enqueue_packet(const AbstractWBPacket &abstractWbPacket);
  /**
   * on cards that support it, change the mcs index used on the next injected packet
   * the mcs index is written in the radiotap header of each injected packet - it is
   * up to the wifi driver weather the mcs index is used or not. Confirmed working on rtl8812au.
   * @param mcs_index
   */
  void set_mcs_index(int mcs_index);
 private:
  // this one is used for injecting packets
  PcapTransmitter m_pcap_transmitter;
  const std::string m_wlan;
  // Written on each injected packet
  Ieee80211Header m_ieee_80211_header;
  uint16_t m_ieee80211_seq = 0;
  // Also written on each injected packet
  RadiotapHeader m_radiotap_header;
  // extra fifo data queue, to smooth out spikes and more importantly, have a queue we can reason about /
  // enqueue packets on with a proper timeout (since the kernel wifi driver(s) timeout seems to be not configurable / broken,
  // at least on rtl8812au and ar9271.
  moodycamel::BlockingReaderWriterCircularBuffer<std::shared_ptr<std::vector<uint8_t>>> m_data_queue{128};
  // we have a thread for feeding packets to the kernel wifi driver
  std::unique_ptr<std::thread> m_process_data_thread;
  std::atomic<bool> m_process_data_thread_run=true;
  void loop_process_data();
  // always called from the same thread
  void inject_packet(const uint8_t* packet,std::size_t packet_len,uint16_t radio_port);
};

#endif  // WIFIBROADCAST_SRC_WBMULTIPACKETINJECTOR_H_
