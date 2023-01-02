//
// Created by consti10 on 03.05.22.
//

#ifndef WIFIBROADCAST_UDPWFIBROADCASTWRAPPER_HPP
#define WIFIBROADCAST_UDPWFIBROADCASTWRAPPER_HPP

#include "WBTransmitter.h"
#include "HelperSources/SocketHelper.hpp"

#include <memory>
#include <thread>
#include <mutex>
#include <utility>
#include <list>

/**
 * Creates a WB Transmitter that gets its input data stream from an UDP Port
 */
class UDPWBTransmitter {
 public:
  UDPWBTransmitter(RadiotapHeader::UserSelectableParams radiotapHeaderParams,
                   TOptions options1,
                   const std::string &client_addr,
                   int client_udp_port,
                   std::optional<int> wanted_recv_buff_size=std::nullopt) {
    wbTransmitter = std::make_unique<WBTransmitter>(radiotapHeaderParams, std::move(options1));
    udpReceiver = std::make_unique<SocketHelper::UDPReceiver>(client_addr,
                                                              client_udp_port,
                                                              [this](const uint8_t *payload,
                                                                     const std::size_t payloadSize) {
          wbTransmitter->enqueue_packet(payload, payloadSize);
                                                              },wanted_recv_buff_size);
  }
  /**
   * Loop until an error occurs.
   * Blocks the calling thread.
   */
  void loopUntilError() {
    udpReceiver->loopUntilError();
  }
  /**
   * Start looping in the background, creates a new thread.
   */
  void runInBackground() {
    udpReceiver->runInBackground();
  }
  void stopBackground(){
    udpReceiver->stopBackground();
  }
  WBTransmitter& get_wb_tx(){
    return *wbTransmitter;
  }
 private:
  std::unique_ptr<WBTransmitter> wbTransmitter;
  std::unique_ptr<SocketHelper::UDPReceiver> udpReceiver;
};


#endif //WIFIBROADCAST_UDPWFIBROADCASTWRAPPER_HPP
