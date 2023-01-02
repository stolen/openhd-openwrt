//
// Created by consti10 on 23.11.22.
//

#ifndef WIFIBROADCAST_SRC_UDPWBRECEIVER_H_
#define WIFIBROADCAST_SRC_UDPWBRECEIVER_H_

#include "WBReceiver.h"
#include "HelperSources/SocketHelper.hpp"

#include <memory>
#include <thread>
#include <mutex>
#include <utility>
#include <list>

/**
 * Creates a WB Receiver whose data is forwarded to one or more UDP host::port tuples.
 */
class UDPWBReceiver {
 public:
  UDPWBReceiver(ROptions options1, std::string client_addr, int client_udp_port) {
    udpMultiForwarder = std::make_unique<SocketHelper::UDPMultiForwarder>();
    addForwarder(std::move(client_addr), client_udp_port);
    wbReceiver = std::make_unique<WBReceiver>(std::move(options1), [this](const uint8_t *payload, const std::size_t payloadSize) {
      onNewData(payload, payloadSize);
      _anyDataReceived=true;
    });
  }
  ~UDPWBReceiver(){
    stop_looping();
  }
  /**
   * Loop until an error occurs. Blocks the calling thread.
   */
  void loopUntilError() {
    wbReceiver->loop();
  }
  void stop_looping(){
    wbReceiver->stop_looping();
    if(backgroundThread && backgroundThread->joinable()){
      backgroundThread->join();
    }
  }
  /**
   * Start looping in the background, creates a new thread.
   */
  void runInBackground() {
    backgroundThread = std::make_unique<std::thread>(&UDPWBReceiver::loopUntilError, this);
  }
  void addForwarder(std::string client_addr, int client_udp_port) {
    udpMultiForwarder->addForwarder(client_addr, client_udp_port);
  }
  void removeForwarder(std::string client_addr, int client_udp_port) {
    udpMultiForwarder->removeForwarder(client_addr, client_udp_port);
  }
  [[nodiscard]] bool anyDataReceived()const{
    return _anyDataReceived;
  }
  WBReceiver& get_wb_rx(){
    return *wbReceiver;
  }
  typedef std::function<void(std::shared_ptr<std::vector<uint8_t>> data)> TMP_CB;
  void tmp_register_cb(TMP_CB cb){
    m_cb=cb;
  }
  TMP_CB m_cb;
 private:
  // forwards the data to all registered udp forwarder instances.
  void onNewData(const uint8_t *payload, const std::size_t payloadSize) {
    udpMultiForwarder->forwardPacketViaUDP(payload, payloadSize);
    if(m_cb){
      auto shared=std::make_shared<std::vector<uint8_t>>(payload,payload+payloadSize);
      m_cb(shared);
    }
  }
  std::unique_ptr<SocketHelper::UDPMultiForwarder> udpMultiForwarder;
  std::unique_ptr<WBReceiver> wbReceiver;
  std::unique_ptr<std::thread> backgroundThread;
  bool _anyDataReceived=false;
};

// Tmp, dirty
// Just a quick wrapper around WBReceiver that runs in creates its own thread to pull data
// To make migration from UDP to callbacks easier in OpenHD
class AsyncWBReceiver : public WBReceiver{
 public:
  AsyncWBReceiver(ROptions options1,WBReceiver::OUTPUT_DATA_CALLBACK cb): WBReceiver(std::move(options1),std::move(cb)){
  }
  ~AsyncWBReceiver(){
    stop_async();
  }
  void start_async(){
    backgroundThread = std::make_unique<std::thread>(&AsyncWBReceiver::x_loop, this);
  }
  void stop_async(){
    WBReceiver::stop_looping();
    if(backgroundThread){
      backgroundThread->join();
    }
  }
  void x_loop(){
    WBReceiver::loop();
  }
 private:
  std::unique_ptr<std::thread> backgroundThread;
};

#endif  // WIFIBROADCAST_SRC_UDPWBRECEIVER_H_
