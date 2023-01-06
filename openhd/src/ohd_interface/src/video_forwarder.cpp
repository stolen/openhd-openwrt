//
// Created by consti10 on 09.12.22.
//

#include "video_forwarder.h"

GroundVideoForwarder::GroundVideoForwarder() {
  udpMultiForwarder = std::make_unique<SocketHelper::UDPMultiForwarder>();
  addForwarder("127.0.0.1",5600);
  //addForwarder("0.0.0.0",5600);
}

void GroundVideoForwarder::addForwarder(std::string client_addr,int client_udp_port) {
  udpMultiForwarder->addForwarder(client_addr, client_udp_port);
}

void GroundVideoForwarder::removeForwarder(std::string client_addr,int client_udp_port) {
  udpMultiForwarder->removeForwarder(client_addr, client_udp_port);
}

void GroundVideoForwarder::forward_data(const int stream_idx,const uint8_t *data, int data_len) {
  udpMultiForwarder->forwardPacketViaUDP(data,data_len);
}
