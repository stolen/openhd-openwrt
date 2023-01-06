//
// Created by consti10 on 20.04.22.
// This one just exists to test the compilation with cmake,nothing else.
//
#include "../src/HelperSources/SocketHelper.hpp"
#include "../src/HelperSources/EmulatedPacketDrop.hpp"

#include <memory>

static std::unique_ptr<SocketHelper::UDPReceiver> udp_receiver;
static std::unique_ptr<SocketHelper::UDPForwarder> udp_forwarder;
static std::unique_ptr<PacketDropEmulator> packet_drop_emulator;

static void on_new_udp_data(const uint8_t *payload, const std::size_t payloadSize){
  if(packet_drop_emulator->drop_packet()){
    return;
  }
  udp_forwarder->forwardPacketViaUDP(payload,payloadSize);
}

int main(int argc, char *const *argv) {

  udp_forwarder=std::make_unique<SocketHelper::UDPForwarder>("127.0.0.1",5600);
  packet_drop_emulator=std::make_unique<PacketDropEmulator>(0);

  udp_receiver=std::make_unique<SocketHelper::UDPReceiver>("127.0.0.1",5599,[](const uint8_t *payload, const std::size_t payloadSize){
    on_new_udp_data(payload,payloadSize);
  });
  udp_receiver->runInBackground();

  while (true){
    printf("Write new drop percentage and press enter to change\n");
    std::string input;
    std::cin>>input;
    std::cout<<"Got:["<<input<<"]\n";
    const int perc=std::stoi(input);
    if(perc>=0 && perc<=100){
      packet_drop_emulator->set_new_percentage(perc);
      std::cout<<"Changed drop to "<<perc<<"%\n";
    }
  }
  udp_receiver->stopBackground();
  return 0;
}