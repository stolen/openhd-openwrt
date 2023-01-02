//
// Created by consti10 on 21.04.22.
//

#include <thread>
#include <chrono>
#include "../src/HelperSources/SocketHelper.hpp"

static void test_send_and_receive() {
  static constexpr auto XPORT = 5600;
  std::size_t nReceivedBytes = 0;
  SocketHelper::UDPReceiver receiver(SocketHelper::ADDRESS_LOCALHOST,
									 XPORT,
									 [&nReceivedBytes](const uint8_t *payload, const std::size_t payloadSize) {
									   //std::cout<<"Got data\n";
									   nReceivedBytes += payloadSize;
									 });
  receiver.runInBackground();
  // wait a bit to account for OS delay
  std::this_thread::sleep_for(std::chrono::seconds(1));
  //SocketHelper::UDPForwarder forwarder(SocketHelper::ADDRESS_LOCALHOST,XPORT);
  SocketHelper::UDPMultiForwarder forwarder{};
  forwarder.addForwarder(SocketHelper::ADDRESS_LOCALHOST, XPORT);
  std::vector<uint8_t> data(1024);
  std::size_t nForwardedBytes = 0;
  for (int i = 0; i < 100; i++) {
	forwarder.forwardPacketViaUDP(data.data(), data.size());
	nForwardedBytes += data.size();
	std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  // wait a bit to account for OS delays
  std::this_thread::sleep_for(std::chrono::seconds(1));
  std::cout << "Test end\n";
  receiver.stopBackground();
  std::cout << "N sent bytes:" << nForwardedBytes << " Received:" << nReceivedBytes << "\n";
  if (nForwardedBytes != nReceivedBytes) {
	throw std::runtime_error("Dropped packets or impl bugged\n");
  }
}

// Here we have a simple test for adding and removing new forwarding IP addresses.
// (UDPMultiForwarder)
static void test_add_and_remove_forwarder() {
  SocketHelper::UDPMultiForwarder udpMultiForwarder{};
  udpMultiForwarder.addForwarder("192.168.0.0", 5600);
  udpMultiForwarder.addForwarder("192.168.0.0", 5600);
  if (udpMultiForwarder.getForwarders().size() != 1) {
	throw std::runtime_error("Should not contain duplicates\n");
  }
  udpMultiForwarder.addForwarder("192.168.0.1", 5600);
  if (udpMultiForwarder.getForwarders().size() != 2) {
	throw std::runtime_error("Should have 2 forwarders\n");
  }
  udpMultiForwarder.removeForwarder("192.168.0.1", 5600);
  if (udpMultiForwarder.getForwarders().size() != 1) {
	throw std::runtime_error("Should have 1 forwarder\n");
  }
  udpMultiForwarder.removeForwarder("192.168.0.0", 5600);
  if (!udpMultiForwarder.getForwarders().empty()) {
	throw std::runtime_error("Should have 0 forwarder\n");
  }
}

int main(int argc, char *const *argv) {

  test_send_and_receive();
  test_add_and_remove_forwarder();
  return 0;
}