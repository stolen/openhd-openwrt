#include <pcap/pcap.h>
#include <poll.h>
#include <unistd.h>

#include <cassert>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <memory>
#include <sstream>
#include <string>

#include "../src/HelperSources/SchedulingHelper.hpp"
#include "../src/HelperSources/SocketHelper.hpp"
#include "../src/UdpWBReceiver.hpp"

int main(int argc, char *const *argv) {
  int opt;
  ROptions options{};
  int client_udp_port = 5600;
  std::string client_addr = "127.0.0.1";// default to localhost
  print_optimization_method();

  while ((opt = getopt(argc, argv, "K:c:u:r:n:k:")) != -1) {
    switch (opt) {
      case 'K':options.keypair = optarg;
        break;
      case 'c':client_addr = std::string(optarg);
        break;
      case 'u':client_udp_port = std::stoi(optarg);
        break;
      case 'r':options.radio_port = std::stoi(optarg);
        break;
      case 'k':
      case 'n':
        std::cout << "-n is deprecated. Please read https://github.com/Consti10/wifibroadcast/blob/master/README.md \n";
        exit(1);
      default: /* '?' */
      show_usage:
        fprintf(stderr,
                "Local receiver: %s [-K rx_key] [-c client_addr] [-u udp_client_port] [-r radio_port] interface1 [interface2] ...\n",
                argv[0]);
        fprintf(stderr, "Default: K='%s', connect=%s:%d, radio_port=%d\n",
                "none", client_addr.c_str(), client_udp_port, options.radio_port);
        fprintf(stderr, "WFB version "
                WFB_VERSION
                        "\n");
        exit(1);
    }
  }
  const int nRxInterfaces = argc - optind;
  if (nRxInterfaces > MAX_RX_INTERFACES) {
    std::cout << "Too many RX interfaces " << nRxInterfaces << "\n";
    goto show_usage;
  }
  SchedulingHelper::setThreadParamsMaxRealtime();

  //testLol();

  options.rxInterfaces.resize(nRxInterfaces);
  for (int i = 0; i < nRxInterfaces; i++) {
    options.rxInterfaces[i] = std::string(argv[optind + i]);
  }
  try {
    UDPWBReceiver udpwbReceiver{options, client_addr, client_udp_port};
    udpwbReceiver.runInBackground();
    while (true){
      std::cout << udpwbReceiver.get_wb_rx().createDebugState();
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  } catch (std::runtime_error &e) {
    fprintf(stderr, "Error: %s\n", e.what());
    exit(1);
  }
  return 0;
}
