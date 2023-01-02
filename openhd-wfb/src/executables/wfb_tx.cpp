#include <fcntl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cassert>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "../src/HelperSources/SchedulingHelper.hpp"
#include "../src/HelperSources/SocketHelper.hpp"
#include "../src/UdpWBTransmitter.hpp"

int main(int argc, char *const *argv) {
  int opt;
  TOptions options{};
  // input UDP port
  int udp_port = 5600;

  RadiotapHeader::UserSelectableParams wifiParams{20, false, 0, false, 1};

  std::cout << "MAX_PAYLOAD_SIZE:" << FEC_MAX_PAYLOAD_SIZE << "\n";
  print_optimization_method();

  while ((opt = getopt(argc, argv, "K:k:p:u:r:B:G:S:L:M:n:")) != -1) {
    switch (opt) {
      case 'K':options.keypair = optarg;
        break;
      case 'k':{
        const auto fec_k=std::stoi(optarg);
        if(fec_k>=0){
          options.enable_fec= true;
          options.tx_fec_options.fixed_k=fec_k;
        }
      }break;
      case 'p':
        options.tx_fec_options.overhead_percentage = std::stoi(optarg);
        break;
      case 'u':udp_port = std::stoi(optarg);
        break;
      case 'r':options.radio_port = std::stoi(optarg);
        break;
      case 'B':wifiParams.bandwidth = std::stoi(optarg);
        break;
      case 'G':wifiParams.short_gi = (optarg[0] == 's' || optarg[0] == 'S');
        break;
      case 'S':wifiParams.stbc = std::stoi(optarg);
        break;
      case 'L':wifiParams.ldpc = std::stoi(optarg);
        break;
      case 'M':wifiParams.mcs_index = std::stoi(optarg);
        break;
      case 'n':
        std::cerr << "-n is deprecated. Please read https://github.com/Consti10/wifibroadcast/blob/master/README.md \n";
        exit(1);
      default: /* '?' */
      show_usage:
        fprintf(stderr,
                "Usage: %s [-K tx_key] [-k FEC_K or 0 for variable fec] [-p FEC_PERCENTAGE] [-u udp_port] [-r radio_port] [-B bandwidth] [-G guard_interval] [-S stbc] [-L ldpc] [-M mcs_index] interface \n",
                argv[0]);
        fprintf(stderr, "Radio MTU: %lu\n", (unsigned long)FEC_MAX_PAYLOAD_SIZE);
        fprintf(stderr, "WFB version "
                WFB_VERSION
                        "\n");
        exit(1);
    }
  }
  if (optind >= argc) {
    goto show_usage;
  }
  options.wlan = argv[optind];

  //RadiotapHelper::debugRadiotapHeader((uint8_t*)&radiotapHeader,sizeof(RadiotapHeader));
  //RadiotapHelper::debugRadiotapHeader((uint8_t*)&OldRadiotapHeaders::u8aRadiotapHeader80211n, sizeof(OldRadiotapHeaders::u8aRadiotapHeader80211n));
  //RadiotapHelper::debugRadiotapHeader((uint8_t*)&OldRadiotapHeaders::u8aRadiotapHeader, sizeof(OldRadiotapHeaders::u8aRadiotapHeader));
  SchedulingHelper::setThreadParamsMaxRealtime();

  try {
    UDPWBTransmitter udpwbTransmitter{wifiParams, options, SocketHelper::ADDRESS_LOCALHOST, udp_port};
    udpwbTransmitter.runInBackground();
    while (true){
      std::cout << udpwbTransmitter.get_wb_tx().createDebugState();
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  } catch (std::runtime_error &e) {
    fprintf(stderr, "Error: %s\n", e.what());
    exit(1);
  }
  return 0;
}
