//
// Created by consti10 on 21.12.20.
//

#ifndef WIFIBROADCAST_RAWRECEIVER_H
#define WIFIBROADCAST_RAWRECEIVER_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <sys/socket.h>

#include <cstdint>
#include <functional>
#include <unordered_map>
#include <variant>
#include <optional>

#include "HelperSources/Helper.hpp"
#include "HelperSources/TimeHelper.hpp"
#include "Ieee80211Header.hpp"
#include "RadiotapHeader.hpp"
#include "wifibroadcast-spdlog.h"
#include "pcap_helper.h"

// This is a single header-only file you can use to build your own wifibroadcast
// link
// It doesn't specify if / what FEC to use and so on

// stuff that helps for receiving data with pcap
namespace RawReceiverHelper {


// Set timestamp type to PCAP_TSTAMP_HOST if available
static void iteratePcapTimestamps(pcap_t *ppcap) {
  int *availableTimestamps;
  const int nTypes = pcap_list_tstamp_types(ppcap, &availableTimestamps);
  wifibroadcast::log::get_default()->debug("TS types:{}", wifibroadcast::pcap_helper::tstamp_types_to_string(availableTimestamps,nTypes));
  //"N available timestamp types "<<nTypes<<"\n";
  for (int i = 0; i < nTypes; i++) {
    if (availableTimestamps[i] == PCAP_TSTAMP_HOST) {
      wifibroadcast::log::get_default()->debug("Setting timestamp to host");
      pcap_set_tstamp_type(ppcap, PCAP_TSTAMP_HOST);
    }
  }
  pcap_free_tstamp_types(availableTimestamps);
}


static std::string create_program_everything_except_excluded(const std::string &wlan,const int link_encap,const std::vector<int>& exclued_radio_ports){
  assert(link_encap==DLT_PRISM_HEADER || link_encap==DLT_IEEE802_11_RADIO);
  std::stringstream ss;
  ss<<"!(";
  for(int i=0;i<exclued_radio_ports.size();i++){
    const bool last = (i==exclued_radio_ports.size()-1);
    if(link_encap==DLT_PRISM_HEADER){
      ss<<StringFormat::convert("(radio[0x4a:4]==0x13223344 && radio[0x4e:2] == 0x55%.2x)",exclued_radio_ports.at(i));
    }else{
      ss<<StringFormat::convert("(ether[0x0a:4]==0x13223344 && ether[0x0e:2] == 0x55%.2x)",exclued_radio_ports.at(i));
    }
    if(!last){
      ss<<" || ";
    }
  }
  ss<<")";
  return ss.str();
}

static std::string create_program_specific_port_only(const std::string &wlan,const int link_encap,const int radio_port){
  std::string program;
  switch (link_encap) {
    case DLT_PRISM_HEADER:
      wifibroadcast::log::get_default()->debug("{} has DLT_PRISM_HEADER Encap",wlan);
      program = StringFormat::convert("radio[0x4a:4]==0x13223344 && radio[0x4e:2] == 0x55%.2x", radio_port);
      break;
    case DLT_IEEE802_11_RADIO:
      wifibroadcast::log::get_default()->debug("{} has DLT_IEEE802_11_RADIO Encap",wlan);
      program = StringFormat::convert("ether[0x0a:4]==0x13223344 && ether[0x0e:2] == 0x55%.2x", radio_port);
      break;
    default:{
      wifibroadcast::log::get_default()->error("unknown encapsulation on {}", wlan.c_str());
    }
  }
  return program;
}

static void set_pcap_filer(const std::string &wlan,pcap_t* ppcap,const int radio_port){
  const int link_encap = pcap_datalink(ppcap);
  struct bpf_program bpfprogram{};
  const std::string program= create_program_specific_port_only(wlan,link_encap,radio_port);
  if (pcap_compile(ppcap, &bpfprogram, program.c_str(), 1, 0) == -1) {
    wifibroadcast::log::get_default()->error("Unable to compile [{}] {}", program.c_str(), pcap_geterr(ppcap));
  }
  if (pcap_setfilter(ppcap, &bpfprogram) == -1) {
    wifibroadcast::log::get_default()->error("Unable to set filter [{}] {}", program.c_str(), pcap_geterr(ppcap));
  }
  pcap_freecode(&bpfprogram);
}

static void set_pcap_filer2(const std::string &wlan,pcap_t* ppcap,const std::vector<int>& exclued_radio_ports){
  const int link_encap = pcap_datalink(ppcap);
  struct bpf_program bpfprogram{};
  const std::string program= create_program_everything_except_excluded(wlan,link_encap,exclued_radio_ports);
  wifibroadcast::log::get_default()->debug("Program [{}]",program);
  if (pcap_compile(ppcap, &bpfprogram, program.c_str(), 1, 0) == -1) {
    wifibroadcast::log::get_default()->error("Unable to compile [{}] {}", program.c_str(), pcap_geterr(ppcap));
  }
  if (pcap_setfilter(ppcap, &bpfprogram) == -1) {
    wifibroadcast::log::get_default()->error("Unable to set filter [{}] {}", program.c_str(), pcap_geterr(ppcap));
  }
  pcap_freecode(&bpfprogram);
}

// creates a pcap handle for the given wlan and sets common params for wb
// returns nullptr on failure, a valid pcap handle otherwise
static pcap_t *helper_open_pcap_rx(const std::string &wlan) {
  pcap_t *ppcap= nullptr;
  char errbuf[PCAP_ERRBUF_SIZE];
  ppcap = pcap_create(wlan.c_str(), errbuf);
  if (ppcap == nullptr) {
    wifibroadcast::log::get_default()->error("Unable to open interface {} in pcap: {}", wlan.c_str(), errbuf);
    return nullptr;
  }
  iteratePcapTimestamps(ppcap);
  if (pcap_set_snaplen(ppcap, 4096) != 0) wifibroadcast::log::get_default()->error("set_snaplen failed");
  if (pcap_set_promisc(ppcap, 1) != 0) wifibroadcast::log::get_default()->error("set_promisc failed");
  //if (pcap_set_rfmon(ppcap, 1) !=0) wifibroadcast::log::get_default()->error("set_rfmon failed");
  if (pcap_set_timeout(ppcap, -1) != 0) wifibroadcast::log::get_default()->error("set_timeout failed");
  //if (pcap_set_buffer_size(ppcap, 2048) !=0) wifibroadcast::log::get_default()->error("set_buffer_size failed");
  // Important: Without enabling this mode pcap buffers quite a lot of packets starting with version 1.5.0 !
  // https://www.tcpdump.org/manpages/pcap_set_immediate_mode.3pcap.html
  if (pcap_set_immediate_mode(ppcap, true) != 0){
    wifibroadcast::log::get_default()->warn("pcap_set_immediate_mode failed: {}",pcap_geterr(ppcap));
  }
  if (pcap_activate(ppcap) != 0){
    wifibroadcast::log::get_default()->error("pcap_activate failed: {}",pcap_geterr(ppcap));
  }
  if (pcap_setnonblock(ppcap, 1, errbuf) != 0){
    wifibroadcast::log::get_default()->error("set_nonblock failed: {}",errbuf);
  }
  return ppcap;
}


struct RssiForAntenna {
  // which antenna the value refers to
  const uint8_t antennaIdx;
  // https://www.radiotap.org/fields/Antenna%20signal.html
  const int8_t rssi;
};
struct ParsedRxPcapPacket {
  // Size can be anything from size=1 to size== N where N is the number of Antennas of this adapter
  const std::vector<RssiForAntenna> allAntennaValues;
  const Ieee80211Header *ieee80211Header;
  const uint8_t *payload;
  const std::size_t payloadSize;
  // Atheros forwards frames even though the fcs check failed ( this packet is corrupted)
  const bool frameFailedFCSCheck;
};
static std::string all_rssi_to_string(const std::vector<RssiForAntenna>& all_rssi){
  std::stringstream ss;
  int idx=0;
  for(const auto& rssiForAntenna:all_rssi){
    ss<<"RssiForAntenna"<<idx<<"{"<<(int)rssiForAntenna.rssi<<"}\n";
    idx++;
  }
  return ss.str();
}
// It looks as if RTL88xxau reports 3 rssi values - for example,
//RssiForAntenna0{10}
//RssiForAntenna1{10}
//RssiForAntenna2{-18}
//Now this doesn't make sense, so this helper should fix it
static std::optional<int8_t> get_best_rssi_of_card(const std::vector<RssiForAntenna>& all_rssi){
  if(all_rssi.empty())return std::nullopt;
  // best rssi == highest value
  int8_t highest_value=INT8_MIN;
  for(const auto& rssiForAntenna:all_rssi){
    if(rssiForAntenna.rssi>highest_value){
      highest_value=rssiForAntenna.rssi;
    }
  }
  return highest_value;
}

// Returns std::nullopt if radiotap was unable to parse the header
// else return the *parsed information*
// To avoid confusion it might help to treat this method as a big black Box :)
static std::optional<ParsedRxPcapPacket> processReceivedPcapPacket(const pcap_pkthdr &hdr, const uint8_t *pkt,const bool fixup_rssi_rtl8812au) {
  int pktlen = hdr.caplen;
  //
  //RadiotapHelper::debugRadiotapHeader(pkt,pktlen);
  // Copy the value of this flag once present and process it after the loop is done
  uint8_t tmpCopyOfIEEE80211_RADIOTAP_FLAGS = 0;
  //RadiotapHelper::debugRadiotapHeader(pkt, pktlen);
  struct ieee80211_radiotap_iterator iterator{};
  // With AR9271 I get 39 as length of the radio-tap header
  // With my internal laptop wifi chip I get 36 as length of the radio-tap header.
  int ret = ieee80211_radiotap_iterator_init(&iterator, (ieee80211_radiotap_header *) pkt, pktlen, NULL);
  // weird, unfortunately it is not really documented / specified how raditap reporting dBm values with multiple antennas works
  // we store all values reported by IEEE80211_RADIOTAP_ANTENNA in here
  // ? there can be multiple ?
  //std::vector<uint8_t> radiotap_antennas;
  // and all values reported by IEEE80211_RADIOTAP_DBM_ANTSIGNAL in here
  //std::vector<int8_t> radiotap_antsignals;
  // for rtl8812au fixup
  bool is_first_reported_antenna_value= true;

  uint8_t currentAntenna = 0;
  // not confirmed yet, but one pcap packet might include stats for multiple antennas
  std::vector<RssiForAntenna> allAntennaValues;
  while (ret == 0) {
    ret = ieee80211_radiotap_iterator_next(&iterator);
    if (ret) {
      continue;
    }
    /* see if this argument is something we can use */
    switch (iterator.this_arg_index) {
      case IEEE80211_RADIOTAP_ANTENNA:
        // RADIOTAP_DBM_ANTSIGNAL should come directly afterwards
        currentAntenna = iterator.this_arg[0];
        //radiotap_antennas.push_back(iterator.this_arg[0]);
        break;
      case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:{
        int8_t value;
        std::memcpy(&value,iterator.this_arg,1);
        //const int8_t value=*(int8_t*)iterator.this_arg;
        if(fixup_rssi_rtl8812au){
          // Dirty fixup for rtl8812au: Throw out the first reported value
          if(is_first_reported_antenna_value){
            is_first_reported_antenna_value= false;
          }else{
            allAntennaValues.push_back({currentAntenna,value});
          }
        }else{
          allAntennaValues.push_back({currentAntenna,value});
        }
      }
        break;
      case IEEE80211_RADIOTAP_FLAGS:
        tmpCopyOfIEEE80211_RADIOTAP_FLAGS = *(uint8_t *) (iterator.this_arg);
        break;
      default:break;
    }
  }  /* while more rt headers */
  if (ret != -ENOENT) {
    //wifibroadcast::log::get_default()->warn("Error parsing radiotap header!\n";
    return std::nullopt;
  }
  bool frameFailedFcsCheck = false;
  if (tmpCopyOfIEEE80211_RADIOTAP_FLAGS & IEEE80211_RADIOTAP_F_BADFCS) {
    //wifibroadcast::log::get_default()->warn("Got packet with bad fsc\n";
    frameFailedFcsCheck = true;
  }
  // the fcs is at the end of the packet
  if (tmpCopyOfIEEE80211_RADIOTAP_FLAGS & IEEE80211_RADIOTAP_F_FCS) {
    //<<"Packet has IEEE80211_RADIOTAP_F_FCS";
    pktlen -= 4;
  }
#ifdef ENABLE_ADVANCED_DEBUGGING
  wifibroadcast::log::get_default()->debug(RadiotapFlagsToString::flagsIEEE80211_RADIOTAP_MCS(mIEEE80211_RADIOTAP_MCS));
  wifibroadcast::log::get_default()->debug(RadiotapFlagsToString::flagsIEEE80211_RADIOTAP_FLAGS(mIEEE80211_RADIOTAP_FLAGS));
  // With AR9271 I get 39 as length of the radio-tap header
  // With my internal laptop wifi chip I get 36 as length of the radio-tap header
  wifibroadcast::log::get_default()->debug("iterator._max_length was {}",iterator._max_length);
#endif
  //assert(iterator._max_length==hdr.caplen);
  /* discard the radiotap header part */
  pkt += iterator._max_length;
  pktlen -= iterator._max_length;
  //
  const Ieee80211Header *ieee80211Header = (Ieee80211Header *) pkt;
  const uint8_t *payload = pkt + Ieee80211Header::SIZE_BYTES;
  const std::size_t payloadSize = (std::size_t) pktlen - Ieee80211Header::SIZE_BYTES;
  //
  /*std::stringstream ss;
  ss<<"Antennas:";
  for(const auto& antenna : radiotap_antennas){
    ss<<(int)antenna<<",";
  }
  ss<<"\nAntsignals:";
  for(const auto& antsignal : radiotap_antsignals){
    ss<<(int)antsignal<<",";
  }
  std::cout<<ss.str();*/
  return ParsedRxPcapPacket{allAntennaValues, ieee80211Header, payload, payloadSize, frameFailedFcsCheck};
}
}

// This class listens for WIFI data on the specified wlan for wifi packets with the right RADIO_PORT
// Processing of data is done by the callback
// It uses a slightly complicated pattern:
// 1) check if data is available via the fd
// 2) then call loop_iter().
// loop_iter loops over all packets for this wifi card that are not processed yet, then returns.
class PcapReceiver {
 public:
  // this callback is called with the received packet from pcap
  typedef std::function<void(const uint8_t wlan_idx, const pcap_pkthdr &hdr, const uint8_t *pkt)>
      PROCESS_PACKET_CALLBACK;
  // This constructor only takes one wlan (aka one wlan adapter)
  PcapReceiver(const std::string &wlan, int wlan_idx, int radio_port, PROCESS_PACKET_CALLBACK callback)
      : WLAN_NAME(wlan), WLAN_IDX(wlan_idx), RADIO_PORT(radio_port), mCallback(callback) {
    ppcap = RawReceiverHelper::helper_open_pcap_rx(wlan);
    RawReceiverHelper::set_pcap_filer(wlan,ppcap,RADIO_PORT);
    fd = pcap_get_selectable_fd(ppcap);
  }
  // Exp
  PcapReceiver(const std::string &wlan, int wlan_idx, std::vector<int> excluded_radio_ports, PROCESS_PACKET_CALLBACK callback)
      : WLAN_NAME(wlan), WLAN_IDX(wlan_idx), RADIO_PORT(-1), mCallback(callback) {
    ppcap = RawReceiverHelper::helper_open_pcap_rx(wlan);
    RawReceiverHelper::set_pcap_filer2(wlan,ppcap,excluded_radio_ports);
    fd = pcap_get_selectable_fd(ppcap);
  }
  ~PcapReceiver() {
    close(fd);
    pcap_close(ppcap);
  }
  /**
   * Process data packets on this wifi interface until no more data is available.
   * Returns when no more data is available.
   * @return the n of packets polled until no more data was available.
   */
  int loop_iter() {
    // loop while incoming queue is not empty
    int nPacketsPolledUntilQueueWasEmpty = 0;
    for (;;) {
      struct pcap_pkthdr hdr{};
      const uint8_t *pkt = pcap_next(ppcap, &hdr);
      if (pkt == nullptr) {
#ifdef ENABLE_ADVANCED_DEBUGGING
        nOfPacketsPolledFromPcapQueuePerIteration.add(nPacketsPolledUntilQueueWasEmpty);
       wifibroadcast::log::get_default()->debug("nOfPacketsPolledFromPcapQueuePerIteration: {}",nOfPacketsPolledFromPcapQueuePerIteration.getAvgReadable());
        nOfPacketsPolledFromPcapQueuePerIteration.reset();
#endif
        break;
      }
      timeForParsingPackets.start();
      mCallback(WLAN_IDX, hdr, pkt);
      timeForParsingPackets.stop();
#ifdef ENABLE_ADVANCED_DEBUGGING
      // how long the cpu spends on agg.processPacket
      timeForParsingPackets.printInIntervalls(std::chrono::seconds(1));
#endif
      nPacketsPolledUntilQueueWasEmpty++;
    }
    return nPacketsPolledUntilQueueWasEmpty;
  }
  [[nodiscard]] int getfd() const { return fd; }
 public:
  // name of the wlan
  const std::string WLAN_NAME;
  // index of the wifi interface this receiver listens on (not the radio port)
  // used to differentiate data coming from the different usb wifi card's in the callback.
  const int WLAN_IDX;
  // the radio port it filters pacp packets for
  const int RADIO_PORT;
 public:
  // this callback is called with valid data when doing loop_iter()
  const PROCESS_PACKET_CALLBACK mCallback;
  // this fd is created by pcap
  int fd;
  pcap_t *ppcap;
  // measures the cpu time spent on the callback
  Chronometer timeForParsingPackets{"PP"};
  // If each iteration pulls too many packets out your CPU is most likely too slow
  AvgCalculatorSize nOfPacketsPolledFromPcapQueuePerIteration;
};

// This class supports more than one Receiver (aka multiple wlan adapters)
class MultiRxPcapReceiver {
 public:
  typedef std::function<void()> GENERIC_CALLBACK;
  struct Options{
    std::vector<std::string> rxInterfaces;
    int radio_port;
    std::vector<int> excluded_radio_ports;
    std::chrono::milliseconds log_interval;
    // this callback is called with the received packets from pcap
    // NOTE 1: If you are using only wifi card as RX: I personally did not see any packet reordering with my wifi adapters, but according to svpcom this would be possible
    // NOTE 2: If you are using more than one wifi card as RX, There are probably duplicate packets and packets do not arrive in order.
    PcapReceiver::PROCESS_PACKET_CALLBACK dataCallback;
    // This callback is called regularly independent weather data was received or not
    GENERIC_CALLBACK logCallback;
  };
  /**
   * @param rxInterfaces list of wifi adapters to listen on
   * @param radio_port  radio port (aka stream ID) to filter packets for
   * @param log_interval the log callback is called in the interval specified by @param log_interval
   * @param flush_interval the flush callback is called every time no data has been received for more than @param flush_interval milliseconds
   */
  explicit MultiRxPcapReceiver(Options options) :
    m_options(std::move(options)) {
    const auto N_RECEIVERS = m_options.rxInterfaces.size();
    mReceivers.resize(N_RECEIVERS);
    mReceiverFDs.resize(N_RECEIVERS);
    memset(mReceiverFDs.data(), '\0', mReceiverFDs.size() * sizeof(pollfd));
    std::stringstream ss;
    ss << "MultiRxPcapReceiver ";
    if(m_options.radio_port==-1){
      ss<<"Excluded radio_ports:"<<StringHelper::vectorAsString(m_options.excluded_radio_ports);
    }else{
      ss<<"Assigned radio_port:"<<m_options.radio_port;
    }
    ss<<" Assigned WLAN(s):"<<StringHelper::string_vec_as_string(m_options.rxInterfaces);
    ss << " LOG_INTERVAL(ms)" << (int) m_options.log_interval.count();
    wifibroadcast::log::get_default()->debug(ss.str());

    for (int i = 0; i < N_RECEIVERS; i++) {
      if(m_options.radio_port==-1){
        mReceivers[i] = std::make_unique<PcapReceiver>(m_options.rxInterfaces[i], i, m_options.excluded_radio_ports, m_options.dataCallback);
      }else{
        mReceivers[i] = std::make_unique<PcapReceiver>(m_options.rxInterfaces[i], i, m_options.radio_port, m_options.dataCallback);
      }
      mReceiverFDs[i].fd = mReceivers[i]->getfd();
      mReceiverFDs[i].events = POLLIN;
    }
  }
  void stop(){
    keep_running=false;
    for(auto& receiver:mReceivers){
      receiver.reset();
    }
    mReceivers.resize(0);
  }
  // Those errors hint at a disconnected / crashed wifi card
  uint64_t get_n_receiver_errors(){
    return m_n_receiver_errors;
  }
  // Runs until destructor or an error occurs
  void loop() {
    std::chrono::steady_clock::time_point log_send_ts{};
    while (keep_running) {
      auto cur_ts = std::chrono::steady_clock::now();
      const int timeoutMS = (int) std::chrono::duration_cast<std::chrono::milliseconds>(m_options.log_interval).count();
      int rc = poll(mReceiverFDs.data(), mReceiverFDs.size(), timeoutMS);

      if (rc < 0) {
        if (errno == EINTR || errno == EAGAIN) continue;
        wifibroadcast::log::get_default()->warn("Poll error: {}", strerror(errno));
      }

      cur_ts = std::chrono::steady_clock::now();

      if (cur_ts >= log_send_ts) {
        if(m_options.logCallback){
          m_options.logCallback();
        }
        log_send_ts = std::chrono::steady_clock::now() + m_options.log_interval;
      }

      if (rc == 0) {
        // timeout expired
        continue;
      }
      // TODO Optimization: If rc>1 we have data on more than one wifi card. It would be better to alternating process a couple of packets from card 1, then card 2 or similar
      for (int i = 0; rc > 0 && i < mReceiverFDs.size(); i++) {
        if (mReceiverFDs[i].revents & (POLLERR | POLLNVAL)) {
          if(keep_running){
            // we should only get errors here if the card is disconnected
            m_n_receiver_errors++;
            // limit logging here
            const auto elapsed=std::chrono::steady_clock::now()-m_last_receiver_error_log;
            if(elapsed>std::chrono::seconds(1)){
              wifibroadcast::log::get_default()->warn("RawReceiver errors {} on pcap fds {} (wlan {})",get_n_receiver_errors(),i,m_options.rxInterfaces[i]);
              m_last_receiver_error_log=std::chrono::steady_clock::now();
            }
          }else{
            return;
          }
        }
        if (mReceiverFDs[i].revents & POLLIN) {
          mReceivers[i]->loop_iter();
          rc -= 1;
        }
      }
    }
    wifibroadcast::log::get_default()->debug("MultiRxPcapReceiver::exitLoop");
  }
 private:
  bool keep_running=true;
  const Options m_options;
  std::vector<std::unique_ptr<PcapReceiver>> mReceivers;
  std::vector<pollfd> mReceiverFDs;
  std::atomic<uint32_t> m_n_receiver_errors{};
  std::chrono::steady_clock::time_point m_last_receiver_error_log=std::chrono::steady_clock::now();
 public:
};

#endif //WIFIBROADCAST_RAWRECEIVER_H
