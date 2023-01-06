//
// Created by consti10 on 12.12.20.
//

#ifndef WIFIBROADCAST_RAWTRANSMITTER_HPP
#define WIFIBROADCAST_RAWTRANSMITTER_HPP

#include "Ieee80211Header.hpp"
#include "RadiotapHeader.hpp"
#include "wifibroadcast-spdlog.h"

#include <cstdlib>
#include <endian.h>
#include <fcntl.h>
#include <ctime>
#include <sys/mman.h>
#include <string>
#include <vector>
#include <chrono>
#include <optional>
#include <poll.h>
#include "pcap_helper.h"

// This is a single header-only file you can use to build your own wifibroadcast link
// It doesn't specify if / what FEC to use and so on

// Doesn't specify what / how big the custom header is.
// This way it is easy to make the injection part generic for future changes
// by using a pointer / size tuple the data for the customHeader and payload can reside at different memory locations
// When injecting the packet we have to always copy the data anyways since Radiotap and IEE80211 header
// are stored at different locations, too
class AbstractWBPacket {
 public:
  // constructor for packet without header (or the header is already merged into payload)
  AbstractWBPacket(const uint8_t *payload, const std::size_t payloadSize) :
      customHeader(nullptr), customHeaderSize(0), payload(payload), payloadSize(payloadSize) {};
  // constructor for packet with header and payload at different memory locations
  AbstractWBPacket(const uint8_t *customHeader,
                   const std::size_t customHeaderSize,
                   const uint8_t *payload,
                   const std::size_t payloadSize) :
      customHeader(customHeader), customHeaderSize(customHeaderSize), payload(payload), payloadSize(payloadSize) {};
  AbstractWBPacket(AbstractWBPacket &) = delete;
  AbstractWBPacket(AbstractWBPacket &&) = delete;
 public:
  // can be nullptr if size 0
  const uint8_t *customHeader;
  // can be 0 for special use cases
  const std::size_t customHeaderSize;
  // can be nullptr if size 0
  const uint8_t *payload;
  // can be 0 for special use cases
  const std::size_t payloadSize;
};

namespace RawTransmitterHelper {
// construct a radiotap packet with the following data layout:
// [RadiotapHeader | Ieee80211Header | customHeader (if not size 0) | payload (if not size 0)]
static std::vector<uint8_t>
createRadiotapPacket(const RadiotapHeader &radiotapHeader,
                     const Ieee80211Header &ieee80211Header,
                     const AbstractWBPacket &abstractWbPacket) {
  const auto customHeaderAndPayloadSize = abstractWbPacket.customHeaderSize + abstractWbPacket.payloadSize;
  std::vector<uint8_t> packet(radiotapHeader.getSize() + ieee80211Header.getSize() + customHeaderAndPayloadSize);
  uint8_t *p = packet.data();
  // radiotap wbDataHeader
  memcpy(p, radiotapHeader.getData(), radiotapHeader.getSize());
  p += radiotapHeader.getSize();
  // ieee80211 wbDataHeader
  memcpy(p, ieee80211Header.getData(), ieee80211Header.getSize());
  p += ieee80211Header.getSize();
  if (abstractWbPacket.customHeaderSize > 0) {
    // customHeader
    memcpy(p, abstractWbPacket.customHeader, abstractWbPacket.customHeaderSize);
    p += abstractWbPacket.customHeaderSize;
  }
  if (abstractWbPacket.payloadSize > 0) {
    // payload
    memcpy(p, abstractWbPacket.payload, abstractWbPacket.payloadSize);
  }
  return packet;
}

// copy paste from svpcom
static pcap_t *openTxWithPcap(const std::string &wlan) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *p = pcap_create(wlan.c_str(), errbuf);
  if (p == nullptr) {
    wifibroadcast::log::get_default()->error("Unable to open interface {} in pcap: {}", wlan.c_str(), errbuf);
  }
  if (pcap_set_snaplen(p, 4096) != 0) wifibroadcast::log::get_default()->warn("set_snaplen failed");
  if (pcap_set_promisc(p, 1) != 0) wifibroadcast::log::get_default()->warn("set_promisc failed");
  //if (pcap_set_rfmon(p, 1) !=0) wifibroadcast::log::get_default()->warn("set_rfmon failed";
  // Used to be -1 at some point, which is undefined behaviour. -1 can cause issues on older kernels, according to @Pete
  const int timeout_ms=10;
  if (pcap_set_timeout(p, timeout_ms) != 0) wifibroadcast::log::get_default()->warn("set_timeout {} failed",timeout_ms);
  //if (pcap_set_buffer_size(p, 2048) !=0) wifibroadcast::log::get_default()->warn("set_buffer_size failed";
  // NOTE: Immediate not needed on TX
  if (pcap_activate(p) != 0){
    wifibroadcast::log::get_default()->error("pcap_activate failed: {}",
                                             pcap_geterr(p));
  }
  //if (pcap_setnonblock(p, 1, errbuf) != 0) wifibroadcast::log::get_default()->warn(string_format("set_nonblock failed: %s", errbuf));
  return p;
}

}

class IRawPacketInjector {
 public:
  /**
   * Inject the packet data after prefixing it with Radiotap and IEEE80211 header
   * @return time it took to inject the packet
   */
  virtual std::chrono::steady_clock::duration injectPacket(const RadiotapHeader &radiotapHeader,
                                                           const Ieee80211Header &ieee80211Header,
                                                           const AbstractWBPacket &abstractWbPacket) const = 0;
};

// Pcap Transmitter injects packets into the wifi adapter using pcap
// It does not specify what the payload is and therefore is just a really small wrapper around the pcap interface
// that properly opens / closes the interface on construction/destruction
class PcapTransmitter : public IRawPacketInjector {
 public:
  explicit PcapTransmitter(const std::string &wlan) {
    ppcap = RawTransmitterHelper::openTxWithPcap(wlan);
  }
  ~PcapTransmitter() {
    pcap_close(ppcap);
  }
  // inject packet by prefixing wifibroadcast packet with the IEE and Radiotap header
  // return: time it took to inject the packet.If the injection time is absurdly high, you might want to do something about it
  [[nodiscard]] std::chrono::steady_clock::duration injectPacket(const RadiotapHeader &radiotapHeader,
                                                   const Ieee80211Header &ieee80211Header,
                                                   const AbstractWBPacket &abstractWbPacket) const override {
    const auto packet = RawTransmitterHelper::createRadiotapPacket(radiotapHeader, ieee80211Header, abstractWbPacket);
    const auto before = std::chrono::steady_clock::now();
    const auto len_injected=pcap_inject(ppcap, packet.data(), packet.size());
    if (len_injected != (int) packet.size()) {
      // This basically should never fail - if the tx queue is full, pcap seems to wait ?!
      wifibroadcast::log::get_default()->warn("pcap -unable to inject packet size:{} ret:{} err:{}",packet.size(),len_injected, pcap_geterr(ppcap));
    }
    return std::chrono::steady_clock::now() - before;
  }
  void injectControllFrame(const RadiotapHeader &radiotapHeader, const std::vector<uint8_t> &iee80211ControllHeader) {
    std::vector<uint8_t> packet(radiotapHeader.getSize() + iee80211ControllHeader.size());
    memcpy(packet.data(), &radiotapHeader, RadiotapHeader::SIZE_BYTES);
    memcpy(&packet[RadiotapHeader::SIZE_BYTES], iee80211ControllHeader.data(), iee80211ControllHeader.size());
    const auto len_injected=pcap_inject(ppcap, packet.data(), packet.size());
    if (len_injected != (int) packet.size()) {
      // This basically should never fail - if the tx queue is full, pcap seems to wait ?!
      wifibroadcast::log::get_default()->warn("pcap -unable to inject controll packet size:{} ret:{} err;{}",packet.size(),len_injected, pcap_geterr(ppcap));
    }
  }
 private:
  pcap_t *ppcap;
};

// Doesn't use pcap but somehow directly talks to the OS via socket
// note that you still have to prefix data with the proper RadiotapHeader in this mode (just as if you were using pcap)
// NOTE: I didn't measure any advantage for RawSocketTransmitter compared to PcapTransmitter, so I'd recommend using PcapTransmitter only
class RawSocketTransmitter : public IRawPacketInjector {
 public:
  explicit RawSocketTransmitter(const std::string &wlan) {
    wifibroadcast::log::get_default()->debug("RawSocketTransmitter on {}",wlan);
    sockFd = openWifiInterfaceAsTxRawSocket(wlan);
  }
  ~RawSocketTransmitter() {
    close(sockFd);
  }
  // inject packet by prefixing wifibroadcast packet with the IEE and Radiotap header
  // return: time it took to inject the packet.If the injection time is absurdly high, you might want to do something about it
  [[nodiscard]] std::chrono::steady_clock::duration injectPacket(const RadiotapHeader &radiotapHeader,
                                                   const Ieee80211Header &ieee80211Header,
                                                   const AbstractWBPacket &abstractWbPacket) const override {
    const auto packet = RawTransmitterHelper::createRadiotapPacket(radiotapHeader, ieee80211Header, abstractWbPacket);
    const auto before = std::chrono::steady_clock::now();
    const auto len_written=write(sockFd, packet.data(), packet.size());
    if (len_written != packet.size()) {
      wifibroadcast::log::get_default()->error("raw -unable to inject packet size:{} ret:{} err:{}",packet.size(),len_written,strerror(errno));
    }
    return std::chrono::steady_clock::now() - before;
  }
  static int get_socket_send_buffer_size(int sockfd){
    int sendBufferSize=INT_MIN;
    socklen_t len=sizeof(sendBufferSize);
    if(getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sendBufferSize, &len)!=0){
      wifibroadcast::log::get_default()->debug("Cannot get socket sendbuffer size");
    }
    return sendBufferSize;
  }
  static int64_t get_socket_timeout_us(int sockfd){
    struct timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = 0; // timeout of 1 ms
    socklen_t len=sizeof(timeout);
    if (getsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO,(void*) &timeout, &len) != 0) {
      wifibroadcast::log::get_default()->warn("cannot get socket_timeout");
      return -1;
    }
    return (timeout.tv_sec*1000*1000)+timeout.tv_usec;
  }
  // taken from https://github.com/OpenHD/Open.HD/blob/2.0/wifibroadcast-base/tx_rawsock.c#L86
  // open wifi interface using a socket (somehow this works ?!)
  static int openWifiInterfaceAsTxRawSocket(const std::string &wifi) {
    struct sockaddr_ll ll_addr{};
    struct ifreq ifr{};
    int sock = socket(AF_PACKET, SOCK_RAW, 0);
    if (sock == -1) {
      std::stringstream ss;
      ss<<"RawSocketTransmitter:: open socket failed "<<wifi.c_str()<<" "<<strerror(errno);
      wifibroadcast::log::get_default()->error(ss.str());
    }

    ll_addr.sll_family = AF_PACKET;
    ll_addr.sll_protocol = 0;
    ll_addr.sll_halen = ETH_ALEN;

    strncpy(ifr.ifr_name, wifi.c_str(), IFNAMSIZ);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
      wifibroadcast::log::get_default()->error("ioctl(SIOCGIFINDEX) failed");
    }

    ll_addr.sll_ifindex = ifr.ifr_ifindex;

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
      wifibroadcast::log::get_default()->error("ioctl(SIOCGIFHWADDR) failed");
    }

    memcpy(ll_addr.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    if (bind(sock, (struct sockaddr *) &ll_addr, sizeof(ll_addr)) == -1) {
      close(sock);
      wifibroadcast::log::get_default()->error("bind failed");
    }
    struct timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = 1*1000; // timeout of 1 ms
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
      wifibroadcast::log::get_default()->warn("setsockopt SO_SNDTIMEO");
    }
    // for some reason setting the timeout does not seem to work here, I always get 10ms back
    wifibroadcast::log::get_default()->debug("RawSocketTransmitter::timeout: {}ms", static_cast<double>(get_socket_timeout_us(sock))/1000.0);
    wifibroadcast::log::get_default()->debug("RawSocketTransmitter::curr_send_buffer_size:{}",get_socket_send_buffer_size(sock));
    const int wanted_sendbuff = 128*1024; //131072
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &wanted_sendbuff, sizeof(wanted_sendbuff)) < 0) {
      wifibroadcast::log::get_default()->warn("setsockopt SO_SNDBUF");
    }
    wifibroadcast::log::get_default()->debug("RawSocketTransmitter::applied_send_buffer_size:{}",get_socket_send_buffer_size(sock));
    return sock;
  }
 private:
  int sockFd;
};

#endif //WIFIBROADCAST_RAWTRANSMITTER_HPP
