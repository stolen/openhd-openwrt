// Copyright (C) 2017, 2018, 2019 Vasily Evseenko <svpcom@p2ptech.org>
// 2020 Constantin Geier
/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 3.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#ifndef __WIFIBROADCAST_HPP__
#define __WIFIBROADCAST_HPP__

#include "Ieee80211Header.hpp"
#include "RadiotapHeader.hpp"

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <resolv.h>
#include <cstring>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>
#include <endian.h>
#include <fcntl.h>
#include <ctime>
#include <sys/mman.h>
#include <endian.h>
#include <string>
#include <vector>
#include <chrono>
#include <optional>
// need it for the "size" definitions
#include <sodium.h>

/**
 * Wifibroadcast protocol:
 * radiotap_header
 * * ieee_80211_header
 * ** if WFB_PACKET_KEY
 * *** WBSessionKeyPacket
 * ** if WFB_PACKET_DATA
 * *** uint64_t nonce (usage left up to the implementation,e.g FEC)
 * *** payload, left up to the implementation (e.g. FEC)
 */

static constexpr const uint8_t WFB_PACKET_DATA = 0x1;
static constexpr const uint8_t WFB_PACKET_KEY = 0x2;
// for testing, do not use in production (just don't send it on the tx)
static constexpr const uint8_t WFB_PACKET_LATENCY_BEACON = 0x3;

// the encryption key is sent every n seconds ( but not re-created every n seconds, it is only re-created when reaching the max sequence number)
// also it is only sent if a new packet needs to be transmitted, to save bandwidth (since the tx instance might exist, but not being used)
// it needs to be sent multiple times instead of once since it might get lost on the first or nth time respective
static constexpr const auto SESSION_KEY_ANNOUNCE_DELTA = std::chrono::seconds(1);

// Session key packet
// Since the size of each session key packet never changes, this memory layout is the easiest
class WBSessionKeyPacket {
 public:
  // note how this member doesn't add up to the size of this class (c++ is so great !)
  static constexpr auto
      SIZE_BYTES = 1 + crypto_box_NONCEBYTES + crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES + 1 + 2 ;//+ 16;
 public:
  const uint8_t packet_type = WFB_PACKET_KEY;
  std::array<uint8_t, crypto_box_NONCEBYTES> sessionKeyNonce{};  // random data
  std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES> sessionKeyData{}; // encrypted session key
  uint8_t IS_FEC_ENABLED = 0; // ether true or false
  uint16_t unused = 0;
  // extraData is usage-specific information that is unique per session.
  // For example, the plan is to change the session in OpenHD when the video format changes
  //std::array<uint8_t, 16> extraData{0};
}__attribute__ ((packed));
static_assert(sizeof(WBSessionKeyPacket) == WBSessionKeyPacket::SIZE_BYTES, "ALWAYS_TRUE");

// This header comes with each FEC packet (primary or secondary)
// This part is not encrypted ! (though used for checksum)
class WBDataHeader {
 public:
  explicit WBDataHeader(uint64_t nonce1,uint16_t seq_nr) : nonce(nonce1),sequence_number_extra(seq_nr) {};
 public:
  const uint8_t packet_type = WFB_PACKET_DATA;
  const uint16_t sequence_number_extra=0;
  const uint64_t nonce;  // it is left up to the implementation on how to use nonce
}  __attribute__ ((packed));
static_assert(sizeof(WBDataHeader) == 8 + 1+2, "ALWAYS_TRUE");


struct LatencyTestingPacket {
  const uint8_t packet_type = WFB_PACKET_LATENCY_BEACON;
  const int64_t timestampNs =
      std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}__attribute__ ((packed));

// The final packet size ( radiotap header + iee80211 header + payload ) is never bigger than that
// the reasoning behind this value: https://github.com/svpcom/wifibroadcast/issues/69
static constexpr const auto PCAP_MAX_PACKET_SIZE = 1510;
// Max n of wifi cards connected as an RX array
static constexpr const auto MAX_RX_INTERFACES = 8;
// This is the max number of bytes usable for the (FEC) implementation
static constexpr const auto
    RAW_WIFI_FRAME_MAX_PAYLOAD_SIZE = (PCAP_MAX_PACKET_SIZE - RadiotapHeader::SIZE_BYTES - Ieee80211Header::SIZE_BYTES);
static constexpr const auto WB_FRAME_MAX_PAYLOAD =
    (PCAP_MAX_PACKET_SIZE - RadiotapHeader::SIZE_BYTES - Ieee80211Header::SIZE_BYTES - sizeof(WBDataHeader)
        - crypto_aead_chacha20poly1305_ABYTES);

static_assert(WB_FRAME_MAX_PAYLOAD==1448-2);

// comment this for a release
//#define ENABLE_ADVANCED_DEBUGGING

#ifndef WFB_VERSION
#define WFB_VERSION "WFB_VERSION_EVO_2.2.X"
#endif

#endif //__WIFIBROADCAST_HPP__
