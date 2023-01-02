//
// Created by consti10 on 10.03.21.
//

#ifndef WIFIBROADCAST_FECDISABLED_HPP
#define WIFIBROADCAST_FECDISABLED_HPP

#include <cstdint>
#include <cerrno>
#include <string>
#include <utility>
#include <vector>
#include <array>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <functional>
#include <map>

// FEC Disabled is used for telemetry data in OpenHD.
// We have different requirements on packet loss and/or packet reordering for this type of data stream.

// usage of nonce: Simple, uint64_t number increasing with each packet
class FECDisabledEncoder {
 public:
  typedef std::function<void(const uint64_t nonce, const uint8_t *payload, const std::size_t payloadSize)>
      OUTPUT_DATA_CALLBACK;
  OUTPUT_DATA_CALLBACK outputDataCallback;
  void encodePacket(const uint8_t *buf, const size_t size) {
    outputDataCallback(currPacketIndex, buf, size);
    currPacketIndex++;
    if (currPacketIndex == std::numeric_limits<uint64_t>::max()) {
      currPacketIndex = 0;
    }
  }
 private:
  // With a 64 bit sequence number we will NEVER overrun, no matter how long the tx/rx are running
  uint64_t currPacketIndex = 0;
};

class FECDisabledDecoder {
 public:
  typedef std::function<void(const uint8_t *payload, std::size_t payloadSize)> SEND_DECODED_PACKET;
  // WARNING: Don't forget to register this callback !
  SEND_DECODED_PACKET mSendDecodedPayloadCallback;
 private:
  // Add a limit here to not allocate infinite amounts of memory
  static constexpr std::size_t FEC_DISABLED_MAX_SIZE_OF_MAP = 100;
  std::map<uint64_t, void *> m_known_sequence_numbers;
  bool first_ever_packet = true;
 public:
  //No duplicates, but packets out of order are possible
  //counting lost packets doesn't work in this mode. It should be done by the upper level
  //saves the last FEC_DISABLED_MAX_SIZE_OF_MAP sequence numbers. If the sequence number of a new packet is already inside the map, it is discarded (duplicate)
  void processRawDataBlockFecDisabled(const uint64_t packetSeq, const std::vector<uint8_t> &decrypted) {
    assert(mSendDecodedPayloadCallback);
    if (first_ever_packet) {
      // first ever packet. Map should be empty
      m_known_sequence_numbers.clear();
      mSendDecodedPayloadCallback(decrypted.data(), decrypted.size());
      m_known_sequence_numbers.insert({packetSeq, nullptr});
      first_ever_packet = false;
    }
    // check if packet is already known (inside the map)
    const auto search = m_known_sequence_numbers.find(packetSeq);
    if (search == m_known_sequence_numbers.end()) {
      // if packet is not in the map it was not yet received(unless it is older than MAX_SIZE_OF_MAP, but that is basically impossible)
      mSendDecodedPayloadCallback(decrypted.data(), decrypted.size());
      m_known_sequence_numbers.insert({packetSeq, nullptr});
    }// else this is a duplicate
    // house keeping, do not increase size to infinity
    if (m_known_sequence_numbers.size() >= FEC_DISABLED_MAX_SIZE_OF_MAP - 1) {
      // remove oldest element
      m_known_sequence_numbers.erase(m_known_sequence_numbers.begin());
    }
  }
};

#endif //WIFIBROADCAST_FECDISABLED_HPP
