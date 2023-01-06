//
// Created by consti10 on 26.11.22.
//

#ifndef WIFIBROADCAST_SRC_WBTRANSMITTERSTATS_HPP_
#define WIFIBROADCAST_SRC_WBTRANSMITTERSTATS_HPP_

struct WBTxStats{
  int64_t n_injected_packets;
  int64_t n_injected_bytes;
  uint64_t current_provided_bits_per_second;
  //
  uint64_t current_injected_bits_per_second;
  // Other than bits per second, packets per second is also an important metric -
  // Sending a lot of small packets for example should be avoided)
  uint64_t current_injected_packets_per_second;
  // tx errors, first sign the tx can't keep up with the provided bitrate
  uint64_t count_tx_injections_error_hint;
  // N of dropped packets, increases when both the internal driver queue and the extra 124 packets queue of the tx fill up
  uint64_t n_dropped_packets;
};

struct FECTxStats{
  MinMaxAvg<std::chrono::nanoseconds> curr_fec_encode_time{};
  MinMaxAvg<uint16_t> curr_fec_block_length{};
};

#endif  // WIFIBROADCAST_SRC_WBTRANSMITTERSTATS_HPP_
