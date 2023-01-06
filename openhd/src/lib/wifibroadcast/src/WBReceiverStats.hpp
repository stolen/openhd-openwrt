//
// Created by consti10 on 06.12.20.
//

#ifndef WIFIBROADCAST_OPENHDSTATISTICSWRITER_H
#define WIFIBROADCAST_OPENHDSTATISTICSWRITER_H

#include <cstdint>
#include <optional>

#include "HelperSources/TimeHelper.hpp"
#include <optional>

// TODO what happens here has to be decided yet
// write the fec decoding stats (and optionally RSSI ) for each rx stream


// Stores the min, max and average of the rssi values reported for this wifi card
// Doesn't differentiate from which antenna the rssi value came
//https://www.radiotap.org/fields/Antenna%20signal.html
class RSSIForWifiCard {
 public:
  RSSIForWifiCard() = default;
  void addRSSI(int8_t rssi) {
    last_rssi=rssi;
    if (count_all == 0) {
      rssi_min = rssi;
      rssi_max = rssi;
    } else {
      rssi_min = std::min(rssi, rssi_min);
      rssi_max = std::max(rssi, rssi_max);
    }
    rssi_sum += rssi;
    count_all += 1;
  }
  int8_t getAverage() const {
    if (rssi_sum == 0)return 0;
    return rssi_sum / count_all;
  }
  void reset() {
    count_all = 0;
    rssi_sum = 0;
    rssi_min = 0;
    rssi_max = 0;
  }
  int32_t count_all = 0;
  int32_t rssi_sum = 0;
  int8_t rssi_min = 0;
  int8_t rssi_max = 0;
  int8_t last_rssi=INT8_MIN;
};
static std::ostream& operator<<(std::ostream& strm, const RSSIForWifiCard& obj){
  std::stringstream ss;
  ss<<"RSSIForWifiCard{last:"<<(int)obj.last_rssi<<",avg:"<<(int)obj.getAverage()<<",min:"<<(int)obj.rssi_min
     <<",max:"<<(int)obj.rssi_max<<"}";
  strm<<ss.str();
  return strm;
}

static std::string bitrate_to_string(uint64_t bits_per_second){
  const double mBits_per_second=static_cast<double>(bits_per_second)/(1000*1000);
  if(mBits_per_second>1){
    return std::to_string(mBits_per_second)+"mBit/s";
  }
  const double kBits_per_second=static_cast<double>(bits_per_second)/1000;
  return std::to_string(kBits_per_second)+"kBit/s";
}

// receiving, validating and decrypting raw wifi packets
struct WBRxStats{
  // n of all received packets, absolute
  uint64_t count_p_all = 0;
  // n of received packets that are bad for any reason
  uint64_t count_p_bad = 0;
  // encryption stats
  uint64_t count_p_decryption_err = 0;
  uint64_t count_p_decryption_ok = 0;
  // n of total received bytes, before FEC decoding
  uint64_t count_bytes_data_received=0;
  // current incoming bitrate, in bits per second.
  // includes FEC overhead
  uint64_t curr_incoming_bits_per_second =0;
  // current packet loss, in percent
  int16_t curr_packet_loss_percentage=-1;
  // N of "big gaps", recalculated in regular intervals. Together with the packet loss
  // in percent this gives a good overview over the current quality of the link.
  // What exactly counts as a "big gap" cannot be exactly defined.
  int curr_n_of_big_gaps=-1;
  // should only increase when the wifi card disconnects / crashes
  uint64_t n_receiver_likely_disconnect_errors=0;
};
static std::ostream& operator<<(std::ostream& strm, const WBRxStats& obj){
  std::stringstream ss;
  ss<<"WBRxStats{all:"<<obj.count_p_all<<",bad:"<<obj.count_p_bad<<",decrypt_err:"<<obj.count_p_decryption_err
     <<",decrypt_ok:"<<obj.count_p_decryption_ok<<",bytes:"<<obj.count_bytes_data_received
     <<",bitrate:"<<bitrate_to_string(obj.curr_incoming_bits_per_second)<<"}";
  strm<<ss.str();
  return strm;
}

// matches FECDecoder
struct FECRxStats {
  // total block count
  uint64_t count_blocks_total = 0;
  // a block counts as "lost" if it was removed before being fully received or recovered
  uint64_t count_blocks_lost = 0;
  // a block counts as "recovered" if it was recovered using FEC packets
  uint64_t count_blocks_recovered = 0;
  // n of primary fragments that were reconstructed during the recovery process of a block
  uint64_t count_fragments_recovered = 0;
  // n of forwarded bytes
  uint64_t count_bytes_forwarded=0;
  MinMaxAvg<std::chrono::nanoseconds> curr_fec_decode_time{};
};
static std::ostream& operator<<(std::ostream& strm, const FECRxStats& obj){
  std::stringstream ss;
  ss<<"FECRxStats{blocks_total:"<<obj.count_blocks_total<<",blocks_lost:"<<obj.count_blocks_lost<<",blocks_recovered:"<<obj.count_blocks_recovered
     <<",fragments_recovered:"<<obj.count_fragments_recovered<<",bytes_forwarded:"<<obj.count_bytes_forwarded<<"}";
  strm<<ss.str();
  return strm;
}

struct WBReceiverStats {
  // the unique stream ID this data refers to
  uint8_t radio_port = 0;
  // min max and avg rssi for each wifi card since the last call.
  // if count_all for a card at position N is 0 nothing has been received on this card from the last call (or the card at position N is not used for this instance)
  std::array<RSSIForWifiCard, 8> rssiPerCard{};
  // Available regardless if FEC is enabled or disabled
  WBRxStats wb_rx_stats;
  // only if FEC enabled
  std::optional<FECRxStats> fec_rx_stats;
};

static std::ostream& operator<<(std::ostream& strm, const WBReceiverStats& data){
  std::stringstream ss;
  ss<<"Stats for "<<(int)data.radio_port<<"\n";
  ss<<data.wb_rx_stats;
  if(data.fec_rx_stats.has_value()){
    ss<<"\n"<<data.fec_rx_stats.value();
  }
  strm<<ss.str();
  return strm;
}
#endif //WIFIBROADCAST_OPENHDSTATISTICSWRITER_H
