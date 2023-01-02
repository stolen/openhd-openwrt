//
// Created by consti10 on 02.12.20.
//

#ifndef WIFIBROADCAST_FECENABLED_HPP
#define WIFIBROADCAST_FECENABLED_HPP

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "FEC.hpp"
#include "HelperSources/TimeHelper.hpp"
#include "WBReceiverStats.hpp"
#include "wifibroadcast-spdlog.h"

// RN this module depends on "wifibroadcast.hpp", since it holds the "packet size(s)" needed to calculate FEC_MAX_PAYLOAD_SIZE
// Removing this dependency (to write your own customized link) would be easy to do though.

static_assert(__BYTE_ORDER == __LITTLE_ENDIAN, "This code is written for little endian only !");
// nonce: 64 bit value, consisting of
// 32 bit block idx
// 16 bit fragment idx
// 16 bit "extra data": 1 bit flag and 15 bit number
// flag==0: This is a primary fragment. If it is the last primary fragment for this block, number=n of all primary fragments in this block, else number=0
// flag==1: This is a secondary fragment. Then number== n of all primary fragments in this block
struct FECNonce {
  uint32_t blockIdx;
  uint16_t fragmentIdx;
  uint8_t flag: 1;
  uint16_t number: 15;
  // 15.3.21: Unfortunately,on ARM (rpi) you need to explicitly
  // memcpy instead of reinterpret_cast FECNonce to uint64_t.
  explicit operator uint64_t() const {
    //return *reinterpret_cast<const uint64_t*>(this);
    uint64_t ret;
    memcpy(&ret, this, sizeof(uint64_t));
    return ret;
  }
}__attribute__ ((packed));
static_assert(sizeof(FECNonce) == sizeof(uint64_t));
static FECNonce fecNonceFrom(const uint64_t nonce) {
  //return *reinterpret_cast<const FECNonce*>(&nonce);
  FECNonce fecNonce;
  memcpy(&fecNonce, &nonce, sizeof(FECNonce));
  return fecNonce;
}
static constexpr uint64_t MAX_BLOCK_IDX = std::numeric_limits<uint32_t>::max();

// this header is written before the data of each primary FEC fragment
// ONLY for primary FEC fragments though !
// (up to n bytes workaround,in conjunction with zeroing out bytes, but never transmitting the zeroed out bytes)
class FECPayloadHdr {
 private:
  // private member to make sure it is always used properly
  uint16_t packet_size;
 public:
  explicit FECPayloadHdr(const std::size_t packetSize1) {
    assert(packetSize1 <= std::numeric_limits<uint16_t>::max());
    // convert to big endian if needed
    packet_size = htobe16(packetSize1);
  }
  // convert from big endian if needed
  [[nodiscard]] std::size_t getPrimaryFragmentSize() const {
    return be16toh(packet_size);
  }
}  __attribute__ ((packed));
static_assert(sizeof(FECPayloadHdr) == 2, "ALWAYS_TRUE");

// 1510-(13+24+9+16+2)
//A: Any UDP with packet size <= 1466. For example x264 inside RTP or Mavlink.
// set here to remove dependency on wifibroadcast.hpp
static constexpr const auto FEC_MAX_PACKET_SIZE = 1448-2;
//static constexpr const auto FEC_MAX_PACKET_SIZE= WB_FRAME_MAX_PAYLOAD;
static constexpr const auto FEC_MAX_PAYLOAD_SIZE = FEC_MAX_PACKET_SIZE - sizeof(FECPayloadHdr);
static_assert(FEC_MAX_PAYLOAD_SIZE == 1446-2);
// max 255 primary and secondary fragments together for now. Theoretically, this implementation has enough bytes in the header for
// up to 15 bit fragment indices, 2^15=32768
// Note: currently limited by the fec c implementation
static constexpr const uint16_t MAX_N_P_FRAGMENTS_PER_BLOCK = 128;
static constexpr const uint16_t MAX_N_S_FRAGMENTS_PER_BLOCK = 128;
static constexpr const uint16_t
    MAX_TOTAL_FRAGMENTS_PER_BLOCK = MAX_N_P_FRAGMENTS_PER_BLOCK + MAX_N_S_FRAGMENTS_PER_BLOCK;

// For dynamic block sizes, we switched to a FEC overhead "percentage" value.
// e.g. the final data throughput ~= original data troughput * fec overhead percentage
static uint32_t calculate_n_secondary_fragments(uint32_t n_primary_fragments,uint32_t fec_overhead_perc){
  if(fec_overhead_perc<=0)return 0;
  return std::lroundf(static_cast<float>(n_primary_fragments) * static_cast<float>(fec_overhead_perc) / 100.0f);
}

// Takes a continuous stream of packets and
// encodes them via FEC such that they can be decoded by FECDecoder
// The encoding is slightly different from traditional FEC. It
// a) makes sure to send out data packets immediately
// b) Handles packets of size up to N instead of packets of exact size N
// Due to b) the packet size has to be written into the first two bytes of each data packet. See https://github.com/svpcom/wifibroadcast/issues/67
// c) allows ending a block at any time when putting in a new primary fragment. This way primary fragments can be forwarded immediately to the
// transmitter, and each fec block can be aligned to the end of a fragmented packet.
class FECEncoder {
 public:
  typedef std::function<void(const uint64_t nonce, const uint8_t *payload, const std::size_t payloadSize)>
      OUTPUT_DATA_CALLBACK;
  OUTPUT_DATA_CALLBACK outputDataCallback;
  // If you want to use the encoder for a fixed k, just use k for K_MAX and never call
  // encodePacket(...,true).
  // Else, if you want to use the encoder for variable k, just use K_MAX=MAX_N_P_FRAGMENTS_PER_BLOCK and call
  // encodePacket(...,true) as needed.
  // Note: you can change the fec overhead percentage value at any time, itl be applied on the next fec encode step
  explicit FECEncoder(unsigned int k_max, unsigned int fec_overhead_perc):
    m_curr_fec_k_max(k_max), m_curr_fec_overhead_perc(fec_overhead_perc) {
    blockBuffer.resize(MAX_TOTAL_FRAGMENTS_PER_BLOCK);
    validate_and_debug_current_params();
  }
  FECEncoder(const FECEncoder &other) = delete;
 private:
  uint32_t currBlockIdx = 0;
  uint16_t currFragmentIdx = 0;
  size_t currMaxPacketSize = 0;
  // Pre-allocated to have space for storing primary fragments (they are needed once the fec step needs to be performed)
  // and creating the wanted amount of secondary packets
  std::vector<std::array<uint8_t, FEC_MAX_PACKET_SIZE>> blockBuffer{};
  std::atomic<uint32_t> m_curr_fec_k_max;
  std::atomic<uint32_t> m_curr_fec_overhead_perc;
  AvgCalculator m_fec_block_encode_time;
  MinMaxAvg<std::chrono::nanoseconds> m_curr_fec_block_encode_time{};
  BaseAvgCalculator<uint16_t> m_block_sizes{};
  MinMaxAvg<uint16_t> m_curr_fec_block_sizes{};
 public:
  /**
   * encode packet such that it can be decoded by FECDecoder. Data is forwarded via the callback.
   * @param endBlock if true, the FEC step is applied immediately
   * else, the FEC step is only applied if reaching m_curr_fec_k_max
   * @return true if the fec step was performed, false otherwise
   */
  bool encodePacket(const uint8_t *buf, const size_t buff_size, const bool endBlock = false) {
    // Drop and log warning if the packet size is not valid
    if (buff_size <= 0 || buff_size >FEC_MAX_PAYLOAD_SIZE) {
      wifibroadcast::log::get_default()->warn("Invalid packet size {}",buff_size);
      return false;
    }
    FECPayloadHdr dataHeader(buff_size);
    // write the size of the data part into each primary fragment.
    // This is needed for the 'up to n bytes' workaround
    memcpy(blockBuffer[currFragmentIdx].data(), &dataHeader, sizeof(dataHeader));
    // write the actual data
    memcpy(blockBuffer[currFragmentIdx].data() + sizeof(dataHeader), buf,buff_size);
    // zero out the remaining bytes such that FEC always sees zeroes
    // same is done on the rx. These zero bytes are never transmitted via wifi
    const auto writtenDataSize = sizeof(FECPayloadHdr) + buff_size;
    memset(blockBuffer[currFragmentIdx].data() + writtenDataSize, '\0', FEC_MAX_PACKET_SIZE - writtenDataSize);

    // check if we need to end the block right now (aka do FEC step on tx)
    const int currNPrimaryFragments = currFragmentIdx + 1;
    // end block if we either reached mKMax or the caller requested it
    // we use greater than or equal here because the k_max might change atomically
    const bool lastPrimaryFragment = (currNPrimaryFragments >= m_curr_fec_k_max) || endBlock;

    sendPrimaryFragment(sizeof(dataHeader) + buff_size, lastPrimaryFragment);
    // the packet size for FEC encoding is determined by calculating the max of all primary fragments in this block.
    // Since the rest of the bytes are zeroed out we can run FEC with dynamic packet size.
    // As long as the deviation in packet size of primary fragments isn't too high the loss in raw bandwidth is negligible
    // Note,the loss in raw bandwidth comes from the size of the FEC secondary packets, which always has to be the max of all primary fragments
    // Not from the primary fragments, they are transmitted without the "zeroed out" part
    currMaxPacketSize = std::max(currMaxPacketSize, sizeof(dataHeader) + buff_size);
    currFragmentIdx += 1;
    // if this is not the last primary fragment, wo don't need to do anything else
    if (!lastPrimaryFragment) {
      return false;
    }
    //wifibroadcast::log::get_default()->debug("Doing FEC step on block size {}",currNPrimaryFragments);
    // prepare for the fec step
    auto nSecondaryFragments = calculate_n_secondary_fragments(currNPrimaryFragments,m_curr_fec_overhead_perc);
    if(nSecondaryFragments>MAX_N_S_FRAGMENTS_PER_BLOCK){
      wifibroadcast::log::get_default()->warn("Too many secondary fragments {}, reduce % value",nSecondaryFragments);
      nSecondaryFragments=MAX_N_S_FRAGMENTS_PER_BLOCK;
    }
    m_block_sizes.add(currNPrimaryFragments);
    if(m_block_sizes.get_delta_since_last_reset()>=std::chrono::seconds(1)){
      //wifibroadcast::log::get_default()->debug("Block sizes: {}",m_block_sizes.getAvgReadable());
      m_curr_fec_block_sizes=m_block_sizes.getMinMaxAvg();
      m_block_sizes.reset();
    }
    //wifibroadcast::log::get_default()->debug("Creating block ("<<currNPrimaryFragments<<":"<<currNPrimaryFragments+nSecondaryFragments<<")\n";
    const auto before=std::chrono::steady_clock::now();
    // once enough data has been buffered, create all the secondary fragments
    fecEncode(currMaxPacketSize, blockBuffer, currNPrimaryFragments, nSecondaryFragments);
    m_fec_block_encode_time.add(std::chrono::steady_clock::now()-before);
    if(m_fec_block_encode_time.get_delta_since_last_reset()>=std::chrono::seconds(1)){
      //wifibroadcast::log::get_default()->debug("FEC encode time:{}",m_fec_block_encode_time.getAvgReadable());
      m_curr_fec_block_encode_time=m_fec_block_encode_time.getMinMaxAvg();
      m_fec_block_encode_time.reset();
    }
    // and send them all out
    while (currFragmentIdx < currNPrimaryFragments + nSecondaryFragments) {
      sendSecondaryFragment(currMaxPacketSize, currNPrimaryFragments);
      currFragmentIdx += 1;
    }
    currBlockIdx += 1;
    currFragmentIdx = 0;
    currMaxPacketSize = 0;
    return true;
  }

  void update_fec_overhead_percentage(uint32_t fec_overhead_perc){
    m_curr_fec_overhead_perc=fec_overhead_perc;
    validate_and_debug_current_params();
  }

  void update_fec_k(uint32_t fec_k){
    m_curr_fec_k_max =fec_k;
    validate_and_debug_current_params();
  }

  void validate_and_debug_current_params(){
    const auto tmp_n = calculateN(m_curr_fec_k_max, m_curr_fec_overhead_perc);
    wifibroadcast::log::get_default()->debug( "FEC with k max: {} and percentage: {}", m_curr_fec_k_max,m_curr_fec_overhead_perc);
    wifibroadcast::log::get_default()->debug("For a block size of k max this is {}:{} in old (K:N) terms.",
        m_curr_fec_k_max,tmp_n);
    assert(m_curr_fec_k_max > 0);
    assert(m_curr_fec_k_max <= MAX_N_P_FRAGMENTS_PER_BLOCK);
    assert(tmp_n <= MAX_TOTAL_FRAGMENTS_PER_BLOCK);
  }

  MinMaxAvg<std::chrono::nanoseconds> get_current_fec_blk_encode_time(){
    return m_curr_fec_block_encode_time;
  }
  MinMaxAvg<uint16_t> get_current_fec_blk_sizes(){
    return m_curr_fec_block_sizes;
  }

  // returns true if the block_idx has reached its maximum
  // You want to send a new session key in this case
  bool resetOnOverflow() {
    if (currBlockIdx > MAX_BLOCK_IDX) {
      currBlockIdx = 0;
      currFragmentIdx = 0;
      return true;
    }
    return false;
  }
  // returns true if the last block was already fully processed.
  // in this case, you don't need to finish the current block until you put data in the next time
  // also, in the beginning the pipeline is already flushed due to no data packets yet
  bool isAlreadyInFinishedState() const {
    return currFragmentIdx == 0;
  }
  // calculate n from k and percentage as used in FEC terms
  // (k: number of primary fragments, n: primary + secondary fragments)
  static unsigned int calculateN(const unsigned int k, const unsigned int percentage) {
    return k + calculate_n_secondary_fragments(k,percentage);
  }
 private:
  // calculate proper nonce (such that the rx can decode it properly), then forward via callback
  void sendPrimaryFragment(const std::size_t packet_size, const bool isLastPrimaryFragment) {
    // remember we start counting from 0 not 1
    const FECNonce
        nonce{currBlockIdx, currFragmentIdx, false, (uint16_t) (isLastPrimaryFragment ? (currFragmentIdx + 1) : 0)};
    const uint8_t *dataP = blockBuffer[currFragmentIdx].data();
    outputDataCallback((uint64_t) nonce, dataP, packet_size);
  }
  // calculate proper nonce (such that the rx can decode it properly), then forward via callback
  void sendSecondaryFragment(const std::size_t packet_size, const int nPrimaryFragments) {
    const FECNonce nonce{currBlockIdx, currFragmentIdx, true, (uint16_t) nPrimaryFragments};
    const uint8_t *dataP = blockBuffer[currFragmentIdx].data();
    outputDataCallback((uint64_t) nonce, dataP, packet_size);
  }
};

// This encapsulates everything you need when working on a single FEC block on the receiver
// for example, addFragment() or pullAvailablePrimaryFragments()
// it also provides convenient methods to query if the block is fully forwarded
// or if it is ready for the FEC reconstruction step.
class RxBlock {
 public:
  // @param maxNFragmentsPerBlock max number of primary and secondary fragments for this block.
  // you could just use MAX_TOTAL_FRAGMENTS_PER_BLOCK for that, but if your tx then uses (4:8) for example, you'd
  // allocate much more memory every time for a new RX block than needed.
  explicit RxBlock(const unsigned int maxNFragmentsPerBlock, const uint64_t blockIdx1) :
      blockIdx(blockIdx1),
      fragment_map(maxNFragmentsPerBlock,
                   FragmentStatus::UNAVAILABLE), //after creation of the RxBlock every f. is marked as unavailable
      blockBuffer(maxNFragmentsPerBlock) {
    assert(fragment_map.size() == blockBuffer.size());
  }
  // No copy constructor for safety
  RxBlock(const RxBlock &) = delete;
  // two blocks are the same if they refer to the same block idx:
  constexpr bool operator==(const RxBlock &other) const {
    return blockIdx == other.blockIdx;
  }
  // same for not equal operator
  constexpr bool operator!=(const RxBlock &other) const {
    return !(*this == other);
  }
  ~RxBlock() = default;
 public:
  // returns true if this fragment has been already received
  bool hasFragment(const FECNonce &fecNonce) {
    assert(fecNonce.blockIdx == blockIdx);
    return fragment_map[fecNonce.fragmentIdx] == AVAILABLE;
  }
  // returns true if we are "done with this block" aka all data has been already forwarded
  bool allPrimaryFragmentsHaveBeenForwarded() const {
    // if k is not known for this block,last primary fragment for this block is missing
    if (fec_k == -1)return false;
    // never send out secondary fragments !
    assert(nAlreadyForwardedPrimaryFragments <= fec_k);
    return nAlreadyForwardedPrimaryFragments == fec_k;
  }
  // returns true if enough FEC secondary fragments are available to replace all missing primary fragments
  bool allPrimaryFragmentsCanBeRecovered() const {
    // return false if k is not known for this block yet (which means we didn't get a secondary fragment yet,
    // since each secondary fragment contains k)
    if (fec_k == -1)return false;
    // ready for FEC step if we have as many secondary fragments as we are missing on primary fragments
    if (nAvailablePrimaryFragments + nAvailableSecondaryFragments >= fec_k)return true;
    return false;
  }
  // returns true if suddenly all primary fragments have become available
  bool allPrimaryFragmentsAreAvailable() const {
    if (fec_k == -1)return false;
    return nAvailablePrimaryFragments == fec_k;
  }
  // copy the fragment data and mark it as available
  // you should check if it is already available with hasFragment() to avoid storing a fragment multiple times
  // when using multiple RX cards
  void addFragment(const FECNonce &fecNonce, const uint8_t *data, const std::size_t dataLen) {
    assert(!hasFragment(fecNonce));
    assert(fecNonce.blockIdx == blockIdx);
    assert(fragment_map[fecNonce.fragmentIdx] == UNAVAILABLE);
    assert(fecNonce.fragmentIdx < blockBuffer.size());
    // write the data (doesn't matter if FEC data or correction packet)
    memcpy(blockBuffer[fecNonce.fragmentIdx].data(), data, dataLen);
    // set the rest to zero such that FEC works
    memset(blockBuffer[fecNonce.fragmentIdx].data() + dataLen, '\0', FEC_MAX_PACKET_SIZE - dataLen);
    // mark it as available
    fragment_map[fecNonce.fragmentIdx] = FragmentStatus::AVAILABLE;
    if (fecNonce.flag == 0) {
      nAvailablePrimaryFragments++;
      // when we receive the last primary fragment for this block we know the "K" parameter
      if (fecNonce.number != 0) {
        fec_k = fecNonce.number;
        //wifibroadcast::log::get_default()->debug("K is known now(P)"<<fec_k<<"\n";
      }
    } else {
      nAvailableSecondaryFragments++;
      // when we receive any secondary fragment we now know k for this block
      if (fec_k == -1) {
        fec_k = fecNonce.number;
        //wifibroadcast::log::get_default()->debug("K is known now(S)"<<fec_k<<"\n";
      } else {
        assert(fec_k == fecNonce.number);
      }
      // and we also know the packet size used for the FEC step
      if (sizeOfSecondaryFragments == -1) {
        sizeOfSecondaryFragments = dataLen;
      } else {
        // where all the secondary fragments shall have the same size
        assert(sizeOfSecondaryFragments == dataLen);
      }
    }
    if (firstFragmentTimePoint == std::nullopt) {
      firstFragmentTimePoint = std::chrono::steady_clock::now();
    }
    //wifibroadcast::log::get_default()->debug("block_idx:"<<blockIdx<<" frag_idx:"<<(int)fecNonce.fragmentIdx<<" k:"<<fec_k<<" nP:"<<nAvailablePrimaryFragments<<"nS:"<<nAvailableSecondaryFragments<<"\n";
  }
  /**
   * @returns the indices for all primary fragments that have not yet been forwarded and are available (already received or reconstructed).
   * Once an index is returned here, it won't be returned again
   * (Therefore, as long as you immediately forward all primary fragments returned here,everything happens in order)
   * @param discardMissingPackets : if true, gaps are ignored and fragments are forwarded even though this means the missing ones are irreversible lost
   * Be carefully with this param, use it only before you need to get rid of a block */
  std::vector<uint16_t> pullAvailablePrimaryFragments(const bool discardMissingPackets = false) {
    // note: when pulling the available fragments, we do not need to know how many primary fragments this block actually contains
    std::vector<uint16_t> ret;
    for (int i = nAlreadyForwardedPrimaryFragments; i < nAvailablePrimaryFragments; i++) {
      if (fragment_map[i] == FragmentStatus::UNAVAILABLE) {
        if (discardMissingPackets) {
          continue;
        } else {
          break;
        }
      }
      ret.push_back(i);
    }
    // make sure these indices won't be returned again
    nAlreadyForwardedPrimaryFragments += (int) ret.size();
    return ret;
  }
  const uint8_t *getDataPrimaryFragment(const uint16_t primaryFragmentIdx) {
    assert(fragment_map[primaryFragmentIdx] == AVAILABLE);
    return blockBuffer[primaryFragmentIdx].data();
  }
  // returns the n of primary and secondary fragments for this block
  int getNAvailableFragments() const {
    return nAvailablePrimaryFragments + nAvailableSecondaryFragments;
  }
  // make sure to check if enough secondary fragments are available before calling this method !
  // reconstructing only part of the missing data is not supported !
  // return: the n of reconstructed packets
  int reconstructAllMissingData() {
    //wifibroadcast::log::get_default()->debug("reconstructAllMissingData"<<nAvailablePrimaryFragments<<" "<<nAvailableSecondaryFragments<<" "<<fec.FEC_K<<"\n";
    // NOTE: FEC does only work if nPrimaryFragments+nSecondaryFragments>=FEC_K
    assert(fec_k != -1);
    // do not reconstruct if reconstruction is impossible
    assert(nAvailablePrimaryFragments + nAvailableSecondaryFragments >= fec_k);
    // also do not reconstruct if reconstruction is not needed
    assert(nAvailablePrimaryFragments < fec_k);
    assert(nAvailableSecondaryFragments > 0);
    assert(sizeOfSecondaryFragments != -1);
    const int nMissingPrimaryFragments = fec_k - nAvailablePrimaryFragments;
    // greater than or equal would also work, but mean the fec step is called later than needed, introducing latency
    assert(nMissingPrimaryFragments == nAvailableSecondaryFragments);
    auto recoveredFragmentIndices = fecDecode(sizeOfSecondaryFragments, blockBuffer, fec_k, fragment_map);
    for (const auto idx: recoveredFragmentIndices) {
      fragment_map[idx] = AVAILABLE;
    }
    nAvailablePrimaryFragments += recoveredFragmentIndices.size();
    // n of reconstructed packets
    return recoveredFragmentIndices.size();
  }
  [[nodiscard]] uint64_t getBlockIdx() const {
    return blockIdx;
  }
  [[nodiscard]] std::optional<std::chrono::steady_clock::time_point> getFirstFragmentTimePoint() const {
    return firstFragmentTimePoint;
  }
  // Returns the number of missing primary packets (e.g. the n of actual data packets that are missing)
  // This only works if we know the "fec_k" parameter
  std::optional<int> get_missing_primary_packets(){
    if(fec_k<=0)return std::nullopt;
    return fec_k-nAvailablePrimaryFragments;
  }
  std::string get_missing_primary_packets_readable(){
    const auto tmp=get_missing_primary_packets();
    if(tmp==std::nullopt)return "?";
    return std::to_string(tmp.value());
  }
 private:
  // the block idx marks which block this element refers to
  const uint64_t blockIdx = 0;
  // n of primary fragments that are already pulled out
  int nAlreadyForwardedPrimaryFragments = 0;
  // for each fragment (via fragment_idx) store if it has been received yet
  std::vector<FragmentStatus> fragment_map;
  // holds all the data for all received fragments (if fragment_map says UNAVALIABLE at this position, content is undefined)
  std::vector<std::array<uint8_t, FEC_MAX_PACKET_SIZE>> blockBuffer;
  int nAvailablePrimaryFragments = 0;
  int nAvailableSecondaryFragments = 0;
  // time point when the first fragment for this block was received (via addFragment() )
  std::optional<std::chrono::steady_clock::time_point> firstFragmentTimePoint = std::nullopt;
  // we don't know how many primary fragments this block contains until we either receive the last primary fragment for this block
  // or receive any secondary fragment.
  int fec_k = -1;
  // for the fec step, we need the size of the fec secondary fragments, which should be equal for all secondary fragments
  int sizeOfSecondaryFragments = -1;
};

// Takes a continuous stream of packets (data and fec correction packets) and
// processes them such that the output is exactly (or as close as possible) to the
// Input stream fed to FECEncoder.
// Most importantly, it also handles re-ordering of packets and packet duplicates due to multiple rx cards
class FECDecoder {
 public:
  // Does not need to know k,n or if tx does variable block length or not.
  // If the tx doesn't use the full range of fragment indices (aka K is fixed) use
  // @param maxNFragmentsPerBlock for a more efficient memory usage
  explicit FECDecoder(const unsigned int rx_queue_max_depth,const unsigned int maxNFragmentsPerBlock = MAX_TOTAL_FRAGMENTS_PER_BLOCK,
                      bool enable_log_debug=false) :
  RX_QUEUE_MAX_SIZE(rx_queue_max_depth),
  maxNFragmentsPerBlock(maxNFragmentsPerBlock),
  m_enable_log_debug(enable_log_debug){
    assert(rx_queue_max_depth<20);
    assert(rx_queue_max_depth>=1);
  }
  FECDecoder(const FECDecoder &other) = delete;
  ~FECDecoder() = default;
  // data forwarded on this callback is always in-order but possibly with gaps
  typedef std::function<void(const uint8_t *payload, std::size_t payloadSize)> SEND_DECODED_PACKET;
  // WARNING: Don't forget to register this callback !
  SEND_DECODED_PACKET mSendDecodedPayloadCallback;
  // A value too high doesn't really give much benefit and increases memory usage
  const unsigned int RX_QUEUE_MAX_SIZE;
  const unsigned int maxNFragmentsPerBlock;
  const bool m_enable_log_debug;
  AvgCalculator m_fec_decode_time{};
 public:
  // returns false if the packet fragment index doesn't match the set FEC parameters (which should never happen !)
  bool validateAndProcessPacket(const uint64_t nonce, const std::vector<uint8_t> &decrypted) {
    // normal FEC processing
    const FECNonce fecNonce = fecNonceFrom(nonce);

    // Should never happen due to generating new session key on tx side
    if (fecNonce.blockIdx > MAX_BLOCK_IDX) {
      wifibroadcast::log::get_default()->warn("block_idx overflow");
      return false;
    }
    if (fecNonce.fragmentIdx >= maxNFragmentsPerBlock) {
      wifibroadcast::log::get_default()->warn("invalid fragment_idx: {}",fecNonce.fragmentIdx);
      return false;
    }
    processFECBlockWitRxQueue(fecNonce, decrypted);
    return true;
  }
 private:
  // since we also need to search this data structure, a std::queue is not enough.
  // since we have an upper limit on the size of this dequeue, it is basically a searchable ring buffer
  std::deque<std::unique_ptr<RxBlock>> rx_queue;
  uint64_t last_known_block = ((uint64_t) -1);  //id of last known block
  /**
   * For this Block,
   * starting at the primary fragment we stopped on last time,
   * forward as many primary fragments as they are available until there is a gap
   * @param discardMissingPackets : if true, gaps are ignored and fragments are forwarded even though this means the missing ones are irreversible lost
   * Be carefully with this param, use it only before you need to get rid of a block
   */
  void forwardMissingPrimaryFragmentsIfAvailable(RxBlock &block, const bool discardMissingPackets = false){
    assert(mSendDecodedPayloadCallback);
    // TODO remove me
    if(discardMissingPackets){
      if(m_enable_log_debug){
        wifibroadcast::log::get_default()->warn("Forwarding block that is not yet fully finished: {} with n fragments: {} missing: {}",
                                                block.getBlockIdx(),block.getNAvailableFragments(),block.get_missing_primary_packets_readable());
      }
    }
    const auto indices = block.pullAvailablePrimaryFragments(discardMissingPackets);
    for (auto primaryFragmentIndex: indices) {
      const uint8_t *primaryFragment = block.getDataPrimaryFragment(primaryFragmentIndex);
      const FECPayloadHdr &packet_hdr = *(FECPayloadHdr *) primaryFragment;
      // data pinter and actual size of payload
      const uint8_t *payload = primaryFragment + sizeof(FECPayloadHdr);
      const auto packet_size = packet_hdr.getPrimaryFragmentSize();
      if (packet_size > FEC_MAX_PAYLOAD_SIZE || packet_size <= 0) {
        // this should never happen !
        wifibroadcast::log::get_default()->warn("corrupted packet on FECDecoder out ({}:{}) : {}B",block.getBlockIdx(),primaryFragmentIndex,packet_size);
      } else {
        mSendDecodedPayloadCallback(payload, packet_size);
        stats.count_bytes_forwarded+=packet_size;
      }
    }
  }
  // also increase lost block count if block is not fully recovered
  void rxQueuePopFront() {
    assert(rx_queue.front() != nullptr);
    if (!rx_queue.front()->allPrimaryFragmentsHaveBeenForwarded()) {
      stats.count_blocks_lost++;
    }
    rx_queue.pop_front();
  }
  // create a new RxBlock for the specified block_idx and push it into the queue
  // NOTE: Checks first if this operation would increase the size of the queue over its max capacity
  // In this case, the only solution is to remove the oldest block before adding the new one
  void rxRingCreateNewSafe(const uint64_t blockIdx) {
    // check: make sure to always put blocks into the queue in order !
    if (!rx_queue.empty()) {
      // the newest block in the queue should be equal to block_idx -1
      // but it must not ?!
      if (rx_queue.back()->getBlockIdx() != (blockIdx - 1)) {
        // If we land here, one or more full blocks are missing, which can happen on bad rx links
        //wifibroadcast::log::get_default()->debug("In queue: {} But new: {}",rx_queue.back()->getBlockIdx(),blockIdx);
      }
      //assert(rx_queue.back()->getBlockIdx() == (blockIdx - 1));
    }
    // we can return early if this operation doesn't exceed the size limit
    if (rx_queue.size() < RX_QUEUE_MAX_SIZE) {
      rx_queue.push_back(std::make_unique<RxBlock>(maxNFragmentsPerBlock, blockIdx));
      stats.count_blocks_total++;
      return;
    }
    //Ring overflow. This means that there are more unfinished blocks than ring size
    //Possible solutions:
    //1. Increase ring size. Do this if you have large variance of packet travel time throught WiFi card or network stack.
    //   Some cards can do this due to packet reordering inside, diffent chipset and/or firmware or your RX hosts have different CPU power.
    //2. Reduce packet injection speed or try to unify RX hardware.

    // forward remaining data for the (oldest) block, since we need to get rid of it
    auto &oldestBlock = rx_queue.front();
    forwardMissingPrimaryFragmentsIfAvailable(*oldestBlock, true);
    // and remove the block once done with it
    rxQueuePopFront();

    // now we are guaranteed to have space for one new block
    rx_queue.push_back(std::make_unique<RxBlock>(maxNFragmentsPerBlock, blockIdx));
    stats.count_blocks_total++;
  }

  // If block is already known and not in the queue anymore return nullptr
  // else if block is inside the ring return pointer to it
  // and if it is not inside the ring add as many blocks as needed, then return pointer to it
  RxBlock *rxRingFindCreateBlockByIdx(const uint64_t blockIdx) {
    // check if block is already in the ring
    auto found = std::find_if(rx_queue.begin(), rx_queue.end(),
                              [&blockIdx](const std::unique_ptr<RxBlock> &block) {
                                return block->getBlockIdx() == blockIdx;
                              });
    if (found != rx_queue.end()) {
      return found->get();
    }
    // check if block is already known and not in the ring then it is already processed
    if (last_known_block != (uint64_t) -1 && blockIdx <= last_known_block) {
      return nullptr;
    }

    // don't forget to increase the lost blocks counter if we do not add blocks here due to no space in the rx queue
    // (can happen easily if the rx queue has a size of 1)
    const auto n_needed_new_blocks = last_known_block != (uint64_t) -1 ? blockIdx - last_known_block : 1;
    if(n_needed_new_blocks>RX_QUEUE_MAX_SIZE){
      stats.count_blocks_lost+=n_needed_new_blocks-RX_QUEUE_MAX_SIZE;
    }
    // add as many blocks as we need ( the rx ring mustn't have any gaps between the block indices).
    // but there is no point in adding more blocks than RX_RING_SIZE
    const int new_blocks = (int) std::min(n_needed_new_blocks,
                                          (uint64_t) FECDecoder::RX_QUEUE_MAX_SIZE);
    last_known_block = blockIdx;

    for (int i = 0; i < new_blocks; i++) {
      rxRingCreateNewSafe(blockIdx + i + 1 - new_blocks);
    }
    // the new block we've added is now the most recently added element (and since we always push to the back, the "back()" element)
    assert(rx_queue.back()->getBlockIdx() == blockIdx);
    return rx_queue.back().get();
  }

  void processFECBlockWitRxQueue(const FECNonce &fecNonce, const std::vector<uint8_t> &decrypted) {
    auto blockP = rxRingFindCreateBlockByIdx(fecNonce.blockIdx);
    //ignore already processed blocks
    if (blockP == nullptr) return;
    // cannot be nullptr
    RxBlock &block = *blockP;
    // ignore already processed fragments
    if (block.hasFragment(fecNonce)) {
      return;
    }
    block.addFragment(fecNonce, decrypted.data(), decrypted.size());
    //
    if (block == *rx_queue.front()) {
      //wifibroadcast::log::get_default()->debug("In front\n";
      // we are in the front of the queue (e.g. at the oldest block)
      // forward packets until the first gap
      forwardMissingPrimaryFragmentsIfAvailable(block);
      // We are done with this block if either all fragments have been forwarded or it can be recovered
      if (block.allPrimaryFragmentsHaveBeenForwarded()) {
        // remove block when done with it
        rxQueuePopFront();
        return;
      }
      if (block.allPrimaryFragmentsCanBeRecovered()) {
        // apply fec for this block
        const auto before_encode=std::chrono::steady_clock::now();
        stats.count_fragments_recovered += block.reconstructAllMissingData();
        stats.count_blocks_recovered++;
        m_fec_decode_time.add(std::chrono::steady_clock::now()-before_encode);
        if(m_fec_decode_time.get_delta_since_last_reset()>std::chrono::seconds(1)){
          //wifibroadcast::log::get_default()->debug("FEC decode took {}",m_fec_decode_time.getAvgReadable());
          stats.curr_fec_decode_time=m_fec_decode_time.getMinMaxAvg();
          m_fec_decode_time.reset();
        }
        forwardMissingPrimaryFragmentsIfAvailable(block);
        assert(block.allPrimaryFragmentsHaveBeenForwarded());
        // remove block when done with it
        rxQueuePopFront();
        return;
      }
      return;
    } else {
      //wifibroadcast::log::get_default()->debug("Not in front\n";
      // we are not in the front of the queue but somewhere else
      // If this block can be fully recovered or all primary fragments are available this triggers a flush
      if (block.allPrimaryFragmentsAreAvailable() || block.allPrimaryFragmentsCanBeRecovered()) {
        // send all queued packets in all unfinished blocks before and remove them
        while (block != *rx_queue.front()) {
          forwardMissingPrimaryFragmentsIfAvailable(*rx_queue.front(), true);
          rxQueuePopFront();
        }
        // then process the block who is fully recoverable or has no gaps in the primary fragments
        if (block.allPrimaryFragmentsAreAvailable()) {
          forwardMissingPrimaryFragmentsIfAvailable(block);
          assert(block.allPrimaryFragmentsHaveBeenForwarded());
        } else {
          // apply fec for this block
          stats.count_fragments_recovered += block.reconstructAllMissingData();
          stats.count_blocks_recovered++;
          forwardMissingPrimaryFragmentsIfAvailable(block);
          assert(block.allPrimaryFragmentsHaveBeenForwarded());
        }
        // remove block
        rxQueuePopFront();
      }
    }
  }
 public:
  void decreaseRxRingSize(int newSize) {
    wifibroadcast::log::get_default()->debug("Decreasing ring size from {} to {}",rx_queue.size(),newSize);
    while (rx_queue.size() > newSize) {
      forwardMissingPrimaryFragmentsIfAvailable(*rx_queue.front(), true);
      rxQueuePopFront();
    }
  }
  // By doing so you are telling the pipeline:
  // It makes no sense to hold on to any blocks. Future packets won't help you to recover any blocks that might still be in the pipeline
  // For example, if the RX doesn't receive anything for N ms any data that is going to arrive will not have a smaller or equal block index than the blocks that are currently in the queue
  void flushRxRing() {
    decreaseRxRingSize(0);
  }
  //TODO maybe this would make sense
  void removeBlocksOlderThan(const std::chrono::steady_clock::duration &maxDelta) {
    // if there is any, find the "newest" block which age is bigger than delta
    const auto now = std::chrono::steady_clock::now();
    for (auto &block: rx_queue) {
      const auto firstFragmentTimePoint = block->getFirstFragmentTimePoint();
      if (firstFragmentTimePoint != std::nullopt) {
        const auto delta = now - *firstFragmentTimePoint;
        if (delta > maxDelta) {
          //wifibroadcast::log::get_default()->debug("Got block"<<block->getBlockIdx()<<" with age"<<MyTimeHelper::R(delta)<<"\n";
        }
      }
    }
  }
 public:
  FECRxStats stats{};
};

// quick math regarding sequence numbers:
//uint32_t holds max 4294967295 . At 10 000 pps (packets per seconds) (which is already completely out of reach) this allows the tx to run for 429496.7295 seconds
// 429496.7295 / 60 / 60 = 119.304647083 hours which is also completely overkill for OpenHD (and after this time span, a "reset" of the sequence number happens anyways)
// unsigned 24 bits holds 16777215 . At 1000 blocks per second this allows the tx to create blocks for 16777.215 seconds or 4.6 hours. That should cover a flight (and after 4.6h a reset happens,
// which means you might lose a couple of blocks once every 4.6 h )
// and 8 bits holds max 255.



#endif //WIFIBROADCAST_FECENABLED_HPP
