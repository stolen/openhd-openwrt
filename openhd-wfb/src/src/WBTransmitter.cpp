
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

#include "WBTransmitter.h"

#include <utility>

#include "BlockSizeHelper.hpp"
#include "HelperSources/SchedulingHelper.hpp"

WBTransmitter::WBTransmitter(RadiotapHeader::UserSelectableParams radioTapHeaderParams, TOptions options1,std::shared_ptr<spdlog::logger> opt_console) :
    options(std::move(options1)),
      m_pcap_transmitter(options.wlan),
      m_encryptor(options.keypair),
      m_radioTapHeaderParams(radioTapHeaderParams),
    kEnableFec(options.enable_fec),
    m_tx_fec_options(options.tx_fec_options),
    mRadiotapHeader{RadiotapHeader{m_radioTapHeaderParams}},
    m_console(std::move(opt_console)){
  if(!m_console){
    m_console=wifibroadcast::log::create_or_get("wb_tx"+std::to_string(options.radio_port));
  }
  assert(m_console);
  m_console->info("WBTransmitter radio_port: {} wlan: {} keypair:{}", options.radio_port, options.wlan.c_str(),
                  (options.keypair.has_value() ? options.keypair.value() : "none" ));
  m_encryptor.makeNewSessionKey(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData);
  if (kEnableFec) {
    // for variable k we manually specify when to end the block, of course we cannot do more than what the FEC impl. supports
    // and / or what the max compute allows (NOTE: compute increases exponentially with increasing length).
    const int kMax= options.tx_fec_options.fixed_k > 0 ? options.tx_fec_options.fixed_k : MAX_N_P_FRAGMENTS_PER_BLOCK;
    m_console->info("fec enabled, kMax:{}",kMax);
    m_fec_encoder = std::make_unique<FECEncoder>(kMax, options.tx_fec_options.overhead_percentage);
    m_fec_encoder->outputDataCallback = notstd::bind_front(&WBTransmitter::sendFecPrimaryOrSecondaryFragment, this);
  } else {
    m_console->info("fec disabled");
    m_fec_disabled_encoder = std::make_unique<FECDisabledEncoder>();
    m_fec_disabled_encoder->outputDataCallback =
        notstd::bind_front(&WBTransmitter::sendFecPrimaryOrSecondaryFragment, this);
  }
  // the rx needs to know if FEC is enabled or disabled. Note, both variable and fixed fec counts as FEC enabled
  sessionKeyPacket.IS_FEC_ENABLED = kEnableFec;
  // send session key a couple of times on startup to make it more likely an already running rx picks it up immediately
  m_console->info("Sending Session key on startup");
  for (int i = 0; i < 5; i++) {
    sendSessionKey();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  // next session key in delta ms if packets are being fed
  session_key_announce_ts = std::chrono::steady_clock::now()+SESSION_KEY_ANNOUNCE_DELTA;

  m_process_data_thread_run=true;
  m_process_data_thread=std::make_unique<std::thread>(&WBTransmitter::loop_process_data, this);
}

WBTransmitter::~WBTransmitter() {
  m_process_data_thread_run=false;
  if(m_process_data_thread && m_process_data_thread->joinable()){
    m_process_data_thread->join();
  }
}

void WBTransmitter::sendPacket(const AbstractWBPacket &abstractWbPacket) {
  count_bytes_data_injected+=abstractWbPacket.payloadSize;
  mIeee80211Header.writeParams(options.radio_port, ieee80211_seq);
  ieee80211_seq += 16;
  //mIeee80211Header.printSequenceControl();
  std::lock_guard<std::mutex> guard(m_radiotapHeaderMutex);
  const auto injectionTime = m_pcap_transmitter.injectPacket(mRadiotapHeader, mIeee80211Header, abstractWbPacket);
  if(injectionTime>MAX_SANE_INJECTION_TIME){
    count_tx_injections_error_hint++;
    //m_console->warn("Injecting PCAP packet took really long:",MyTimeHelper::R(injectionTime));
  }
  nInjectedPackets++;
}

void WBTransmitter::sendFecPrimaryOrSecondaryFragment(const uint64_t nonce,
                                                      const uint8_t *payload,
                                                      const std::size_t payloadSize) {
  //m_console->info("WBTransmitter::sendFecBlock {}",(int)payloadSize);
  const WBDataHeader wbDataHeader(nonce,m_curr_seq_nr);
  m_curr_seq_nr++;
  const auto encryptedData =
      m_encryptor.encryptPacket(nonce, payload, payloadSize, wbDataHeader);
  //
  sendPacket({(const uint8_t *) &wbDataHeader, sizeof(WBDataHeader), encryptedData.data(), encryptedData.size()});
#ifdef ENABLE_ADVANCED_DEBUGGING
  //LatencyTestingPacket latencyTestingPacket;
  //sendPacket((uint8_t*)&latencyTestingPacket,sizeof(latencyTestingPacket));
#endif
}

void WBTransmitter::sendSessionKey() {
  sendPacket({(uint8_t *) &sessionKeyPacket, WBSessionKeyPacket::SIZE_BYTES});
  nInjectedSessionKeypackets++;
}

std::string WBTransmitter::createDebugState() const {
  std::stringstream ss;
  // input packets & injected packets
  const auto nInjectedDataPackets=nInjectedPackets-nInjectedSessionKeypackets;
  //ss << runTimeSeconds << "\tTX:in:("<<nInputPackets<<")out:(" << nInjectedDataPackets << ":" << nInjectedSessionKeypackets << ")\n";
  ss <<"TX:in:("<<nInputPackets<<")out:(" << nInjectedDataPackets << ":" << nInjectedSessionKeypackets << ")\n";
  return ss.str();
}

bool WBTransmitter::enqueue_packet(const uint8_t *buf, size_t size,std::optional<bool> end_block) {
  count_bytes_data_provided+=size;
  auto packet=std::make_shared<std::vector<uint8_t>>(buf,buf+size);
  auto item=std::make_shared<Item>();
  item->data=packet;
  item->end_block=end_block;
  const bool res=m_data_queue.try_enqueue(item);
  if(!res){
    m_n_dropped_packets++;
    // TODO not exactly the correct solution - include dropped packets in the seq nr, such that they are included
    // in the loss (perc) on the ground
    m_curr_seq_nr++;
  }
  return res;
}

bool WBTransmitter::enqueue_packet(std::shared_ptr<std::vector<uint8_t>> packet,std::optional<bool> end_block) {
  count_bytes_data_provided+=packet->size();
  auto item=std::make_shared<Item>();
  item->data=packet;
  item->end_block=end_block;
  const bool res=m_data_queue.try_enqueue(item);
  if(!res){
    m_n_dropped_packets++;
    // TODO not exactly the correct solution - include dropped packets in the seq nr, such that they are included
    // in the loss (perc) on the ground
    m_curr_seq_nr++;
  }
  return res;
}

void WBTransmitter::tmp_feed_frame_fragments(
    const std::vector<std::shared_ptr<std::vector<uint8_t>>> &frame_fragments,bool use_fixed_fec_instead) {
  // we calculated the best fit and fragmented the frame before calling this method
  for(int i=0;i<frame_fragments.size();i++){
    std::optional<bool> end_block=std::nullopt;
    if(i==frame_fragments.size()-1){
      end_block=true;
    }else{
      end_block=false;
    }
    if(use_fixed_fec_instead){
      end_block=std::nullopt;
    }
    enqueue_packet(frame_fragments[i], end_block);
    // TODO
    // If we fail on any fragment while enqueueing a frame, there is no point in enqueueing the rest of the frame,
    // since the rx cannot do anything with a partial frame missing a fragment anyways
  }
}

void WBTransmitter::tmp_split_and_feed_frame_fragments(const std::vector<std::shared_ptr<std::vector<uint8_t>>> &frame_fragments,const int max_block_size) {
  auto blocks=blocksize::split_frame_if_needed(frame_fragments,max_block_size);
  for(auto& block:blocks){
    //m_console->debug("max {} Has {} blocks",max_block_size,block.size());
    tmp_feed_frame_fragments(block, false);
  }
}


void WBTransmitter::update_mcs_index(uint8_t mcs_index) {
  m_console->debug("Changing mcs index to {}",mcs_index);
  m_radioTapHeaderParams.mcs_index=mcs_index;
  auto newRadioTapHeader=RadiotapHeader{m_radioTapHeaderParams};
  std::lock_guard<std::mutex> guard(m_radiotapHeaderMutex);
  mRadiotapHeader=newRadioTapHeader;
}

void WBTransmitter::loop_process_data() {
  SchedulingHelper::setThreadParamsMaxRealtime();
  static constexpr std::int64_t timeout_usecs=100*1000;
  std::shared_ptr<Item> packet;
  while (m_process_data_thread_run){
    if(m_data_queue.wait_dequeue_timed(packet,timeout_usecs)){
      feedPacket2(packet->data->data(),packet->data->size(),packet->end_block);
    }
  }
}

void WBTransmitter::feedPacket2(const uint8_t *buf, size_t size,std::optional<bool> end_block) {
  if (size <= 0 || size > FEC_MAX_PAYLOAD_SIZE) {
    m_console->warn("Fed packet with incompatible size:",size);
    return;
  }
  const auto cur_ts = std::chrono::steady_clock::now();
  // send session key in SESSION_KEY_ANNOUNCE_DELTA intervals
  if ((cur_ts >= session_key_announce_ts)) {
    // Announce session key
    sendSessionKey();
    session_key_announce_ts = cur_ts + SESSION_KEY_ANNOUNCE_DELTA;
  }
  // this calls a callback internally
  if (kEnableFec) {
    if(end_block.has_value()){
      // Variable FEC k (block size)
      m_fec_encoder->encodePacket(buf, size, end_block.value());
    }else {
      // Fixed FEC k (block size)
      m_fec_encoder->encodePacket(buf, size);
    }
    if (m_fec_encoder->resetOnOverflow()) {
      // running out of sequence numbers should never happen during the lifetime of the TX instance, but handle it properly anyways
      m_encryptor.makeNewSessionKey(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData);
      sendSessionKey();
    }
  } else {
    m_fec_disabled_encoder->encodePacket(buf, size);
  }
  nInputPackets++;
}

void WBTransmitter::update_fec_percentage(uint32_t fec_percentage) {
  if(!kEnableFec){
    m_console->warn("Cannot change fec overhead when fec is disabled");
    return;
  }
  assert(m_fec_encoder);
  m_fec_encoder->update_fec_overhead_percentage(fec_percentage);
}

void WBTransmitter::update_fec_k(int fec_k) {
  if(!kEnableFec){
    m_console->warn("Cannot update_fec_k, fec disabled");
    return;
  }
  if(fec_k<0 || fec_k>MAX_N_P_FRAGMENTS_PER_BLOCK){
    m_console->warn("Invalid fec_k value {}",fec_k);
    return;
  }
  if(fec_k==0){
    m_tx_fec_options.fixed_k=0;
    m_fec_encoder->update_fec_k(MAX_N_P_FRAGMENTS_PER_BLOCK);
  }else{
    assert(fec_k>0);
    m_tx_fec_options.fixed_k=fec_k;
    m_fec_encoder->update_fec_k(fec_k);
  }
}

WBTxStats WBTransmitter::get_latest_stats() {
  WBTxStats ret{};
  ret.n_injected_packets=nInjectedPackets;
  ret.n_injected_bytes=static_cast<int64_t>(count_bytes_data_injected);
  ret.current_injected_bits_per_second=bitrate_calculator_injected_bytes.get_last_or_recalculate(count_bytes_data_injected,std::chrono::seconds(2));
  ret.current_provided_bits_per_second=bitrate_calculator_data_provided.get_last_or_recalculate(count_bytes_data_provided,std::chrono::seconds(2));
  ret.count_tx_injections_error_hint=count_tx_injections_error_hint;
  ret.n_dropped_packets=m_n_dropped_packets;
  ret.current_injected_packets_per_second=_packets_per_second_calculator.get_last_or_recalculate(nInjectedPackets,std::chrono::seconds(2));
  return ret;
}

FECTxStats WBTransmitter::get_latest_fec_stats() {
  FECTxStats ret{};
  if(m_fec_encoder){
    ret.curr_fec_encode_time=m_fec_encoder->get_current_fec_blk_encode_time();
    ret.curr_fec_block_length=m_fec_encoder->get_current_fec_blk_sizes();
  }
  return ret;
}