
// Copyright (C) 2017, 2018 Vasily Evseenko <svpcom@p2ptech.org>
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
#include "WBReceiver.h"
#include "RawReceiver.hpp"
#include "wifibroadcast.hpp"
#include "HelperSources/SchedulingHelper.hpp"
#include <cassert>
#include <cinttypes>
#include <unistd.h>
#include <pcap/pcap.h>
#include <memory>
#include <string>
#include <sstream>
#include <utility>

WBReceiver::WBReceiver(ROptions options1, OUTPUT_DATA_CALLBACK output_data_callback,std::shared_ptr<spdlog::logger> console) :
    options(std::move(options1)),
    mDecryptor(options.keypair),
    mOutputDataCallback(std::move(output_data_callback)) {
  if(!console){
    m_console=wifibroadcast::log::create_or_get("wb_rx"+std::to_string(options.radio_port));
  }else{
    m_console=console;
  }
  MultiRxPcapReceiver::Options multi_rx_options;
  multi_rx_options.rxInterfaces=options.rxInterfaces;
  multi_rx_options.dataCallback=notstd::bind_front(&WBReceiver::processPacket, this);
  multi_rx_options.logCallback=notstd::bind_front(&WBReceiver::recalculate_statistics, this);
  multi_rx_options.log_interval=std::chrono::seconds (1);
  multi_rx_options.radio_port=options.radio_port;
  receiver = std::make_unique<MultiRxPcapReceiver>(multi_rx_options);
  m_console->info("WFB-RX RADIO_PORT: {}",(int) options.radio_port);
}

void WBReceiver::loop() {
  receiver->loop();
}

void WBReceiver::stop_looping() {
  receiver->stop();
}

std::string WBReceiver::createDebugState() const {
  std::stringstream ss;
  ss<<wb_rx_stats<<"\n";
  if(mFECDDecoder){
    auto stats=mFECDDecoder->stats;
    ss<<stats<<"\n";
  }
  return ss.str();
}

void WBReceiver::recalculate_statistics() {
  wb_rx_stats.curr_incoming_bits_per_second =
      m_received_bitrate_calculator.recalculateSinceLast(wb_rx_stats.count_bytes_data_received);
  wb_rx_stats.curr_packet_loss_percentage=m_seq_nr_helper.get_current_loss_percent();
  wb_rx_stats.curr_n_of_big_gaps=0;
  if(receiver){
    wb_rx_stats.n_receiver_likely_disconnect_errors=receiver->get_n_receiver_errors();
  }
  std::optional<FECRxStats> fec_stream_stats=std::nullopt;
  if(mFECDDecoder){
    fec_stream_stats=mFECDDecoder->stats;
  }
  WBReceiverStats all_wb_rx_stats{options.radio_port,rssiForWifiCard,wb_rx_stats,fec_stream_stats};
  set_latest_stats(all_wb_rx_stats);
  // it is actually much more understandable when I use the absolute values for the logging
#ifdef ENABLE_ADVANCED_DEBUGGING
  std::cout<<"avgPcapToApplicationLatency: "<<avgPcapToApplicationLatency.getAvgReadable()<<"\n";
  //std::cout<<"avgLatencyBeaconPacketLatency"<<avgLatencyBeaconPacketLatency.getAvgReadable()<<"\n";
  //std::cout<<"avgLatencyBeaconPacketLatencyX:"<<avgLatencyBeaconPacketLatency.getNValuesLowHigh(20)<<"\n";
  //std::cout<<"avgLatencyPacketInQueue"<<avgLatencyPacketInQueue.getAvgReadable()<<"\n";
#endif
}

void WBReceiver::processPacket(const uint8_t wlan_idx, const pcap_pkthdr &hdr, const uint8_t *pkt) {
#ifdef ENABLE_ADVANCED_DEBUGGING
  const auto tmp=GenericHelper::timevalToTimePointSystemClock(hdr.ts);
  const auto latency=std::chrono::system_clock::now() -tmp;
  avgPcapToApplicationLatency.add(latency);
#endif
  wb_rx_stats.count_p_all++;
  // The radio capture header precedes the 802.11 header.
  const auto parsedPacket = RawReceiverHelper::processReceivedPcapPacket(hdr, pkt,options.rtl8812au_rssi_fixup);
  if (parsedPacket == std::nullopt) {
    m_console->warn("Discarding packet due to pcap parsing error!");
    wb_rx_stats.count_p_bad++;
    return;
  }
  if (parsedPacket->frameFailedFCSCheck) {
    m_console->warn("Discarding packet due to bad FCS!");
    wb_rx_stats.count_p_bad++;
    return;
  }
  if (!parsedPacket->ieee80211Header->isDataFrame()) {
    // we only process data frames
    m_console->warn("Got packet that is not a data packet {}",(int) parsedPacket->ieee80211Header->getFrameControl());
    wb_rx_stats.count_p_bad++;
    return;
  }
  if (parsedPacket->ieee80211Header->getRadioPort() != options.radio_port) {
    // If we have the proper filter on pcap only packets with the right radiotap port should pass through
    m_console->warn("Got packet with wrong radio port ",(int) parsedPacket->ieee80211Header->getRadioPort());
    //RadiotapHelper::debugRadiotapHeader(pkt,hdr.caplen);
    wb_rx_stats.count_p_bad++;
    return;
  }
  // All these edge cases should NEVER happen if using a proper tx/rx setup and the wifi driver isn't complete crap
  if (parsedPacket->payloadSize <= 0) {
    m_console->warn("Discarding packet due to no actual payload !");
    wb_rx_stats.count_p_bad++;
    return;
  }
  if (parsedPacket->payloadSize > RAW_WIFI_FRAME_MAX_PAYLOAD_SIZE) {
    m_console->warn("Discarding packet due to payload exceeding max {}",(int) parsedPacket->payloadSize);
    wb_rx_stats.count_p_bad++;
    return;
  }
  if (parsedPacket->allAntennaValues.size() > MAX_N_ANTENNAS_PER_WIFI_CARD) {
    m_console->warn( "Wifi card with {} antennas",parsedPacket->allAntennaValues.size());
  }
  if(wlan_idx <rssiForWifiCard.size()){
    auto &thisWifiCard = rssiForWifiCard.at(wlan_idx);
    //m_console->debug("{}",all_rssi_to_string(parsedPacket->allAntennaValues));
    const auto best_rssi=RawReceiverHelper::get_best_rssi_of_card(parsedPacket->allAntennaValues);
    //m_console->debug("best_rssi:{}",(int)best_rssi);
    if(best_rssi.has_value()){
      thisWifiCard.addRSSI(best_rssi.value());
    }
    /*for (const auto &value: parsedPacket->allAntennaValues) {
      // don't care from which antenna the value came
      // There seems to be a bug where sometimes the reported rssi is 0 ???!!
      if(value.rssi!=0){
        thisWifiCard.addRSSI(value.rssi);
      }
    }*/
  }else{
    m_console->warn("wlan idx out of bounds");
  }

  //RawTransmitterHelper::writeAntennaStats(antenna_stat, WLAN_IDX, parsedPacket->antenna, parsedPacket->rssi);
  //const Ieee80211Header* tmpHeader=parsedPacket->ieee80211Header;
  //std::cout<<"RADIO_PORT"<<(int)tmpHeader->getRadioPort()<<" IEEE_SEQ_NR "<<(int)tmpHeader->getSequenceNumber()<<"\n";
  //std::cout<<"FrameControl:"<<(int)tmpHeader->getFrameControl()<<"\n";
  //std::cout<<"DurationOrConnectionId:"<<(int)tmpHeader->getDurationOrConnectionId()<<"\n";
  //parsedPacket->ieee80211Header->printSequenceControl();
  //mSeqNrCounter.onNewPacket(*parsedPacket->ieee80211Header);


  // now to the actual payload
  const uint8_t *packetPayload = parsedPacket->payload;
  const size_t packetPayloadSize = parsedPacket->payloadSize;

  if (packetPayload[0] == WFB_PACKET_KEY) {
    if (packetPayloadSize != WBSessionKeyPacket::SIZE_BYTES) {
      m_console->warn("invalid session key packet");
      wb_rx_stats.count_p_bad++;
      return;
    }
    WBSessionKeyPacket &sessionKeyPacket = *((WBSessionKeyPacket *) parsedPacket->payload);
    if (mDecryptor.onNewPacketSessionKeyData(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData)) {
      m_console->debug("Initializing new session. IS_FEC_ENABLED:{} ",(int)sessionKeyPacket.IS_FEC_ENABLED);
      // We got a new session key (aka a session key that has not been received yet)
      wb_rx_stats.count_p_decryption_ok++;
      IS_FEC_ENABLED = sessionKeyPacket.IS_FEC_ENABLED;
      auto callback = [this](const uint8_t *payload, std::size_t payloadSize) {
        if (mOutputDataCallback != nullptr) {
          mOutputDataCallback(payload, payloadSize);
        } else {
          m_console->debug("No data callback registered");
        }
      };
      if (IS_FEC_ENABLED) {
        mFECDDecoder = std::make_unique<FECDecoder>(options.rx_queue_depth,MAX_TOTAL_FRAGMENTS_PER_BLOCK);
        mFECDDecoder->mSendDecodedPayloadCallback = callback;
      } else {
        mFECDisabledDecoder = std::make_unique<FECDisabledDecoder>();
        mFECDisabledDecoder->mSendDecodedPayloadCallback = callback;
      }
    } else {
      wb_rx_stats.count_p_decryption_ok++;
    }
    return;
  } else if (packetPayload[0] == WFB_PACKET_DATA) {
    if (packetPayloadSize < sizeof(WBDataHeader) + sizeof(FECPayloadHdr)) {
      m_console->warn("Too short packet (fec header missing)");
      wb_rx_stats.count_p_bad++;
      return;
    }
    const WBDataHeader &wbDataHeader = *((WBDataHeader *) packetPayload);
    assert(wbDataHeader.packet_type == WFB_PACKET_DATA);
    wb_rx_stats.count_bytes_data_received+=packetPayloadSize;
    //
    m_seq_nr_helper.on_new_sequence_number(wbDataHeader.sequence_number_extra);
    const auto decryptedPayload = mDecryptor.decryptPacket(wbDataHeader.nonce, packetPayload + sizeof(WBDataHeader),
                                                           packetPayloadSize - sizeof(WBDataHeader), wbDataHeader);
    if (decryptedPayload == std::nullopt) {
      //m_console->warn("unable to decrypt packet :",std::to_string(wbDataHeader.nonce));
      wb_rx_stats.count_p_decryption_err++;
      return;
    }

    wb_rx_stats.count_p_decryption_ok++;

    assert(decryptedPayload->size() <= FEC_MAX_PACKET_SIZE);
    if (IS_FEC_ENABLED) {
      if (!mFECDDecoder) {
        m_console->warn("FEC K,N is not set yet (enabled)");
        return;
      }
      if (!mFECDDecoder->validateAndProcessPacket(wbDataHeader.nonce, *decryptedPayload)) {
        wb_rx_stats.count_p_bad++;
      }
    } else {
      if (!mFECDisabledDecoder) {
        m_console->warn("FEC K,N is not set yet(disabled)");
        return;
      }
      mFECDisabledDecoder->processRawDataBlockFecDisabled(wbDataHeader.nonce, *decryptedPayload);
    }
  }
#ifdef ENABLE_ADVANCED_DEBUGGING
    else if(payload[0]==WFB_PACKET_LATENCY_BEACON){
        // for testing only. It won't work if the tx and rx are running on different systems
            assert(payloadSize==sizeof(LatencyTestingPacket));
            const LatencyTestingPacket* latencyTestingPacket=(LatencyTestingPacket*)payload;
            const auto timestamp=std::chrono::time_point<std::chrono::steady_clock>(std::chrono::nanoseconds(latencyTestingPacket->timestampNs));
            const auto latency=std::chrono::steady_clock::now()-timestamp;
            //std::cout<<"Packet latency on this system is "<<std::chrono::duration_cast<std::chrono::nanoseconds>(latency).count()<<"\n";
            avgLatencyBeaconPacketLatency.add(latency);
    }
#endif
  else {
    m_console->warn("Unknown packet type {}",(int) packetPayload[0]);
    wb_rx_stats.count_p_bad += 1;
    return;
  }
}

void WBReceiver::set_latest_stats(WBReceiverStats new_stats) {
  std::lock_guard<std::mutex> lock(m_last_stats_mutex);
  m_last_stats=new_stats;
}

WBReceiverStats WBReceiver::get_latest_stats(){
  std::lock_guard<std::mutex> lock(m_last_stats_mutex);
  return m_last_stats;
}
