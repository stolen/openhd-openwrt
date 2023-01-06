//
// Created by consti10 on 05.12.22.
//

#include "MEndpoint.h"

// WARNING BE CAREFULL TO REMOVE ON RELEASE
//#define OHD_TELEMETRY_TESTING_ENABLE_PACKET_LOSS

MEndpoint::MEndpoint(std::string tag)
    : TAG(std::move(tag)),m_mavlink_channel(checkoutFreeChannel()) {
  openhd::log::get_default()->debug("{} using channel:{}",TAG,m_mavlink_channel);
}

void MEndpoint::sendMessages(const std::vector<MavlinkMessage>& messages) {
  if(messages.empty())return;
  m_tx_n_bytes+= get_size(messages);
  //openhd::log::create_or_get(TAG)->debug("N messages send:{}",messages.size());
  const auto res= sendMessagesImpl(messages);
  m_n_messages_sent+=messages.size();
  if(!res){
    m_n_messages_send_failed+=messages.size();
  }
}

void MEndpoint::registerCallback(MAV_MSG_CALLBACK cb) {
  if (m_callback != nullptr) {
    // this might be a common programming mistake - you can only register one callback here
    openhd::log::get_default()->warn("Overwriting already existing callback");
  }
  m_callback = std::move(cb);
}

bool MEndpoint::isAlive() const {
  return (std::chrono::steady_clock::now() - lastMessage) < std::chrono::seconds(5);
}

std::string MEndpoint::createInfo() const {
  std::stringstream ss;
  ss<<TAG<<" {sent:"<<m_n_messages_sent<<" send_failed:"<<m_n_messages_send_failed<<" recv:"<<m_n_messages_received<<" alive:"<<(isAlive() ? "Y" : "N") << "}\n";
  return ss.str();
}

void MEndpoint::parseNewData(const uint8_t* data, const int data_len) {
  //<<TAG<<" received data:"<<data_len<<" "<<MavlinkHelpers::raw_content(data,data_len)<<"\n";
  m_rx_n_bytes+=data_len;
  std::vector<MavlinkMessage> messages;
  mavlink_message_t msg;
  for (int i = 0; i < data_len; i++) {
    uint8_t res = mavlink_parse_char(m_mavlink_channel, (uint8_t)data[i], &msg, &receiveMavlinkStatus);
    if (res) {
      messages.push_back(MavlinkMessage{msg});
    }
  }
  onNewMavlinkMessages(messages);
}

void MEndpoint::onNewMavlinkMessages(std::vector<MavlinkMessage> messages) {
  if(messages.empty())return;
  //openhd::log::create_or_get(TAG)->debug("N messages receive:{}",messages.size());
  lastMessage = std::chrono::steady_clock::now();
  m_n_messages_received+=messages.size();
  if (m_callback != nullptr) {
    m_callback(messages);
  } else {
    openhd::log::get_default()->warn("No callback set,did you forget to add it ?");
  }
}

std::string MEndpoint::get_tx_rx_stats() {
  return fmt::format("Tx bps:{} Rx bps:{}",
                     m_tx_calc.get_last_or_recalculate(m_tx_n_bytes,std::chrono::seconds(1)),
                     m_rx_calc.get_last_or_recalculate(m_rx_n_bytes,std::chrono::seconds(1)));
}
