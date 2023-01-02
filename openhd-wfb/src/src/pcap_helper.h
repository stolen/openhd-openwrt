//
// Created by consti10 on 17.12.22.
//

#ifndef WIFIBROADCAST_SRC_PCAP_HELPER_H_
#define WIFIBROADCAST_SRC_PCAP_HELPER_H_

#include <string>

#include <pcap/pcap.h>

namespace wifibroadcast::pcap_helper{

// debugging
static std::string tstamp_types_to_string(int* ts_types,int n){
  std::stringstream ss;
  ss<<"[";
  for(int i=0;i<n;i++){
    const char *name = pcap_tstamp_type_val_to_name(ts_types[i]);
    const char *description = pcap_tstamp_type_val_to_description(ts_types[i]);
    ss<<name<<"="<<description<<",";
  }
  ss<<"]";
  return ss.str();
}


}

#endif  // WIFIBROADCAST_SRC_PCAP_HELPER_H_
