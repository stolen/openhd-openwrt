#!/bin/bash
# This script enables monitor mode on 2 wifi cards (both connected to the same pc) and
# starts injecting generated packets on the tx card. At the same time, the packets received
# on the rx are validated. This is a simple test to make sure that injecting and receiving packets works,
# and that the received packets have the right content.

ASUS="wlx244bfeb71c05" #ASUS card
ASUS2="wlxac9e175ac9e8" #ASUS card 2

MY_RX=$ASUS
MY_TX=$ASUS2

#MY_WIFI_CHANNEL=149 #5ghz channel
MY_WIFI_CHANNEL=153 #5ghz channel
#MY_WIFI_CHANNEL=13 #2.4ghz channel

#WFB_FOLDER="/home/consti10/Desktop/wifibroadcast"
WFB_FOLDER="/home/consti10/Desktop/Open.HD/OpenHD/lib/wifibroadcast/cmake-build-debug"
#WFB_FOLDER="/home/pi/Desktop/wifibroadcast"

# enable monitor mode on rx card, start wfb_rx
sh ./enable_monitor_mode.sh $MY_RX $MY_WIFI_CHANNEL

xterm -hold -e $WFB_FOLDER/wfb_rx -u 6200 -r 60 $MY_RX &


# enable monitor mode on tx card, start wfb_tx
sh ./enable_monitor_mode.sh $MY_TX $MY_WIFI_CHANNEL

xterm -hold -e $WFB_FOLDER/wfb_tx -u 6000 -r 60 -M 5 -B 20 $MY_TX &


# validate incoming packets
xterm -hold -e $WFB_FOLDER/udp_generator_validator -u 6200 -v 1 -t 30 &

# start the generator
$WFB_FOLDER/udp_generator_validator -u 6000 -p 100 -t 30