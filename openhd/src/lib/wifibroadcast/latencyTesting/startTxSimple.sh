#!/bin/bash
# Given a PC with 2 wifi cards connected that support monitor mode,
# This starts the tx on one of them and the rx on the other one

TAOBAO="wlx00e0863200b9" #Taobao card
ASUS="wlx244bfeb71c05" #ASUS card
#ASUS2="wlxac9e175ac9e8" #ASUS card 2
ASUS2="wlxac9e17596103"

#MY_TX="wlp3s0"
#MY_TX="wlxc4e984126183"
#MY_TX="wlx000f00460445" # ALFA card
#MY_TX="wlx6cfdb9b2a156" #PW-DN421
#MY_TX="wlx0018e7bd24db"
#MY_RX="wlx0018e7bd24db" #Ralink card aliexpress
#MY_RX="wlxc4e9840e3cbe" #tp-link rx
#MY_RX_SECONDARY="wlxc4e984126183"

#MY_TX=$ASUS
#MY_RX=$ASUS2
MY_TX="wlan1" #rpi testing
MY_RX="wlan2" #rpi testing

#WFB_FOLDER="/home/consti10/Desktop/wifibroadcast/build"
WFB_FOLDER="/home/openhd/wifibroadcast/build"
#WFB_FOLDER="/home/pi/Desktop/wifibroadcast"

FEC_K=0
FEC_PERCENTAGE=0

RADIO_PORT=60

MY_WIFI_CHANNEL=149 #5ghz channel
#MY_WIFI_CHANNEL=13 #2.4ghz channel

sudo rfkill unblock wifi
#sudo killall ifplugd #stop management of interface

sudo ifconfig $MY_TX down
sudo iw dev $MY_TX set monitor otherbss fcsfail
sudo ifconfig $MY_TX up
sudo iwconfig $MY_TX channel $MY_WIFI_CHANNEL
#sudo iw dev $MY_TX set channel "6" HT40+
#sudo iwconfig $MY_TX rts off

#sudo ifconfig $MY_RX down
#sudo iw dev $MY_RX set monitor otherbss fcsfail
#sudo ifconfig $MY_RX up
#sudo iwconfig $MY_RX channel $MY_WIFI_CHANNEL
#sudo iwconfig $MY_RX channel "6" HT40+

## test with multiple RXes
#sudo ifconfig $MY_RX_SECONDARY down
#sudo iw dev $MY_RX_SECONDARY set monitor otherbss fcsfail
#sudo ifconfig $MY_RX_SECONDARY up
#sudo iwconfig $MY_RX_SECONDARY channel 6


# $WFB_FOLDER/wfb_tx -k $FEC_K -n $FEC_N -u 6000 -p 60 -M 7 -K $WFB_FOLDER/drone.key $MY_TX
$WFB_FOLDER/wfb_tx -k $FEC_K -p $FEC_PERCENTAGE -u 5600 -r $RADIO_PORT -M 6 -B 20 $MY_TX

#$WFB_FOLDER/wfb_rx -c 127.0.0.1 -u 5601 -r $RADIO_PORT -K $WFB_FOLDER/gs.key $MY_RX

#other usefull commands:
#sudo iw dev
#nc -u localhost 6000
#nc -u -l localhost 6100
