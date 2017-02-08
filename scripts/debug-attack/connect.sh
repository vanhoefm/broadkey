#!/bin/bash
rfkill unblock wifi
wpa_supplicant -d -K -D nl80211 -i wlp5s0 -c testnetwerk.conf
