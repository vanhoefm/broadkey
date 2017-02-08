#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 interface"
	exit 1
fi

INTERFACE=$1

rfkill unblock wifi
ifconfig $INTERFACE down
sudo iw $INTERFACE set type monitor
ifconfig $INTERFACE up
iw $INTERFACE set channel 11
