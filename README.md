#  Predicting, Decrypting, and Abusing WPA2/802.11 Group Keys

This project contains attacks against predictable random number generators (RNGs) used in Wi-Fi Access Points (APs),
and in other Wi-Fi related programs.

This work was the result of the paper [Predicting, Decrypting, and Abusing WPA2/802.11 Group Keys](https://lirias.kuleuven.be/handle/123456789/547640) ([PDF here](https://lirias.kuleuven.be/bitstream/123456789/547640/1/usenix2016-wifi.pdf)) presented at USENIX Security 2016. Parts of this work were also [presented at the 33rd Chaos Communication Congress (33C3)](https://fahrplan.events.ccc.de/congress/2016/Fahrplan/events/8195.html).

## Dependencies

This project relies on OpenCL, and was tested using an NVidia card on Arch Linux.

## Getting started & Demonstration

First compile the project:

	$ make packages

In case compilation fails, make sure you have the required libraries and dependencies installed. Based on the displayed error you should be able to google the library you are missing, and find how to install this library on your Linux distribution. Once compiled, you can run the brute-force scripts. To re-run the capture made during my 33C3 presentation, you can run:

	$ cd scripts
	$ ./3_bruteforce.sh

## Making your own captures

### MediaTek

**You are unlikely to recover the GTK of a real MediaTek router: the code has been tuned against a specific firmware version.** Nevertheless, to make your own capture, you can do the following:

	$ cd scripts
	$ 1_set_monitor.sh wlan0
	$ 2_make_capture.py $MACROUTER
	$ optirun ./broadattack.py mediatek capture.pcap

Replace `wlan0` with your wireless interface, and `$MACROUTER` with the BSSID of the router (this is commonly the MAC address of the router). This should successfully recover the group key (GTK). On my mobile graphics card this takes less than 5 minutes (GeForce GTX 950M). Note that this is experimental code, so don't be afraid to change things if something doesn't work!

If you want to run it against another firmware version, first compile the target firmware yourself based on open source code. Print the jiffies values that were uwed in the GenRandom calls, and then modify the file `scripts/broadkey.py` at the following locations:
- In the function `predict_gtk_jiffies`: supply the correct jiffies.
- In the function `ralink_broadkey_prediction`: make sure `gmkJiffies` is properly set in step 4.

Note 1: a router model can be detected based on the MAC address, the [Information Element fingerprint](https://lirias.kuleuven.be/bitstream/123456789/543617/1/asiaccs2016.pdf), and how it reacts to certain packets. When it is not possible to differentiate between minor firmware changes, the script will have try all possible jiffies values for all possible firmware versions. Since the attack is fast, this should not pose a problem.

Note 2: while the attack can be generalized as described above, we did not do this ourselves to dissuade people from abusing it. We restricted ourselves to a proof-of-concept against our device, which is sufficient to demonstrate the weakness and motivate vendors to use a more secure random number generator.

### Broadcom

We only simulate an attack against Broadcom, so processing is real capture is not yet supported. If you have a device using the Broadcom time-based RNG, you can always extend the code! Currently a "fake" summary of a capture is provided to our scripts, this has to be changed in a summary extracted from a real capture.

