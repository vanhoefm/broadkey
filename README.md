#  Predicting, Decrypting, and Abusing WPA2/802.11 Group Keys

This project contains attacks against predictable random number generators (RNGs) used in Wi-Fi Access Points (APs),
and in other Wi-Fi related programs.

This work was the result of the paper [Predicting, Decrypting, and Abusing WPA2/802.11 Group Keys](https://lirias.kuleuven.be/handle/123456789/547640) ([PDF here](https://lirias.kuleuven.be/bitstream/123456789/547640/1/usenix2016-wifi.pdf)) presented at USENIX Security 2016. Parts of this work were also [presented at the 33rd Chaos Communication Congress (33C3)](https://fahrplan.events.ccc.de/congress/2016/Fahrplan/events/8195.html).

## Dependencies

This project relies on OpenCL, and was tested using an NVidia card on Arch Linux.

## Getting started

First compile the project:

		$ make packages

Then you can run the brute-force scripts. To re-run the capture made during my 33C3 presentation, you can run:

		$ cd scripts
		$ ./3_bruteforce.sh

This should successfully recover the group key (GTK). On my mobile graphics card this takes less than 5 minutes (GeForce GTX 950M).

## Making your own captures

### MediaTek

**This is unlikely to rover the GTK: the code has been tuned against a specific firmware version.** If you want to run it against another firmware version, first compile the target firmware yourself based on open source code. Print the jiffies values that were uwed in the GenRandom calls, and then modify the file `scripts/broadkey.py` at the locations:
- The function `predict_gtk_jiffies` to supply the correct jiffies.
- In the function `ralink_broadkey_prediction` step 4 where `gmkJiffies` is set.

Note that a router model can be detected based on the MAC address, the [Information Element fingerprint](https://lirias.kuleuven.be/bitstream/123456789/543617/1/asiaccs2016.pdf), and how it reacts to certain packets. When it is not possible to differentiate between minor firmware changes, the attack would have to try all possible jiffies values over the possible firmware versions that a victim may be using. Since the attack is fast, this should not pose a problem.

### Broadcom

We only simulate an attack against Broadcom, so processing is real capture is not yet supported. If you have a device using the Broadcom time-based RNG, you can always extend the code! Currently a "fake" summary of a capture is provided to our scripts, this has to be changed in a summary extracted from a real capture.

