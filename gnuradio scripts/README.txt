The RX directory contains RECEIVE ONLY Gnu Radio scripts. 

The narrowband scripts, named with "RTLSDR", capture only 1MHz of data, thus making them suitable for inexpensive low bandwidth SDRs. 

The "Meshtastic_US_allPresets.grc" is a 20MHz wide all-preset capturing script. You will need a HackRF, LimeSDR, BladeRF or other SDR that is capable of capturing 20MHz. The default configured device is a HackRF.

All other scripts work with the RTLSDR, since bandwidth is limited to narrow bands.  

European users have this much easier. The total band is much smaller, meaning you can capture all presets with just an RTLSDR for everything.