cgminer-scrypt
==============

CGMiner 4.3.0 with Scrypt and GridSeed GC3355 dual-mining support.

	./autogen.sh
	./configure --enable-scrypt --enable-gridseed
	make

GC3355-specific options can be specified via `--gridseed-options` or
`"gridseed-options"` in the configuration file as a comma-separated list of
sub-options:

* baud - miner baud rate (default 115200)
* freq - any frequency multiple of 12.5 MHz, non-integer frequencies rounded up (default 600)
* pll_r, pll_f, pll_od - fine-grained frequency tuning; see below
* chips - number of chips per device (default 5)
* per_chip_stats - print per-chip nonce generations and hardware failures
* start_port - first port number for scrypt proxy mode (default 3350); see below
* voltage - switch the voltage to the GC3355 chips; see below
* led_off - turn off the LEDs on the Gridseed miner

When mining scrypt only this version of cgminer does not initialize the SHA cores so that
power usage is low. On a 5-chip USB miner, power usage is around 10 W.

Scrypt code was ported from cgminer version 3.7.2. Gridseed support is based largely on
the original [Gridseed CGMiner][] and [dtbartle][]'s scrypt modifications.

[Gridseed CGMiner]: <https://github.com/gridseed/usb-miner/>
[dtbartle]: <https://github.com/dtbartle/cgminer-gc3355/>

Frequency Tuning
----------------

If `pll_r/pll_f/pll_od` are specified, freq is ignored, and calculated as follows:
* Fin = 25
* Fref = int(Fin / (pll_r + 1))
* Fvco = int(Fref * (pll_f + 1))
* Fout = int(Fvco / (1 << pll_od))
* freq = Fout

Dual Mining
-----------

When dual-mining `start_port` will set the listening proxy port of the first gridseed
device on the SHA256 instance of cgminer, with additional miners using successive ports.
The scrypt instance of cgminer will attempt to connect starting at this port.

When dual mining, start the SHA mining instance of cgminer first, wait for it to begin
mining and then start the scrypt version. The second instance will detect that the USB
ports are in use and will attempt to connect to the first via UDP.

If everything is working the same devices will appear in both cgminer windows.

Voltage Modding
---------------

If `voltage=1` is set the gridseed chips will be switched to an alternate voltage.
Specifically, this flag will cause the MCU to assert the VID0 input to the voltage
regulator. This *requires* a voltmodded miner. On a stock unit this will actually
reduce the regulator's output voltage.

More Complex Options
--------------------

The options can also be specified for each device individually by serial number via
`--gridseed-freq` or `--gridseed-override` or their configuration file equivalents.
`--gridseed-freq` takes a comma-separated list of serial number to frequency mappings
while `--gridseed-override` takes the same format as `--gridseed-options`:

	--gridseed-freq "<SERIAL>=<FREQ>[,...]"

	--gridseed-override "<SERIAL>:freq=<FREQ>,voltage=<0/1>[,...];<SERIAL>:freq=<FREQ>[,...[;...]]"

