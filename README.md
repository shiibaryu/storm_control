# Storm Control for Linux
This is a linux kernel module to prevent BUM storm in layer 2 network. <br>
By using this module, you can limit a specific traffic at the interface you specified.  <br>

When a packet come in the interface you specified, <br>
this module use netdev_rx_handler to check a packet type and mesure a traffic amount following the setting. <br>
Then, by one minute, this module check whethere tha traffic amount are more than the threshold or not. <br>
If the blocking started, the traffic amount is checked based on the low threshold.

## Compile
We tested this module on
- Ubuntu 18.04, kernel 4.15.0-43-generic
- Debian9.8.0, kernel 4.9.0.8 (storm_control_debian.c)

```shell-session
$ sudo apt install flex bison # for iproute2

$ git clone https://github.com/shiibaryu/storm_control.git
$ cd storm_control
$ make # compile a object file for ubuntu version as is.
```
In addition to the kernel module and tools, a modified iproute2 will
be compiled.<br>
If some compilation in this iproute2 files may be failed, you don't neet to mind.(it will not affect)<br>

## Install

```shell-session
$ cd storm_control
$ sudo make install
$ cd k_mod
$ insmod test.ko
```
The modified iproute2 contained in this repository can configure 
the setting using ip command.

```shell-session
$ ./iproute2-4.10.0/ip/ip storm help

		"Usage: ip storm add dev NAME\n"
		"          type { broadcast | multicast | unknown_unicast }\n"
		"          { pps | bps | level } threshold low_threshold\n"
		"\n"
		"       ip storm del dev NAME\n"
		"\n"
		"       ip storm show\n"
		"\n"
		);
    
$ sudo /sbin/ip storm add dev ens0 type broadcast pps 1000 100
```

## To do next

We should mesure the performance of it's module and put those results together in a report.
