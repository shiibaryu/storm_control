# Traffic Strom Control module for Linux
"now developing" <br>
This is a linux kernel module about storm control. <br>
There are no linux function to prevent storm in network at present.<br>
Howebver, this function is needed in linux because of using linux as a general server.<br>
Therefore, I try to implement this function as a linux kernel module.<br>

# Usage
make<br>
insmod storm_control.ko storm_control d_name = "interface name" traffic_type = "broadcast or unknown_unicast or multicast" 
threshold="threshold packet per second" low_threshold="low_threshold packet per second"

# Authors
Ryusei shiiba


