Flags

--host : IP address or network address
    - Currently using --hostname or --cidr
--protocol : tcp or udp 
    - nmap has the option for full TCP connect scans or half-open "stealth" scans. This would be great to add
--ports : Specify individual ports or a range of ports (22,80,53,100-200 etc.)
    - If not port is specified need to add logic to scan top 100 most common ports.
--debug : Enables debugging
--banner : Enables banner retrieval
--help : Print a help summary


Version 2.0

Better implement and seperate the flags for better control and code readbility
Improve file structure
Improve the debug command to show more information
Multithreading could use better timing or print statements needs more detail incase they get sent later you can tell what the statement is for

Issues:

--host www.google.com(or xxx.xxx.xxx.xxx),xxx.xxx.xxx.xxx/xx  errors out. Need to correct logic to split at comma and then parse and add to host_list