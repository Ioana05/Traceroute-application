# Traceroute-application 🗺️
 Traceroute is a network diagnostic tool used to track in real-time the pathway taken by a packet on an IP network from source to destination, reporting the IP addreses of all the routers it pinged in between.

## Project overview
This project aims to implement a fully functional traceroute application using <b> scapy </b> and works by sending consecutive UDP packets with incremented TTL, starting with 1. Each router decrements the packet's TTL(time to live) value by one. When the TTL expires, the router sends back an ICMP: "Time Exceeded: TTL expired in transit" message, enabling the sender to map out the route.

To enhance the utility of the traceroute application, I've integrated an IP gealocation feature("ip-api"), that can fetch location information for each public IP address obtained during the traceroute process. The extracted data will then be used to print a map, utilizing Plotly express.
    
