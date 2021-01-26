# Simple-Router
Simulate a simple router with a static routing table.  Create the forwarding logic to make packets go to the correct interface.

Write a simple router with a static routing table. Your router will receive raw Ethernet frames. 
It will process the packets just like a real router, then forward them to the correct outgoing interface. 
The goal is to give you hands-on experience as to how a router really works. 
We’ll make sure you receive the Ethernet frames; your job is to create the forwarding logic so packets go to the correct interface.

Your router will route packets from an emulated host (client) to two (2) emulated application servers (HTTP Server 1 and 2) sitting behind your router. 
The application servers are each running an HTTP server. 
When you have finished the forwarding path of your router, you should be able to access these servers using regular client software. 
In addition, you should be able to ping and traceroute to and through a functioning Internet router.
