Pinecrypt Gateway firewall service handles `iptables` and `ip6tables` rule generation based on the MongoDB contents.

This allows without restarting any Docker services:

* Enable/disable replicas
* WIP: Fine tune MTU, MSS parameters
* WIP: Toggle masquerading packets
