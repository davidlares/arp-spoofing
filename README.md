# ARP Spoofing

The following repository is part of a workshop that reflects a way of performing LAN network attacks.

The `spoofing.py` script performs an `ARP spoofing` attack with the help of `Scapy`, a Python package for packet crafting.

The `ARP spoofing` attack is the foundation for intercepting connections between different users on the same subnet. Basically the script is going to perform a `MITM` connection instead of performing an original connection. The `ARP packet` allows the users to identify themself on a network, computers do not understand IP addresses, and for that, every machine has an `ARP table` which contains the `MAC addresses` and their corresponded `IP address` for each element on the LAN.

The whole idea is send responses ("malformed packets") to the `router` and to the `victim` telling that the router is the `MAC address` of the `attacker machine`, this will change the whole data flow and the victim's traffic will be forwarded to the attacker machine.

## Scenario

For this example, I used a` Windows 10 machine` (192.168.1.130) as the `victim`, and a `Kali machine` as the `attacker` (192.168.1.111). The router used the `GW Ip address` (the 192.168.1.1)

Basically, its something like the following:

- The `victim` asks for the `MAC address` of the `router`
- Sends a request, and the machine with that particular `MAC address` will respond
- The `victim` PC will update its `ARP table` with the` MAC address` of the requested machine
- The `ARP spoofing` generates a communication between the victim and the attacker (tricking the user by saying that we are the router)
- Later we can sniff communications on the `LAN network` and check for `non-encrypted data` passed

## How it works

Using `Scapy` lets you craft or construct your own packets, sending it by your own needs, this means that we can manipulate request data, responses and plenty more.

Internally does the following.

1. Creates an Ethernet broadcast package using the `router MAC address`
2. AN `ARP packet` is created with the `router IP destination`
3. Another packet is created, and it concatenates both the `Ether` and the `ARP`. This is sent to the network (to the `router` actually)
4. The victim will receive the `router's` `hwsrc` (hardware source) MAC address.  This part is tricky because the `source` element is the router, it is the response, with that value, we are able to perform the second part of the MITM

### What's behind the MITM

Just we need to create a malformed packet which flip the `hwsrc` and `hwdst`, this will let you fool the `ARP table`, by telling that the router MAC address is our MAC address.

## Forwarding traffic

When the complete `MITM cycle` is done, the victim machine will lose internet connection, this makes the attack very obvious. The victim can check the `ARP table` with the `arp -a` command and see what's going on with the router. Basically this attack results in a `DoS` to the whole LAN network

So, for this particular scenario, we can forward the traffic letting the router act as well, the victim machine will resolve the internet connection and the attacker will have the capability to persist the `ARP spoofing`.

Check the `/proc/sys/net/ipv4/ip_forward`, on the attacker machine, if the value is `0`, which means that the interface is not supporting the network forwarding.

Do `echo 1 > /proc/sys/net/ipv4/ip_forward` and run the script again.


## Usage

Check and correct (if necessary) the hard-coded IP addresses, give execution permissions and run the file, like:

`./spoofing.py`

Once the program is interrupted, the restoring function is triggered. (Default MAC addresses)

## Set up

Simple, just.

`virtualenv -p python3 <name_of_the_env>`

Important: check the `requirements.txt` for dependencies

## Credits

 - [David E Lares](https://twitter.com/davidlares3)

## License

 - [MIT](https://opensource.org/licenses/MIT)
