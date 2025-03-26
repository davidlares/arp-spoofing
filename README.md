# ARP Spoofing Tool

#### Description

This tool demonstrates how to perform an ARP spoofing attack on a Local Area Network (LAN) using Python and the `Scapy` library. The ARP spoofing attack redirects network traffic from the victim to the attacker by sending forged ARP responses, allowing for a Man-in-the-Middle (MITM) attack. The attacker impersonates the router or gateway to intercept the victim's traffic and forward it through the attacker's machine.

With this script, you can simulate a MITM attack, allowing the attacker to intercept non-encrypted traffic from the target device.

#### How ARP Spoofing Works

1. The attacker sends fake ARP responses to both the victim and the router, associating the attacker's MAC address with the router's IP address.
2. This causes the victim to send its traffic to the attacker, believing it to be the router.
3. The attacker forwards the traffic to the actual router, intercepting and potentially manipulating the data.

#### Scenario

For this example:
- **Victim**: Windows 10 machine (`192.168.1.130`)
- **Attacker**: Kali Linux machine (`192.168.1.111`)
- **Router**: Default gateway (`192.168.1.1`)

#### Steps:

1. The victim sends an ARP request to find the MAC address of the router.
2. The attacker sends a fake ARP response, claiming that the attacker's MAC address is associated with the router's IP.
3. The victim updates its ARP table with the attacker's MAC address, redirecting traffic to the attacker instead of the router.

#### Forwarding Traffic

To prevent a Denial of Service (DoS) situation where the victim loses internet access, you need to enable IP forwarding on the attacker's machine. This allows the attacker to pass traffic between the victim and the router, maintaining the internet connection while still intercepting traffic.

To enable IP forwarding on Linux:
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

#### Usage

Make sure to specify the correct IP addresses and the network interface.

#### Command:
```bash
sudo ./spoofing.py -t <target_ip> -s <spoofed_ip> -i <interface>
```

#### Example:
```bash
sudo ./spoofing.py -t 192.168.1.130 -s 192.168.1.1 -i eth0
```

- `-t` or `--target`: The victim's IP address.
- `-s` or `--spoof`: The IP address you want to spoof (e.g., the router).
- `-i` or `--interface`: The network interface to use (e.g., `eth0`, `wlan0`).

When the program is interrupted (e.g., by pressing `CTRL+C`), the script will automatically restore the ARP tables of the victim and the router to their original state.

#### Setup

1. (Optional) Set up a virtual environment:
   ```bash
   virtualenv -p python3 <env_name>
   source <env_name>/bin/activate
   ```
   
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

#### Dependencies

- **Scapy**: A powerful Python library for packet crafting and network analysis.
- **argparse**: For command-line argument parsing.
- **colorama**: For adding colored output to terminal messages.

#### Check Out My Books

- **Mastering Linux Networking and Security: Essential and Advanced Techniques**  
  [Support on BuyMeACoffee](https://www.buymeacoffee.com/halildeniz/e/315997)

- **Mastering Scapy: A Comprehensive Guide to Network Analysis**  
  [Support on BuyMeACoffee](https://www.buymeacoffee.com/halildeniz/e/182908)

- **Mastering Python for Ethical Hacking: A Comprehensive Guide to Building Hacking Tools**  
  [Support on BuyMeACoffee](https://buymeacoffee.com/halildeniz/e/296372)

#### Join the Community

Feel free to join our **Production Brain** Discord server to discuss cybersecurity, Python projects, and more:  
[Join Production Brain Discord](https://discord.gg/nGBpfMHX4u)

This project continues to grow with community feedback and contributions!

#### Credits

- **Original Author**: [David E Lares](https://twitter.com/davidlares3)
- **Updated by**: Halil İbrahim ([denizhalil.com](https://denizhalil.com))

#### License

- [MIT License](https://opensource.org/licenses/MIT)
