import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys, socket, string, binascii, threading, signal, os
from sys import stdout
from subprocess import check_output, CalledProcessError

MAC_LIST = []
TIMEOUT = {}
TIMEOUT['timer'] = 0.4
THREAD_POOL = []
THREAD_CNT = 1
optionslist = {"server_id":"DHCP Server", 66:"Boot File Server", 67:"Boot File Name", "subnet_mask":"Subnet Mask"}

def usage():
    print "\n[-] Usage: The script takes one parameter, a network interface"
    print "[-] Example: python %s eth0\n" % sys.argv[0]

def randomMAC():
    global MAC_LIST
    if len(MAC_LIST) > 0:
        curr = MAC_LIST.pop()
        MAC_LIST = [curr] + MAC_LIST
        return curr
    mac = [0x11, 0x11,
           random.randint(0x00, 0x29),
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))

def sendPacket(pkt):
    sendp(pkt, iface=conf.iface, verbose=False)

def signal_handler(signal, frame):
    print "\n[+] Killing Threads"
    for t in THREAD_POOL:
        t.kill_received = True
    sys.exit(0)

def initialchecks():
    if len(sys.argv) != 2:
        usage()
        sys.exit(-1)
    try:
        up = subprocess.check_output(['cat','/sys/class/net/%s/operstate' % sys.argv[1]])
        if up != "up\n":
            print "\n[-] Interface requested doesn't appear to be up\n"
            sys.exit(-1)
    except CalledProcessError:
        os.system('clear')
        print "\n[-] Interface requested isn't valid\n"
        sys.exit(-1)

class send_dhcp(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.kill_received = False

    def run(self):
        global TIMEOUT
        while not self.kill_received:
            m = randomMAC()
            myxid = random.randint(1, 900000000)
            mymac = get_if_hwaddr(conf.iface)
            hostname =  ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(8))

            myoptions = [
                ("message-type", "discover"),
                ("param_req_list", "\x01", "\x02", "\x03", "\x04", "\x11", "\x12", "\x13", "\x14", "\x15", "\x16", "\x17", "\x18", "\x22", "\x23", "\x28", "\x40", "\x41", "\x42", "\x43", "\x50", "\x51", "\x54", "\x58", "\x59", "\x60", "\x66", "\x67"),
                ("max_dhcp_size", 1500),
                ("client_id", chr(1), mac2str(m)),
                ("lease_time", 10000),
                ("hostname", hostname),
                ("end", '00000000000000')
            ]

            dhcp_discover = Ether(src=mymac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0",dst="255.255.255.255") / UDP(sport=68,dport=67) / BOOTP(chaddr=[mac2str(m)], xid=myxid, flags=0xFFFFFF) / DHCP(options=myoptions)
            sendPacket(dhcp_discover)

class sniff_dhcp(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.filter = "(udp and src port 67 and dst port 68)"
        self.kill_received = False

    def run(self):
        while not self.kill_received:
            sniff(filter=self.filter, prn=self.detect_dhcp, store=0, timeout=3, iface=conf.iface)

    def detect_dhcp(self, pkt):
            global nodes, optionslist
            if DHCP in pkt:
                if pkt[DHCP] and pkt[DHCP].options[0][1] == 2:
                    self.dhcpcount = 0
                    mymac = get_if_hwaddr(conf.iface)
                    myip = pkt[BOOTP].yiaddr
                    sip = pkt[BOOTP].siaddr
                    localxid = pkt[BOOTP].xid

                    zearray = pkt[DHCP].options
                    #print zearray
                    for item in zearray:
                        if isinstance(item, (tuple, list)):
                            k, v = item
                            if k in optionslist:
                                print "\t{}: {}".format(optionslist[k],v)
                    for t in THREAD_POOL:
                        signal_handler(signal.SIGINT, 1)
                        t.join()


def main():
    initialchecks() 
    conf.iface = sys.argv[1]
    print "[+] Using interface %s" % conf.iface
    signal.signal(signal.SIGINT, signal_handler)
    print "[+] Thread %d - (Sniffer) READY" % len(THREAD_POOL)
    t = sniff_dhcp()
    t.start()
    THREAD_POOL.append(t)

    print "[+] Thread %d - (Sender) READY" % len(THREAD_POOL)
    print "[+] Sending packets until DHCP OFFER\n"
    for i in range(THREAD_CNT):
        t = send_dhcp()
        t.start()
        THREAD_POOL.append(t)

if __name__ == '__main__':
    main()
