import random, threading, os, subprocess, itertools, sys

MAC_LIST = []
THREAD_POOL = []
TOTAL_PORTS = []
SWITCHES = []

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

def nmapScan(ranMAC):
	global TOTAL_PORTS
	OPEN_PORTS = []
	out = subprocess.check_output(["nmap -p- " + " ".join(SWITCHES) + " --open --spoof-mac=" + ranMAC + " " + sys.argv[1]], shell=True)
	for row in out.split('\n'):
		if 'open' in row:
			port = row.split('/')
			port = str(port[0])	
			OPEN_PORTS.append(port)
	ThreadName = threading.currentThread().getName()

	# Separated for multihost logic later
	if ThreadName == 'Thread0':
		Thread0ports = OPEN_PORTS
		TOTAL_PORTS.append(Thread0ports)
		return
	
	elif ThreadName == 'Thread1':
		Thread1ports = OPEN_PORTS
		TOTAL_PORTS.append(Thread1ports)
		return

	elif ThreadName == 'Thread2':
		Thread2ports = OPEN_PORTS
		TOTAL_PORTS.append(Thread2ports)
		return

def main():
	global THREAD_POOL, TOTAL_PORTS, SWITCHES

	# Options
	NoPing = raw_input("Pingless scan? (Y/N)")
	if NoPing == "Y" or "y":
		SWITCHES.append("-Pn")

	# Start Threads
	print "\n[+] Spinning up threads"
	for x in range(0,3):
		ranMAC = randomMAC()
		t = threading.Thread(name='Thread' + str(x), target=nmapScan, args=(ranMAC,))
		THREAD_POOL.append(t)
		t.start()

	# Kill Threads	
	for x in range(0,3):
		killme = THREAD_POOL.pop()
		killme.join()
	print "[+] Threads killed\n"

	# Total list
	countin = list(itertools.chain.from_iterable(TOTAL_PORTS))

	# Unique ports throughout the total
	unique = sorted(set(countin))

	print "[*] Host: " + sys.argv[1]

	# Logic for open ports
	for x in range(0, len(unique)):
		 if countin.count(str(unique[x])) == 3:
		 	print "\tPort " + str(unique[x]) + " appears open"

if __name__ == '__main__':
	main()
	print "\n"
	sys.exit(-1)
