# CodebreakerWriteups
Writeups for 3 tasks of the NSA Codebreaker Challenge

The NSA Codebreaker Challenge is an annual cybersecurity competition hosted by the National Security Agency. The competition is designed to mirror real-world challenges that NSA professionals work to solve. This year, 6 challenges were set up in increasing difficulty and requiring a variety of different techniques to solve. An additional 4 solo challenges were available once the first 6 were complete. No collaboration between contestants is allowed on solo challenges. 
This will be a brief walkthrough of my solutions to the first 3 challenges.

# Task 1
Topics: Network Analysis, Forensics

Prompt: The NSA Cybersecurity Collaboration Center has a mission to prevent and eradicate threats to the US Defense Industrial Base (DIB). Based on information sharing agreements with several DIB companies, we need to determine if any of those companies are communicating with the actor's infrastructure.

You have been provided a capture of data en route to the listening post as well as a list of DIB company IP ranges. Identify any IPs associated with the DIB that have communicated with the LP.
Enter the IP addresses associated with the DIB that have communicated with the LP, one per line: 
```
```


2 files were provided, a Wireshark file (capture.pcap) and a list of approved DIB IP ranges (ip_ranges.txt). In summary, the goal is to find unauthorized IP addresses that do not match the approved ranges, and report them.

![image](https://media.github.tamu.edu/user/17583/files/d6b66980-c7f0-11ec-8438-6784c7669612)

For simplicity's sake, I sorted the IP ranges in numerical order:
![image](https://media.github.tamu.edu/user/17583/files/ea1b0200-c7fb-11ec-8a44-d322caa371d5)

Then I wrote the following script in Python to enumerate all possible IP address within those ranges and convert it into a Wireshark search filter, to find the :
```
file1 = open("ip_ranges2.txt", "r")

ranges = file1.readlines()
ranges = [ i.strip() for i in ranges ]
output = ""
for j in ranges:
	output += "ip.src==" + j + "||" #Convert to Wireshark syntax
print(output)
```
Which yielded this output when run:
![image](https://media.github.tamu.edu/user/17583/files/83a6db80-c81d-11ec-816e-d9560e514fd1)

Search those IP addresses in Wireshark:
![image](https://media.github.tamu.edu/user/17583/files/121b5d00-c81e-11ec-9aa1-ff8d3900391f)
All the machines were in contact with 172.23.251.63, making this our listening post. 

We now have our list of compromised IP addresses. To solve this task, we need to filter out the IP addresses that belong to the DIB.
Using this list of compromised IP addresses I found from the pcap file, I wrote another Python script using the ip_address library, to check each IP address against ip_ranges.txt and output the ones that match the ranges.
``` IP Addresses:
10.228.151.167
172.16.208.14
172.23.251.63
172.27.146.243
172.29.129.100
172.30.41.254
172.30.75.49
172.30.86.6
172.30.117.181
198.19.245.183
```

``` 
from ipaddress import ip_network, ip_address

file1 = open("ip_ranges2.txt", "r") #DIB ranges
check_ips = open("cbiplist.txt", "r") #IP addresses

ip_ranges_list = file1.readlines()
unauth = [] # List of compromised addresses within DIB range

# Check each address to see whether it falls in range
for check_ip in check_ips:
	check_ip = check_ip.strip()
	inrange = False
	print("--------checking ips:------------" + check_ip)
	for ip in ip_ranges_list:
		ip = ip.rstrip()
		net = ip_network(ip)
		if (ip_address(check_ip) in net):
			inrange = True
			print("In range: ", ip)
			break
	if inrange == True:
		print(check_ip + "in range.")
		unauth.append(check_ip)
#Output DIB IP's
for i in unauth:
	print(i)
		
```
After running this script in the terminal, we now have our solution:
![image](https://media.github.tamu.edu/user/17583/files/5827ef00-c825-11ec-994c-b980be592fd2)


# Task 2

Prompt: NSA notified FBI, which notified the potentially-compromised DIB Companies. The companies reported the compromise to the Defense Cyber Crime Center (DC3). One of them, Online Operations and Production Services (OOPS) requested FBI assistance. At the request of the FBI, we've agreed to partner with them in order to continue the investigation and understand the compromise.

OOPS is a cloud containerization provider that acts as a one-stop shop for hosting and launching all sorts of containers -- rkt, Docker, Hyper-V, and more. They have provided us with logs from their network proxy and domain controller that coincide with the time that their traffic to the cyber actor's listening post was captured.

Identify the logon ID of the user session that communicated with the malicious LP (i.e.: on the machine that sent the beacon and active at the time the beacon was sent).

2 files were provided, oops_subnet.txt providing the subnet for OOPS, proxy.log, and logins.json.

As established in task 1, the listening post is 172.23.251.63. Using the command line to search through proxy.log, I found exactly one instance of activity from this user:
```
> cat proxy.log | grep '172.23.251.63'

2021-03-16 08:00:09 39 10.227.229.227 200 TCP_MISS 12734 479 GET http worsc.invalid activity - - DIRECT 172.23.251.63 application/octet-stream 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)' PROXIED none - 10.227.228.175 SG-HTTP-Service - none -

```
We now know that this user was active at 08:00:09. Now the task is to find the session ID of the malicious user in logins.json. To find this, I ran a python script to parse through the logins.json file and return the session of the user whose IP matched the LP and who logged in before 00:08:09 and logged out afterward.

```
# Some lines left as comments were used in debugging
import json
import datetime
from datetimerange import DateTimeRange
from dateutil.parser import*
from dateutil import*
#Read data from json file
file1 = open("logins.json")
data = []
for line in file1:
	data.append(json.loads(line))
logins = {}
suskey = ""
#Parse the json file into readable input
for x in data:
	if "ServiceSid" not in x["PayloadData3"]:
		loginID = x["PayloadData3"].replace("LogonId: ", "")
		if loginID not in logins:
			logins[loginID] = [""]*2
		if "Successful logon" in x["MapDescription"]:
			logins[loginID][0] = x["TimeCreated"].replace("T"," ").strip("+00:00")
		if "An account was logged off" in x["MapDescription"]:
			logins[loginID][1] = x["TimeCreated"].replace("T"," ").strip("+00:00")
count = 0
#Find the sessions that occurred during the specified time and print their session ID
for key in logins:
	time = parse("2021-03-16 08:00:09")
	#print(str(logins[key][0]), str(logins[key][1]))
	start = parse(logins[key][0])
	end = parse(logins[key][1])
	#print(logins[key][0])
	#str(time.timestamp()) <= str(end.timestamp())
	if time.timestamp() >= start.timestamp() and time.timestamp() <=end.timestamp():
		print(key, logins[key][0], logins[key][1])
		count += 1
print(str(time.timestamp()))
print(count)
```

Unfortunately, despite my attempts to debug the code, there did not seem to be a match. When I modified the script to return the total number of sessions, and the total which matched my criteria, my script returned 0 for the latter.

```
> python3 logparser.py

1615899609.0
0

```
In theory, there should have been exactly one session that matched both the IP of the listening post and the timeframe of the activity shown in the log, which would be our solution.

# Task 3



