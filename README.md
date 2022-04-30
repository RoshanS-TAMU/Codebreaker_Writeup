# CodebreakerWriteups
Writeups for 3 tasks of the NSA Codebreaker Challenge

The NSA Codebreaker Challenge is an annual cybersecurity competition hosted by the National Security Agency. The competition is designed to mirror real-world challenges that NSA professionals work to solve. This year, 

# Task 1

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
We now have our list:





