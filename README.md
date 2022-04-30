# CodebreakerWriteups
Writeups for 3 tasks of the NSA Codebreaker Challenge

The NSA Codebreaker Challenge is an annual cybersecurity competition hosted by the National Security Agency. The competition is designed to mirror real-world challenges that NSA professionals work to solve. This year, 

# Task 1

2 files were provided, a Wireshark file (capture.pcap) and a list of DIB IP ranges (ip_ranges.txt). 

![image](https://media.github.tamu.edu/user/17583/files/d6b66980-c7f0-11ec-8438-6784c7669612)
A cursory glance at the capture file showed that IP host 172.23.251.63 was functioning as the listening post. I wanted to determine

For simplicity's sake, I sorted the IP ranges in numerical order:
![image](https://media.github.tamu.edu/user/17583/files/ea1b0200-c7fb-11ec-8a44-d322caa371d5)

Then I wrote the following script in Python to enumerate all possible IP address within those ranges and convert it into a Wireshark search filter:
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

We now have our list of compromised IP addresses. To solve this task, we need to filter out the IP addresses that belong to the DIB.
Using this list of compromised IP addresses I found from the pcap file, I wrote another Python script to check each IP address against ip_ranges.txt and output the ones that match the ranges.
``` IP Addresses:
```
``` Python code
```




