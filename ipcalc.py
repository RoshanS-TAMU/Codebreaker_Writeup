from ipaddress import ip_network, ip_address

file1 = open("ip_ranges2.txt", "r")
check_ips = open("cbiplist.txt", "r")

ip_ranges_list = file1.readlines()
unauth = []

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
for i in unauth:
	print(i)
		
