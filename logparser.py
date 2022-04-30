import json
import datetime
from datetimerange import DateTimeRange
from dateutil.parser import*
from dateutil import*

file1 = open("logins.json")
data = []
for line in file1:
	data.append(json.loads(line))
#print(data)
#data = []
logins = {}
suskey = ""
for x in data:
	if "ServiceSid" not in x["PayloadData3"]:
		loginID = x["PayloadData3"].replace("LogonId: ", "")
		if loginID not in logins:
			logins[loginID] = [""]*2
		if "Successful logon" in x["MapDescription"]:
			logins[loginID][0] = x["TimeCreated"].replace("T"," ").strip("+00:00")
		if "An account was logged off" in x["MapDescription"]:
			logins[loginID][1] = x["TimeCreated"].replace("T"," ").strip("+00:00")
#print(logins)
count = 0
for key in logins:
#	print(key)
#	print(logins[key])
#	time0 = str(logins[key][0])
#	print("Time = "+ time0)
	time = parse("2021-03-16 08:00:09")
#	print(time)
#	time2 = parse("2021-03-16 07:59:09.123543")
#	if time.timestamp() >= time2.timestamp():
#		print("OK")
#	else:
#		print("No")
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
#for i in filedata:
#	data.append(json.loads(filedata))
#for i in range(len(data)):
#	login = {"type": [],"login_id": [], "time":[]}
#	try:
#		login_id = data[i]["PayloadData3"].replace("LogonId: ", "")
#		if "ServiceSid" not in login_id:
#			login["login_id"] = login_id
#	except:
#		print("Exception: No logon id")
#		break
#	if 'Successful' in data[i]["MapDescription"]:
#		login["type"] = 1
#		login["time"] = (data[i]["TimeCreated"])
#	elif "Logged off" in data[i]["MapDescription"] or "logged off" in data[i]["MapDescription"]:
#		login["type"] = 2
#		login["time"] = (data[i]["TimeCreated"])
#	logins.append(login)
#print(logins)	
	
#print(file1)

