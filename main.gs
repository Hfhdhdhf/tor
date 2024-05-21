mResult = []
shells = []
crypto = include_lib("/lib/crypto.so")
metaxploit = include_lib("/lib/metaxploit.so")
meta = metaxploit
hack = function(ip, port, injection)
	netsession = meta.net_use(ip, to_int(port))
	if not netsession then
		print("failed")
		return
	else
		metalib = netsession.dump_lib
		memory = metaxploit.scan(metalib)
		for mem in memory
			address = metaxploit.scan_address(metalib, mem).split("Unsafe check:")

			for add in address
				value = add[add.indexOf("<b>") + 3 : add.indexOf("</b>")]
				value = value.replace("\n", "")
				result = metalib.overflow(mem, value, injection)
				print(mem + " " + value)
				if typeof(result) == "computer" then
					mResult.push(result)
				end if
				if typeof(result) == "shell" then
					mResult.push(result)
				end if
			end for
		end for
	end if
end function
crack = function(result)
	file = result.host_computer.File("/etc/passwd")
	passwd = file.get_content.split("\n")
	for pass in passwd
		stuff = pass.split(":")
		if stuff[0] == "root" then
			return stuff[0] + ":" + crypto.decipher(stuff[1])
		end if
	end for
end function

main = function(amount)
	for i in range(0, amount-1)
		ip = str(floor(rnd*255)) + "." + str(floor(rnd*255)) + "." + str(floor(rnd*255)) + "." + str(floor(rnd*255))
		router = get_router(ip)
		if router == null or not router then
			print("")
		else
			ports = router.used_ports
			if ports == null or not ports then
				print("")
			else
				for port in ports
					if port.port_number == 22 then
						hack(ip, "22", "0")
						for result in mResult
							if typeof(result) == "shell" then
								file = result.host_computer.File("/etc/passwd")
								if file.has_permission("r") then
									a = crack(result)
									return ip + "=" + a
								end if
							end if
						end for
					end if
				end for
			end if
		end if
	end for
end function

				
		
while true
	option = user_input("1: add connections\n2: connect to tor nodes (beta)\n~> ").to_int
	if option == 1 then
		for i in range(0, 10000)
			a = main(5)
			mResult = []
			print(a)
			if a == null or not a or a == "" then
				print("not a")
			else
				file = get_shell.host_computer.File("/home/guest/nodes")
				file.set_content(file.get_content + a + char(10))
			end if
			
				
		end for
		
	end if
	if option == 2 then
		file = get_shell.host_computer.File("/home/guest/nodes")
		servers = file.get_content.split("\n")
		stuff = get_shell
		servers.shuffle
		stuff = servers.len-1
		print("you got " + stuff + " recorded nodes (that are valid, normally there is one that is the offset used for node extracting)")
		amount = user_input("enter amount of nodes to connect: ").to_int
		amount = amount - 1 
		connected = 0
		stuff = get_shell
		toshow = connected + 1
		for server in servers
			if connected > amount then
				continue
			else
				print("connected to node number: " + toshow)
				connected = connected + 1
				toshow = toshow + 1
				if server == "" then
					print("")
				else
					temp = server.split("=")
					ip = temp[0]
					print(temp)
					login = temp[1].split(":")
					stuff = stuff.connect_service(ip, 22, login[0], login[1])
					if ip == "" then
						print("this is the offset used for later on!")
					else
						print(stuff.host_computer.public_ip)
					end if
					
				end if
			end if
		end for
		stuff.start_terminal
	end if
	
end while



			
				
		
		
		
		
		
