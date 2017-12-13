#!/usr/bin/python
import os
import sys
import re
import shutil
import nmap
import time

# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
Y = '\033[93m'
BOLD = '\033[1m'
END = '\033[0m'

#Banner Disply

def banner():

        print O+'###########################################################################################'
        print '#                               <<<Project Subdomain IG>>>                                  #'
        print '#                              Subdomain Information Gathering                              #'
        print '#                                Made by <<RISHABH SHARMA>>                                 #'
        print '#                                  Twitter : @blacknet22                                    #'
        print '#                                 operating system : KALI                                   #'
        print '#                                AUTOMATED Subdomain IG TOOL                                #'
        print '#  Thanks: Sublister,Knockpy,theharvester,Nmap,Webscreenshot,Whatweb,Wpscan,Nikto,Gobuster  #'
        print '#                                                                                           #'
        print '############################################################################################'+END




#Domain Enumeration By Sublister

def sublist3r(domaintoexploit):

	print BOLD+O+"Sublist3r Start..."+END
	sublist3r_command = 'sudo python Modules/sublist3r/sublist3r.py -v -e Netcraft,DNSdumpster,Virustotal,Yahoo,Bing,ThreatCrowd,SSL,Baidu,Ask,PassiveDNS -t 50 -o '+ 'Output/'+domaintoexploit +'.txt' + ' -d '+ domaintoexploit
	#sublist3r_command = 'sudo python Modules/sublist3r/sublist3r.py -v -e DNSdumpster -t 50 -o '+ 'Output/'+domaintoexploit +'.txt' + ' -d '+ domaintoexploit
	os.system(sublist3r_command)
	src = 'Output/'+domaintoexploit+'.txt'
	dst = 'Output/'+domaintoexploit+'_Sublist3r.txt' 
	shutil.copy (src,dst)
	if os.path.isfile (dst):
		print BOLD+R+"File Saved: "+END+Y+'Output/'+domaintoexploit+'.txt'+END

#Domain Enumeration By Bruteforce By Using Knockpy

def Knockpy(domaintoexploit):
	print BOLD+O+"Knockpy Start..."+END
	knock_command = 'sudo python Modules/knock/knockpy/knockpy.py -c '+domaintoexploit
	os.system(knock_command)
	src = domaintoexploit+'_knockpy.csv'
	dst = 'Output/'
	shutil.move(src,dst)
	if os.path.isfile (dst): 
                print BOLD+R+"File Saved...."+END
	extract_domain = "cat Output/"+domaintoexploit+"_knockpy.csv | tr ',' ' ' | awk '{print$4}' > Output/"+domaintoexploit+"_knockextract.txt"
	os.system(extract_domain)
	cmd1 = 'Output/'+domaintoexploit+'.txt'
        sublist3r_domain = open(cmd1 , 'a+')
        cmd2 = 'Output/'+domaintoexploit+'_knockextract.txt'
        with open(cmd2 , 'r') as domain:
                contents = domain.readlines()
                for eachdomain in contents:
                        sublist3r_domain.write(eachdomain)
        domain.close()
        sublist3r_domain.close()
	cmd3 = 'sudo cat Output/'+domaintoexploit+'.txt | sort -u > Output/test.txt && sudo rm Output/'+domaintoexploit+'.txt && sudo cp Output/test.txt Output/'+domaintoexploit+'.txt && sudo rm Output/test.txt'
	os.system(cmd3)
	print BOLD+R+"File Moved to Output Folder...."+END
	print BOLD+R+"File Saved: "+END+Y+'Output/'+domaintoexploit+'.txt'+END
	print BOLD+R+"Extracting "+domaintoexploit+" domain from file.."+END
	extractdomain = 'Output/'+domaintoexploit+'.txt'
	temp = 'Output/temp.txt'
	opentemp = open(temp, 'a+')
	with open(extractdomain, 'r') as f:
		content = f.readlines()
		for domain in content:
			searchobj = re.search(r'(.*)(\.)('+domaintoexploit+')', domain, re.I)
			if searchobj:
				domain = searchobj.group(1)+searchobj.group(2)+searchobj.group(3)
				opentemp.write(domain)
				opentemp.write('\n')
	opentemp.close()
	cmd4 = 'sudo rm Output/'+domaintoexploit+'.txt && sudo cp Output/temp.txt Output/'+domaintoexploit+'.txt && sudo rm Output/temp.txt'
	os.system(cmd4)
	print "Done...."

#This module is #, Use this module if you enumerate Email Addresses.

def theharvester_search(domaintoexploit):
        print BOLD+O+"TheHarvester Collecting Data..."+END
	theharvester_command = 'python theHarvester/theHarvester.py -h -l 500 -b all -d '+domaintoexploit+' -f ' + '/root/project_dracula/project_dracula/Output/theharvester/'+domaintoexploit
	os.system(theharvester_command)
	print "__________________________________"
        print BOLD+R+"TheHarvester Scan Completed...\n"+END


#-----------------------------------------------------Domain Enumeration Done---------------------------------------------------------------------------------------#

def Nmap_Scanner(domaintoexploit):
	nm = nmap.PortScanner()
	domain_list = 'Output/'+domaintoexploit+'.txt'
	with open(domain_list,'r') as d:
		subdomain = d.readlines()
		count = len(subdomain)
		for eachdomain in subdomain:
			try:
				eachdomain = eachdomain.rstrip()
				subdomain_log = 'Output/Scan_Logs/'+eachdomain
				if not os.path.exists(subdomain_log):
					os.makedirs(subdomain_log)
				port_log = 'Output/Scan_Logs/'+eachdomain+'/ports.txt'
				port_save = open(port_log,'a')
				nmap_logs = 'Output/Scan_Logs/'+eachdomain+'/nmap_logs.txt'
				nmap_save = open(nmap_logs,'w')
				print BOLD+R+'No. of Domains left: '+END+Y+str(count)+END
				count = count - 1
				print BOLD+R+'Time: '+END+Y+str(time.ctime(time.time()))
				print BOLD+R+"Scanning URL: "+END+Y+eachdomain+END
				logs = nm.scan(eachdomain,arguments='-sS --open -sV -p 80-443')
				print BOLD+R+'Nmap Command: '+END+Y+nm.command_line()+END
				for host in nm.all_hosts():
                                	print BOLD+G+'--------------------------------------------------------------------------------------------------------------------------------'+END
					#print('Host : %s (%s)'% (host, nm[host].hostname()))
					print BOLD+R+'Host: '+END+Y+str(host)+' ('+str(nm[host].hostname())+')'+END
                                	#print('State : %s' %nm[host].state())
					print BOLD+R+'State: '+END+Y+str(nm[host].state())+END
                                	for proto in nm[host].all_protocols():
                                        	print('----------')
                                        	print(BOLD+R+'Protocol: '+END+Y+str(proto))
                                        	lport = nm[host][proto].keys()
                                        	lport.sort()
                                        	#print 'lport: ',lport
                                        	for port in lport:
                                                	#print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
							data = (nm[host][proto][port])
							service = data['name']
							product = data['product']
							version = data['version']

							print  BOLD+O+'Port : '+END+Y+str(port)+END+BOLD+O+'\tState : '+END+Y+str(nm[host][proto][port]['state'])+END+BOLD+O+'\tService : '+END+Y+service+END+BOLD+O+'\tVersion : '+END+Y+version+END+BOLD+O+'\tProduct : '+END+Y+product+END
							nmap_out = 'Port : '+str(port)+' |State : '+str(nm[host][proto][port]['state'])+' |Service : '+service+' |Version : '+version+' |Product : '+product
							nmap_save.write(nmap_out)
							nmap_save.write('\n')
                                                	port = str(port)
							if (port == '80'):
								port = 'http://'+eachdomain
                                                		port_save.write(port)
                                                		port_save.write('\n')
							elif(port == '443'):
								port = 'https://'+eachdomain
                                                                port_save.write(port)
                                                                port_save.write('\n')
							elif(service == 'http' and port != '80'):
								port = 'http://'+eachdomain+':'+port
                                                                port_save.write(port)
                                                                port_save.write('\n')
							elif(service == 'https' and port != '443'):
								port = service+'://'+eachdomain+':'+port
								port_save.write(port)
                                                                port_save.write('\n')
                        	print BOLD+G+'------------------------------------------------------------------------------------------------------------------------------'+END
				nmap_save.close()
                		port_save.close()
				webscreenshot(eachdomain)
				whatweb(eachdomain)


			except KeyboardInterrupt:
				print "Keyboard Interrupt..."
				continue

                	except IOError,i:
				print "Input Output Error..."
				print i
				continue
                	except Exception,e:
				print "Error in file..."
				print e
				continue

def webscreenshot(eachdomain):
        port_log = 'Output/Scan_Logs/'+eachdomain+'/ports.txt'
        with open(port_log,'r') as f:
                content = f.readlines()
                for x in content:
                        x = x.rstrip()
                        print BOLD+R+'[Taking Screenshoht]: '+END,Y+x+END
                        y = x.replace('//','_')
                        y = y.replace(':','_')
                        webscreenshot = './Modules/phantomjs/bin/phantomjs Modules/phantomjs/bin/rasterize.js '+x+' Output/Scan_Logs/'+eachdomain+'/'+y+'.png'
                        print BOLD+GR+webscreenshot+END
                        os.system(webscreenshot)

def whatweb(eachdomain):
	print BOLD+P+'_______________________________________________________________________________________________________________________________________________________'+END
	port_log = 'Output/Scan_Logs/'+eachdomain+'/ports.txt'
	with open(port_log,'r') as f:
		contents = f.readlines()
		for domain in contents:
			domain = domain.rstrip()
			gobuster(eachdomain,domain)
			print BOLD+R+'[Whatweb Domain Scan]: '+END,Y+domain+END
			domain_save = domain
			domain_save = domain.replace('/','_')
			whatweb_command = 'sudo whatweb -U="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36" --no-errors '+domain+' --log-verbose=Output/Scan_Logs/'+eachdomain+'/'+domain_save+'_whatweb.txt'
			print BOLD+GR+whatweb_command+END
			os.system(whatweb_command)
			try:
				whatweb_log = 'Output/Scan_Logs/'+eachdomain+'/'+domain_save+'_whatweb.txt'
				Searching_Tech = 'grep  "WordPress" -F '+whatweb_log
				if (os.system(Searching_Tech) == 0):
					wpscan(eachdomain,domain)
				else:
					Searching_Tech = 'grep  "Drupal" -F '+whatweb_log
					if (os.system(Searching_Tech) == 0):
						#Drupal_Scan(eachdomain,domain)
						Nikto_Scan(eachdomain,domain)
					else:
						Searching_Tech = 'grep  "IIS" -F '+whatweb_log
						if(os.system(Searching_Tech) == 0):
							Nikto_Scan(eachdomain,domain)
						else:
							Nikto_Scan(eachdomain,domain)
 
			except KeyboardInterrupt:
                                print "Keyboard Interrupt..."
                                continue

                        except IOError,i:
                                print "Input Output Error..."
                                print i
                                continue
                        except Exception,e:
                                print "Error in file..."
                                print e
                                continue

def wpscan(eachdomain,domain):
	print '\n'
	print BOLD+R+'[Wordpress Scanning Start]: '+END,Y+domain+END
	Wpscan_Scanfolder = 'Modules/wpscan/Scan'
	if not os.path.exists(Wpscan_Scanfolder):
		os.makedirs(Wpscan_Scanfolder)
	domain_save = domain
	domain_save = domain.replace('/','_')
	wpscan_command = 'sudo ruby Modules/wpscan/wpscan.rb -r --follow-redirection --batch --threads 25 --throttle 3 --verbose --log Scan/'+domain_save+'_wpscan.txt -u '+domain
	print BOLD+GR+wpscan_command+END
	os.system(wpscan_command)
	print BOLD+R+"Wordpress Scan Completed...\n"+END
	src = 'Modules/wpscan/Scan/'+domain_save+'_wpscan.txt'
	dst = 'Output/Scan_Logs/'+eachdomain+'/'+domain_save+'_wpscan.txt'
	shutil.move(src,dst)
	print BOLD+P+'_________________________________________________________________________________________________________________________________________________________________'+END

def Nikto_Scan(eachdomain,domain):
	print '\n'
	print BOLD+R+'[Nikto Scanning Start]: '+END,Y+domain+END
	domain_save = domain
	domain_save = domain.replace('/','_')
	nikto_command = 'sudo nikto -Tuning x 6 -maxtime 5m -timeout 5 -evasion 1 -Format txt -output Output/Scan_Logs/'+eachdomain+'/'+domain_save+'_Nikto.txt -h '+domain
	print BOLD+GR+nikto_command+END
	os.system(nikto_command)
	print BOLD+R+"Nikto Scan Completed...\n"+END
	print BOLD+P+'_________________________________________________________________________________________________________________________________________________________________'+END


def gobuster(eachdomain,domain):
	print '\n'
	print BOLD+R+'[Hidden File Scanning Start]: '+END,Y+domain+END
	domain_save = domain
        domain_save = domain.replace('/','_')
	gobuster = 'sudo gobuster -t 50 -s "200" -q -r -n -w Modules/wordlist.txt -u '+domain+'/ > Output/Scan_Logs/'+eachdomain+'/'+domain_save+'_gobuster.txt'
	print BOLD+GR+gobuster+END
	os.system(gobuster)


def main():
        banner()
        domaintoexploit = raw_input(BOLD+O+"Enter Domain Name to Bruteforce (ex: microsoft.com): "+END)
	print '\n'
	Output_Folder = 'Output'
        if not os.path.exists(Output_Folder):
		os.makedirs(Output_Folder)
	sublist3r(domaintoexploit)
	Knockpy(domaintoexploit)
	#theharvester_search(domaintoexploit)
	scan_logs = "Output/Scan_Logs"
	if not os.path.exists(scan_logs):
                os.makedirs(scan_logs)
	Nmap_Scanner(domaintoexploit)

if __name__ =='__main__':
        main()

