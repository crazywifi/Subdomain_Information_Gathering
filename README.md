## Subdomain Information Gathering

**What is Subdomain Information Gathering tool?**

*This script is a automation of many tools, this script gather subdomains and run scan on it.*

**How it's work?**

*Below are the steps how it's work.*

Step 1: Gather subdomain from different search engines (Netcraft,DNSdumpster,Virustotal,Yahoo,Bing...) by using Sublist3r.

Step 2: Gather subdomain by bruteforcing using knockpy.

Step 3: Make a single list of unique domains.

Step 4: Harvester:*It's optional. If you want to use it remove '#' in the code.

Step 5: Then it scan for open ports. Default(20-20000) ports. Make a list and save it in Output -> Scan_Logs folder. Extract all http and https ports and save it in different list.

Step 6: Then take a screenshot of each webpage and save it in Scan_Logs folder.

Step 7: Then search if "Wordpress" is running or not, if wordpress is running then using "wpscan" tool it scan the URL and save the output in Scan_Logs folder if not then scan using "Nikto".

Step 8: Then scan for *Gold*, bruteforce directories.

Step 9: For one URL process completed then go for other URLs.

