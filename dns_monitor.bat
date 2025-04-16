@echo off
:: Save DNS cache to overwrite the file each time
ipconfig /displaydns > "dns_cache.txt"
:: Optional success message (useful for manual testing)
echo DNS cache saved successfully!
:: Remove 'pause' to allow Task Scheduler to run silently
exit
