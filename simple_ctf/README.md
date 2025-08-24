# TryHackMe Simple CTF write-up

The Simple CTF challenge on the TryHackMe platform is designed for beginners to learn how to scan, enummerate, research, exploit, and utilize privelage escalation. Enjoy!

Target IP: 10.201.96.113

## 1. Recon

### Rustscan

The first thing I do on every room is perform a scan for any open ports I could use to my advantage.

Most folks use the nmap tool, which is still a good tool, however I personally use Rustscan since it scans ports more efficiently than nmap does. Both tools can work for this challenge. Below is a a screenshot of the rustscan tool I used.

![Simple CTF Screenshot](img/initial_rustscan)

From the results, we can see that the following ports are open...

- 21 (ftp)
- 80 (http)
- 2222 (ssh)

**Q1: How many services are running under port 1000?**

- *Answer: 2*
- Port 21 (ftp) and port 80 (http) are two services that have ports under 1000*

**Q2: What is running on the higher port?**

- *Answer: SSH*

Knowing that this is a website being hosted, lets visit it to see if it gives us anything.

