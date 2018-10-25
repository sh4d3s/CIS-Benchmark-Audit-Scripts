#!/bin/bash
echo "1.1.1.1 Ensure mounting of cramfs filesystems is disabled"
modprobe -n -v cramfs
lsmod | grep cramfs

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.1.2 Ensure mounting of freevxfs filesystems is disabled"
modprobe -n -v freevxfs
lsmod | grep freevxfs

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.1.3 Ensure mounting of jffs2 filesystems is disabled"
modprobe -n -v jffs2
lsmod | grep jffs2

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.1.4 Ensure mounting of hfs filesystems is disabled"
modprobe -n -v hfs
lsmod | grep hfs

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.1.5 Ensure mounting of hfsplus filesystems is disabled"
modprobe -n -v hfsplus
lsmod | grep hfsplus

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.1.6 Ensure mounting of udf filesystems is disabled"
modprobe -n -v udf
lsmod | grep udf

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.3 Ensure nodev option set on /tmp partition"
mount | grep /tmp

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.4 Ensure nosuid option set on /tmp partition"
mount | grep /tmp

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.7 Ensure nodev option set on /var/tmp partition"
mount | grep /var/tmp

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.8 Ensure nosuid option set on /var/tmp partition"
mount | grep /var/tmp

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.9 Ensure noexec option set on /var/tmp partition"
mount | grep /var/tmp

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.13 Ensure nodev option set on /home partition"
mount | grep /home

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.14 Ensure nodev option set on /run/shm partition"
mount | grep /run/shm

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.15 Ensure nosuid option set on /run/shm partition"
mount | grep /run/shm

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.16 Ensure noexec option set on /run/shm partition"
mount | grep /run/shm

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.17 Ensure nodev option set on removable media partitions"
mount

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.18 Ensure nosuid option set on removable media partitions"
mount

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.19 Ensure noexec option set on removable media partitions"
mount

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.20 Ensure sticky bit is set on all world-writable directories"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.1.21 Disable Automounting"
initctl show-config autofs

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.2.1 Ensure package manager repositories are configured"
apt-cache policy

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.2.2 Ensure GPG keys are configured"
apt-key list

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.3.1 Ensure AIDE is installed"
dpkg -s aide

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.3.2 Ensure filesystem integrity is regularly checked"
crontab -u root -l | grep aide
grep -r aide /etc/cron.* /etc/crontab

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.4.1 Ensure permissions on bootloader config are configured"
stat /boot/grub/grub.cfg

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.4.2 Ensure bootloader password is set"
grep "^set superusers" /boot/grub/grub.cfg
grep "^password" /boot/grub/grub.cfg

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.4.3 Ensure authentication required for single user mode"
grep ^root:[*\!]: /etc/shadow

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.5.1 Ensure core dumps are restricted"
grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*
sysctl fs.suid_dumpable
grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.5.2 Ensure XD/NX support is enabled"
dmesg | grep NX

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.5.3 Ensure address space layout randomization (ASLR) is enabled"
sysctl kernel.randomize_va_space
grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.5.4 Ensure prelink is disabled"
dpkg -s prelink

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.7.1.1 Ensure message of the day is configured properly"
cat /etc/motd
egrep '(\\v|\\r|\\m|\\s)' /etc/motd

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.7.1.2 Ensure local login warning banner is configured properly"
cat /etc/issue
egrep '(\\v|\\r|\\m|\\s)' /etc/issue

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.7.1.3 Ensure remote login warning banner is configured properly"
cat /etc/issue.net
egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.7.1.4 Ensure permissions on /etc/motd are configured"
stat /etc/motd

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.7.1.5 Ensure permissions on /etc/issue are configured"
stat /etc/issue

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.7.1.6 Ensure permissions on /etc/issue.net are configured"
stat /etc/issue.net

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.7.2 Ensure GDM login banner is configured"
cat /etc/dconf/profile/gdm
cat /etc/dconf/db/gdm.d/01-banner-message

echo "-------------------------------------------------------------------"
printf "\n"
echo "1.8 Ensure updates, patches, and additional security software are installed"
apt-get -s upgrade

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.1.1 Ensure chargen services are not enabled"
grep -R "^chargen" /etc/inetd.*

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.1.2 Ensure daytime services are not enabled"
grep -R "^daytime" /etc/inetd.*

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.1.3 Ensure discard services are not enabled"
grep -R "^discard" /etc/inetd.*

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.1.4 Ensure echo services are not enabled"
echo "services are not enabled"
grep -R "^echo" /etc/inetd.*

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.1.5 Ensure time services are not enabled"
grep -R "^time" /etc/inetd.*

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.1.6 Ensure rsh server is not enabled"
grep -R "^shell" /etc/inetd.*
grep -R "^login" /etc/inetd.* 
grep -R "^exec" /etc/inetd.* 

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.1.7 Ensure talk server is not enabled"
grep -R "^talk" /etc/inetd.*
grep -R "^ntalk" /etc/inetd.* 

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.1.8 Ensure telnet server is not enabled"
grep -R "^telnet" /etc/inetd.*

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.1.9 Ensure tftp server is not enabled"
grep -R "^tftp" /etc/inetd.*

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.1.10 Ensure xinetd is not enabled"
initctl show-config xinetd

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.1.11 Ensure openbsd-inetd is not installed"
dpkg -s openbsd-inetd

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.1.1 Ensure time synchronization is in use"
dpkg -s ntp
dpkg -s chrony

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.1.2 Ensure ntp is configured"
grep "^restrict" /etc/ntp.conf
grep "^(server|pool)" /etc/ntp.conf
grep "RUNASUSER=ntp" /etc/init.d/ntp

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.1.3 Ensure chrony is configured"
grep "^(server|pool)" /etc/chrony/chrony.conf

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.2 Ensure X Window System is not installed"
dpkg -l xserver-xorg*

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.3 Ensure Avahi Server is not enabled"
initctl show-config avahi-daemon

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.4 Ensure CUPS is not enabled"
initctl show-config cups

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.5 Ensure DHCP Server is not enabled"
initctl show-config isc-dhcp-server
initctl show-config isc-dhcp-server6

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.6 Ensure LDAP server is not enabled"
ls /etc/rc*.d/S*slapd

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.7 Ensure NFS and RPC are not enabled"
ls /etc/rc*.d/S*nfs-kernel-server
initctl show-config rpcbind

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.8 Ensure DNS Server is not enabled"
ls /etc/rc*.d/S*bind9

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.9 Ensure FTP Server is not enabled"
initctl show-config vsftpd

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.10 Ensure HTTP server is not enabled"
ls /etc/rc*.d/S*apache2

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.11 Ensure IMAP and POP3 server is not enabled"
initctl show-config dovecot

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.12 Ensure Samba is not enabled"
initctl show-config smbd

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.13 Ensure HTTP Proxy Server is not enabled"
initctl show-config squid3

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.14 Ensure SNMP Server is not enabled"
ls /etc/rc*.d/S*snmpd

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.15 Ensure mail transfer agent is configured for local-only mode"
netstat -an | grep LIST | grep ":25[[:space:]]"

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.16 Ensure rsync service is not enabled"
grep ^RSYNC_ENABLE /etc/default/rsync

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.2.17 Ensure NIS Server is not enabled"
initctl show-config ypserv

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.3.1 Ensure NIS Client is not installed"
dpkg -s nis

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.3.2 Ensure rsh client is not installed"
dpkg -s rsh-client
dpkg -s rsh-redone-client 

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.3.3 Ensure talk client is not installed"
dpkg -s talk

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.3.4 Ensure telnet client is not installed"
dpkg -s telnet

echo "-------------------------------------------------------------------"
printf "\n"
echo "2.3.5 Ensure LDAP client is not installed"
dpkg -s ldap-utils

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.1.1 Ensure IP forwarding is disabled"
sysctl net.ipv4.ip_forward
grep "net\.ipv4\.ip_forward" /etc/sysctl.conf /etc/sysctl.d/*

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.1.2 Ensure packet redirect sending is disabled"
sysctl net.ipv4.conf.all.send_redirects
sysctl net.ipv4.conf.default.send_redirects
grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.2.1 Ensure source routed packets are not accepted"
sysctl net.ipv4.conf.all.accept_source_route
sysctl net.ipv4.conf.default.accept_source_route
grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.2.2 Ensure ICMP redirects are not accepted"
sysctl net.ipv4.conf.all.accept_redirects
sysctl net.ipv4.conf.default.accept_redirects
grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.2.3 Ensure secure ICMP redirects are not accepted"
sysctl net.ipv4.conf.all.secure_redirects
sysctl net.ipv4.conf.default.secure_redirects
grep "net\.ipv4\.conf\.all\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.2.4 Ensure suspicious packets are logged"
sysctl net.ipv4.conf.all.log_martians
sysctl net.ipv4.conf.default.log_martians
grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.2.5 Ensure broadcast ICMP requests are ignored"
sysctl net.ipv4.icmp_
echo_ignore_broadcasts
grep "net\.ipv4\.icmp_
echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/*

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.2.6 Ensure bogus ICMP responses are ignored"
sysctl net.ipv4.icmp_ignore_bogus_error_responses
grep "net\.ipv4\.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/*

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.2.7 Ensure Reverse Path Filtering is enabled"
sysctl net.ipv4.conf.all.rp_filter
sysctl net.ipv4.conf.default.rp_filter
grep "net\.ipv4\.conf\.all\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.2.8 Ensure TCP SYN Cookies is enabled"
sysctl net.ipv4.tcp_syncookies
grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/*

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.3.1 Ensure IPv6 router advertisements are not accepted"
sysctl net.ipv6.conf.all.accept_ra
sysctl net.ipv6.conf.default.accept_ra
grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.3.2 Ensure IPv6 redirects are not accepted"
sysctl net.ipv6.conf.all.accept_redirects
sysctl net.ipv6.conf.default.accept_redirects
grep "net\.ipv6\.conf\.all\.accept_redirect" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv6\.conf\.default\.accept_redirect" /etc/sysctl.conf /etc/sysctl.d/*

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.3.3 Ensure IPv6 is disabled"
grep "^\s*linux" /boot/grub/grub.cfg

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.4.1 Ensure TCP Wrappers is installed"
dpkg -s tcpd

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.4.2 Ensure /etc/hosts.allow is configured"
cat /etc/hosts.allow

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.4.3 Ensure /etc/hosts.deny is configured"
cat /etc/hosts.deny

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.4.4 Ensure permissions on /etc/hosts.allow are configured"
stat /etc/hosts.allow

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.4.5 Ensure permissions on /etc/hosts.deny are configured"
stat /etc/hosts.deny

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.5.1 Ensure DCCP is disabled"
modprobe -n -v dccp
lsmod | grep dccp

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.5.2 Ensure SCTP is disabled"
modprobe -n -v sctp
lsmod | grep sctp

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.5.3 Ensure RDS is disabled"
modprobe -n -v rds
lsmod | grep rds

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.5.4 Ensure TIPC is disabled"
modprobe -n -v tipc
lsmod | grep tipc

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.6.1 Ensure iptables is installed"
dpkg -s iptables

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.6.2 Ensure default deny firewall policy"
iptables -L

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.6.3 Ensure loopback traffic is configured"
iptables -L INPUT -v -n

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.6.4 Ensure outbound and established connections are configured"
iptables -L -v -n

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.6.5 Ensure firewall rules exist for all open ports"
netstat -ln
iptables -L INPUT -v -n

echo "-------------------------------------------------------------------"
printf "\n"
echo "3.7 Ensure wireless interfaces are disabled"
iwconfig
ip link show up

echo "-------------------------------------------------------------------"
printf "\n"
echo "4.2.1.1 Ensure rsyslog Service is enabled"
initctl show-config rsyslog

echo "-------------------------------------------------------------------"
printf "\n"
echo "4.2.1.2 Ensure logging is configured"
ls -l /var/log/

echo "-------------------------------------------------------------------"
printf "\n"
echo "4.2.1.3 Ensure rsyslog default file permissions configured"
grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf

echo "-------------------------------------------------------------------"
printf "\n"
echo "4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host"
grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf

echo "-------------------------------------------------------------------"
printf "\n"
echo "4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts."
grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf

echo "-------------------------------------------------------------------"
printf "\n"
echo "4.2.2.1 Ensure syslog-ng service is enabled"
ls /etc/rc*.d/S*syslog-ng

echo "-------------------------------------------------------------------"
printf "\n"
echo "4.2.2.2 Ensure logging is configured"
ls -l /var/log/

echo "-------------------------------------------------------------------"
printf "\n"
echo "4.2.2.3 Ensure syslog-ng default file permissions configured"
grep ^options /etc/syslog-ng/syslog-ng.conf

echo "-------------------------------------------------------------------"
printf "\n"
echo "4.2.2.4 Ensure syslog-ng is configured to send logs to a remote log host"
cat /etc/syslog-ng/syslog-ng.conf

echo "-------------------------------------------------------------------"
printf "\n"
echo "4.2.2.5 Ensure remote syslog-ng messages are only accepted on designated log hosts"
cat /etc/syslog-ng/syslog-ng.conf

echo "-------------------------------------------------------------------"
printf "\n"
echo "4.2.3 Ensure rsyslog or syslog-ng is installed"
dpkg -s rsyslog
dpkg -s syslog-ng

echo "-------------------------------------------------------------------"
printf "\n"
echo "4.2.4 Ensure permissions on all logfiles are configured"
find /var/log -type f -ls

echo "-------------------------------------------------------------------"
printf "\n"
echo "4.3 Ensure logrotate is configured"
cat /etc/logrotate.conf
cat /etc/logrotate.d/*

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.1.1 Ensure cron daemon is enabled"
/sbin/initctl show-config cron

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.1.2 Ensure permissions on /etc/crontab are configured"
stat /etc/crontab

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.1.3 Ensure permissions on /etc/cron.hourly are configured"
stat /etc/cron.hourly

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.1.4 Ensure permissions on /etc/cron.daily are configured"
stat /etc/cron.daily

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.1.5 Ensure permissions on /etc/cron.weekly are configured"
stat /etc/cron.weekly

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.1.6 Ensure permissions on /etc/cron.monthly are configured"
stat /etc/cron.monthly

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.1.7 Ensure permissions on /etc/cron.d are configured"
stat /etc/cron.d

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.1.8 Ensure at/cron is restricted to authorized users"
stat /etc/cron.deny
stat /etc/at.deny
stat /etc/cron.allow
stat /etc/at.allow

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured"
stat /etc/ssh/sshd_config

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.2.2 Ensure SSH Protocol is set to 2"
grep "^Protocol" /etc/ssh/sshd_config

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.2.3 Ensure SSH LogLevel is set to INFO"
grep "^LogLevel" /etc/ssh/sshd_config

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.2.4 Ensure SSH X11 forwarding is disabled"
grep "^X11Forwarding" /etc/ssh/sshd_config

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.2.5 Ensure SSH MaxAuthTries is set to 4 or less"
grep "^MaxAuthTries" /etc/ssh/sshd_config

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.2.6 Ensure SSH IgnoreRhosts is enabled"
grep "^IgnoreRhosts" /etc/ssh/sshd_config

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.2.7 Ensure SSH HostbasedAuthentication is disabled"
grep "^HostbasedAuthentication" /etc/ssh/sshd_config

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.2.8 Ensure SSH root login is disabled"
grep "^PermitRootLogin" /etc/ssh/sshd_config

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.2.9 Ensure SSH PermitEmptyPasswords is disabled"
grep "^PermitEmptyPasswords" /etc/ssh/sshd_config

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.2.10 Ensure SSH PermitUserEnvironment is disabled"
grep PermitUserEnvironment /etc/ssh/sshd_config

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.2.11 Ensure only approved MAC algorithms are used"
grep "MACs" /etc/ssh/sshd_config

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.2.12 Ensure SSH Idle Timeout Interval is configured"
grep "^ClientAliveInterval" /etc/ssh/sshd_config
grep "^ClientAliveCountMax" /etc/ssh/sshd_config

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.2.13 Ensure SSH LoginGraceTime is set to one minute or less"
grep "^LoginGraceTime" /etc/ssh/sshd_config

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.2.14 Ensure SSH access is limited"
grep "^AllowUsers" /etc/ssh/sshd_config
grep "^AllowGroups" /etc/ssh/sshd_config
grep "^DenyUsers" /etc/ssh/sshd_config
grep "^DenyGroups" /etc/ssh/sshd_config

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.2.15 Ensure SSH warning banner is configured"
grep "^Banner" /etc/ssh/sshd_config

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.3.1 Ensure password creation requirements are configured"
grep pam_pwquality.so /etc/pam.d/common-password
grep ^minlen /etc/security/pwquality.conf
grep ^dcredit /etc/security/pwquality.conf
grep ^lcredit /etc/security/pwquality.conf
grep ^ocredit /etc/security/pwquality.conf
grep ^ucredit /etc/security/pwquality.conf

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.3.2 Ensure lockout for failed password attempts is configured"
grep "pam_tally2" /etc/pam.d/common-auth

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.3.3 Ensure password reuse is limited"
egrep '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/common-password

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.3.4 Ensure password hashing algorithm is SHA-512"
egrep '^password\s+\S+\s+pam_unix.so' /etc/pam.d/common-password

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.4.1.1 Ensure password expiration is 365 days or less"
grep PASS_MAX_DAYS /etc/login.defs
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
chage --list $(whoami)

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.4.1.2 Ensure minimum days between password changes is 7 or more"
grep PASS_MIN_DAYS /etc/login.defs
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
chage --list $(whoami)

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.4.1.3 Ensure password expiration warning days is 7 or more"
grep PASS_WARN_AGE /etc/login.defs
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
chage --list $(whoami)

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.4.1.4 Ensure inactive password lock is 30 days or less"
useradd -D | grep INACTIVE
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
chage --list $(whoami)

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.4.1.5 Ensure all users last password change date is in the past"
cat /etc/shadow | cut -d: -f1
chage --list $(whoami)

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.4.2 Ensure system accounts are non-login"
egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false") {print}'

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.4.3 Ensure default group for the root account is GID 0"
grep "^root:" /etc/passwd | cut -f4 -d:

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.4.4 Ensure default user umask is 027 or more restrictive"
grep "umask" /etc/bash.bashrc
grep "umask" /etc/profile /etc/profile.d/*.sh

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.5 Ensure root login is restricted to system console"
cat /etc/securetty

echo "-------------------------------------------------------------------"
printf "\n"
echo "5.6 Ensure access to the su command is restricted"
grep pam_wheel.so /etc/pam.d/su
grep wheel /etc/group

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.1.2 Ensure permissions on /etc/passwd are configured"
stat /etc/passwd

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.1.3 Ensure permissions on /etc/shadow are configured"
stat /etc/shadow

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.1.4 Ensure permissions on /etc/group are configured"
stat /etc/group

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.1.5 Ensure permissions on /etc/gshadow are configured"
stat /etc/gshadow

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.1.6 Ensure permissions on /etc/passwd- are configured"
stat /etc/passwd-

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.1.7 Ensure permissions on /etc/shadow- are configured"
stat /etc/shadow-

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.1.8 Ensure permissions on /etc/group- are configured"
stat /etc/group-

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.1.9 Ensure permissions on /etc/gshadow- are configured"
stat /etc/gshadow-

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.1.10 Ensure no world writable files exist"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.1.11 Ensure no unowned files or directories exist"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.1.12 Ensure no ungrouped files or directories exist"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.1.13 Audit SUID executables"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.1.14 Audit SGID executables"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.1 Ensure password fields are not empty"
cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}'

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.2 Ensure no legacy "+" entries exist in /etc/passwd"
grep '^\+:' /etc/passwd

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.3 Ensure no legacy "+" entries exist in /etc/shadow"
grep '^\+:' /etc/shadow

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.4 Ensure no legacy "+" entries exist in /etc/group"
grep '^\+:' /etc/group

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.5 Ensure root is the only UID 0 account"
cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.6 Ensure root PATH Integrity"
if [ "`echo $PATH | grep :: `" != "" ]; then
 echo "Empty Directory in PATH (::)"
fi

if [ "`echo $PATH | grep :$`" != "" ]; then
 echo "Trailing : in PATH"
fi

p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
 if [ "$1" = "." ]; then
 echo "PATH contains ."
 shift
 continue
 fi
 if [ -d $1 ]; then
 dirperm=`ls -ldH $1 | cut -f1 -d" "`
 if [ `echo $dirperm | cut -c6 ` != "-" ]; then
 echo "Group Write permission set on directory $1"
 fi
 if [ `echo $dirperm | cut -c9 ` != "-" ]; then
 echo "Other Write permission set on directory $1"
 fi
 dirown=`ls -ldH $1 | awk '{print $3}'`
 if [ "$dirown" != "root" ] ; then
 echo $1 is not owned by root
 fi
 else
 echo $1 is not a directory
 fi
 shift
done

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.7 Ensure all users' home directories exist"
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
  if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
    echo "The home directory ($dir) of user $user does not exist." 
  fi 
done

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.8 Ensure users' home directories permissions are 750 or more restrictive"

for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
  dirperm=`ls -ld $dir | cut -f1 -d" "` 
  if [ `echo $dirperm | cut -c6 ` != "-" ]; then
    echo "Group Write permission set on directory $dir" 
  fi 
  if [ `echo $dirperm | cut -c8 ` != "-" ]; then 
    echo "Other Read permission set on directory $dir" 
  fi 
  if [ `echo $dirperm | cut -c9 ` != "-" ]; then
    echo "Other Write permission set on directory $dir" 
  fi
  if [ `echo $dirperm | cut -c10 ` != "-" ]; then
    echo "Other Execute permission set on directory $dir" 
  fi 
done

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.9 Ensure users own their home directories"
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
  if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" ]; then
  owner=$(stat -L -c "%U" "$dir") 
    if [ "$owner" != "$user" ]; then
    echo "The home directory ($dir) of user $user is owned by $owner." 
    fi 
  fi 
done

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.10 Ensure users' dot files are not group or world writable"
for dir in `cat /etc/passwd | egrep -v '(root|sync|halt|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
  for file in $dir/.[A-Za-z0-9]*; do
    if [ ! -h "$file" -a -f "$file" ]; then
      fileperm=`ls -ld $file | cut -f1 -d" "` 
      if [ `echo $fileperm | cut -c6 ` != "-" ]; then
       echo "Group Write permission set on file $file" 
      fi 
      if [ `echo $fileperm | cut -c9 ` != "-" ]; then
       echo "Other Write permission set on file $file" 
      fi 
    fi 
  done 
done

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.11 Ensure no users have .forward files"
for dir in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
  if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
    echo ".forward file $dir/.forward exists" 
  fi 
done

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.12 Ensure no users have .netrc files"
for dir in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
  if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
    echo ".netrc file $dir/.netrc exists" 
  fi 
done

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.13 Ensure users' .netrc Files are not group or world accessible"
for dir in `cat /etc/passwd | egrep -v '(root|sync|halt|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
  for file in $dir/.netrc; do
    if [ ! -h "$file" -a -f "$file" ]; then
      fileperm=`ls -ld $file | cut -f1 -d" "` 
      if [ `echo $fileperm | cut -c5 ` != "-" ]; then
        echo "Group Read set on $file" 
      fi 
      if [ `echo $fileperm | cut -c6 ` != "-" ]; then
        echo "Group Write set on $file" 
      fi 
      if [ `echo $fileperm | cut -c7 ` != "-" ]; then 
        echo "Group Execute set on $file" 
      fi 
      if [ `echo $fileperm | cut -c8 ` != "-" ]; then 
        echo "Other Read set on $file" 
      fi 
      if [ `echo $fileperm | cut -c9 ` != "-" ]; then 
        echo "Other Write set on $file" 
      fi 
      if [ `echo $fileperm | cut -c10 ` != "-" ]; then 
        echo "Other Execute set on $file" 
      fi 
    fi 
  done 
done

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.14 Ensure no users have .rhosts files"
for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
  for file in $dir/.rhosts; do
    if [ ! -h "$file" -a -f "$file" ]; then
      echo ".rhosts file in $dir" 
    fi 
  done 
done

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.15 Ensure all groups in /etc/passwd exist in /etc/group"
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
  grep -q -P "^.*?:[^:]*:$i:" /etc/group 
  if [ $? -ne 0 ]; then 
    echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group" 
  fi 
done

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.16 Ensure no duplicate UIDs exist"
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
  [ -z "${x}" ] && break 
  set - $x 
  if [ $1 -gt 1 ]; then 
    users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs` 
    echo "Duplicate UID ($2): ${users}" 
  fi 
done

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.17 Ensure no duplicate GIDs exist"
cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
  [ -z "${x}" ] && break 
  set - $x 
  if [ $1 -gt 1 ]; then
    groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs` 
    echo "Duplicate GID ($2): ${groups}" 
  fi 
done

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.18 Ensure no duplicate user names exist"
cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
  [ -z "${x}" ] && break 
  set - $x 
  if [ $1 -gt 1 ]; then 
    uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs` 
    echo "Duplicate User Name ($2): ${uids}" 
  fi 
done

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.19 Ensure no duplicate group names exist"
cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
  [ -z "${x}" ] && break 
  set - $x 
  if [ $1 -gt 1 ]; then
    gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs` 
    echo "Duplicate Group Name ($2): ${gids}" 
  fi 
done

echo "-------------------------------------------------------------------"
printf "\n"
echo "6.2.20 Ensure shadow group is empty"
grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group
awk -F: '($4 == "") { print }' /etc/passwd