# Backup to Your Server

**This script runs on the remote backup server. Prepare your OECP public IPs in the file `ip_list.txt`.**

**Warning: After the backup, all the transferred files will be deleted on the OECP nodes. You can change this option in the `backup_toRun.sh`.**

## Run the Script

Configure your `ip_list.txt` first, and fill in your public IPs to backup.


```bash
cd backup
bash ./backup_toRun.sh [path to store your docker] [file of ips] [date to backup]
```
> The default value for [date to backup] is **all the valid dates** on the OECP nodes.

Example
```bash
cd backup
bash ./backup_toRun.sh /myBackup ip_list.txt 20231001
```

## Backup on a Daily Schedule

We backup on a daily schedule with the help of [crontab](https://www.man7.org/linux/man-pages/man1/crontab.1.html).

We present an example of [crontab](https://www.man7.org/linux/man-pages/man1/crontab.1.html) configuration, and please change the paths of scripts and backup files in this example.
```bash
SHELL=/bin/bash
0 0 * * * /bin/bash /deployment/backup/backup_toRun.sh /deployment/backup/ip_list.txt $(date -d -1day +"%Y%m%d") >> /myBackup/logs
```
