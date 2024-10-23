# Deployment

Bash scripts to automatically deploy *OneThing Cloud*/*Tiptime* OECP nodes in the Docker. 

## Get Started

```bash
cd ./collect_traffic
bash ./run.sh [wxedge/tiptime] [path to store your docker]
```
> `wxedge` stands for OneThing Cloud.

Example
```bash
cd ./collect_traffic
bash ./run.sh wxedge /EC
```

### Files Structure
```
.
├── README.md
├── backup
│   ├── README.md
│   ├── backup_toRun.sh
│   └── ip_list.txt
└── collect_traffic
    ├── config_miniupnp.sh
    ├── get_stat.sh
    ├── get_url_fromlog.sh
    ├── miniupnpd.zip
    ├── record_log.sh
    ├── requirements.sh
    ├── run.sh
    └── tcpdump.sh
```

- backup_toRun.sh: The backup script on the remote server.
- ip_list.txt The public IPs list to backup on the remote server.
- config_miniupnp.sh: Script to configure miniupnpd for OneThing Cloud.
- get_url_fromlog.sh: Extract the urls from the OneThing Cloud `server*.log` files.
- record_log.sh: Save the all the plain text log files of OneThing Cloud.
- requirements.sh: Configure a new OECP node and run the OECP docker.
- run.sh: The main script to run.
- tcpdump.sh: Run the `tcpdump` command.

## Options

### Tcpdump

To capture the traffic of a running OECP node, and skip the configuration steps, you can simply run the `tcpdump.sh`.

```bash
cd ./collect_traffic
bash ./tcpdump.sh [wxedge/tiptime] [path to store your docker]
```

Example
```bash
cd ./collect_traffic
bash ./tcpdump.sh wxedge /EC
```

### Backup

In case traffic files are too large to store in an OECP node for multiple days, you can prepare a remote backup server and find the scripts to automatically backup in [./backup](./backup/README.md).


### Run on a Daily Schedule

We capture the traffic files on a daily schedule with the help of [crontab](https://www.man7.org/linux/man-pages/man1/crontab.1.html).

We present an example of [crontab](https://www.man7.org/linux/man-pages/man1/crontab.1.html) configuration, and please change the paths of scripts and backup files in this example.

#### OneThing Cloud

```bash
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 0 * * * /bin/bash /root/deployment/collect_traffic/run.sh wxedge > /dev/null 2>&1 
```

#### Tiptime

```bash
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 0 * * * /bin/bash /root/deployment/collect_traffic/run.sh tiptime > /dev/null 2>&1 
```

### Miniupnpd

To meet the strict resource demand of some OECP tasks of OneThing Cloud, we prepared the script to automatically configure miniupnpd. It's disabled in default.

To turn it on, please remove the relevant comment section of `requirements.sh`.
