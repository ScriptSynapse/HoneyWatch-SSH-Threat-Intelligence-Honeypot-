"""
fake_fs.py — Stateful virtual filesystem for the honeypot shell.
Each session gets its own FS instance with tracked cwd, created files, etc.
"""

import random
import time

# ── Canary / deception content ─────────────────────────────────────────────
CANARY_AWS = """[default]
aws_access_key_id     = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
"""

CANARY_SSH_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5RJr9vZPFkMFYmFpFn4kCOHFyCQBP5Cqf
ckbMkBqd2aRggVQKQ3a6U0E/aQXPgRSbZWFpjqILAHDRHaGpOmEWDQiCfVqoW8s
FAKE_KEY_DATA_DO_NOT_USE_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIf
-----END RSA PRIVATE KEY-----
"""

CANARY_DB_CONFIG = """<?php
// WordPress Database Configuration
define('DB_NAME',     'wordpress_prod');
define('DB_USER',     'wp_admin');
define('DB_PASSWORD', 'Sup3rS3cr3tPa$$w0rd!');
define('DB_HOST',     'db.internal.company.com');
define('DB_CHARSET',  'utf8mb4');
?>
"""

CANARY_BASH_HISTORY = """ls -la
cd /var/www/html
cat wp-config.php
mysql -u root -pMySQL_r00t_P@ss wordpress_prod
ssh deploy@prod-server-01.internal
aws s3 ls s3://company-backups-prod/
kubectl get secrets --all-namespaces
cat /root/.ssh/id_rsa
cat /root/.aws/credentials
sudo su -
"""

# ── Static file tree ──────────────────────────────────────────────────────────
STATIC_FILES: dict[str, str | None] = {
    "/etc/passwd":    "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
    "/etc/shadow":    "root:$6$rounds=5000$Kz0MaCWNxNfwQ0Tk$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:19700:0:99999:7:::\n",
    "/etc/hostname":  "ubuntu-server\n",
    "/etc/os-release":"NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\nVERSION_ID=\"22.04\"\n",
    "/etc/crontab":   "# /etc/crontab\nSHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n17 * * * * root    cd / && run-parts --report /etc/cron.hourly\n",
    "/proc/version":  "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-059) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\n",
    "/proc/cpuinfo":  "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\ncpu MHz\t\t: 2399.998\ncache size\t: 35840 KB\nbogomips\t: 4799.99\n\nprocessor\t: 1\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\ncpu MHz\t\t: 2399.998\n",
    "/proc/meminfo":  "MemTotal:        3987044 kB\nMemFree:         2145300 kB\nMemAvailable:    3201244 kB\nBuffers:          125812 kB\nCached:           987344 kB\n",
    "/root/.bash_history":        CANARY_BASH_HISTORY,
    "/root/.aws/credentials":     CANARY_AWS,
    "/root/.ssh/id_rsa":          CANARY_SSH_KEY,
    "/root/.ssh/authorized_keys": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2 deploy@jumphost\n",
    "/var/www/html/wp-config.php": CANARY_DB_CONFIG,
    "/root/.env":                 "DATABASE_URL=postgres://admin:P@ssw0rd123@localhost:5432/appdb\nSECRET_KEY=django-insecure-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    "/tmp":           None,  # directory
    "/var/log/auth.log": "Apr 10 08:22:01 ubuntu-server sshd[1204]: Failed password for root from 10.0.1.5 port 54322 ssh2\nApr 10 08:22:03 ubuntu-server sshd[1204]: Failed password for admin from 10.0.1.5 port 54323 ssh2\n",
}

DIR_LISTINGS: dict[str, str] = {
    "/":            "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var",
    "/root":        ".aws  .bash_history  .bashrc  .env  .profile  .ssh",
    "/root/.ssh":   "authorized_keys  id_rsa  id_rsa.pub  known_hosts",
    "/root/.aws":   "credentials  config",
    "/etc":         "apt  bash.bashrc  cron.d  crontab  environment  fstab  group  hostname  hosts  init.d  motd  os-release  passwd  profile  shadow  ssh  sudoers  systemd",
    "/tmp":         "",
    "/var/www/html":"index.php  wp-admin  wp-config.php  wp-content  wp-includes",
    "/home":        "ubuntu",
    "/home/ubuntu": ".bash_history  .bashrc  .profile  .ssh",
    "/proc":        "1  512  1204  cpuinfo  meminfo  version  net",
    "/usr":         "bin  include  lib  local  sbin  share",
    "/var":         "backups  cache  lib  log  mail  opt  run  spool  tmp  www",
    "/var/log":     "auth.log  dpkg.log  kern.log  syslog  wtmp",
}

# Fake process list (randomised slightly each call)
_PROCESSES = [
    ("root",      1,   "0.0", "0.1", "/sbin/init"),
    ("root",      2,   "0.0", "0.0", "[kthreadd]"),
    ("root",    512,   "0.0", "0.0", "/usr/sbin/sshd -D"),
    ("www-data", 834,  "0.0", "0.2", "/usr/sbin/apache2 -k start"),
    ("root",    835,   "0.0", "0.0", "nginx: master process /usr/sbin/nginx"),
    ("mysql",   901,   "0.1", "1.2", "/usr/sbin/mysqld"),
    ("root",   1100,   "0.0", "0.0", "cron"),
]


class FakeFS:
    """Per-session stateful filesystem."""

    def __init__(self):
        self.cwd       = "/root"
        self._created  = {}   # path → content (session-local files)
        self._start    = time.time()

    # ── path resolution ─────────────────────────────────────────────────────
    def _resolve(self, path: str) -> str:
        if not path.startswith("/"):
            path = self.cwd.rstrip("/") + "/" + path
        parts, out = path.split("/"), []
        for p in parts:
            if p in ("", "."):
                continue
            if p == "..":
                if out: out.pop()
            else:
                out.append(p)
        return "/" + "/".join(out)

    def _content(self, path: str):
        """Return file content string, or None if not found, or '' if dir."""
        p = self._resolve(path)
        if p in self._created:
            return self._created[p]
        if p in STATIC_FILES:
            return STATIC_FILES[p]   # None means directory
        # Check if it's a known directory
        if p in DIR_LISTINGS:
            return ""   # directory
        return False   # not found

    # ── command handlers ────────────────────────────────────────────────────
    def pwd(self, _args):
        return self.cwd

    def cd(self, args):
        target = args[0] if args else "/root"
        resolved = self._resolve(target)
        # Accept any plausible path
        if resolved in DIR_LISTINGS or resolved in self._created or resolved == "/":
            self.cwd = resolved
            return ""
        return f"bash: cd: {target}: No such file or directory"

    def ls(self, args):
        long = "-la" in args or "-l" in args or "-al" in args
        path = next((a for a in args if not a.startswith("-")), self.cwd)
        resolved = self._resolve(path)

        items = DIR_LISTINGS.get(resolved)
        if items is None:
            return f"ls: cannot access '{path}': No such file or directory"

        names = [x for x in items.split() if x] if items else []
        # Add any session-created files in this dir
        for p in self._created:
            parent = "/".join(p.split("/")[:-1]) or "/"
            if parent == resolved:
                names.append(p.split("/")[-1])

        if not long:
            return "  ".join(names) if names else ""

        lines = [f"total {16 + 4*len(names)}"]
        lines.append("drwxr-xr-x  2 root root 4096 Apr 10 14:22 .")
        lines.append("drwxr-xr-x 18 root root 4096 Jan 12 09:22 ..")
        for name in names:
            perm = "-rw-r--r--" if not name.startswith(".") else "-rw-------"
            sz   = random.randint(512, 8192)
            lines.append(f"{perm}  1 root root {sz:>6} Apr  9 11:{random.randint(10,59)} {name}")
        return "\n".join(lines)

    def cat(self, args):
        if not args:
            return ""
        path = args[0]
        content = self._content(path)
        if content is False:
            return f"cat: {path}: No such file or directory"
        if content is None:
            return f"cat: {path}: Is a directory"
        return content

    def echo(self, args, redirect=None):
        text = " ".join(a for a in args if not a.startswith(">"))
        text = text.strip("'\"")
        if redirect:
            self._created[self._resolve(redirect)] = text + "\n"
            return ""
        return text

    def mkdir(self, args):
        for a in args:
            if not a.startswith("-"):
                p = self._resolve(a)
                DIR_LISTINGS[p] = ""
        return ""

    def touch(self, args):
        for a in args:
            p = self._resolve(a)
            if p not in self._created and p not in STATIC_FILES:
                self._created[p] = ""
        return ""

    def rm(self, args):
        for a in args:
            if a.startswith("-"): continue
            p = self._resolve(a)
            self._created.pop(p, None)
        return ""

    def cp(self, args): return ""
    def mv(self, args): return ""
    def chmod(self, args): return ""
    def chown(self, args): return ""

    def ps(self, args):
        lines = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
        pid_extra = random.randint(1200, 1300)
        for user, pid, cpu, mem, cmd in _PROCESSES:
            lines.append(f"{user:<12} {pid:>5} {cpu:>4} {mem:>4} {random.randint(10000,200000):>6} {random.randint(1000,8000):>5} ?        Ss   Jan12   0:0{random.randint(1,9)} {cmd}")
        lines.append(f"root      {pid_extra:>5}  0.0  0.0  13524   1144 pts/0    R+   14:22   0:00 ps {''.join(args)}")
        return "\n".join(lines)

    def uptime(self, _):
        elapsed = time.time() - self._start
        h, m = divmod(int(elapsed/60), 60)
        return f" {time.strftime('%H:%M:%S')} up 42 days,  {h}:{m:02d},  1 user,  load average: {random.uniform(0.05,0.3):.2f}, {random.uniform(0.08,0.2):.2f}, {random.uniform(0.06,0.15):.2f}"

    def write_file(self, path: str, content: str):
        """Called when wget/curl saves a file."""
        self._created[self._resolve(path)] = content

    def file_exists(self, path: str) -> bool:
        p = self._resolve(path)
        return p in self._created or p in STATIC_FILES


# ── Static command responses ──────────────────────────────────────────────────
STATIC_RESPONSES = {
    "whoami":   "root",
    "id":       "uid=0(root) gid=0(root) groups=0(root)",
    "hostname": "ubuntu-server",
    "uname":    "Linux",
    "uname -a": "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux",
    "uname -r": "5.15.0-91-generic",
    "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n        ether 08:00:27:ab:cd:ef  txqueuelen 1000  (Ethernet)\n        RX packets 152438  bytes 189234567 (189.2 MB)\n        TX packets 94821   bytes 12345678 (12.3 MB)\n",
    "ip a":     "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0\n",
    "ip addr":  "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n2: eth0: mtu 1500\n    inet 10.0.2.15/24 scope global eth0\n",
    "netstat -tulpn": "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address   Foreign Address  State    PID/Program\ntcp        0      0 0.0.0.0:22      0.0.0.0:*        LISTEN   512/sshd\ntcp6       0      0 :::80           :::*             LISTEN   834/apache2\ntcp6       0      0 :::3306         :::*             LISTEN   901/mysqld\n",
    "ss -tulpn": "Netid  State   Recv-Q  Send-Q  Local Address:Port\ntcp    LISTEN  0       128     0.0.0.0:22\ntcp    LISTEN  0       511     *:80\ntcp    LISTEN  0       80      *:3306\n",
    "df -h":    "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   12G   36G  25% /\ntmpfs           2.0G     0  2.0G   0% /dev/shm\n/dev/sda2       100G   45G   50G  48% /var\n",
    "free -h":  "               total        used        free      shared  buff/cache   available\nMem:           3.8Gi       512Mi       2.8Gi        10Mi       512Mi       3.1Gi\nSwap:          2.0Gi          0B       2.0Gi\n",
    "free -m":  "               total        used        free      shared  buff/cache   available\nMem:            3987         512        2145          10         1329        3201\nSwap:           2047           0        2047\n",
    "env":      "SHELL=/bin/bash\nPWD=/root\nLOGNAME=root\nHOME=/root\nUSER=root\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nTERM=xterm-256color\nHISTFILE=/root/.bash_history\n",
    "history":  "    1  ls -la\n    2  cat /etc/passwd\n    3  cat /root/.aws/credentials\n    4  ssh deploy@prod-server-01.internal\n    5  mysql -u root -pMySQL_r00t_P@ss wordpress_prod\n    6  history\n",
    "w":        " 14:22:31 up 42 days,  3:17,  1 user,  load average: 0.08, 0.12, 0.09\nUSER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT\nroot     pts/0    192.168.1.100    14:20    0.00s  0.04s  0.00s w\n",
    "last":     "root     pts/0        192.168.1.100    Tue Apr  9 14:20   still logged in\nroot     pts/0        10.0.1.55        Mon Apr  8 09:12 - 17:33  (08:20)\nreboot   system boot  5.15.0-91-generic Mon Apr  1 08:00\nwtmp begins Mon Jan  1 00:00:01 2024\n",
    "crontab -l": "no crontab for root",
    "lscpu":    "Architecture:            x86_64\n  CPU op-mode(s):        32-bit, 64-bit\nCPU(s):                  2\nVendorID:                GenuineIntel\nModel name:              Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\nCPU MHz:                 2399.998\n",
    "lsblk":    "NAME   MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS\nsda      8:0    0    50G  0 disk\n├─sda1   8:1    0    49G  0 part /\n└─sda2   8:2    0   100G  0 part /var\n",
    "which python3": "/usr/bin/python3",
    "which python":  "/usr/bin/python3",
    "which wget":    "/usr/bin/wget",
    "which curl":    "/usr/bin/curl",
    "python3 --version": "Python 3.10.12",
    "python --version":  "Python 3.10.12",
}
