login
=====

login provides some required infrastructure for logins and for
changing effective user or group IDs, including:
 * login, the program that invokes a user shell on a virtual terminal;
 * nologin, a dummy shell for disabled user accounts;
 * su, a basic tool for executing commands as root or another user.

Reimplement this command in Rust:
* /bin/login
* /usr/bin/faillog
* /usr/bin/lastlog
* /usr/bin/newgrp
* /usr/sbin/nologin
* /usr/bin/sg

Upstream:
https://github.com/shadow-maint/shadow
