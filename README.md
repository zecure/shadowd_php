**Shadow Daemon** is a modular system that **detects and prevents known and unknown attacks against web applications**. It requires no source code changes, is very flexible and can be used for many different tasks, f.i. as *high-interaction honeypot* by security professionals to gather information about vulnerabilities, as *intrusion prevention system* by web administrators to protect internet sites or as *intrusion detection system* by network administrators to detect intruders.

# Documentation
This README is only a short guide to get you started quickly. For the complete user documentation please go to [https://shadowd.zecure.org/docs/current/](https://shadowd.zecure.org/docs/current/).

# Demo
A demonstration of the Shadow Daemon web interface can be found at [https://demo.shadowd.zecure.org/](https://demo.shadowd.zecure.org/).

# Installation
The PHP setting [auto_prepend_file](http://de1.php.net/manual/en/ini.core.php#ini.auto-prepend-file) should be used to load *shadowd_php_connector.php* automatically when a PHP script is executed. This can be done either globally by editing the *php.ini* or locally by editing the web server configuration and overwriting the value for single vhosts only.

You also have to create a configuration file. You can copy *misc/examples/connectors.ini* to */etc/shadowd/connectors.ini* or change the path in the header of *shadowd_php_connector.php*.
