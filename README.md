[![Build Status](https://travis-ci.org/zecure/shadowd_php.svg)](https://travis-ci.org/zecure/shadowd_php)
![Logo](http://shadowd.zecure.org/img/logo_small.png)

**Shadow Daemon** is a collection of tools to **detect**, **record** and **prevent** **attacks** on *web applications*. Technically speaking, Shadow Daemon is a **web application firewall** that intercepts requests and filters out malicious parameters. It is a modular system that separates web application, analysis and interface to increase security, flexibility and expandability.

This component can be used to connect PHP applications with the [background server](https://github.com/zecure/shadowd).

# Documentation
For the full documentation please refer to [shadowd.zecure.org](https://shadowd.zecure.org/).

# Installation
The PHP setting [auto_prepend_file](http://de1.php.net/manual/en/ini.core.php#ini.auto-prepend-file) should be used to load *Connector.php* automatically when a PHP script is executed. This can be done either globally by editing the *php.ini* or locally by editing the web server configuration and overwriting the setting for single vhosts or directories only.

You also have to create a configuration file. You can copy *misc/examples/connectors.ini* to */etc/shadowd/connectors.ini*. The example configuration is annotated and should be self-explanatory.
