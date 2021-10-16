![Logo](http://shadowd.zecure.org/img/logo_small.png)

[![Build Status](https://app.travis-ci.com/zecure/shadowd_php.svg?branch=master)](https://app.travis-ci.com/zecure/shadowd_php)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=zecure_shadowd_php&metric=alert_status)](https://sonarcloud.io/dashboard?id=zecure_shadowd_php)

**Shadow Daemon** is a collection of tools to **detect**, **record** and **prevent** **attacks** on *web applications*.
Technically speaking, Shadow Daemon is a **web application firewall** that intercepts requests and filters out malicious parameters.
It is a modular system that separates web application, analysis and interface to increase security, flexibility and expandability.

This component can be used to connect PHP applications with the [background server](https://github.com/zecure/shadowd).

# Documentation
For the full documentation please refer to [shadowd.zecure.org](https://shadowd.zecure.org/).

# Installation
1. If you are not using a prepackaged release you first have to run `composer install`.
2. You have to create a configuration file at `/etc/shadowd/connectors.ini`. You can find an example configuration at `misc/examples/connectors.ini`. It is annotated and should be self-explanatory.
3. The PHP setting [auto_prepend_file](http://php.net/manual/en/ini.core.php#ini.auto-prepend-file) should be used to load `shadowd.php` automatically.
   It is highly recommended to set `auto_prepend_file` using the capabilities of your web server instead of relying on `php.ini`.
