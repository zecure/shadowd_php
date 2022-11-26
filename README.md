![Logo](https://shadowd.zecure.org/img/logo_small.png)

[![Build Status](https://github.com/zecure/shadowd_php/actions/workflows/analyze.yml/badge.svg)](https://github.com/zecure/shadowd_php/actions/workflows/analyze.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=zecure_shadowd_php&metric=alert_status)](https://sonarcloud.io/dashboard?id=zecure_shadowd_php)

**Shadow Daemon** is a *web application firewall* that intercepts requests at the application level.
This repository contains a component of Shadow Daemon to connect PHP applications with the [shadowd](https://github.com/zecure/shadowd) server.

# Documentation
For the full documentation please refer to [shadowd.zecure.org](https://shadowd.zecure.org/).

# Installation
1. If you are not using a prepackaged release you first have to run `composer install`.
2. You have to create a configuration file at `/etc/shadowd/connectors.ini`. You can find an example configuration at `misc/examples/connectors.ini`. It is annotated and should be self-explanatory.
3. The PHP setting [auto_prepend_file](http://php.net/manual/en/ini.core.php#ini.auto-prepend-file) should be used to load `shadowd.php` automatically.
   It is highly recommended to set `auto_prepend_file` using the capabilities of your web server instead of relying on `php.ini`.
