<?php

/**
 * Shadow Daemon -- Web Application Firewall
 *
 *   Copyright (C) 2014-2021 Hendrik Buchwald <hb@zecure.org>
 *
 * This file is part of Shadow Daemon. Shadow Daemon is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

define('SHADOWD_CONNECTOR_VERSION', '2.1.1-php');
define('SHADOWD_LOG_PREFIX', 'shadowd: ');
define('SHADOWD_ROOT_DIR', realpath(__DIR__ . '/..'));
define('SHADOWD_MISC_TESTS', SHADOWD_ROOT_DIR . '/misc/tests/');
define('SHADOWD_DEFAULT_CONFIG_FILE', '/etc/shadowd/connectors.ini');
define('SHADOWD_DEFAULT_CONFIG_SECTION', 'shadowd_php');
define('SHADOWD_STATUS_OK', '1');
define('SHADOWD_STATUS_BAD_REQUEST', '2');
define('SHADOWD_STATUS_BAD_SIGNATURE', '3');
define('SHADOWD_STATUS_BAD_JSON', '4');
define('SHADOWD_STATUS_ATTACK', '5');
define('SHADOWD_STATUS_CRITICAL_ATTACK', '6');
