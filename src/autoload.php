<?php

/**
 * Shadow Daemon -- Web Application Firewall
 *
 *   Copyright (C) 2014-2018 Hendrik Buchwald <hb@zecure.org>
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

spl_autoload_register(
    function($class) {
        static $classes = null;

        if ($classes === null) {
            $classes = array(
                'shadowd\\connectorhelper' => '/ConnectorHelper.php',
                'shadowd\\connection'      => '/Connection.php',
                'shadowd\\config'          => '/Config.php',
                'shadowd\\input'           => '/Input.php',
                'shadowd\\output'          => '/Output.php',
                'services_json'            => '/libs/json.php'
            );
        }

        $cn = strtolower($class);

        if (isset($classes[$cn])) {
            require __DIR__ . $classes[$cn];
        } elseif (function_exists('__autoload')) {
            __autoload($class);
        }
    }
);

// JSON replacement for old PHP versions.
if (!function_exists('json_decode')) {
    function json_decode($var) {
        $JSON = new \Services_JSON;
        return $JSON->decode($var);
    }
}

if (!function_exists('json_encode')) {
    function json_encode($var) {
        $JSON = new \Services_JSON;
        return $JSON->encode($var);
    }
}

// Fallback for tests.
if (!defined('SHADOWD_CONNECTOR_VERSION')) {
    define('SHADOWD_CONNECTOR_VERSION', '0.0.0');
}
