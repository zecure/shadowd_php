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

namespace shadowd;

class Config
{
    /** @var string */
    private $file;

    /** @var string */
    private $section;

    /** @var array */
    private $data;

    /* Construct a new object and parse ini file. */
    public function __construct()
    {
        if (getenv('SHADOWD_CONNECTOR_CONFIG')) {
            $this->file = getenv('SHADOWD_CONNECTOR_CONFIG');
        } else {
            $this->file = '/etc/shadowd/connectors.ini';
        }

        $this->data = parse_ini_file($this->file, true);

        if (!$this->data) {
            throw new \Exception('config error');
        }

        if (getenv('SHADOWD_CONNECTOR_CONFIG_SECTION')) {
            $this->section = getenv('SHADOWD_CONNECTOR_CONFIG_SECTION');
        } else {
            $this->section = 'shadowd_php';
        }
    }

    /* Get the value or stop if a required value is missing. */
    public function get($key, $required = false)
    {
        if (!isset($this->data[$this->section][$key])) {
            if ($required) {
                throw new \Exception($key . ' in config missing');
            } else {
                return false;
            }
        } else {
            return $this->data[$this->section][$key];
        }
    }
}
