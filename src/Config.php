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

namespace shadowd;

use shadowd\Exceptions\CorruptedFileException;
use shadowd\Exceptions\MissingConfigEntryException;
use shadowd\Exceptions\MissingFileException;

class Config
{
    /** @var string */
    private $section;

    /** @var array */
    private $data;

    /**
     * Construct a new object and parse ini file.
     *
     * @param string $file
     * @throws CorruptedFileException if config file is invalid
     * @throws MissingFileException if config file does not exist
     */
    public function __construct($file)
    {
        if (!file_exists($file)) {
            throw new MissingFileException($file);
        }

        $this->data = parse_ini_file($file, true);

        if (!$this->data) {
            throw new CorruptedFileException($file);
        }

        if (getenv('SHADOWD_CONNECTOR_CONFIG_SECTION')) {
            $this->section = getenv('SHADOWD_CONNECTOR_CONFIG_SECTION');
        } else {
            $this->section = 'shadowd_php';
        }
    }

    /**
     * Get the value or stop if a required value is missing.
     *
     * @param string $key
     * @param bool $required
     * @return string|bool
     * @throws MissingConfigEntryException if value required but missing
     */
    public function get($key, $required = false)
    {
        if (!isset($this->data[$this->section][$key])) {
            if ($required) {
                throw new MissingConfigEntryException($key);
            } else {
                return false;
            }
        } else {
            return $this->data[$this->section][$key];
        }
    }
}
