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

class Output
{
    const LEVEL_DEBUG = 1;
    const LEVEL_CRITICAL = 2;

    /** @var bool */
    private $debug;

    /**
     * Output constructor.
     *
     * @param bool $debug
     */
    public function __construct($debug = true)
    {
        $this->debug = $debug;
    }

    /**
     * Debug settings come from the config but the output object has to exist in case parsing the config fails.
     * Thus the debug flag has to be set after initialization.
     *
     * @param bool $debug
     * @return void
     */
    public function setDebug($debug)
    {
        $this->debug = $debug;
    }

    /**
     * Show a fatal error and stop.
     *
     * @return void
     */
    public function error()
    {
        header($_SERVER['SERVER_PROTOCOL'] . ' 500 Internal Server Error', true, 500);
        exit('<h1>500 Internal Server Error</h1>');
    }

    /**
     * Write message to error log.
     *
     * @param string $message
     * @param int $level
     * @return void
     */
    public function log($message, $level = self::LEVEL_CRITICAL)
    {
        if ($this->debug !== true && $level === self::LEVEL_DEBUG) {
            return;
        }
        error_log(SHADOWD_LOG_PREFIX . $message);
    }
}
