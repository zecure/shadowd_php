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

use shadowd\Exceptions\MissingFileException;

class Template
{
    /** @var string */
    const DEFAULT_KEY = 'default';

    /** @var array<string, string> */
    const TITLES = [
        self::DEFAULT_KEY           => 'Request Blocked',
        MissingFileException::class => 'Missing File'
    ];

    /** @var array<string, string> */
    const FILES = [
        self::DEFAULT_KEY           => 'blocked.html.php',
        MissingFileException::class => 'missing_file.html.php'
    ];

    /** @var \Exception|null */
    private $exception;

    /** @var bool */
    private $debug;

    /**
     * Template constructor.
     *
     * @param \Exception|null $exception
     * @param bool $debug
     */
    public function __construct($exception, $debug)
    {
        $this->exception = $exception;
        $this->debug = $debug;
    }

    /**
     * @return void
     */
    public function show()
    {
        require(SHADOWD_ROOT_DIR . '/tpl/base.html.php');
    }

    /**
     * @return string
     */
    public function getTitle()
    {
        if ($this->exception) {
            $class = get_class($this->exception);
            if (isset(self::TITLES[$class])) {
                return self::TITLES[$class];
            }
        }

        return self::TITLES[self::DEFAULT_KEY];
    }

    /**
     * @return string
     */
    public function getFile()
    {
        if ($this->exception) {
            $class = get_class($this->exception);
            if (isset(self::FILES[$class])) {
                return self::FILES[$class];
            }
        }

        return self::FILES[self::DEFAULT_KEY];
    }

    /**
     * @return void
     */
    public function printDescription()
    {
        require(SHADOWD_ROOT_DIR . '/tpl/' . $this->getFile());
    }

    /**
     * @return bool
     */
    public function isDebug()
    {
        return $this->debug;
    }

    /**
     * @return bool
     */
    public function isException()
    {
        return !is_null($this->exception);
    }

    /**
     * @return false|string
     */
    public function getExceptionClass()
    {
        return get_class($this->exception);
    }

    /**
     * @return string
     */
    public function getExceptionMessage()
    {
        return $this->exception->getMessage();
    }

    /**
     * @return string
     */
    public function getStackTrace()
    {
        return $this->exception->getTraceAsString();
    }
}
