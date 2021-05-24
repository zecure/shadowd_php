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

use shadowd\Exceptions\BadJsonException;
use shadowd\Exceptions\BadRequestException;
use shadowd\Exceptions\BadSignatureException;
use shadowd\Exceptions\CorruptedFileException;
use shadowd\Exceptions\FailedConnectionException;
use shadowd\Exceptions\InvalidProfileException;
use shadowd\Exceptions\MissingConfigEntryException;
use shadowd\Exceptions\MissingFileException;
use shadowd\Exceptions\ProcessingException;
use shadowd\Exceptions\UnknownPathException;

class Template
{
    /** @var string */
    const DEFAULT_KEY = 'default';

    /** @var array<string, string> */
    const TITLES = [
        self::DEFAULT_KEY                  => 'Request Blocked',
        BadJsonException::class            => 'Bad JSON',
        BadRequestException::class         => 'Bad Request',
        BadSignatureException::class       => 'Bad Signature',
        CorruptedFileException::class      => 'Corrupted File',
        FailedConnectionException::class   => 'Failed Connection',
        InvalidProfileException::class     => 'Invalid Profile',
        MissingConfigEntryException::class => 'Missing Config Entry',
        MissingFileException::class        => 'Missing File',
        ProcessingException::class         => 'Processing Error',
        UnknownPathException::class        => 'Unknown Path'
    ];

    /** @var array<string, string> */
    const FILES = [
        self::DEFAULT_KEY                  => 'blocked.html.php',
        BadJsonException::class            => 'bad_json.html.php',
        BadRequestException::class         => 'bad_request.html.php',
        BadSignatureException::class       => 'bad_signature.html.php',
        CorruptedFileException::class      => 'corrupted_file.html.php',
        FailedConnectionException::class   => 'failed_connection.html.php',
        InvalidProfileException::class     => 'invalid_profile.html.php',
        MissingConfigEntryException::class => 'missing_config_entry.html.php',
        MissingFileException::class        => 'missing_file.html.php',
        ProcessingException::class         => 'processing.html.php',
        UnknownPathException::class        => 'unknown_path.html.php'
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
     * Evaluate and print the base template.
     *
     * @return void
     */
    public function show()
    {
        require(SHADOWD_ROOT_DIR . '/tpl/base.html.php');
    }

    /**
     * Return the title that matches the exception.
     *
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
     * Return the file that matches the exception.
     *
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
     * Evaluate and print the description template that matches the exception.
     *
     * @return void
     */
    public function printDescription()
    {
        require(SHADOWD_ROOT_DIR . '/tpl/' . $this->getFile());
    }

    /**
     * Is debug mode enabled?
     *
     * @return bool
     */
    public function isDebug()
    {
        return $this->debug;
    }

    /**
     * Is the error message triggered by an exception?
     *
     * @return bool
     */
    public function isException()
    {
        return !is_null($this->exception);
    }

    /**
     * Return the exception class.
     *
     * @return false|string
     */
    public function getExceptionClass()
    {
        return get_class($this->exception);
    }

    /**
     * Return the exception message.
     *
     * @return string
     */
    public function getExceptionMessage()
    {
        return $this->exception->getMessage();
    }

    /**
     * Return the exception stack trace.
     *
     * @return string
     */
    public function getStackTrace()
    {
        return $this->exception->getTraceAsString();
    }
}
