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
    /** @var int */
    const LEVEL_DEBUG = 1;

    /** @var int */
    const LEVEL_CRITICAL = 2;

    /** @var bool */
    private $showDebug;

    /** @var bool */
    private $showTemplates;

    /**
     * Output constructor.
     *
     * Settings come from the config but the output object has to exist in case parsing the config fails.
     * Thus the settings have to be set after initialization through setters.
     *
     * @param bool $showDebug
     * @param bool $showTemplates
     */
    public function __construct($showDebug = false, $showTemplates = true)
    {
        $this->showDebug = $showDebug;
        $this->showTemplates = $showTemplates;
    }

    /**
     * Set debug flag to show additional information and store logs.
     *
     * @param bool $showDebug
     * @return void
     */
    public function setShowDebug($showDebug)
    {
        $this->showDebug = $showDebug;
    }

    /**
     * Set template flag to show a template instead of generic error in case of a problem.
     *
     * @param bool $showTemplates
     * @return void
     */
    public function setShowTemplates($showTemplates)
    {
        $this->showTemplates = $showTemplates;
    }

    /**
     * Show a fatal error and stop.
     *
     * @param \Exception|null $exception
     * @return void
     */
    public function error($exception = null)
    {
        header($_SERVER['SERVER_PROTOCOL'] . ' 500 Internal Server Error', true, 500);

        if ($this->showTemplates) {
            $template = new Template($exception, $this->showDebug);
            $template->show();
        } else {
            echo '<h1>500 Internal Server Error</h1>';
        }

        exit(1);
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
        if ($this->showDebug !== true && $level === self::LEVEL_DEBUG) {
            return;
        }
        error_log(SHADOWD_LOG_PREFIX . $message);
    }
}
