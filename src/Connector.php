<?php

/**
 * Shadow Daemon -- Web Application Firewall
 *
 *   Copyright (C) 2014-2015 Hendrik Buchwald <hb@zecure.org>
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

require_once(realpath(dirname(__FILE__)) . '/autoload.php');

class Connector
{
    /* Tie all other classes together. */
    public static function start()
    {
        try {
            $config = new Config();

            $input = new Input(array(
                'clientIpKey' => $config->get('client_ip'),
                'callerKey'   => $config->get('caller'),
                'ignoreFile'  => $config->get('ignore')
            ));

            $output = new Output();

            /* Establish a tcp connection with a shadowd server and send the user input. */
            $connection = new Connection(array(
                'host'    => $config->get('host'),
                'port'    => $config->get('port'),
                'profile' => $config->get('profile', true),
                'key'     => $config->get('key', true),
                'ssl'     => $config->get('ssl')
            ));

            $threats = $connection->send($input);

            /* If observe mode is disabled eliminate the threats. */
            if (!$config->get('observe') && $threats) {
                if (!$input->defuseInput($threats)) {
                    if ($config->get('debug')) {
                        $output->log('shadowd: stopped request from client: ' . $input->getClientIp());
                    }

                    return $output->error();
                }
            }

            /* If debug is enabled drop a log message (for fail2ban f.i.). */
            if ($config->get('debug') && $threats) {
                $output->log('shadowd: removed threat from client: ' . $input->getClientIp());
            }
        } catch (\Exception $e) {
            /* Let PHP handle the log writing if debug is enabled. */
            if ($config->get('debug')) {
                $output->log('shadowd: ' . rtrim($e->getMessage()));
            }

            /* If protection mode is enabled we can't let this request pass. */
            if (!$config->get('observe')) {
                return $output->error();
            }
        }
    }
}

Connector::start();
