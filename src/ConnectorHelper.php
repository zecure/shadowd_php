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

class ConnectorHelper
{
    /* Tie all other classes together. */
    public static function start()
    {
        try {
            $output = new Output();
            $config = new Config();

            if (!$output || !$config) {
                throw new \Exception('initialization failed');
            }

            $input = new Input(array(
                'clientIpKey' => $config->get('client_ip'),
                'callerKey'   => $config->get('caller'),
                'ignoreFile'  => $config->get('ignore'),
                'rawData'     => $config->get('raw_data')
            ));

            /* Establish a connection with shadowd and send the user input. */
            $connection = new Connection(array(
                'host'    => $config->get('host'),
                'port'    => $config->get('port'),
                'profile' => $config->get('profile', true),
                'key'     => $config->get('key', true),
                'ssl'     => $config->get('ssl')
            ));

            $status = $connection->send($input);

            /* If observe mode is disabled eliminate the threats. */
            if (!$config->get('observe') && ($status['attack'] === true)) {
                if ($status['critical'] === true) {
                    if ($config->get('debug')) {
                        $output->log(
                            'shadowd: stopped critical attack from client: '
                            . $input->getClientIp()
                        );
                    }

                    return $output->error();
                }

                if (!$input->defuseInput($status['threats'])) {
                    if ($config->get('debug')) {
                        $output->log(
                            'shadowd: stopped attack from client: '
                            . $input->getClientIp()
                        );
                    }

                    return $output->error();
                }

                if ($config->get('debug')) {
                    $output->log(
                        'shadowd: removed threat from client: '
                        . $input->getClientIp()
                    );
                }
            }
        } catch (\Exception $e) {
            /* Stop if there is no config object. */
            if (!$config) {
                $output->log('shadowd: ' . rtrim($e->getMessage()));
                return $output->error();
            }

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
