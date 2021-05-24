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

class Connector
{
    /**
     * Tie all other classes together.
     *
     * @return void
     */
    public function start()
    {
        try {
            $output = new Output();

            [$configFile, $configSection] = $this->getConfigOptions();
            $config = new Config($configFile, $configSection);
            $output->setShowDebug((bool)$config->get('debug'));
            $output->setShowTemplates((bool)$config->get('templates', false, true));

            $input = new Input([
                'clientIpKey' => $config->get('client_ip'),
                'callerKey'   => $config->get('caller'),
                'ignoreFile'  => $config->get('ignore'),
                'rawData'     => $config->get('raw_data')
            ]);

            $connection = new Connection([
                'host'    => $config->get('host'),
                'port'    => $config->get('port'),
                'profile' => $config->get('profile', true),
                'key'     => $config->get('key', true),
                'ssl'     => $config->get('ssl'),
                'timeout' => $config->get('timeout')
            ]);
            $status = $connection->send($input);

            if ($status['attack'] === false || $config->get('observe')) {
                return;
            }

            if ($status['critical'] === true) {
                $output->log(
                    'stopped critical attack from client: ' . $input->getClientIp(),
                    Output::LEVEL_DEBUG
                );
                $output->error();
            }

            $output->log(
                'removed threat from client: ' . $input->getClientIp(),
                Output::LEVEL_DEBUG
            );

            if (!$input->defuseInput($status['threats'])) {
                $output->error();
            }
        } catch (\Exception $exception) {
            $output->log(
                get_class($exception) . ': ' . $exception->getTraceAsString(),
                Output::LEVEL_DEBUG
            );

            // If there is no config or if protection mode is enabled we can't let this request pass.
            if (!isset($config) || !$config->get('observe')) {
                $output->error($exception);
            }
        }
    }

    /**
     * @return array<string>
     */
    private function getConfigOptions()
    {
        if (getenv('SHADOWD_CONNECTOR_CONFIG')) {
            $file = getenv('SHADOWD_CONNECTOR_CONFIG');
        } else {
            $file = SHADOWD_DEFAULT_CONFIG_FILE;
        }

        if (getenv('SHADOWD_CONNECTOR_CONFIG_SECTION')) {
            $section = getenv('SHADOWD_CONNECTOR_CONFIG_SECTION');
        } else {
            $section = SHADOWD_DEFAULT_CONFIG_SECTION;
        }

        return [$file, $section];
    }
}
