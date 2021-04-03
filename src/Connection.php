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
use shadowd\Exceptions\FailedConnectionException;
use shadowd\Exceptions\InvalidProfileException;
use shadowd\Exceptions\ProcessingException;

class Connection
{
    /** @var array */
    private $options;

    /**
     * Construct a new object.
     *
     * @param array $options
     * @throws InvalidProfileException if profile id has incorrect format
     */
    public function __construct($options = array())
    {
        if (empty($options['profile'])) {
            throw new InvalidProfileException('empty');
        } else if (!preg_match('/^[\d]*?$/', $options['profile'])) {
            throw new InvalidProfileException('not integer');
        } else if ((int)$options['profile'] === 0) {
            throw new InvalidProfileException('zero');
        }

        if (!isset($options['host']) || (!$options['host'])) {
            $options['host'] = '127.0.0.1';
        }

        if (!isset($options['port']) || (!$options['port'])) {
            $options['port'] = '9115';
        }

        if (!isset($options['ssl'])) {
            $options['ssl'] = false;
        }

        $this->options = $options;
    }

    /**
     * Send user input to background server.
     *
     * @param Input $input
     * @return array
     * @throws FailedConnectionException if connection can not be established
     */
    public function send(Input $input)
    {
        // Prepare data.
        $data = array(
            'version'   => SHADOWD_CONNECTOR_VERSION,
            'client_ip' => $input->getClientIp(),
            'caller'    => $input->getCaller(),
            'resource'  => $input->getResource(),
            'input'     => $input->getInput(),
            'hashes'    => $input->getHashes()
        );

        $json = json_encode($data);
        $hmac_json = $this->sign($this->options['key'], $json);

        // Establish connection.
        $context = stream_context_create();

        if ($this->options['ssl']) {
            stream_context_set_option($context, 'ssl', 'verify_host', true);
            stream_context_set_option($context, 'ssl', 'cafile', $this->options['ssl']);
            stream_context_set_option($context, 'ssl', 'verify_peer', true);
        }

        $resource = ($this->options['ssl'] ? 'ssl' : 'tcp') . '://' . $this->options['host'] . ':' . $this->options['port'];
        $fp = @stream_socket_client($resource, $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $context);

        if (!$fp) {
            if ($errno) {
                throw new FailedConnectionException($errstr);
            } else {
                throw new FailedConnectionException();
            }
        }

        // Send data.
        fwrite($fp, $this->options['profile'] . "\n" . $hmac_json . "\n" . $json . "\n");

        // Get output.
        $output = '';

        while (!feof($fp)) {
            $output .= fgets($fp, 1024);
        }

        fclose($fp);

        return $this->parseOutput($output);
    }

    /**
     * Parse output from the background server.
     *
     * @param string $output
     * @return array
     * @throws BadRequestException
     * @throws BadSignatureException
     * @throws BadJsonException
     * @throws ProcessingException
     */
    private function parseOutput($output)
    {
        $json = json_decode($output, true);

        switch ($json['status']) {
            case SHADOWD_STATUS_OK:
                return array(
                    'attack' => false
                );
            case SHADOWD_STATUS_BAD_REQUEST:
                throw new BadRequestException();
            case SHADOWD_STATUS_BAD_SIGNATURE:
                throw new BadSignatureException();
            case SHADOWD_STATUS_BAD_JSON:
                throw new BadJsonException();
            case SHADOWD_STATUS_ATTACK:
                return array(
                    'attack'   => true,
                    'critical' => false,
                    'threats'  => $json['threats']
                );
            case SHADOWD_STATUS_CRITICAL_ATTACK:
                return array(
                    'attack'   => true,
                    'critical' => true
                );
            default:
                throw new ProcessingException();
        }
    }

    /* Sign the json encoded message as password verification. */
    private function sign($key, $json)
    {
        return hash_hmac('sha256', $json, $key);
    }
}
