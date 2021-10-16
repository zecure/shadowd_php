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
    /** @var array<string, string> */
    private $options;

    /**
     * Construct a new object.
     *
     * @param array<string, string> $options
     * @throws InvalidProfileException if profile id has incorrect format
     */
    public function __construct($options)
    {
        if (empty($options['profile'])) {
            throw new InvalidProfileException('Profile is empty or null');
        } elseif (!preg_match('/^[\d]*?$/', $options['profile'])) {
            throw new InvalidProfileException('Profile is not an integer');
        }

        if (empty($options['host'])) {
            $options['host'] = '127.0.0.1';
        }

        if (empty($options['port'])) {
            $options['port'] = '9115';
        }

        if (empty($options['ssl'])) {
            $options['ssl'] = false;
        }

        if (empty($options['timeout'])) {
            $options['timeout'] = 5;
        }

        $this->options = $options;
    }

    /**
     * Send user input to background server.
     *
     * @param Input $input
     * @return array<string, mixed>
     * @throws FailedConnectionException
     * @throws BadRequestException
     * @throws BadSignatureException
     * @throws BadJsonException
     * @throws ProcessingException
     */
    public function send(Input $input)
    {
        $fp = $this->establishConnection();
        fwrite($fp, $this->getInputData($input));

        $outputData = '';
        while (!feof($fp)) {
            $outputData .= fgets($fp, 1024);
        }

        fclose($fp);
        return $this->parseOutputData($outputData);
    }

    /**
     * Establish a connection to the background server.
     *
     * @return resource
     * @throws FailedConnectionException if connection can not be established
     */
    private function establishConnection()
    {
        $context = stream_context_create();

        if ($this->options['ssl']) {
            stream_context_set_option($context, 'ssl', 'verify_host', true);
            stream_context_set_option($context, 'ssl', 'cafile', $this->options['ssl']);
            stream_context_set_option($context, 'ssl', 'verify_peer', true);
            $prefix = 'ssl';
        } else {
            $prefix = 'tcp';
        }

        $fp = @stream_socket_client(
            $prefix . '://' . $this->options['host'] . ':' . $this->options['port'],
            $errorCode,
            $errorMessage,
            (int)$this->options['timeout'],
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ($fp) {
            return $fp;
        }

        if ($errorCode) {
            throw new FailedConnectionException($errorMessage);
        }
        throw new FailedConnectionException();
    }

    /**
     * Prepare the message to the background server.
     *
     * @param Input $input
     * @return string
     */
    private function getInputData(Input $input)
    {
        $data = [
            'version'   => SHADOWD_CONNECTOR_VERSION,
            'client_ip' => $input->getClientIp(),
            'caller'    => $input->getCaller(),
            'resource'  => $input->getResource(),
            'input'     => $input->getInput(),
            'hashes'    => $input->getHashes()
        ];

        $json = json_encode($data);
        $hmac = $this->sign($this->options['key'], $json);

        return $this->options['profile'] . "\n" . $hmac . "\n" . $json . "\n";
    }

    /**
     * Parse output from the background server.
     *
     * @param string $outputData
     * @return array<string, mixed>
     * @throws BadRequestException
     * @throws BadSignatureException
     * @throws BadJsonException
     * @throws ProcessingException
     */
    private function parseOutputData($outputData)
    {
        $json = json_decode($outputData, true);

        if (empty($json)) {
            throw new ProcessingException();
        }

        switch ($json['status']) {
            case SHADOWD_STATUS_OK:
                return [
                    'attack' => false
                ];
            case SHADOWD_STATUS_BAD_REQUEST:
                throw new BadRequestException(isset($json['message']) ? $json['message'] : null);
            case SHADOWD_STATUS_BAD_SIGNATURE:
                throw new BadSignatureException();
            case SHADOWD_STATUS_BAD_JSON:
                throw new BadJsonException();
            case SHADOWD_STATUS_ATTACK:
                return [
                    'attack'   => true,
                    'critical' => false,
                    'threats'  => $json['threats']
                ];
            case SHADOWD_STATUS_CRITICAL_ATTACK:
                return [
                    'attack'   => true,
                    'critical' => true
                ];
            default:
                throw new ProcessingException();
        }
    }

    /**
     * Sign the json encoded message as password verification.
     *
     * @param string $key
     * @param string $json
     * @return string
     */
    private function sign($key, $json)
    {
        return hash_hmac('sha256', $json, $key);
    }
}
