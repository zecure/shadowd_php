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

class Connection
{
    /** @var array */
    private $options;

    /**
     * Construct a new object.
     *
     * @param array $options
     * @throws \Exception if options are wrong
     */
    public function __construct($options = array())
    {
        if (!preg_match('/^[0-9]*$/', $options['profile'])) {
            throw new \Exception('profile id not integer');
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
     * @throws \Exception if connection can not be established or data invalid
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
            $result = stream_context_set_option($context, 'ssl', 'verify_host', true);
            $result = stream_context_set_option($context, 'ssl', 'cafile', $this->options['ssl']);
            $result = stream_context_set_option($context, 'ssl', 'verify_peer', true);
        }

        $resource = ($this->options['ssl'] ?
                'ssl' : 'tcp') . '://' . $this->options['host'] . ':' . $this->options['port'];
        $fp = @stream_socket_client($resource, $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $context);

        if (!$fp) {
            if ($errno) {
                throw new \Exception('network error: ' . strtolower($errstr));
            } else {
                throw new \Exception('unknown network error');
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
     * @throws \Exception if something is wrong with the output
     */
    private function parseOutput($output)
    {
        $json = json_decode($output, true);

        switch ($json['status']) {
            case '1': // STATUS_OK
                return array(
                    'attack' => false
                );
            case '2': // STATUS_BAD_REQUEST
                throw new \Exception('bad request');
            case '3': // STATUS_BAD_SIGNATURE
                throw new \Exception('bad signature');
            case '4': // STATUS_BAD_JSON
                throw new \Exception('bad json');
            case '5': // STATUS_ATTACK
                return array(
                    'attack'   => true,
                    'critical' => false,
                    'threats'  => $json['threats']
                );
            case '6': // STATUS_CRITICAL_ATTACK
                return array(
                    'attack'   => true,
                    'critical' => true
                );
            default:
                throw new \Exception('processing error');
        }
    }

    /* Sign the json encoded message as password verification. */
    private function sign($key, $json)
    {
        return hash_hmac('sha256', $json, $key);
    }
}
