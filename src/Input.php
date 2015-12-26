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

class Input
{
    /* Construct a new object. */
    public function __construct($options = array())
    {
        if (!isset($options['clientIpKey']) || !$options['clientIpKey']) {
            $options['clientIpKey'] = 'REMOTE_ADDR';
        }

        if (!isset($options['callerKey']) || !$options['callerKey']) {
            $options['callerKey'] = 'SCRIPT_FILENAME';
        }

        if (!isset($options['ignoreFile'])) {
            $options['ignoreFile'] = false;
        }

        $this->options = $options;
    }

    /* Getter for the client ip. */
    public function getClientIp()
    {
        return $_SERVER[$this->options['clientIpKey']];
    }

    /* Getter for the caller. */
    public function getCaller()
    {
        return $_SERVER[$this->options['callerKey']];
    }

    /* Getter for the resource. */
    public function getResource()
    {
        return $_SERVER['REQUEST_URI'];
    }

    /* Aggregate and get the user input. */
    public function getInput()
    {
        /* Create copies of input sources. */
        $input = array(
            'GET' => $_GET,
            'POST' => $_POST,
            'COOKIE' => $_COOKIE
        );

        /* Stripslash get/post/cookie input if magic_quotes_gpc is activated to get the real values. */
        if (function_exists('get_magic_quotes_gpc') && get_magic_quotes_gpc()) {
            $this->stripslashes($input);
        }

        /* Add names of uploaded files. */
        foreach ($_FILES as $key => $value) {
            $input['FILES'][$key] = $value['name'];
        }

        /* Add headers that contain user input. */
        foreach ($_SERVER as $key => $value) {
            if (strpos($key, 'HTTP_') === 0) {
                $input['SERVER'][$key] = $value;
            }
        }

        $input['SERVER']['PHP_SELF'] = $_SERVER['PHP_SELF'];

        /* Add raw post data if not empty. */
        $rawData = file_get_contents('php://input');

        if ($rawData) {
            $input['DATA']['raw'] = $rawData;
        }

        /* Convert the complete input structure to a flat unique array. */
        $flattenedInput = $this->flatten($input);

        /* Remove user input that should be ignored. */
        if ($this->options['ignoreFile']) {
            $flattenedInput = $this->removeIgnored($flattenedInput);
        }

        return $flattenedInput;
    }

    /* Convert nested arrays to a flat array. */
    public function flatten($input, $key = false, $path = false)
    {
        $output = array();

        /* The next part generates an unique identifier for every input element. */
        $newPath = false;

        if ($key !== false) {
            $key = $this->escapeKey($key);

            /* If there is already a path just append the key, otherwise the key is the complete new path. */
            if ($path !== false) {
                $newPath = $path . '|' . $key;
            } else {
                $newPath = $key;
            }
        }

        /* Now we have to process the input. It can either be an array or a string, but we check both to be sure. */
        if (is_array($input)) {
            /* The current input is an array, so we have to call the convert function again. */
            foreach ($input as $inputKey => $inputValue) {
                $output = array_replace($output, $this->flatten($inputValue, $inputKey, $newPath));
            }
        } elseif (($newPath !== false) && (is_string($input) || is_numeric($input))) {
            // FIXME: the encoding does not work properly all the time yet.
            if (!mb_check_encoding($input, 'UTF-8')) {
                $input = mb_convert_encoding($input, 'UTF-8');
            }

            return array($newPath => $input);
        }

        return $output;
    }

    /* Read in entries that should be ignored and remove them from the input. */
    public function removeIgnored($input)
    {
        $content = file_get_contents($this->options['ignoreFile']);

        if ($content === false) {
            throw new \Exception('could not open ignore file');
        }

        $json = json_decode($content, true);

        foreach ($json as $entry) {
            /* If there is only a caller and the caller matches delete all input. */
            if (!isset($entry['path']) && isset($entry['caller'])) {
                if ($this->getCaller() === $entry['caller']) {
                    return array();
                }
            } else {
                /* Skip entry if caller is set, but does not match. */
                if (isset($entry['caller'])) {
                    if ($this->getCaller() !== $entry['caller']) {
                        continue;
                    }
                }

                /* Delete the input based on its path. */
                if (isset($entry['path'])) {
                    unset($input[$entry['path']]);
                }
            }
        }

        return $input;
    }

    /* Calculate and return cryptographically secure checksums. */
    public function getHashes()
    {
        $hashes = array();

        foreach (array('sha256') as $algorithm) {
            $hashes[$algorithm] = hash_file($algorithm, $_SERVER['SCRIPT_FILENAME']);
        }

        return $hashes;
    }

    /* Iterate over all threats and try to remove them. */
    public function defuseInput($threats)
    {
        foreach ($threats as $path) {
            $pathSplitted = $this->splitPath($path);

            foreach ($pathSplitted as &$key) {
                $key = $this->unescapeKey($key);
            }

            /* A valid path needs at least two pieces. */
            if (count($pathSplitted) < 2) {
                return false;
            }

            $value = null;
            $valueRequest = null;

            /* The first element is the root path. It's not a real variable name, so we have to set it manually. */
            $rootPath = array_shift($pathSplitted);

            switch ($rootPath) {
                case 'GET':
                    $value = &$_GET;
                    $valueRequest = &$_REQUEST;
                    break;
                case 'POST':
                    $value = &$_POST;
                    $valueRequest = &$_REQUEST;
                    break;
                case 'COOKIE':
                    $value = &$_COOKIE;
                    break;
                case 'SERVER':
                    $value = &$_SERVER;
                    break;
                case 'FILES':
                    /* Ignore arrays for files, because of strange structure. */
                    unset($_FILES[$pathSplitted[0]]);

                    /* Continue with next threat. */
                    continue 2;
                case 'DATA':
                    throw new \Exception('threat in raw user input');
                default:
                    throw new \Exception('unknown root path');
            }

            /* Try to get the value of the path. */
            foreach ($pathSplitted as $name) {
                /* Stop if the next layer does not exist. */
                if (!isset($value[$name])) {
                    break;
                }

                /* Change the value reference to the next element. */
                $value = &$value[$name];

                /* Do the same for request. */
                if ($valueRequest && isset($valueRequest[$name])) {
                    $valueRequest = &$valueRequest[$name];
                }
            }

            /* Finally the threat can be removed. */
            $value = null;

            /* Do the same for request. */
            if ($valueRequest) {
                $valueRequest = null;
            }
        }
    }

    /**
     * To avoid a small security problem we have to escape some key chars. The reason for this is that
     * otherwise test[foo][bar] would be the same as test[foo|bar] in the internal representation, so
     * test.php?test[foo|bar]=evil&test[foo][bar]=23 could be used to bypass the filter if the target
     * script uses pipes in a key name.
     */
    public function escapeKey($key)
    {
        return str_replace(array('\\', '|'), array('\\\\', '\\|'), $key);
    }

    /* Escaped keys have to be unescaped before they can be defused. */
    public function unescapeKey($key)
    {
        return str_replace(array('\\\\', '\\|'), array('\\', '|'), $key);
    }

    /* Split path at dash, except if it is escaped. */
    public function splitPath($path)
    {
        return preg_split('/\\\\.(*SKIP)(*FAIL)|\|/s', $path);
    }

    /* Strip slashes recursively if magic_quotes_gpc is enabled. */
    private function stripslashes(&$input)
    {
        if (is_array($input)) {
            return array_walk($input, array($this, 'stripslashes'));
        }

        $input = stripslashes($input);
    }
}