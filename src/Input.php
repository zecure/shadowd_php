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

use shadowd\Exceptions\CorruptedFileException;
use shadowd\Exceptions\MissingFileException;
use shadowd\Exceptions\UnknownPathException;

class Input
{
    /** @var array<string, string> */
    private $options;

    /**
     * Construct a new object.
     *
     * @param array<string, string> $options
     */
    public function __construct($options)
    {
        if (empty($options['clientIpKey'])) {
            $options['clientIpKey'] = 'REMOTE_ADDR';
        }

        if (empty($options['callerKey'])) {
            $options['callerKey'] = 'SCRIPT_FILENAME';
        }

        if (empty($options['ignoreFile'])) {
            $options['ignoreFile'] = false;
        }

        if (empty($options['rawData'])) {
            $options['rawData'] = false;
        }

        $this->options = $options;
    }

    /**
     * Getter for the client ip.
     *
     * @return string|null
     */
    public function getClientIp()
    {
        /* Allow for comma-separated client IP keys. */
        $keys = explode(',', $this->options['clientIpKey']);
        foreach ($keys as $key) {
            $key = trim($key);
            /* Skip empty server keys. */
            if (!empty($_SERVER[$key])) {
                /* X_FORWARD_FOR allows for comma-separated address listing
                 * and the first IP is assumed the actual client IP. */
                $addrs = explode(',', $_SERVER[$key]);
                return array_shift($addrs);
            }
        }
        /* Use the default or return empty string. */
        return empty($_SERVER['REMOTE_ADDR']) ? '' : $_SERVER['REMOTE_ADDR'];
    }

    /**
     * Getter for the caller.
     *
     * @return string|null
     */
    public function getCaller()
    {
        return $_SERVER[$this->options['callerKey']];
    }

    /**
     * Getter for the resource.
     *
     * @return string
     */
    public function getResource()
    {
        return $_SERVER['REQUEST_URI'];
    }

    /**
     * Aggregate and get the user input.
     *
     * @return array<string, string>
     */
    public function getInput()
    {
        // Create copies of input sources. Only GET/POST/COOKIE here!
        $input = [
            'GET'    => $_GET,
            'POST'   => $_POST,
            'COOKIE' => $_COOKIE
        ];

        // Strip slashes of GPC input if magic_quotes_gpc is activated to get the real values.
        if (function_exists('get_magic_quotes_gpc') && get_magic_quotes_gpc()) {
            $this->stripslashes($input);
        }

        // Add names of uploaded files.
        foreach ($_FILES as $key => $value) {
            $input['FILES'][$key] = $value['name'];
        }

        // Add headers that contain user input.
        foreach ($_SERVER as $key => $value) {
            if (strpos($key, 'HTTP_') === 0) {
                $input['SERVER'][$key] = $value;
            }
        }

        $input['SERVER']['PHP_SELF'] = $_SERVER['PHP_SELF'];

        // Add raw post data if not empty.
        if ($this->options['rawData']) {
            $rawData = file_get_contents('php://input');

            if ($rawData) {
                $input['DATA']['raw'] = $rawData;
            }
        }

        // Convert the complete input structure to a flat unique array.
        $flattenedInput = $this->flatten($input);

        // Remove user input that should be ignored.
        if ($this->options['ignoreFile']) {
            $flattenedInput = $this->removeIgnored($flattenedInput);
        }

        return $flattenedInput;
    }

    /**
     * Convert nested arrays to a flat array.
     *
     * @param array<mixed>|string $input
     * @param string|bool $key
     * @param string|bool $path
     * @return array<string, string>
     */
    public function flatten($input, $key = false, $path = false)
    {
        $output = [];

        // The next part generates an unique identifier for every input element.
        $newPath = false;

        if (is_string($key)) {
            $key = $this->escapeKey($key);

            // If there is already a path just append the key, otherwise the key is the complete new path.
            if ($path !== false) {
                $newPath = $path . '|' . $key;
            } else {
                $newPath = $key;
            }
        }

        // Now we have to process the input. It can either be an array or a string, but we check both to be sure.
        if (is_array($input)) {
            // The current input is an array, so we have to call the convert function again.
            foreach ($input as $inputKey => $inputValue) {
                $output = array_replace($output, $this->flatten($inputValue, $inputKey, $newPath));
            }
        } elseif ($newPath !== false) {
            // FIXME: the encoding does not work properly all the time yet.
            if (!mb_check_encoding($input, 'UTF-8')) {
                $input = mb_convert_encoding($input, 'UTF-8');
            }

            return [$newPath => $input];
        }

        return $output;
    }

    /**
     * Read in entries that should be ignored and remove them from the input.
     *
     * @param array<string, string> $input
     * @return array<string, string>
     * @throws CorruptedFileException if ignore file is invalid
     * @throws MissingFileException if ignore file is missing
     */
    public function removeIgnored($input)
    {
        if (!file_exists($this->options['ignoreFile'])) {
            throw new MissingFileException($this->options['ignoreFile']);
        }

        $content = file_get_contents($this->options['ignoreFile']);
        if ($content === false) {
            throw new CorruptedFileException($this->options['ignoreFile']);
        }

        $json = json_decode($content, true);
        if ($json === null) {
            throw new CorruptedFileException($this->options['ignoreFile']);
        }

        foreach ($json as $entry) {
            // If there is only a caller and the caller matches delete all input.
            if (!isset($entry['path']) && isset($entry['caller'])) {
                if ($this->getCaller() === $entry['caller']) {
                    return [];
                }
            } else {
                // Skip entry if caller is set, but does not match.
                if (isset($entry['caller'])) {
                    if ($this->getCaller() !== $entry['caller']) {
                        continue;
                    }
                }

                // Delete the input based on its path.
                if (isset($entry['path'])) {
                    unset($input[$entry['path']]);
                }
            }
        }

        return $input;
    }

    /**
     * Calculate and return cryptographically secure checksums.
     *
     * @return array<string, string>
     */
    public function getHashes()
    {
        $hashes = [];

        foreach (['sha256'] as $algorithm) {
            $hashes[$algorithm] = hash_file($algorithm, $_SERVER['SCRIPT_FILENAME']);
        }

        return $hashes;
    }

    /**
     * Iterate over all threats and try to remove them.
     *
     * Returns false if the complete request has to be blocked.
     *
     * @param string[] $threats
     * @return bool
     * @throws UnknownPathException if root path is invalid
     */
    public function defuseInput($threats)
    {
        foreach ($threats as $path) {
            $pathSplitted = $this->splitPath($path);

            // A valid path needs at least two pieces.
            if (count($pathSplitted) < 2) {
                return false;
            }

            // The first element is the root path.
            $rootPath = array_shift($pathSplitted);

            // Arrays are ignored and completely removed if they contain a threat.
            // This is new in version 2.0 and was a hard decision, but security-wise
            // it is better than just emptying the variables, because it makes
            // injections via array keys impossible.
            $keyPath = $this->unescapeKey(array_shift($pathSplitted));

            switch ($rootPath) {
                case 'GET':
                    if (isset($_GET[$keyPath])) {
                        unset($_GET[$keyPath]);
                    }

                    if (isset($_REQUEST[$keyPath])) {
                        unset($_REQUEST[$keyPath]);
                    }

                    break;
                case 'POST':
                    if (isset($_POST[$keyPath])) {
                        unset($_POST[$keyPath]);
                    }

                    if (isset($_REQUEST[$keyPath])) {
                        unset($_REQUEST[$keyPath]);
                    }

                    break;
                case 'COOKIE':
                    if (isset($_COOKIE[$keyPath])) {
                        unset($_COOKIE[$keyPath]);
                    }

                    if (isset($_REQUEST[$keyPath])) {
                        unset($_REQUEST[$keyPath]);
                    }

                    break;
                case 'SERVER':
                    if (isset($_SERVER[$keyPath])) {
                        unset($_SERVER[$keyPath]);
                    }

                    break;
                case 'FILES':
                    if (isset($_FILES[$keyPath])) {
                        unset($_FILES[$keyPath]);
                    }

                    break;
                case 'DATA':
                    return false;
                default:
                    throw new UnknownPathException($path);
            }
        }

        // Don't stop the complete request.
        return true;
    }

    /**
     * Escape special characters in keys.
     *
     * To avoid a small security problem we have to escape some key chars. The reason for this is that
     * otherwise test[foo][bar] would be the same as test[foo|bar] in the internal representation, so
     * test.php?test[foo|bar]=evil&test[foo][bar]=23 could be used to bypass the filter if the target
     * script uses pipes in a key name.
     *
     * @param string $key
     * @return string
     */
    public function escapeKey($key)
    {
        return str_replace(['\\', '|'], ['\\\\', '\\|'], $key);
    }

    /**
     * Escaped keys have to be unescaped before they can be defused.
     *
     * @param string $key
     * @return string
     */
    public function unescapeKey($key)
    {
        return str_replace(['\\\\', '\\|'], ['\\', '|'], $key);
    }

    /**
     * Split path at dash, except if it is escaped.
     *
     * @param string $path
     * @return string[]
     */
    public function splitPath($path)
    {
        return preg_split('/\\\\.(*SKIP)(*FAIL)|\|/s', $path);
    }

    /**
     * Strip slashes recursively if magic_quotes_gpc is enabled.
     *
     * Warning, this function uses value by reference!
     *
     * @param array<mixed>|string $input
     * @return void
     */
    private function stripslashes(&$input)
    {
        if (is_array($input)) {
            array_walk($input, [$this, 'stripslashes']);
            return;
        }

        $input = stripslashes($input);
    }
}
