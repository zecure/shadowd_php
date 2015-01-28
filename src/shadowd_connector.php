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

/* Namespace to avoid conflicts with the original site. */
namespace shadowd;

define('SHADOWD_CONNECTOR_VERSION', '1.0.0-php');
define('SHADOWD_CONNECTOR_CONFIG', '/etc/shadowd/connectors.ini');
define('SHADOWD_CONNECTOR_CONFIG_SECTION', 'shadowd_php');
define('STATUS_OK', '1');
define('STATUS_BAD_REQUEST', '2');
define('STATUS_BAD_SIGNATURE', '3');
define('STATUS_BAD_JSON', '4');
define('STATUS_ATTACK', '5');

/* JSON replacement for old PHP versions. */
if (!function_exists('json_decode')) {
	require_once(realpath(dirname(__FILE__)) . '/libs/json.php');

	function json_decode($var) {
		$JSON = new \Services_JSON;
		return $JSON->decode($var);
	}
}

if (!function_exists('json_encode')) {
	require_once(realpath(dirname(__FILE__)) . '/libs/json.php');

	function json_encode($var) {
		$JSON = new \Services_JSON;
		return $JSON->encode($var);
	}
}

class Config {
	/* Parse a simple ini file. */
	public function __construct() {
		if (getenv('SHADOWD_CONNECTOR_CONFIG')) {
			$this->file = getenv('SHADOWD_CONNECTOR_CONFIG');
		} else {
			$this->file = SHADOWD_CONNECTOR_CONFIG;
		}

		$this->data = parse_ini_file($this->file, true);

		if (!$this->data) {
			throw new \Exception('config error');
		}

		if (getenv('SHADOWD_CONNECTOR_CONFIG_SECTION')) {
			$this->section = getenv('SHADOWD_CONNECTOR_CONFIG_SECTION');
		} else {
			$this->section = SHADOWD_CONNECTOR_CONFIG_SECTION;
		}
	}

	/* Get the value or stop if a required value is missing. */
	public function get($key, $required = false, $default = false) {
		if (!isset($this->data[$this->section][$key])) {
			if ($required) {
				throw new \Exception($key . ' in config missing');
			} else {
				return $default;
			}
		} else {
			return $this->data[$this->section][$key];
		}
	}
}

class Input {
	/* Construct a new object. */
	public function __construct($config) {
		$this->config = $config;
	}

	/* Getter for the client ip. */
	public function get_client_ip() {
		return $_SERVER[$this->config->get('client_ip', false, 'REMOTE_ADDR')];
	}

	/* Getter for the caller. */
	public function get_caller() {
		return $_SERVER[$this->config->get('caller', false, 'SCRIPT_FILENAME')];
	}

	/* Aggregate and prepare the input. */
	public function gather_input() {
		/* Reset input. */
		$this->input = array();

		/* Create copies of all input sources. */
		$input_collection = array(
			'GET' => $_GET,
			'POST' => $_POST,
			'COOKIE' => $_COOKIE
		);

		/* Stripslash get/post/cookie input if magic_quotes_gpc is activated to get the real values. */
		if (function_exists('get_magic_quotes_gpc') && get_magic_quotes_gpc()) {
			$this->stripslashes($input_collection);
		}

		/* Add header that contain user input. */
		foreach ($_SERVER as $key => $value) {
			if (strpos($key, 'HTTP_') === 0) {
				$input_collection['SERVER'][$key] = $value;
			}
		}

		$input_collection['SERVER']['PHP_SELF'] = $_SERVER['PHP_SELF'];

		/* Convert the complete input structure to a flat unique array. */
		$this->flatten($input_collection);
	}

	/* Convert nested arrays to a flat array. */
	private function flatten(&$input, $key = false, $path = false) {
		/* The next part generates an unique identifier for every input element. */
		$new_path = false;

		if ($key !== false) {
			$key = $this->escape_key($key);

			/* If there is already a path just append the key, otherwise the key is the complete new path. */
			if ($path !== false) {
				$new_path = $path . '|' . $key;
			} else {
				$new_path = $key;
			}
		}

		/* Now we have to process the input. It can either be an array or a string, but we check both to be sure. */
		if (is_array($input)) {
			/* The current input is an array, so we have to call the convert function again. */
			foreach ($input as $input_key => $input_value) {
				$this->flatten($input_value, $input_key, $new_path);
			}
		} elseif (($new_path !== false) && (is_string($input) || is_numeric($input))) {
			// FIXME: the encoding does not work properly all the time yet.
			if (!mb_check_encoding($input, 'UTF-8')) {
				$input = mb_convert_encoding($input, 'UTF-8');
			}

			$this->input[$new_path] = $input;
		}
	}

	/* Iterate over all threats and try to remove them. */
	public function defuse_input($threats) {
		foreach ($threats as $path) {
			$path_split = $this->split_path($path);

			foreach ($path_split as &$key) {
				$key = $this->unescape_key($key);
			}

			/* A valid path needs at least two pieces. */
			if (count($path_split) < 2) {
				return false;
			}

			$value = array();

			/* The first element is the root path. It's not a real variable name, so we have to set it manually. */
			$root_path = array_shift($path_split);

			switch ($root_path) {
				case 'GET':
					$value = &$_GET;
					break;
				case 'POST':
					$value = &$_POST;
					break;
				case 'COOKIE':
					$value = &$_COOKIE;
					break;
				case 'SERVER':
					$value = &$_SERVER;
					break;
				default:
					continue;
			}

			/* Try to get the value of the path. */
			foreach ($path_split as $name) {
				/* Stop if the next layer does not exist. */
				if (!isset($value[$name])) {
					break;
				}

				/* Change the value reference to the next element. */
				$value = &$value[$name];
			}

			/* Finally the threat can be removed. */
			$value = '';
		}
	}

	/* Getter for the flattened input array. */
	public function get_input() {
		return $this->input;
	}

	/* Read in entries that should be ignored and remove them from the input. */
	public function remove_ignored($file) {
		$content = file_get_contents($file);

		if ($content === false) {
			throw new \Exception('could not open ignore file');
		}

		$json = json_decode($content, true);

		foreach ($json as $entry) {
			/* If there is only a caller and the caller matches delete all input. */
			if (!isset($entry['path']) && isset($entry['caller'])) {
				if ($this->get_caller() === $entry['caller']) {
					$this->input = array();

					/* Input is empty, no need to continue with the other entries. */
					break;
				}
			} else {
				/* Skip entry if caller is set, but does not match. */
				if (isset($entry['caller'])) {
					if ($this->get_caller() !== $entry['caller']) {
						continue;
					}
				}

				/* Delete the input based on its path. */
				if (isset($entry['path'])) {
					unset($this->input[$entry['path']]);
				}
			}
		}
	}

	/**
	 * To avoid a small security problem we have to escape some key chars. The reason for this is that
	 * otherwise test[foo][bar] would be the same as test[foo|bar] in the internal representation, so
	 * test.php?test[foo|bar]=evil&test[foo][bar]=23 could be used to bypass the filter if the target
	 * script uses pipes in a key name.
	 */
	private function escape_key($key) {
		return str_replace(array('\\', '|'), array('\\\\', '\\|'), $key);
	}

	/* Escaped keys have to be unescaped before they can be defused. */
	private function unescape_key($key) {
		return str_replace(array('\\\\', '\\|'), array('\\', '|'), $key);
	}

	/* Split path at dash, except if it is escaped. */
	public function split_path($path) {
		return preg_split('/\\\\.(*SKIP)(*FAIL)|\|/s', $path);
	}

	/* Strip slashes recursively if magic_quotes_gpc is enabled. */
	private function stripslashes(&$input) {
		if (is_array($input)) {
			return array_walk($input, array($this, 'stripslashes'));
		}

		$input = stripslashes($input);
	}
}

class Output {
	/* Construct a new object. */
	public function __construct($config) {
		$this->config = $config;
	}

	/* Show a fatal error and stop. */
	public function error() {
		header($_SERVER['SERVER_PROTOCOL'] . ' 500 Internal Server Error', true, 500);
		exit('<h1>500 Internal Server Error</h1>');
	}

	/* Write message to error log. */
	public function log($message) {
		error_log($message);
	}
}

class Connection {
	/* Send user input to background server. */
	public function send(input &$input, $host, $port, $profile, $key, $ssl) {
		$context = stream_context_create();

		if ($ssl) {
			$result = stream_context_set_option($context, 'ssl', 'verify_host', true);
			$result = stream_context_set_option($context, 'ssl', 'cafile', $this->ssl);
			$result = stream_context_set_option($context, 'ssl', 'verify_peer', true);
		}

		$resource = ($ssl ? 'ssl' : 'tcp') . '://' . $host . ':' . $port;
		$fp = @stream_socket_client($resource, $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $context);

		if (!$fp) {
			if ($errno) {
				throw new \Exception('network error: ' . strtolower($errstr));
			} else {
				throw new \Exception('unknown network error');
			}
		}

		$data = array(
			'version' => SHADOWD_CONNECTOR_VERSION,
			'client_ip' => $input->get_client_ip(),
			'caller' => $input->get_caller(),
			'input' => $input->get_input()
		);

		/**
		 * Input format:
		 *   profile_id\n
		 *   hmac(json)\n
		 *   json\n
		 */
		$json = json_encode($data);
		fwrite($fp, $profile . "\n" . $this->sign($key, $json) . "\n" . $json . "\n");

		$output = '';

		while (!feof($fp)) {
			$output .= fgets($fp, 1024);
		}

		fclose($fp);

		return $this->parse_output($output);
	}

	/* Parse output from the background server. */
	private function parse_output($output) {
		$json = json_decode($output, true);

		switch ($json['status']) {
			case STATUS_OK:
				return false;
			case STATUS_BAD_REQUEST:
				throw new \Exception('bad request');
			case STATUS_BAD_SIGNATURE:
				throw new \Exception('bad signature');
			case STATUS_BAD_JSON:
				throw new \Exception('bad json');
			case STATUS_ATTACK:
				return $json['threats'];
			default:
				throw new \Exception('processing error');
		}
	}

	/* Sign the json encoded message as password verification. */
	private function sign($key, $json) {
		return hash_hmac('sha256', $json, $key);
	}
}

class Connector {
	public static function start() {
		try {
			/* Get the configuration. */
			$config = new Config();

			/* Get the input in a flat format, but without sensible data. */
			$input = new Input($config);
			$output = new Output($config);

			$input->gather_input();

			$ignored = $config->get('ignore');
			if ($ignored) {
				$input->remove_ignored($ignored);
			}

			/* Establish a tcp connection with a shadowd server and send the user input. */
			$connection = new Connection();

			$threats = $connection->send(
				$input,
				$config->get('host', false, '127.0.0.1'),
				$config->get('port', false, '9115'),
				$config->get('profile', true),
				$config->get('key', true),
				$config->get('ssl')
			);

			/* If observe mode is disabled eliminate the threats. */
			if (!$config->get('observe') && $threats) {
				$input->defuse_input($threats);
			}

			/* If debug is enabled drop a log message (for fail2ban f.i.). */
			if ($config->get('debug') && $threats) {
				$output->log('shadowd: removed threat from client: ' . $input->get_client_ip());
			}
		} catch (\Exception $e) {
			/* Let PHP handle the log writing if debug is enabled. */
			if ($config->get('debug')) {
				$output->log('shadowd: ' . rtrim($e->getMessage()));
			}

			/* If protection mode is enabled we can't let this request pass. */
			if (!$config->get('observe')) {
				$output->error();
			}
		}
	}
}

Connector::start();

?>
