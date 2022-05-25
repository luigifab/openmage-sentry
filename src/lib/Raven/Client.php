<?php
/**
 * This file is part of Raven.
 *
 * (c) Sentry Team
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code (BSD-3-Clause).
 */

class Raven_Client {

	public const VERSION = '0.1.0';
	public const DEBUG   = 'debug';
	public const INFO    = 'info';
	public const WARN    = 'warning';
	public const WARNING = 'warning';
	public const ERROR   = 'error';
	public const FATAL   = 'fatal';

	public function __construct($options_or_dsn = null, $options = []) {

		if (is_null($options_or_dsn) && !empty($_SERVER['SENTRY_DSN'])) {
			// Read from environment
			$options_or_dsn = $_SERVER['SENTRY_DSN'];
		}
		if (!is_array($options_or_dsn)) {
			if (!empty($options_or_dsn))
				$options_or_dsn = self::parseDSN($options_or_dsn); // Must be a valid DSN
			else
				$options_or_dsn = [];
		}
		$options = array_merge($options_or_dsn, $options);

		$this->servers    = empty($options['servers']) ? null : $options['servers'];
		$this->secret_key = empty($options['secret_key']) ? null : $options['secret_key'];
		$this->public_key = empty($options['public_key']) ? null : $options['public_key'];
		$this->project    = $options['project'] ?? 1;
		$this->auto_log_stacks = $options['auto_log_stacks'] ?? false;
		$this->name = empty($options['name']) ? gethostname() : $options['name'];
		$this->site = empty($options['site']) ? $this->getServerVariable('SERVER_NAME') : $options['site'];
		$this->tags = empty($options['tags']) ? [] : $options['tags'];

		$this->processors = [];
		foreach (($options['processors'] ?? static::getDefaultProcessors()) as $processor)
			$this->processors[] = new $processor($this);

		$this->_lasterror = null;
	}

	public static function getDefaultProcessors() {
		return [
			'Raven_SanitizeDataProcessor',
		];
	}

	public static function parseDSN($dsn) {

		$url = parse_url($dsn);
		$scheme = ($url['scheme'] ?? '');
		if (!in_array($scheme, ['http', 'https', 'udp']))
			throw new InvalidArgumentException('Unsupported Sentry DSN scheme: '.$scheme);

		$netloc = ($url['host'] ?? null);
		$netloc.= (isset($url['port']) ? ':'.$url['port'] : null);
		$rawpath = ($url['path'] ?? null);
		if ($rawpath) {
			$pos = strrpos($rawpath, '/', 1);
			if ($pos !== false) {
				$path = substr($rawpath, 0, $pos);
				$project = substr($rawpath, $pos + 1);
			}
			else {
				$path = '';
				$project = substr($rawpath, 1);
			}
		}
		else {
			$project = null;
			$path = '';
		}

		$username = ($url['user'] ?? null);
		$password = ($url['pass'] ?? null);
		if (empty($netloc) || empty($project) || empty($username))
			throw new InvalidArgumentException('Invalid Sentry DSN: '.$dsn);

		return [
			'servers'    => [sprintf('%s://%s%s/api/store/', $scheme, $netloc, $path)],
			'project'    => $project,
			'public_key' => $username,
			'secret_key' => $password,
		];
	}

	public function getIdent($ident) {
		// XXX: We dont calculate checksums yet, so we only have the ident.
		return $ident;
	}

	public function captureMessage($message, $params = [], $level = self::INFO, $stack = false) {
		// Gracefully handle messages which contain formatting characters, but were intended to be used with formatting
		return $this->capture([
			'message' => empty($params) ? $message : vsprintf($message, $params),
			'level'   => $level,
			'sentry.interfaces.Message' => [
				'message' => $message,
				'params'  => $params,
			],
		], $stack);
	}

	public function captureException($exception, $culprit = null, $logger = null) {

		$exc_message = $exception->getMessage();
		if (empty($exc_message))
			$exc_message = '<unknown exception>';

		$data = [
			'message' => $exc_message,
			'sentry.interfaces.Exception' => [
				'value'  => $exc_message,
				'type'   => $exception->getCode(),
				'module' => $exception->getFile().':'.$exception->getLine(),
			],
		];

		if ($culprit)
			$data['culprit'] = $culprit;
		if ($logger)
			$data['logger'] = $logger;

		/**
		 * Exception::getTrace doesn't store the point at where the exception
		 * was thrown, so we have to stuff it in ourselves. Ugh.
		 */
		$trace = $exception->getTrace();
		$frame_where_exception_thrown = [
			'file' => $exception->getFile(),
			'line' => $exception->getLine(),
		];
		array_unshift($trace, $frame_where_exception_thrown);

		return $this->capture($data, $trace);
	}

	public function capture($data, $stack) {

		$event_id = $this->uuid4();

		if (!isset($data['timestamp']))
			$data['timestamp'] = gmdate('Y-m-d\TH:i:s\Z');
		if (!isset($data['level']))
			$data['level'] = self::ERROR;

		// The function getallheaders() is only available when running in a
		// web-request. The function is missing when run from the commandline..
		$headers = [];
		if (function_exists('getallheaders'))
			$headers = getallheaders();

		$data = array_merge($data, [
			'server_name' => $this->name,
			'event_id'    => $event_id,
			'project'     => $this->project,
			'site'        => $this->site,
			'sentry.interfaces.Http' => [
				'method'       => $this->getServerVariable('REQUEST_METHOD'),
				'url'          => $this->getCurrentUrl(),
				'query_string' => $this->getServerVariable('QUERY_STRNG'),
				'data'         => $_POST,
				'cookies'      => $_COOKIE,
				'headers'      => $headers,
				'env'          => $_SERVER,
			],
		]);

		if ((!$stack && $this->auto_log_stacks) || $stack === True) {
			$stack = debug_backtrace();
			// Drop last stack
			array_shift($stack);
		}

		if (!empty($stack)) {
			/**
			 * PHP's way of storing backstacks seems bass-ackwards to me
			 * 'function' is the function you're in; it's any function being
			 * called, so we have to shift 'function' down by 1. Ugh.
			 */
			for ($i = 0; $i < count($stack) - 1; $i++)
				$stack[$i]['function'] = $stack[$i + 1]['function'];
			$stack[count($stack) - 1]['function'] = null;

			if (!isset($data['sentry.interfaces.Stacktrace']))
				$data['sentry.interfaces.Stacktrace'] = ['frames' => Raven_Stacktrace::get_stack_info($stack)];
		}

		$data = $this->removeInvalidUtf8($data);

		// TODO: allow tags to be specified per event
		$data['tags'] = $this->tags;

		// sanitize data and send
		$this->send($this->process($data));

		return $event_id;
	}

	public function process($data) {
		foreach ($this->processors as $processor)
			$data = $processor->process($data);
		return $data;
	}

	public function send($data) {

		$message = base64_encode(gzcompress(json_encode($data)));

		foreach ($this->servers as $url) {
			$client_string = 'raven-php/'.self::VERSION;
			$timestamp = microtime(true);
			$signature = $this->getSignature($message, $timestamp, $this->secret_key);
			$headers = [
				'User-Agent'    => $client_string,
				'X-Sentry-Auth' => $this->getAuthHeader($signature, $timestamp, $client_string, $this->public_key),
				'Content-Type'  => 'application/octet-stream',
			];
			$result = $this->sendRemote($url, $message, $headers);
		}

		return $result;
	}

	private function sendRemote($url, $data, $headers = []) {

		$parts = parse_url($url);
		$parts['netloc'] = $parts['host'].(isset($parts['port']) ? ':'.$parts['port'] : null);

		if ($parts['scheme'] === 'udp')
			return $this->sendUdp($parts['netloc'], $data, $headers['X-Sentry-Auth']);

		return $this->sendHttp($url, $data, $headers);
	}

	private function sendUdp($netloc, $data, $headers) {

		[$host, $port] = explode(':', $netloc);
		$raw_data = $headers."\n\n".$data;

		$sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
		socket_sendto($sock, $raw_data, strlen($raw_data), 0, $host, $port);
		socket_close($sock);

		return true;
	}

	private function sendHttp($url, $data, $headers = []) {

		$new_headers = [];
		foreach ($headers as $key => $value)
			$new_headers[] = $key.': '.$value;

		$curl = curl_init($url);
		curl_setopt($curl, CURLOPT_POST, 1);
		curl_setopt($curl, CURLOPT_HTTPHEADER, $new_headers);
		curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
		curl_setopt($curl, CURLOPT_VERBOSE, false);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true); // false?
		$ret = curl_exec($curl);
		$code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		$success = ($code == 200);
		curl_close($curl);

		// It'd be nice just to raise an exception here, but it's very PHP-like
		if (!$success)
			$this->_lasterror = $ret;

		return $success;
	}

	private function getSignature($message, $timestamp, $key) {
		return hash_hmac('sha1', sprintf('%F', $timestamp) .' '. $message, $key);
	}

	private function getAuthHeader($signature, $timestamp, $client, $api_key = null) {

		$header = [
			sprintf("sentry_timestamp=%F", $timestamp),
			'sentry_signature='.$signature,
			'sentry_client='.$client,
			'sentry_version=2.0',
		];

		if ($api_key)
			$header[] = 'sentry_key='.$api_key;

		return sprintf('Sentry %s', implode(', ', $header));
	}

	private function uuid4() {
		return str_replace('-', '', sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
			// 32 bits for "time_low"
			random_int(0, 0xffff), random_int(0, 0xffff),
			// 16 bits for "time_mid"
			random_int(0, 0xffff),
			// 16 bits for "time_hi_and_version",
			// four most significant bits holds version number 4
			random_int(0, 0x0fff) | 0x4000,
			// 16 bits, 8 bits for "clk_seq_hi_res",
			// 8 bits for "clk_seq_low",
			// two most significant bits holds zero and one for variant DCE1.1
			random_int(0, 0x3fff) | 0x8000,
			// 48 bits for "node"
			random_int(0, 0xffff), random_int(0, 0xffff), random_int(0, 0xffff)
		));
	}

	private function getCurrentUrl() {

		// When running from commandline the REQUEST_URI is missing.
		if (empty($this->getServerVariable('REQUEST_URI')))
			return '';

		$schema = ((!empty($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] != 'off')) || ($_SERVER['SERVER_PORT'] == 443)) ? "https://" : "http://";
		return $schema.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
	}

	private function getServerVariable($key) {
		return $_SERVER[$key] ?? '';
	}

	private function removeInvalidUtf8($data) {

		if (!function_exists('mb_convert_encoding'))
			return $data;

		foreach ($data as $key => $value) {
			if (is_string($key))
				$key = mb_convert_encoding($key, 'UTF-8', 'UTF-8');
			if (is_string($value))
				$value = mb_convert_encoding($value, 'UTF-8', 'UTF-8');
			if (is_array($value))
				$value = $this->removeInvalidUtf8($value);
			$data[$key] = $value;
		}

		return $data;
	}

	public function getLastError() {
		return $this->_lasterror;
	}
}