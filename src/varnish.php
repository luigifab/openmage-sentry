<?php
/**
 * Created M/20/12/2022
 * Updated V/22/08/2025
 *
 * Copyright 2022-2025 | Fabrice Creuzot (luigifab) <code~luigifab~fr>
 * Copyright 2022-2023 | Fabrice Creuzot <fabrice~cellublue~com>
 * https://github.com/luigifab/openmage-sentry
 *
 * This program is free software, you can redistribute it or modify
 * it under the terms of the Open Software License (OSL 3.0).
 *
 * This program is distributed in the hope that it will be useful,
 * but without any warranty, without even the implied warranty of
 * merchantability or fitness for a particular purpose. See the
 * Open Software License (OSL 3.0) for more details.
 */

chdir(__DIR__);
error_reporting(E_ALL);
ini_set('display_errors', (PHP_VERSION_ID < 80100) ? '1' : 1);

if (PHP_SAPI != 'cli')
	exit(-1);

// run this script on varnish server
// it require php-cli php-curl
//  php .../varnish-sentry.php http://public:secret@sentry.example.com:9000/pid
$cmd = 'varnishlog -q "RespStatus >= 400 or BerespStatus >= 400"';
$dsn = $argv[1] ?? $_SERVER['SENTRY_DSN'] ?? 'empty';

$sentry = new Client();
$sentry->parseDSN($dsn, ['tags' => ['engine' => 'varnish']]);

global $headers; // getallheaders
$headers = [];
global $username; // getusername
$username = 0;

$emptyServer = ['SENTRY_DSN' => $dsn, 'USER' => $_SERVER['USER']];
$stream = [];
$proc   = popen($cmd, 'r');

echo 'Ready! waiting events...',"\n";
echo ' » ',$dsn,"\n";


while (!feof($proc)) {

	$stream[] = trim(fgets($proc));

	// search a complete request from varnishlog
	// *   << Request  >> 34579
	// -   Begin          req 34578 rxreq
	// ...
	// -   End
	$start = false;
	$end   = false;
	$from  = 0;
	$to    = 0;
	foreach ($stream as $idx => $line) {
		if (!$start && (strncasecmp($line, '*   << Request  >>', 18) === 0)) {
			$start = true;
			$from  = $idx;
			$username = trim(substr($line, strrpos($line, '>') + 1));
		}
		if ($start && (strncasecmp($line, '-   End', 7) === 0)) {
			$end = true;
			$to  = $idx;
			break;
		}
	}

	if ($start && $end) {

		$_SERVER = $emptyServer;
		$_COOKIE = [];

		// extract a complete request from varnishlog
		$request = array_slice($stream, $from, $to);
		$stream  = array_slice($stream, $to + 1);
		//print_r($request);

		// extract data
		$reqMet = '';
		$reqSta = '';
		$requestData  = [];

		foreach ($request as $line) {
			if (strncasecmp($line, '-   ReqMethod ', 14) === 0) {
				$reqMet = trim(substr($line, strlen('-   ReqMethod ')));
				$_SERVER['REQUEST_METHOD'] = $reqMet;
			}
			else if (strncasecmp($line, '-   RespStatus ', 15) === 0) {
				$reqSta = trim(substr($line, strlen('-   RespStatus ')));
			}
			else if (strncasecmp($line, '-   ReqProtocol ', 16) === 0) {
				$_SERVER['SERVER_PROTOCOL'] = trim(substr($line, strlen('-   ReqProtocol ')));
			}
			else if (strncasecmp($line, '-   ReqURL ', 11) === 0) {
				$_SERVER['REQUEST_URI'] = trim(substr($line, strlen('-   ReqURL ')));
				if (($pos = strpos($_SERVER['REQUEST_URI'], '?')) !== false)
					$_SERVER['QUERY_STRNG'] = substr($_SERVER['REQUEST_URI'], $pos + 1);
			}
			else if ((strncasecmp($line, '-   RespHeader ', 15) === 0) && (stripos($line, 'Varnish/') !== false)) {
				$_SERVER['SERVER_SOFTWARE'] = trim(substr($line, strpos($line, '(') + 1, -1));
			}
			else if ((strncasecmp($line, '-   ReqHeader ', 14) === 0) && (stripos($line, ' cookie: ') !== false)) {
				$cookies = explode('; ', trim(substr($line, strpos($line, ':') + 1)));
				foreach ($cookies as $cookie) {
					$cookie = (array) explode('=', $cookie, 2); // (yes)
					if (count($cookie) == 2)
						$_COOKIE[$cookie[0]] = $cookie[1];
				}
			}
			else if (strncasecmp($line, '-   ReqHeader ', 14) === 0) {
				$data = array_map('trim', explode(':', substr($line, strlen('-   ReqHeader ')), 2));
				if (count($data) == 2)
					$requestData[$data[0]] = $data[1];
			}
		}

		// sentry client use: SERVER_NAME, REQUEST_METHOD, QUERY_STRNG, REQUEST_URI, HTTPS, SERVER_PORT, HTTP_X_FORWARDED_PROTO, HTTP_HOST
		$_SERVER['SERVER_NAME'] = $requestData['Host'] ?? null;
		$_SERVER['HTTP_X_FORWARDED_PROTO'] = $requestData['X-Forwarded-Proto'] ?? null;
		$_SERVER['HTTP_HOST'] = $requestData['Host'] ?? null;

		if (empty($_SERVER['REQUEST_URI']))
			$_SERVER['REQUEST_URI'] = '';
		if (!empty($requestData['X-Forwarded-Proto']))
			$_SERVER['REQUEST_SCHEME'] = $requestData['X-Forwarded-Proto'];

		if (!empty($requestData['X-Forwarded-For'])) {
			$ips = explode(',', $requestData['X-Forwarded-For']);
			$_SERVER['REMOTE_ADDR'] = trim(array_shift($ips));
		}

		$msg = $reqMet.' '.$reqSta;
		if ($reqSta != 401) { // @todo
			$headers = $requestData; // getallheaders
			$eventId = $sentry->captureMessage(empty($_SERVER['REQUEST_URI']) ? $msg : $msg."\n".$_SERVER['REQUEST_URI'], 'error', ['source' => 'sentry:varnish']);
			echo date('c'),' event: ',$eventId,', message: ',$msg,' ',$_SERVER['REQUEST_URI'],' (',$_SERVER['HTTP_HOST'],")\n";
		}
		else {
			echo date('c'),' event ignored, message: ',$msg,' ',$_SERVER['REQUEST_URI'],' (',$_SERVER['HTTP_HOST'],")\n";
		}
	}
}


function getallheaders() {
	global $headers;
	return $headers;
}

class Client {

	protected $_isEnabled = true;
	protected $_defaultLogger = 'varnish';
	protected $_reports = false;

	// for varnish
	protected function initSentry() {
		return $this->_isEnabled;
	}

	protected function getUsername() {
		global $username;
		return 'varnish:'.$username;
	}

	protected function addSourceFile($exception, $trace = []) {
		return true;
	}


	/**
	 * This part is a (simplified) part of Raven 0.1.0 - BSD-3-Clause - https://github.com/getsentry/raven-php
	 * Copyright 2012 Sentry Team and individual contributors
	 *
	 * Redistribution and use in source and binary forms, with or without modification,
	 * are permitted provided that the following conditions are met:
	 *
	 *  1. Redistributions of source code must retain the above copyright notice,
	 *  this list of conditions and the following disclaimer.
	 *
	 *  2. Redistributions in binary form must reproduce the above copyright notice,
	 *  this list of conditions and the following disclaimer in the documentation
	 *  and/or other materials provided with the distribution.
	 *
	 *  3. Neither the name of the Raven nor the names of its contributors may be
	 *  used to endorse or promote products derived from this software without specific
	 *  prior written permission.
	 */
	private $_clientName = 'varnish-sentry-connector';
	private $_serverUrl;
	private $_secretKey;
	private $_publicKey;
	private $_project;
	private $_logStacks;
	private $_name;
	private $_tags;

	// Raven_Client
	public function captureMessage($message, $level = 'info', $tags = [], $stack = false) {

		return $this->capture([
			'message' => $message,
			'level'   => $level,
			'sentry.interfaces.Message' => [
				'message' => $message,
			],
		], $stack, $tags);
	}

	public function captureException($exception, $customMessage = null, $tags = []) {

		$message = $exception->getMessage();
		if (empty($message))
			$message = '<unknown exception>';

		// Sentry levels: debug, info, warning, error, fatal
		// PHP level => [Sentry level, OpenMage/Maho label from mageCoreErrorHandler]
		$levels = [
			E_ERROR             => ['error',   'Error'],
			E_WARNING           => ['warning', 'Warning'],
			E_PARSE             => ['error',   'Parse Error'],
			E_NOTICE            => ['info',    'Notice'],
			E_CORE_ERROR        => ['error',   'Core Error'],
			E_CORE_WARNING      => ['warning', 'Core Warning'],
			E_COMPILE_ERROR     => ['error',   'Compile Error'],
			E_COMPILE_WARNING   => ['warning', 'Compile Warning'],
			E_USER_ERROR        => ['error',   'User Error'],
			E_USER_WARNING      => ['warning', 'User Warning'],
			E_USER_NOTICE       => ['info',    'User Notice'],
			E_RECOVERABLE_ERROR => ['error',   'Recoverable Error'],
			E_DEPRECATED        => ['info',    'Deprecated functionality'],
		];

		if (PHP_VERSION_ID < 80400)
			$levels['E_STRICT']  = ['info', 'Strict Notice'];

		$type = empty($exception->getCode()) ? get_class($exception) : (string) $exception->getCode();
		$hasSeverity = method_exists($exception, 'getSeverity');
		if ($hasSeverity)
			$type = $levels[$exception->getSeverity()][1] ?? $type;

		$data = [
			'message' => $customMessage,
			'level'   => $hasSeverity ? ($levels[$exception->getSeverity()][0] ?? 'error') : 'error',
			'sentry.interfaces.Exception' => [
				'value'  => $message,
				'type'   => $type,
				'module' => $exception->getFile().':'.$exception->getLine(),
			],
		];

		// Exception::getTrace doesn't store the point at where the exception
		// was thrown, so we have to stuff it in ourselves. Ugh.
		$trace = $exception->getTrace();
		if ($this->addSourceFile($exception, $trace))
			array_unshift($trace, ['file' => $exception->getFile(), 'line' => $exception->getLine()]);

		return $this->capture($data, $trace, $tags);
	}

	public function parseDSN(string $dsn, array $options) {

		$url = parse_url($dsn);
		if (!is_array($url))
			throw new InvalidArgumentException('Unsupported Sentry DSN (parse_url): '.$dsn);

		$scheme = $url['scheme'] ?? '';
		if (empty($scheme))
			throw new InvalidArgumentException('Unsupported Sentry DSN (scheme not found): '.$dsn);

		if (!in_array($scheme, ['http', 'https', 'udp']))
			throw new InvalidArgumentException('Unsupported Sentry DSN scheme: '.$scheme);

		$netloc  = $url['host'] ?? null;
		$netloc .= isset($url['port']) ? ':'.$url['port'] : null;

		$rawpath = $url['path'] ?? null;
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

		$username = $url['user'] ?? null;
		$password = $url['pass'] ?? 'secret';

		if (empty($netloc) || empty($project) || empty($username) || empty($password))
			throw new InvalidArgumentException('Invalid Sentry DSN: '.$dsn);

		if (empty($options['tags']['runtime']))
			$options['tags']['runtime'] = 'PHP '.PHP_VERSION;

		$this->_serverUrl = sprintf('%s://%s%s/api/%s/store/', $scheme, $netloc, $path, $project);
		$this->_secretKey = (string) $password;
		$this->_publicKey = (string) $username;
		$this->_project   = (int) $project;
		$this->_logStacks = (bool) ($options['auto_log_stacks'] ?? false);
		$this->_name      = (string) (empty($options['name']) ? gethostname() : $options['name']);
		$this->_tags      = $options['tags'];

		return $this;
	}

 	private function capture($data, $stack, $tags = []) {

		//echo '<pre>'; debug_print_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS); exit;
		if ($this->initSentry() !== true)
			return false;

		if (!isset($data['logger']))
			$data['logger'] = $this->_defaultLogger;
		if (!isset($data['timestamp']))
			$data['timestamp'] = gmdate('Y-m-d\TH:i:s\Z');
		if (!isset($data['level']) || !in_array($data['level'], ['debug', 'info', 'warning', 'error', 'fatal']))
			$data['level'] = 'error';

		// the function getallheaders() is only available when running in a web-request
		$headers = function_exists('getallheaders') ? array_filter(getallheaders(), '\strlen') : [];
		$eventId = $this->getUuid4();

		$serverWithoutHttp = [];
		foreach ($_SERVER as $key => $value) {
			if (!empty($value) && (strncmp($key, 'HTTP_', 5) !== 0))
				$serverWithoutHttp[$key] = $value;
		}

		$data = array_merge($data, [
			'server_name' => $this->_name,
			'event_id'    => $eventId,
			'project'     => $this->_project,
			'site'        => $_SERVER['SERVER_NAME'] ?? '',
			'sentry.interfaces.Http' => [
				'method'       => $_SERVER['REQUEST_METHOD'] ?? 'CLI',
				'url'          => $this->getCurrentUrl(),
				'query_string' => $_SERVER['QUERY_STRNG'] ?? '',
				'data'         => $_POST,
				'cookies'      => $_COOKIE,
				'headers'      => $headers,
				'env'          => $serverWithoutHttp,
			],
		]);

		if ((!$stack && $this->_logStacks) || ($stack === true)) {
			$stack = debug_backtrace();
			// drop last stack
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
				$data['sentry.interfaces.Stacktrace'] = ['frames' => $this->getStackInfo($stack)];
		}

		$data['tags'] = $this->_tags + $tags;
		if (!empty($user = $this->getUsername()))
			$data['tags']['username'] = $user;

		$this->send($this->apply($this->removeInvalidUtf8($data)));
		return $eventId;
	}

	private function send($data) {

		$message   = base64_encode(gzcompress(json_encode($data)));
		$timestamp = microtime(true);
		$signature = $this->getSignature($message, $timestamp, $this->_secretKey);

		return $this->sendRemote($this->_serverUrl, $message, [
			'User-Agent'    => $this->_clientName,
			'X-Sentry-Auth' => $this->getAuthHeader($signature, $timestamp, $this->_clientName, $this->_publicKey),
			'Content-Type'  => 'application/octet-stream',
		]);
	}

	private function sendRemote($url, $data, $headers) {

		$parts = (array) parse_url($url); // (yes)
		$parts['netloc'] = $parts['host'].(isset($parts['port']) ? ':'.$parts['port'] : null);

		if ($parts['scheme'] == 'udp') {

			if (is_array($this->_reports)) {
				$this->_reports[] = ['type' => 'sendUdp', 'url' => $parts['netloc'], 'data' => $data, 'headers' => $headers['X-Sentry-Auth']];
				return true;
			}

			return $this->sendUdp($parts['netloc'], $data, $headers['X-Sentry-Auth']);
		}

		if (is_array($this->_reports)) {
			$this->_reports[] = ['type' => 'sendHttp', 'url' => $url, 'data' => $data, 'headers' => $headers];
			return true;
		}

		return $this->sendHttp($url, $data, $headers);
	}

	private function sendUdp($netloc, $data, $headers) {

		[$host, $port] = explode(':', $netloc);
		$rawData = $headers."\n\n".$data;

		$sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
		socket_sendto($sock, $rawData, strlen($rawData), 0, $host, $port);
		socket_close($sock);

		return true;
	}

	private function sendHttp($url, $data, $headers) {

		$newHeaders = [];
		foreach ($headers as $key => $value)
			$newHeaders[] = $key.': '.$value;

		$curl = curl_init($url);
		curl_setopt($curl, CURLOPT_POST, 1);
		curl_setopt($curl, CURLOPT_HTTPHEADER, $newHeaders);
		curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
		curl_setopt($curl, CURLOPT_VERBOSE, false);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false); // yes
		curl_exec($curl);
		$code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		curl_close($curl);

		return $code == 200;
	}

	private function getSignature($message, $timestamp, $key) {
		return hash_hmac('sha1', sprintf('%F', $timestamp).' '.$message, $key);
	}

	private function getAuthHeader($signature, $timestamp, $client, $apiKey = null) {

		$header = [
			sprintf('sentry_timestamp=%F', $timestamp),
			'sentry_signature='.$signature,
			'sentry_client='.$client,
			'sentry_version=2.0',
		];

		if ($apiKey)
			$header[] = 'sentry_key='.$apiKey;

		return sprintf('Sentry %s', implode(', ', $header));
	}

	private function getUuid4() {
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

		// when running from command line the REQUEST_URI is missing
		if (empty($_SERVER['REQUEST_URI']))
			return '';

		$schema = (
			(!empty($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] != 'off')) ||
			(!empty($_SERVER['SERVER_PORT']) && ($_SERVER['SERVER_PORT'] == 443)) ||
			(!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && ($_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https'))
		) ? 'https://' : 'http://';

		return $schema.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
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

	// Raven_Stacktrace
	private function getStackInfo($stack) {

		$result = [];
		foreach ($stack as $frame) {

			if (isset($frame['file'])) {
				$context  = $this->readSourceFile($frame['file'], $frame['line']);
				$absPath  = $frame['file'];
				$fileName = basename($frame['file']);
			}
			else {
				if (isset($frame['args']))
					$args = is_string($frame['args']) ? $frame['args'] : @json_encode($frame['args']);
				else
					$args = 'n/a';

				if (isset($frame['class']))
					$context['line'] = sprintf('%s%s%s(%s)', $frame['class'], $frame['type'], $frame['function'], $args);
				else
					$context['line'] = sprintf('%s(%s)', $frame['function'], $args);

				$absPath  = '';
				$fileName = '[Anonymous function]';
				$context['prefix'] = [];
				$context['suffix'] = [];
				$context['filename'] = $fileName;
				$context['lineno'] = 0;
			}

			$module = $fileName;
			if (isset($frame['class']))
				$module .= ':'.$frame['class'];

			$result[] = [
				'abs_path'     => $absPath,
				'filename'     => $context['filename'],
				'lineno'       => $context['lineno'],
				'module'       => $module,
				'function'     => $frame['function'],
				'vars'         => [],
				'pre_context'  => $context['prefix'],
				'context_line' => $context['line'],
				'post_context' => $context['suffix'],
			];
		}

		return array_reverse($result);
	}

	private function readSourceFile($fileName, $lineNo) {

		$frame = [
			'prefix'   => [],
			'line'     => '',
			'suffix'   => [],
			'filename' => $fileName,
			'lineno'   => $lineNo,
		];

		if (($fileName === null) || ($lineNo === null))
			return $frame;

		// Code which is eval'ed have a modified filename.. Extract the
		// correct filename + linenumber from the string.
		$matched = preg_match("/^(.*?)\((\d+)\) : eval\(\)'d code$/", $fileName, $matches);
		if ($matched) {
			[, $fileName, $lineNo] = $matches;
			$frame['filename'] = $fileName;
			$frame['lineno']   = $lineNo;
		}

		// Try to open the file. We wrap this in a try/catch block in case
		// someone has modified the error_trigger to throw exceptions.
		try {
			$fh = fopen($fileName, 'rb');
			if ($fh === false)
				return $frame;
		}
		catch (Throwable $t) {
			return $frame;
		}

		$cur_lineno = 0;
		while (!feof($fh)) {

			$cur_lineno++;
			$line = fgets($fh);

			if ($cur_lineno == $lineNo)
				$frame['line'] = $line;
			else if ($lineNo - $cur_lineno > 0 && $lineNo - $cur_lineno < 3)
				$frame['prefix'][] = $line;
			else if ($line && $lineNo - $cur_lineno > -3 && $lineNo - $cur_lineno < 0)
				$frame['suffix'][] = $line; // when line is false, it can be eof, so ignore it
		}
		fclose($fh);

		return $frame;
	}

	// Raven_SanitizeData
	private function apply($value, $key = null) {

		if (is_array($value)) {

			foreach ($value as $k => $v)
				$value[$k] = $this->apply($v, $k);

			return $value;
		}

		return $this->sanitize($key, $value);
	}

	private function sanitize($key, $value) {

		if (empty($value))
			return $value;

		if (is_object($value))
			return '#OBJECT! '.get_class($value);

		if (preg_match('/^\d{16}$/', (string) $value))
			return '********';

		if (preg_match('/(authorization|password|passwd|secret)/i', (string) $key))
			return '********';

		return $value;
	}
}