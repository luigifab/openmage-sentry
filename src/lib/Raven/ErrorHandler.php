<?php
/**
 * This file is part of Raven.
 *
 * (c) Sentry Team
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code (BSD-3-Clause).
 */

class Raven_ErrorHandler {

	private $oldExceptionHandler;
	private $callExistingExceptionHandler = false;
	private $oldErrorHandler;
	private $callExistingErrorHandler = false;

	public function __construct($client) {
		$this->client = $client;
	}

	public function handleException($e, $isError = false) {
		$e->event_id = $this->client->getIdent($this->client->captureException($e));
		if (!$isError && $this->callExistingExceptionHandler && $this->oldExceptionHandler)
			call_user_func($this->oldExceptionHandler, $e);
	}

	public function handleError($code, $message, $file = '', $line = 0, $context = []) {
		$e = new ErrorException($message, 0, $code, $file, $line);
		$this->handleException($e, true);
		if ($this->callExistingErrorHandler && $this->oldErrorHandler)
			call_user_func($this->oldErrorHandler, $code, $message, $file, $line, $context);
	}

	public function registerExceptionHandler($callExistingExceptionHandler = true) {
		$this->oldExceptionHandler = set_exception_handler([$this, 'handleException']);
		$this->callExistingExceptionHandler = $callExistingExceptionHandler;
	}

	public function registerErrorHandler($callExistingErrorHandler = true, $error_types = E_ALL) {
		$this->oldErrorHandler = set_error_handler([$this, 'handleError'], $error_types);
		$this->callExistingErrorHandler = $callExistingErrorHandler;
	}
}