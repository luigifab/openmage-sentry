<?php
/**
 * AMG Sentry
 *
 * This source file is subject to the Open Software License (OSL 3.0)
 * that is bundled with this package in the file LICENSE.txt.
 * It is also available through the world-wide-web at this URL:
 * https://opensource.org/licenses/osl-3.0.php
 *
 * @category      AMG
 * @package       AMG_Sentry
 * @copyright     Copyright © 2012 Jean Roussel <contact@jean-roussel.fr>
 * @license       https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

require_once(Mage::getBaseDir('lib').'/Raven/Autoloader.php');
Raven_Autoloader::register();

class AMG_Sentry_Model_Client extends Raven_Client {

	protected static $_logger;

	public function __construct() {

		$data = [];
		$data['tags']['runtime'] = 'PHP '.PHP_VERSION;

		parent::__construct(Mage::getStoreConfig('dev/amg-sentry/dsn'), $data);
	}

	/**
	 * Send a message to Sentry.
	 *
	 * @param string $title Message title
	 * @param string $description Message description
	 * @param string $level Message level
	 * @return array|string Sentry event ID
	 */
	public function sendMessage($title, $description = '', $level = self::INFO) {
		return $this->captureMessage($title, ['description' => $description], $level);
	}

	/**
	 * Send an exception to Sentry.
	 *
	 * @param Exception $exception Exception
	 * @param string $description Exception description
	 * @return array|string Sentry event ID
	 */
	public function sendException($exception, $description = '') {
		return $this->captureException($exception, $description);
	}

	/**
	 * Log a message to sentry
	 */
	public function capture($data, $stack) {
		if (!Mage::getStoreConfigFlag('dev/amg-sentry/active')) {
			return true;
		}
		if (!empty($data['sentry.interfaces.Message']['params']['description'])) {
			$data['culprit'] = $data['message'];
			$data['message'] = $data['sentry.interfaces.Message']['params']['description'];
			unset($data['sentry.interfaces.Message']['params']['description']);
		}
		if (!empty($data['sentry.interfaces.Exception']['value'])) {
			$data['message'] = $data['culprit'] ?? 'n/a';
			$data['culprit'] = $data['sentry.interfaces.Exception']['value'];
		}
		if (!isset($data['logger'])) {
			if (self::$_logger !== null) {
				$data['logger'] = self::$_logger;
			} else {
				$data['logger'] = Mage::getStoreConfig('dev/amg-sentry/logger');
			}
		}
		return parent::capture($data, $stack);
	}

	/**
	 * Set Sentry logger
	 */
	public function setLogger($logger) {
		$this->_logger = $logger;
	}

	/**
	 * Reset Sentry logger
	 */
	public function resetLogger() {
		$this->_logger = null;
	}
}