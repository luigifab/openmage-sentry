<?php
/**
 * This file is part of Raven.
 *
 * (c) Sentry Team
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code (BSD-3-Clause).
 */

class Raven_Autoloader {

	public static function register() {
		ini_set('unserialize_callback_func', 'spl_autoload_call');
		spl_autoload_register([new self, 'autoload']);
	}

	public static function autoload($class) {

		if (strncmp($class, 'Raven', 5) !== 0)
			return;

		if (is_file($file = __DIR__ .'/../'.str_replace(['_', "\0"], ['/', ''], $class).'.php'))
			require $file;
	}
}