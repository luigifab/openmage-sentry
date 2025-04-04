<?php
/**
 * Created D/09/04/2023
 * Updated S/16/12/2023
 *
 * Copyright 2012      | Jean Roussel <contact~jean-roussel~fr>
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

class Luigifab_Sentry_Block_Help extends Mage_Adminhtml_Block_Abstract implements Varien_Data_Form_Element_Renderer_Interface {

	public function render(Varien_Data_Form_Element_Abstract $element) {

		$msg = '<a href="https://github.com/luigifab/openmage-sentry" style="margin:0;">github.com/luigifab/openmage-sentry</a>';

		$src = 'app/code/core/Mage/Core/Model/App.php';
		$app = file_get_contents(BP.'/'.$src);
		if (!str_contains($app, '$sentry = new Luigifab_Sentry_Model_Client();'))
			return '<div class="comment"><strong>INCOMPLETE MODULE INSTALLATION!</strong> Changes in <em>'.$src.'</em> are not present.<br />'.$msg.'</div>';

		global $sentry;
		if (!$sentry || !is_object($sentry))
			return '<div class="comment"><strong>INCOMPLETE MODULE INSTALLATION!</strong> The <em>$sentry</em> global variable is empty.<br />'.$msg.'</div>';

		return '<div class="comment">'.$msg.'</div>';
	}
}