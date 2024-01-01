<?php
/**
 * Created J/08/12/2022
 * Updated J/02/11/2023
 *
 * Copyright 2012      | Jean Roussel <contact~jean-roussel~fr>
 * Copyright 2022-2024 | Fabrice Creuzot (luigifab) <code~luigifab~fr>
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

class Luigifab_Sentry_Block_Test extends Mage_Adminhtml_Block_System_Config_Form_Field {

	public function render(Varien_Data_Form_Element_Abstract $element) {
		$element->unsScope()->unsCanUseWebsiteValue()->unsCanUseDefaultValue()->unsPath();
		return parent::render($element);
	}

	protected function _getElementHtml(Varien_Data_Form_Element_Abstract $element) {

		if (str_contains($element->getHtmlId(), 'php'))
			return sprintf('<input type="checkbox" name="%s" id="%s" />', $element->getHtmlId(), $element->getHtmlId());

		return sprintf('<button type="button" name="%s" id="%s" onclick="test();">Test</button>', $element->getHtmlId(), $element->getHtmlId());
	}
}