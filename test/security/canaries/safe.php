<?php

declare(strict_types=1);

namespace OPNsense\SSO\SecurityCanary;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\SSO\ReturnUrl;

final class SafeController extends ApiControllerBase
{
	public function redirect(): void
	{
		$this->response->redirect(ReturnUrl::sanitize((string)$this->request->get('url')));
	}


	public function html(): void
	{
		echo htmlspecialchars((string)$this->request->get('value'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
	}


	public function backend(): void
	{
		// configdpRun quotes structured parameters; the action name is literal.
		(new Backend())->configdpRun('sso vpn_kill', [(string)$this->request->get('username')]);
	}
}
