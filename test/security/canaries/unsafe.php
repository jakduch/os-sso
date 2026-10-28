<?php

declare(strict_types=1);

namespace OPNsense\SSO\SecurityCanary;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\SSO\ReturnUrl;

// Analysis-only positive controls. Never load these fixtures in the plugin.
final class UnsafeController extends ApiControllerBase
{
	public function header(): void
	{
		$this->response->setHeader('X-Test', (string)$this->request->get('value')); // expect: TaintedHeader
	}


	public function body(): void
	{
		echo $this->request->getRawBody(); // expect: TaintedHtml
	}


	public function backend(): void
	{
		(new Backend())->configdpRun((string)$this->request->get('action')); // expect: TaintedShell
	}


	public function shell(): void
	{
		shell_exec((string)$this->request->get('command')); // expect: TaintedShell
	}


	public function html(): void
	{
		// A redirect validator does not make a path safe to render as HTML.
		echo ReturnUrl::sanitize((string)$this->request->get('value')); // expect: TaintedHtml
	}
}
