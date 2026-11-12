<?php

declare(strict_types=1);

T::group('Request objects: failed publication never returns an id');
foreach (['write', 'short-write', 'chmod', 'rename'] as $failure) {
	$pipes = [];
	$process = proc_open(
		[PHP_BINARY, dirname(__DIR__) . '/integration/request_object_store.php', $failure],
		[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
		$pipes,
	);
	if (!is_resource($process)) {
		T::ko('publication subprocess starts', $failure);
		continue;
	}
	fclose($pipes[0]);
	$output = stream_get_contents($pipes[1]);
	$error = stream_get_contents($pipes[2]);
	fclose($pipes[1]);
	fclose($pipes[2]);
	eq(0, proc_close($process), 'failure fixture completes: ' . $failure . ' ' . $error);
	$result = json_decode($output, true);
	eq(false, $result['accepted'] ?? null, 'no id is returned after ' . $failure);
	eq([], $result['remaining'] ?? null, 'no temporary or published file survives ' . $failure);
}
