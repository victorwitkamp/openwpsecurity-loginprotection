<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Presentation\Templates;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class TemplateRenderer {
	public function render( string $template_name, array $variables = array() ): string {
		$template_path = OPENWPSECURITY_LOGINPROTECTION_DIR . 'templates/' . $template_name;

		if ( ! file_exists( $template_path ) ) {
			throw new \RuntimeException( 'Firewall template file was not found.' );
		}

		$this->enqueue_runtime_assets();

		ob_start();

		foreach ( $variables as $key => $value ) {
			${$key} = $value;
		}

		include $template_path;

		return (string) ob_get_clean();
	}

	private function enqueue_runtime_assets(): void {
		wp_enqueue_style(
			'openwpsecurity-loginprotection-runtime',
			OPENWPSECURITY_LOGINPROTECTION_URL . 'assets/css/runtime.css',
			array(),
			OPENWPSECURITY_LOGINPROTECTION_VERSION
		);

		wp_enqueue_script(
			'openwpsecurity-loginprotection-runtime',
			OPENWPSECURITY_LOGINPROTECTION_URL . 'assets/js/runtime.js',
			array(),
			OPENWPSECURITY_LOGINPROTECTION_VERSION,
			true
		);
	}
}
