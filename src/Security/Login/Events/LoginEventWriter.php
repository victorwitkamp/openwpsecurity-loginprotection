<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events;

use VictorWitkamp\OpenWPSecurity\Core\Logging\EventWriter as CoreEventWriter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginEventWriter extends CoreEventWriter {
	public function __construct( LoginEventTable $login_event_table, LoginEventSchema $login_event_schema ) {
		parent::__construct( $login_event_table, $login_event_schema->table_schema() );
	}
}
