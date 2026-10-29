<?php
/**
 * Custom wpdb wrapper for Vandam-WP
 * Intercepts SQL database queries prior to application-level execution.
 */

if (!defined('ABSPATH')) {
    exit;
}

class Vandam_DB {
    public function __construct() {
        // Reserved for database query sanitization hooks if needed
    }
}
