<?php
/**
 * Plugin Name: vandam
 * Plugin URI: https://kinnector.dev/vandam/
 * Description: Application-level security engine for WordPress. Protects against RCE/LFI/RFI/SQLi and unauthorized access. Integrates with the vandam server agent when available.
 * Version: 1.1.0
 * Author: kinnector
 * Text Domain: vandam
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if (!defined('ABSPATH')) {
    exit;
}

define('VANDAM_VERSION',           '1.1.0');
define('VANDAM_PLUGIN_DIR',        plugin_dir_path(__FILE__));
define('VANDAM_PLUGIN_FILE',       __FILE__);
define('VANDAM_DATA_DIR',          VANDAM_PLUGIN_DIR . 'data/');
define('VANDAM_COMMUNITY_VULN_DB', VANDAM_DATA_DIR . 'vuln-plugins.json');
define('VANDAM_COMMUNITY_VULN_URL','https://raw.githubusercontent.com/kinnector/kinnector-protect-community/main/wordpress/vuln-plugins.json');

require_once VANDAM_PLUGIN_DIR . 'src/class-vandam-client.php';
require_once VANDAM_PLUGIN_DIR . 'src/class-vandam-admin.php';
require_once VANDAM_PLUGIN_DIR . 'src/class-vandam-db.php';

// Lifecycle hooks registered before singleton instantiation
register_activation_hook(VANDAM_PLUGIN_FILE,   ['Vandam_Helper', 'on_activation']);
register_deactivation_hook(VANDAM_PLUGIN_FILE, ['Vandam_Helper', 'on_deactivation']);

class Vandam_Helper {

    // ── Scoring engine: requests scoring at or above this are hard-blocked
    const BLOCK_THRESHOLD   = 50;
    // ── Email rate-limit: one alert per event_key per N seconds (24h)
    const EMAIL_COOLDOWN    = 86400;
    // ── Webhook rate-limit: one webhook per event_key per N seconds (15 min)
    const WEBHOOK_COOLDOWN  = 900;

    private static $instance = null;
    private $client;
    private $admin;
    private $vuln_data = null; // lazy-loaded once per request lifecycle

    // =========================================================================
    // SINGLETON
    // =========================================================================

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->client = new Vandam_Client();

        if (is_admin()) {
            $this->admin = new Vandam_Admin($this->client);
        }

        $this->init_security_hooks();
        $this->init_cron_hooks();
    }

    // =========================================================================
    // PLUGIN LIFECYCLE
    // =========================================================================

    /**
     * Runs on plugin activation.
     *
     * FP-2.1 Fix: Seeds approved admin list immediately from existing admins
     * so the first cron run never flags all legitimate admins as unauthorized.
     * FP-5.4 Fix: Establishes proper data directory structure.
     * FP-4.1/4.2 Fix: Runs uploads hardening with pre-scan on activation.
     */
    public static function on_activation() {
        $instance = self::get_instance();

        // ── Seed approved admins from current site admins
        if (empty(get_option('vandam_approved_admins', []))) {
            $users  = get_users(['role' => 'administrator', 'fields' => ['user_login']]);
            $logins = array_column($users, 'user_login');
            update_option('vandam_approved_admins', $logins);
        }

        // ── Ensure data directory exists for community vuln DB
        if (!is_dir(VANDAM_DATA_DIR)) {
            wp_mkdir_p(VANDAM_DATA_DIR);
        }

        // ── Download fresh community vuln DB
        $instance->refresh_community_vuln_db();

        // ── Write uploads hardening (with pre-scan + server check)
        $instance->harden_uploads_directory();

        // ── Schedule cron events
        if (!wp_next_scheduled('vandam_daily_scan')) {
            wp_schedule_event(time(), 'daily', 'vandam_daily_scan');
        }
        if (!wp_next_scheduled('vandam_filesystem_snapshot')) {
            wp_schedule_event(time(), 'vandam_6hourly', 'vandam_filesystem_snapshot');
        }
    }

    public static function on_deactivation() {
        wp_clear_scheduled_hook('vandam_daily_scan');
        wp_clear_scheduled_hook('vandam_filesystem_snapshot');
    }

    // =========================================================================
    // HOOK REGISTRATION
    // =========================================================================

    private function init_security_hooks() {
        // Register custom cron interval
        add_filter('cron_schedules', [$this, 'add_cron_intervals']);

        // ── init hook (after auth cookies parsed — gives us current_user_can())
        // Priority 1: main request scoring engine (Layer 2 + 3)
        add_action('init', [$this, 'validate_incoming_requests'], 1);
        // Priority 2: plugin-specific exploit signature guards (Layer 1)
        add_action('init', [$this, 'register_exploit_signature_guards'], 2);
        // Priority 3: output buffer anomaly detection (Layer 5)
        add_action('init', [$this, 'maybe_start_output_buffer'], 3);

        // ── Administrator escalation monitoring
        add_action('user_register',  [$this, 'scan_new_user_creation'],    10, 1);
        add_action('profile_update', [$this, 'scan_user_profile_update'],  10, 2);
        add_action('add_user_role',  [$this, 'scan_user_role_change'],     10, 2);
        add_action('set_user_role',  [$this, 'scan_user_role_change'],     10, 2);
        // FP-2.2 Fix: Multisite super admin escalation
        add_action('grant_super_admin', [$this, 'scan_super_admin_grant'], 10, 1);

        // ── Plugin install monitoring (webhook on every new plugin installed)
        add_action('upgrader_process_complete', [$this, 'on_upgrader_process_complete'], 10, 2);

        // ── Admin login & failed login monitoring
        add_action('wp_login',        [$this, 'on_admin_login'],        10, 2);
        add_action('wp_login_failed', [$this, 'on_admin_login_failed'], 10, 1);
    }

    public function add_cron_intervals($schedules) {
        $schedules['vandam_6hourly'] = [
            'interval' => 21600,
            'display'  => 'Every 6 Hours',
        ];
        return $schedules;
    }

    private function init_cron_hooks() {
        add_action('vandam_daily_scan',          [$this, 'run_daily_security_scans']);
        add_action('vandam_filesystem_snapshot', [$this, 'run_filesystem_snapshot']);

        if (!wp_next_scheduled('vandam_daily_scan')) {
            wp_schedule_event(time(), 'daily', 'vandam_daily_scan');
        }
        if (!wp_next_scheduled('vandam_filesystem_snapshot')) {
            wp_schedule_event(time(), 'vandam_6hourly', 'vandam_filesystem_snapshot');
        }
    }

    // =========================================================================
    // LAYER 1 — PLUGIN-SPECIFIC EXPLOIT SIGNATURE GUARDS
    // =========================================================================

    /**
     * Loads exploit signatures for installed vulnerable plugins and registers
     * targeted O(1) request guards per known CVE exploitation path.
     * Only runs for unauthenticated requests — zero cost for logged-in users.
     */
    public function register_exploit_signature_guards() {
        if (is_user_logged_in()) return;

        $vuln_data = $this->load_vuln_data();
        if (empty($vuln_data)) return;

        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $installed = get_plugins();

        foreach ($installed as $plugin_file => $plugin_data) {
            $slug    = $this->resolve_plugin_slug($plugin_file, $plugin_data);
            $version = $plugin_data['Version'];

            foreach ($vuln_data as $vuln) {
                if ($vuln['slug'] !== $slug)                    continue;
                if (!$this->is_version_vulnerable($version, $vuln)) continue;
                if (empty($vuln['exploit_signatures']))          continue;

                foreach ($vuln['exploit_signatures'] as $sig) {
                    $this->evaluate_exploit_signature($sig, $vuln);
                }
            }
        }
    }

    /**
     * Evaluates one exploit signature against the current request immediately.
     */
    private function evaluate_exploit_signature(array $sig, array $vuln) {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $method      = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

        // Method constraint
        if (!empty($sig['method']) && $sig['method'] !== '*') {
            if ($method !== strtoupper($sig['method'])) return;
        }

        // Context constraint
        if (!empty($sig['context']) && $sig['context'] === 'unauthenticated_only') {
            if (is_user_logged_in()) return;
        }

        $matched = false;
        switch ($sig['type']) {
            case 'request_path':
                $matched = strpos($request_uri, $sig['match']) !== false;
                break;

            case 'request_param':
                $key = $sig['key'] ?? '';
                $val = (string) ($_GET[$key] ?? $_POST[$key] ?? '');
                if (!empty($sig['match_any']) && is_array($sig['match_any'])) {
                    foreach ($sig['match_any'] as $m) {
                        if (stripos($val, $m) !== false) { $matched = true; break; }
                    }
                } elseif (!empty($sig['match'])) {
                    $matched = stripos($val, $sig['match']) !== false;
                }
                break;

            case 'file_extension':
                foreach ($_FILES as $file) {
                    $names = is_array($file['name']) ? $file['name'] : [$file['name']];
                    foreach ($names as $name) {
                        $parts = explode('.', strtolower((string) $name));
                        foreach ($parts as $ext) {
                            if ($ext === strtolower($sig['match'])) { $matched = true; break 2; }
                        }
                    }
                }
                break;
        }

        if (!$matched) return;

        $this->log_security_event('Threat.Server.WordPressAnomaly', [
            'type'   => 'Exploit_Signature_Match',
            'cve'    => $vuln['cve']  ?? 'N/A',
            'slug'   => $vuln['slug'] ?? '',
            'detail' => sprintf('Active exploit signature matched for installed vulnerable plugin "%s" (%s)', $vuln['slug'], $vuln['cve'] ?? 'N/A'),
            'sig'    => $sig,
        ]);

        if (($sig['action'] ?? 'log') === 'block') {
            $this->render_block_page('Exploit Signature Match');
        }
    }

    // =========================================================================
    // LAYER 2 + 3 — SCORING ENGINE + WRAPPER/TRAVERSAL/FILE UPLOAD INTERCEPTORS
    // =========================================================================

    /**
     * Main request validation entry point (init priority 1).
     *
     * Replaces the old block-or-pass single-pattern approach with a weighted
     * threat scoring engine. Requests scoring >= BLOCK_THRESHOLD are hard-blocked.
     * Requests scoring >= 20 are logged only (suspicious, not blocked).
     *
     * FP-1.1/1.5 Fix: $_COOKIE removed from scan scope entirely.
     * FP-1.3 Fix:     Backtick pattern removed; replaced by context-aware scoring.
     * FP-1.4 Fix:     Shell keyword patterns replaced by scored signals requiring operators.
     */
    public function validate_incoming_requests() {
        // Skip validation for WP-CLI or authorized users to prevent false positives on admin actions
        if (defined('WP_CLI') && WP_CLI) {
            return;
        }
        if (is_user_logged_in() && (current_user_can('edit_posts') || current_user_can('read'))) {
            return;
        }

        $score   = 0;
        $signals = [];

        // ── Scan scope: GET, POST, and raw body only — NO $_COOKIE (FP-1.5 fix)
        $raw_input = file_get_contents('php://input');
        $request_data = [
            'GET'  => $_GET,
            'POST' => $_POST,
        ];
        if (!empty($raw_input) && strlen($raw_input) <= 65536) {
            $request_data['RAW'] = [$raw_input];
        }

        // Walk all string values through the scoring engine
        $accumulate = function ($value) use (&$score, &$signals) {
            if (!is_string($value) || strlen($value) < 3) return;
            $result  = $this->score_value($value);
            $score  += $result['score'];
            $signals  = array_merge($signals, $result['signals']);
        };
        array_walk_recursive($request_data, $accumulate);

        // ── Unauthenticated access to admin-area paths
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        if (!is_user_logged_in() && strpos($uri, '/wp-admin/') !== false) {
            $score += 25;
            $signals[] = 'Unauthenticated request to wp-admin path';
        }

        // ── Known scanner / exploit tool User-Agents
        $ua = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
        foreach (['sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'nuclei', 'wpscan', 'dirbuster', 'hydra'] as $s) {
            if (strpos($ua, $s) !== false) {
                $score += 20;
                $signals[] = "Scanner UA: $s";
                break;
            }
        }

        // ── Layer 3: $_FILES audit (only when a file upload is present)
        if (!empty($_FILES)) {
            $file_result = $this->audit_file_uploads();
            $score      += $file_result['score'];
            $signals     = array_merge($signals, $file_result['signals']);
        }

        if ($score >= self::BLOCK_THRESHOLD) {
            $detail = sprintf('Threat score %d exceeded block threshold %d', $score, self::BLOCK_THRESHOLD);
            $this->log_security_event('Threat.Server.WordPressAnomaly', [
                'type'    => 'RCE_Attempt',
                'detail'  => $detail,
                'signals' => $signals,
                'uri'     => $uri,
            ]);
            $this->send_webhook_notification('rce_attempt', [
                'event'   => 'Possible RCE Attempt Blocked',
                'detail'  => $detail,
                'signals' => $signals,
                'uri'     => $uri,
                'ip'      => $_SERVER['REMOTE_ADDR'] ?? '',
                'score'   => $score,
            ], 'rce_' . md5($uri . implode(',', $signals)));
            $this->render_block_page('Threat Score Threshold Exceeded');
        }

        if ($score >= 20) {
            $this->log_security_event('Threat.Server.WordPressAnomaly', [
                'type'    => 'Suspicious_Request',
                'detail'  => sprintf('Threat score %d (below block threshold — logged only)', $score),
                'signals' => $signals,
                'uri'     => $uri,
            ]);
        }
    }

    /**
     * Scores a single string value across all Layer 2 + 3 signal categories.
     * Pure function — no side effects, returns ['score' => int, 'signals' => string[]].
     */
    private function score_value(string $value): array {
        $score   = 0;
        $signals = [];

        // ── PHP stream wrappers (LFI / RFI primary vectors)
        static $wrappers = [
            'php://', 'data://', 'zip://', 'phar://', 'expect://', 'glob://', 'ftp://',
            'php%3a%2f%2f', 'data%3a%2f%2f',   // URL-encoded
            'php%253a%252f%252f',               // Double URL-encoded
        ];
        foreach ($wrappers as $w) {
            if (stripos($value, $w) !== false) {
                $score += 40; $signals[] = "PHP stream wrapper: $w"; break;
            }
        }

        // ── Path traversal sequences
        static $traversals = ['../', '..\\.', '%2e%2e%2f', '%2e%2e/', '..%2f', '%252e%252e', '....//'];
        foreach ($traversals as $t) {
            if (stripos($value, $t) !== false) {
                $score += 30; $signals[] = "Path traversal: $t"; break;
            }
        }

        // ── Null byte injection
        if (strpos($value, "\x00") !== false || stripos($value, '%00') !== false) {
            $score += 35; $signals[] = 'Null byte injection';
        }

        // ── Double URL encoding (evasion attempt)
        if (preg_match('/%25[0-9a-fA-F]{2}/', $value)) {
            $score += 30; $signals[] = 'Double URL encoding';
        }

        // ── Known LFI target strings
        static $lfi_targets = ['/etc/passwd', '/etc/shadow', '/etc/hosts', 'wp-config.php', '/proc/self/environ', '/proc/version'];
        foreach ($lfi_targets as $t) {
            if (stripos($value, $t) !== false) {
                $score += 45; $signals[] = "Known LFI target: $t"; break;
            }
        }

        // ── PHP execution function calls (narrow: only score actual call syntax)
        if (preg_match('/\b(system|shell_exec|passthru|exec|proc_open|popen|assert)\s*\(/i', $value)) {
            $score += 20; $signals[] = 'PHP execution function call';
        }
        if (preg_match('/\beval\s*\(/i', $value)) {
            $score += 30; $signals[] = 'eval() call';
        }
        // preg_replace /e modifier (code execution via regex)
        if (preg_match('/preg_replace\s*\(.*\/[a-z]*e[a-z]*[\'\"]/i', $value)) {
            $score += 35; $signals[] = 'preg_replace /e modifier (code execution)';
        }

        // ── Base64 decode: only flag if the ENTIRE value is base64 AND decodes to dangerous content
        // (FP-1.2 fix: avoids flagging partial base64 in normal form data / nonces)
        if (preg_match('/^[A-Za-z0-9+\/]{32,}={0,2}$/', trim($value))) {
            $decoded = base64_decode($value, true);
            if ($decoded !== false && preg_match('/\b(system|eval|exec|shell_exec|passthru|proc_open)\s*\(/i', $decoded)) {
                $score += 40; $signals[] = 'Base64-encoded PHP execution payload';
            }
        }

        // ── data:// URI with embedded code (RFI via data wrapper)
        if (preg_match('/data:\s*(text\/html|text\/plain|application\/octet-stream).*<\?php/i', $value)) {
            $score += 50; $signals[] = 'data:// URI with embedded PHP';
        }

        return ['score' => $score, 'signals' => $signals];
    }

    /**
     * Layer 3: Audits $_FILES for upload bypass techniques.
     * Catches: double extensions, MIME/extension mismatch, PHP content in files.
     */
    private function audit_file_uploads(): array {
        $score   = 0;
        $signals = [];

        static $dangerous_exts = [
            'php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'php7',
            'pht', 'phps', 'shtml', 'shtm', 'cgi', 'pl', 'py', 'asp', 'aspx',
        ];

        foreach ($_FILES as $file) {
            $names = is_array($file['name']) ? $file['name'] : [$file['name']];
            $types = is_array($file['type']) ? $file['type'] : [$file['type']];
            $tmps  = is_array($file['tmp_name']) ? $file['tmp_name'] : [$file['tmp_name']];

            foreach ($names as $i => $name) {
                if (empty($name)) continue;

                // Double-extension bypass: check all extension parts
                $parts     = explode('.', strtolower((string) $name));
                $final_ext = end($parts);
                array_shift($parts); // remove basename

                foreach ($parts as $ext) {
                    if (in_array($ext, $dangerous_exts, true)) {
                        $score += 50; $signals[] = "Dangerous extension in upload: .$ext ($name)"; break;
                    }
                }

                // MIME vs final extension mismatch
                $claimed_mime = strtolower($types[$i] ?? '');
                if (in_array($claimed_mime, ['image/jpeg', 'image/png', 'image/gif'], true) &&
                    in_array($final_ext, $dangerous_exts, true)) {
                    $score += 20; $signals[] = "MIME/extension mismatch: $claimed_mime but .$final_ext";
                }

                // Content inspection: PHP opening tag in uploaded file
                $tmp = $tmps[$i] ?? '';
                if (!empty($tmp) && is_readable($tmp)) {
                    $header = (string) file_get_contents($tmp, false, null, 0, 512);
                    if (strpos($header, '<?php') !== false || strpos($header, '<?=') !== false) {
                        $score += 60; $signals[] = "PHP code detected in uploaded file: $name";
                    }
                }
            }
        }

        return ['score' => $score, 'signals' => $signals];
    }

    // =========================================================================
    // LAYER 5 — OUTPUT BUFFER ANOMALY DETECTION
    // =========================================================================

    /**
     * Starts PHP output buffering for unauthenticated requests only when
     * at least one actively-exploited vulnerable plugin is installed (set by
     * daily scan). Catches successful runtime exploitation that evaded all
     * earlier request-level checks.
     */
    public function maybe_start_output_buffer() {
        return; // Vetting disabled per request
        if (is_user_logged_in())                           return;
        if (empty(get_transient('vandam_active_exploits'))) return;

        ob_start([$this, 'analyze_output_buffer']);
    }

    /**
     * Registered as ob_start() callback — runs after WordPress outputs the page.
     * Scans response for indicators of successful exploitation.
     */
    public function analyze_output_buffer(string $output): string {
        static $indicators = [
            '/root:x:0:0:root/'                    => '/etc/passwd read',
            '/uid=\d+\(\w+\)\s+gid=\d+/'          => 'id command output',
            '/drwx[-r][-w][-x]/'                   => 'ls -la directory listing',
            '/PHP Fatal error.*in\s+\//'            => 'Internal path leak via PHP error',
            '/Warning:.*include.*failed to open/i' => 'Include path disclosure',
        ];

        foreach ($indicators as $pattern => $label) {
            if (preg_match($pattern, $output)) {
                $this->log_security_event('Threat.Server.WordPressAnomaly', [
                    'type'     => 'Active_Exploitation_Detected',
                    'detail'   => "Output buffer: $label found in HTTP response — possible successful exploitation",
                    'evidence' => substr($output, 0, 1024),
                ]);
                $this->send_alert_email(
                    '[Vandam CRITICAL] Active Exploitation Detected',
                    "Vandam detected signs of successful exploitation in your site's HTTP response output.\n\nSignal: $label\n\nReview your server logs immediately.",
                    'active_exploitation'
                );
                $this->send_webhook_notification('possible_compromise', [
                    'event'   => 'Possible Compromise: Active Exploitation Detected',
                    'detail'  => "Output anomaly detected in HTTP response: $label",
                    'signal'  => $label,
                    'site'    => get_site_url(),
                ], 'active_exploitation');
                status_header(500);
                return '<h1>Internal Server Error</h1>';
            }
        }

        return $output;
    }

    // =========================================================================
    // ADMINISTRATOR ESCALATION MONITORING
    // =========================================================================

    public function scan_new_user_creation(int $user_id) {
        $user = get_userdata($user_id);
        if ($user && in_array('administrator', (array) $user->roles)) {
            $this->flag_admin_escalation($user_id, 'New Registration');
        }
    }

    public function scan_user_profile_update(int $user_id, $old_user_data) {
        $user = get_userdata($user_id);
        if ($user && in_array('administrator', (array) $user->roles) &&
            !in_array('administrator', (array) $old_user_data->roles)) {
            $this->flag_admin_escalation($user_id, 'Role Upgrade');
        }
    }

    public function scan_user_role_change(int $user_id, string $role) {
        if ($role === 'administrator') {
            $this->flag_admin_escalation($user_id, 'Direct Role Set');
        }
    }

    /** FP-2.2 Fix: Multisite super admin escalation hook. */
    public function scan_super_admin_grant(int $user_id) {
        $this->flag_admin_escalation($user_id, 'Super Admin Grant (Multisite)');
    }

    private function flag_admin_escalation(int $user_id, string $context_type) {
        $user = get_userdata($user_id);
        if (!$user) return;

        $daemon_active = $this->client->is_daemon_active();
        $event_details = [
            'user_id'    => $user_id,
            'user_login' => $user->user_login,
            'user_email' => $user->user_email,
            'context'    => $context_type,
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
        ];

        if ($daemon_active) {
            $this->client->send_daemon_event('user-mgmt', ['action' => 'admin_added', 'details' => $event_details]);
            return;
        }

        // Shared hosting: check if the creator is authorized
        // FP-2.3 Fix: accept manage_options (restricted reseller admins) as well as create_users
        $creator_authorized =
            current_user_can('create_users') ||
            current_user_can('manage_options') ||
            php_sapi_name() === 'cli' ||
            (defined('WP_CLI') && WP_CLI);

        $approved = get_option('vandam_approved_admins', []);

        if ($creator_authorized) {
            // Auto-approve and add to allowlist
            if (!in_array($user->user_login, $approved, true)) {
                $approved[] = $user->user_login;
                update_option('vandam_approved_admins', $approved);
            }
            return;
        }

        if (!in_array($user->user_login, $approved, true)) {
            $this->log_security_event('Threat.Server.WordPressAnomaly', [
                'type'     => 'Unauthorized_Admin_Escalation',
                'detail'   => sprintf('New administrator "%s" created without approved session context.', $user->user_login),
                'metadata' => $event_details,
            ]);
            // FP-6.2 Fix: rate-limited email
            $this->send_alert_email(
                '[Vandam Security Alert] Unauthorized Administrator Added',
                sprintf("A new administrator account was registered outside an authorized session.\n\nLogin: %s\nContext: %s\nIP: %s\n\nIf this was not you, audit and remove the account immediately.", $user->user_login, $context_type, $event_details['ip_address']),
                'admin_escalation_' . $user->user_login
            );
            $this->send_webhook_notification('possible_hijack', [
                'event'      => 'Possible Account Hijack: Unauthorized Admin Added',
                'detail'     => sprintf('New administrator "%s" created without an approved session context (%s).', $user->user_login, $context_type),
                'user_login' => $user->user_login,
                'user_email' => $user->user_email,
                'context'    => $context_type,
                'ip'         => $event_details['ip_address'],
                'site'       => get_site_url(),
            ], 'admin_escalation_' . $user->user_login);
        } else {
            // Authorized admin added — still notify (informational)
            $this->send_webhook_notification('new_admin', [
                'event'      => 'New Administrator Added',
                'detail'     => sprintf('Administrator "%s" was added by an authorized session (%s).', $user->user_login, $context_type),
                'user_login' => $user->user_login,
                'user_email' => $user->user_email,
                'context'    => $context_type,
                'ip'         => $event_details['ip_address'],
                'site'       => get_site_url(),
            ], 'new_admin_' . $user->user_login);
        }
    }

    // =========================================================================
    // ADMIN LOGIN MONITORING
    // =========================================================================

    /**
     * Fires on every successful wp_login. Records the event to
     * vandam_admin_login_history (capped at 200) and dispatches a
     * webhook, rate-limited to one per admin user per hour.
     */
    public function on_admin_login(string $user_login, WP_User $user) {
        if (!in_array('administrator', (array) $user->roles, true)) return;

        $entry = [
            'user_login' => $user_login,
            'user_email' => $user->user_email,
            'ip'         => $_SERVER['REMOTE_ADDR']     ?? '',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'timestamp'  => time(),
            'failed'     => false,
        ];

        $history = get_option('vandam_admin_login_history', []);
        array_unshift($history, $entry);
        if (count($history) > 200) array_pop($history);
        update_option('vandam_admin_login_history', $history);

        $this->send_webhook_notification('admin_login', [
            'event'      => 'Administrator Login',
            'detail'     => sprintf('Administrator "%s" logged in successfully from %s.', $user_login, $entry['ip']),
            'user_login' => $user_login,
            'user_email' => $user->user_email,
            'ip'         => $entry['ip'],
            'user_agent' => $entry['user_agent'],
            'site'       => get_site_url(),
        ], 'admin_login_' . $user_login . '_' . floor(time() / 3600));
    }

    /**
     * Fires on every failed wp_login attempt. Records the event if the
     * username belongs to a known administrator, then fires a
     * possible_hijack webhook when ≥ 3 failures occur within 10 minutes
     * (brute-force heuristic).
     */
    public function on_admin_login_failed(string $username) {
        $user = get_user_by('login', $username);
        if (!$user || !in_array('administrator', (array) $user->roles, true)) return;

        $entry = [
            'user_login' => $username,
            'user_email' => $user->user_email,
            'ip'         => $_SERVER['REMOTE_ADDR']     ?? '',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'timestamp'  => time(),
            'failed'     => true,
        ];

        $history = get_option('vandam_admin_login_history', []);
        array_unshift($history, $entry);
        if (count($history) > 200) array_pop($history);
        update_option('vandam_admin_login_history', $history);

        // Brute-force heuristic: ≥ 3 failures for this user in the last 10 minutes
        $cutoff   = time() - 600;
        $failures = array_filter(
            $history,
            fn($e) => !empty($e['failed'])
                && ($e['timestamp'] ?? 0) >= $cutoff
                && ($e['user_login'] ?? '') === $username
        );

        if (count($failures) >= 3) {
            $this->log_security_event('Threat.Server.WordPressAnomaly', [
                'type'   => 'Admin_Brute_Force',
                'detail' => sprintf('%d failed login attempts for "%s" in 10 min from %s.', count($failures), $username, $entry['ip']),
            ]);
            $this->send_webhook_notification('possible_hijack', [
                'event'      => 'Possible Brute-Force: Repeated Admin Login Failures',
                'detail'     => sprintf('%d failed login attempts for admin "%s" in the last 10 minutes from IP %s.', count($failures), $username, $entry['ip']),
                'user_login' => $username,
                'ip'         => $entry['ip'],
                'failures'   => count($failures),
                'site'       => get_site_url(),
            ], 'brute_force_' . $username . '_' . floor(time() / 600));
        }
    }

    // =========================================================================
    // CRON — DAILY SECURITY SCANS
    // =========================================================================

    public function run_daily_security_scans() {
        $this->sync_daemon_alerts();
        $this->refresh_community_vuln_db();
        $this->audit_core_checksums();
        $this->scan_and_update_vulnerable_plugins();
        $this->audit_database_admins();
    }

    /**
     * Daily database audit for stealth-injected admin accounts.
     * FP-2.1 Fix: Initialization is now done on activation, so empty approved
     * list here is only a genuine edge case — still handled safely.
     */
    public function audit_database_admins() {
        global $wpdb;

        $meta_key  = $wpdb->prefix . 'capabilities';
        $admin_ids = $wpdb->get_col(
            $wpdb->prepare(
                "SELECT user_id FROM $wpdb->usermeta WHERE meta_key = %s AND meta_value LIKE %s",
                $meta_key, '%administrator%'
            )
        );

        $current_logins = [];
        foreach ($admin_ids as $id) {
            $login = $wpdb->get_var($wpdb->prepare("SELECT user_login FROM $wpdb->users WHERE ID = %d", $id));
            if ($login) $current_logins[] = $login;
        }

        $approved = get_option('vandam_approved_admins', []);
        // Edge-case safety: if empty, seed now and return
        if (empty($approved)) {
            update_option('vandam_approved_admins', $current_logins);
            return;
        }

        foreach ($current_logins as $login) {
            if (!in_array($login, $approved, true)) {
                $this->log_security_event('Threat.Server.WordPressAnomaly', [
                    'type'   => 'Stealth_Admin_Injected',
                    'detail' => sprintf('Unapproved administrator "%s" found in database audit.', $login),
                ]);
                $this->send_alert_email(
                    '[Vandam Alert] Unauthorized Admin Account Discovered',
                    sprintf("Database audit discovered an unapproved administrator account: %s\n\nThis may indicate direct database manipulation by an attacker.", $login),
                    'stealth_admin_' . $login
                );
                $this->send_webhook_notification('possible_hijack', [
                    'event'      => 'Possible Site Hijack: Stealth Admin Injected',
                    'detail'     => sprintf('Unapproved administrator "%s" found via database audit — possible direct DB manipulation.', $login),
                    'user_login' => $login,
                    'site'       => get_site_url(),
                ], 'stealth_admin_' . $login);
            }
        }
    }

    /**
     * Core file checksum auditor.
     * FP-3.1 Fix: 'missing' PHP files → warning; 'modified' files → critical.
     * FP-3.2 Fix: Fetches $wp_version fresh from the DB via get_bloginfo().
     */
    private function audit_core_checksums() {
        // FP-3.2: get_bloginfo('version') reads fresh from DB; avoids stale global
        $wp_version = get_bloginfo('version');
        $locale     = get_locale();

        $response = wp_remote_get("https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}&locale={$locale}");
        if (is_wp_error($response)) return;

        $data = json_decode(wp_remote_retrieve_body($response), true);
        if (!isset($data['checksums'])) return;

        // FP-3.1: non-critical files excluded from mismatch tracking
        static $skip_patterns = ['wp-config-sample.php', 'readme.html', 'license.txt'];

        $modified = [];
        $missing  = [];

        foreach ($data['checksums'] as $file => $expected_hash) {
            $skip = false;
            foreach ($skip_patterns as $pattern) {
                if (strpos($file, $pattern) !== false) { $skip = true; break; }
            }
            if ($skip) continue;

            $local_file = ABSPATH . $file;
            if (!file_exists($local_file)) {
                // FP-3.1: Only flag missing PHP files — locale/translation files are optional
                if (pathinfo($file, PATHINFO_EXTENSION) === 'php') {
                    $missing[] = ['file' => $file, 'status' => 'missing'];
                }
                continue;
            }

            if (md5_file($local_file) !== $expected_hash) {
                $modified[] = ['file' => $file, 'status' => 'modified'];
            }
        }

        // FP-3.1: Two separate events with different severity
        if (!empty($modified)) {
            $detail = sprintf('%d core file(s) have been MODIFIED from official checksums.', count($modified));
            $this->log_security_event('Threat.Server.WordPressAnomaly', [
                'type'       => 'Core_File_Integrity_Failure',
                'severity'   => 'critical',
                'detail'     => $detail,
                'mismatches' => $modified,
            ]);
            $this->send_webhook_notification('possible_compromise', [
                'event'      => 'Possible Compromise: Core File Tampering',
                'detail'     => $detail,
                'files'      => array_column($modified, 'file'),
                'site'       => get_site_url(),
            ], 'core_modified_' . md5(serialize($modified)));
        }
        if (!empty($missing)) {
            $this->log_security_event('Threat.Server.WordPressAnomaly', [
                'type'     => 'Core_File_Missing',
                'severity' => 'warning',
                'detail'   => sprintf('%d expected core PHP file(s) are absent from installation.', count($missing)),
                'missing'  => $missing,
            ]);
        }
    }

    /**
     * Scans installed plugins against the vuln DB and auto-updates critical ones.
     *
     * FP-5.4 Fix: Uses VANDAM_COMMUNITY_VULN_DB constant (plugin-relative) — NOT hardcoded dev path.
     * FP-5.1 Fix: Better slug resolution via resolve_plugin_slug().
     * FP-5.2 Fix: Non-semver version strings are skipped.
     * FP-5.3 Fix: Autoupdate runs only for 'critical' severity.
     */
    private function scan_and_update_vulnerable_plugins() {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $installed = get_plugins();
        $vuln_data = $this->load_vuln_data();
        if (empty($vuln_data)) return;

        $flagged         = [];
        $active_exploits = [];

        foreach ($installed as $plugin_file => $plugin_data) {
            $slug    = $this->resolve_plugin_slug($plugin_file, $plugin_data);
            $version = $plugin_data['Version'];

            // FP-5.2: Skip non-semver (date-versioned, RC, beta) plugins
            if (!$this->is_semver($version)) continue;

            foreach ($vuln_data as $vuln) {
                if ($vuln['slug'] !== $slug)                    continue;
                if (!$this->is_version_vulnerable($version, $vuln)) continue;

                $flagged[] = [
                    'file'            => $plugin_file,
                    'name'            => $plugin_data['Name'],
                    'slug'            => $slug,
                    'current_version' => $version,
                    'patched_version' => $vuln['patched_version'] ?? '',
                    'severity'        => $vuln['severity']        ?? 'low',
                    'cve'             => $vuln['cve']             ?? '',
                    'description'     => $vuln['description']     ?? '',
                ];

                if (!empty($vuln['actively_exploited'])) {
                    $active_exploits[] = $slug;
                }
            }
        }

        // Update Layer 5 transient so output buffer knows which plugins are hot-exploited
        if (!empty($active_exploits)) {
            set_transient('vandam_active_exploits', array_unique($active_exploits), 86400);
        } else {
            delete_transient('vandam_active_exploits');
        }

        if (empty($flagged)) return;

        $this->log_security_event('Threat.Server.WordPressAnomaly', [
            'type'    => 'Vulnerable_Plugins_Detected',
            'detail'  => sprintf('Discovered %d vulnerable plugin(s) active on this server.', count($flagged)),
            'plugins' => $flagged,
        ]);

        // FP-5.3: Autoupdate only for critical severity
        $autoupdate_enabled = get_option('vandam_autoupdate_vuln', '1') === '1';
        if (!$autoupdate_enabled) return;

        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        require_once ABSPATH . 'wp-admin/includes/file.php';

        foreach ($flagged as $f) {
            if ($f['severity'] !== 'critical')    continue; // FP-5.3
            if (empty($f['patched_version']))     continue;

            $upgrader = new Plugin_Upgrader(new Automatic_Upgrader_Skin());
            $result   = $upgrader->upgrade($f['file']);

            $this->log_security_event('Threat.Server.WordPressAnomaly', [
                'type'   => is_wp_error($result) ? 'Autoupdate_Failure' : 'Autoupdate_Success',
                'detail' => is_wp_error($result)
                    ? sprintf('Failed to auto-update %s: %s', $f['name'], $result->get_error_message())
                    : sprintf('Auto-updated "%s" to %s (resolved %s)', $f['name'], $f['patched_version'], $f['cve']),
            ]);
        }
    }

    // =========================================================================
    // LAYER 4 — FILESYSTEM SNAPSHOT MONITOR (ASYNC, 6-HOURLY CRON)
    // =========================================================================

    /**
     * Incremental filesystem snapshot: mtime-first strategy catches new or
     * modified PHP files since last run without full hash scanning every time.
     * Zero per-request cost — async cron only.
     */
    public function run_filesystem_snapshot() {
        $last_run = (int) get_option('vandam_snapshot_last_run', 0);
        update_option('vandam_snapshot_last_run', time());

        static $php_exts = ['php', 'phtml', 'phar', 'php5', 'php7', 'shtml'];
        $scan_roots = [
            WP_CONTENT_DIR . '/uploads',
            WP_CONTENT_DIR . '/plugins',
            WP_CONTENT_DIR . '/themes',
            WP_CONTENT_DIR,
        ];

        $suspects = [];
        foreach ($scan_roots as $root) {
            if (!is_dir($root)) continue;
            try {
                $iter = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST
                );
                foreach ($iter as $file) {
                    if (!$file->isFile()) continue;
                    if (!in_array(strtolower($file->getExtension()), $php_exts, true)) continue;
                    if ($file->getMTime() > $last_run) {
                        $suspects[] = $file->getPathname();
                    }
                }
            } catch (Exception $e) { /* Permission denied on some dirs — skip */ }
        }

        if (!empty($suspects)) {
            $this->scan_suspect_files($suspects);
        }
    }

    /**
     * Content-scans a set of suspect PHP files for webshell indicators.
     */
    private function scan_suspect_files(array $files) {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        // Build list of trusted plugin directories
        $trusted_roots = [];
        foreach (array_keys(get_plugins()) as $plugin_file) {
            $dir = dirname($plugin_file);
            if ($dir !== '.') {
                $trusted_roots[] = WP_PLUGIN_DIR . '/' . $dir . '/';
            }
        }

        foreach ($files as $path) {
            $in_uploads = strpos($path, WP_CONTENT_DIR . '/uploads') === 0;

            if ($in_uploads) {
                // PHP files MUST NOT exist in uploads/ under any circumstances
                $this->log_security_event('Threat.Server.WordPressAnomaly', [
                    'type'     => 'PHP_File_In_Uploads',
                    'severity' => 'critical',
                    'detail'   => sprintf('PHP file detected in uploads directory: %s', $path),
                ]);
                $this->send_alert_email(
                    '[Vandam CRITICAL] PHP File Detected in Uploads',
                    sprintf("A PHP file was detected in the uploads directory — this is a strong indicator of a backdoor upload.\n\nFile: %s\n\nReview and remove this file immediately.", $path),
                    'php_in_uploads_' . md5($path)
                );
                $this->send_webhook_notification('possible_compromise', [
                    'event'  => 'Possible Compromise: PHP Backdoor in Uploads',
                    'detail' => sprintf('PHP file detected in uploads directory — possible backdoor: %s', $path),
                    'file'   => $path,
                    'site'   => get_site_url(),
                ], 'php_in_uploads_' . md5($path));
                continue;
            }

            // For plugin/theme dirs: check against trusted plugin list
            $is_trusted = false;
            foreach ($trusted_roots as $root) {
                if (strpos($path, $root) === 0) { $is_trusted = true; break; }
            }

            // Unknown PHP file outside trusted paths: deep content inspection
            if (!$is_trusted && is_readable($path)) {
                $content = (string) file_get_contents($path, false, null, 0, 8192);
                if ($this->is_webshell_content($content)) {
                    $this->log_security_event('Threat.Server.WordPressAnomaly', [
                        'type'     => 'Webshell_Detected',
                        'severity' => 'critical',
                        'detail'   => sprintf('Webshell indicators found in new/modified PHP file: %s', $path),
                    ]);
                    $this->send_alert_email(
                        '[Vandam CRITICAL] Possible Webshell Detected',
                        sprintf("Vandam detected a suspicious PHP file that exhibits webshell behavior.\n\nFile: %s\n\nReview this file and quarantine it immediately.", $path),
                        'webshell_' . md5($path)
                    );
                    $this->send_webhook_notification('possible_compromise', [
                        'event'  => 'Possible Compromise: Webshell Detected',
                        'detail' => sprintf('Webshell indicators found in new/modified PHP file: %s', $path),
                        'file'   => $path,
                        'site'   => get_site_url(),
                    ], 'webshell_' . md5($path));
                }
            }
        }
    }

    /**
     * Heuristic webshell content detector.
     * Requires: PHP opening tag + (superglobal access AND exec function) OR eval+b64 OR obfuscation pattern.
     */
    private function is_webshell_content(string $content): bool {
        if (empty($content)) return false;
        if (strpos($content, '<?php') === false && strpos($content, '<?=') === false) return false;

        $has_superglobal = (bool) preg_match('/\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/i', $content);
        $has_exec        = (bool) preg_match('/\b(system|shell_exec|passthru|exec|proc_open|popen|assert)\s*\(/i', $content);
        $has_eval_b64    = (bool) preg_match('/eval\s*\(\s*(base64_decode|gzinflate|str_rot13)/i', $content);
        $has_obfuscation = (bool) preg_match('/\$[a-zA-Z_]\w*\s*=\s*[a-zA-Z_]\w*\s*\(\s*[a-zA-Z_]\w*\s*\(\s*[a-zA-Z_]\w*/i', $content);

        return ($has_superglobal && $has_exec) || $has_eval_b64 || $has_obfuscation;
    }

    // =========================================================================
    // UPLOADS DIRECTORY HARDENING
    // =========================================================================

    /**
     * FP-4.1 Fix: Detects server software; warns + logs if Nginx (htaccess ignored).
     * FP-4.2 Fix: Scans for pre-existing PHP files before writing the rule.
     */
    public function harden_uploads_directory() {
        $uploads_dir = wp_upload_dir()['basedir'];
        $htaccess    = $uploads_dir . '/.htaccess';

        // FP-4.1: Detect server software
        $server_sw    = strtolower($_SERVER['SERVER_SOFTWARE'] ?? '');
        $htaccess_ok  = strpos($server_sw, 'apache') !== false || strpos($server_sw, 'litespeed') !== false;

        if (!$htaccess_ok && !empty($server_sw)) {
            $this->log_security_event('Threat.Server.WordPressAnomaly', [
                'type'    => 'Htaccess_Hardening_Ineffective',
                'severity' => 'warning',
                'detail'  => sprintf('Server "%s" does not honor .htaccess. Uploads PHP block may not be enforced — consider Nginx-level restrictions.', $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown'),
            ]);
        }

        // FP-4.2: Warn about existing PHP files before hardening
        $existing_php = [];
        if (is_dir($uploads_dir)) {
            try {
                $iter = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($uploads_dir, FilesystemIterator::SKIP_DOTS)
                );
                foreach ($iter as $file) {
                    if ($file->isFile() && strtolower($file->getExtension()) === 'php') {
                        $existing_php[] = $file->getPathname();
                    }
                }
            } catch (Exception $e) {}
        }

        if (!empty($existing_php)) {
            $this->log_security_event('Threat.Server.WordPressAnomaly', [
                'type'     => 'PHP_Files_In_Uploads_Pre_Hardening',
                'severity' => 'critical',
                'detail'   => sprintf('%d PHP file(s) exist in uploads before hardening. Review immediately.', count($existing_php)),
                'files'    => $existing_php,
            ]);
        }

        // Write the .htaccess execution blocker
        $rule =
            "# Vandam-WP: Block PHP execution in uploads\n" .
            "<FilesMatch \"(?i)\\.(php|phtml|php3|php4|php5|pht|phps|phar)$\">\n" .
            "    Order Deny,Allow\n    Deny from all\n" .
            "</FilesMatch>\n";

        if (!file_exists($htaccess) || strpos((string) file_get_contents($htaccess), 'Vandam-WP') === false) {
            @file_put_contents($htaccess, $rule, FILE_APPEND);
        }
    }

    // =========================================================================
    // PUBLIC API — ADMIN DASHBOARD DATA
    // =========================================================================

    /**
     * Returns aggregate threat statistics from the local alert store.
     * Used by the Overview tab of the admin dashboard.
     */
    public function get_security_stats(): array {
        $alerts = get_option('vandam_local_alerts', []);
        $stats  = ['total' => count($alerts), 'critical' => 0, 'warning' => 0, 'info' => 0];

        static $critical_types = [
            'RCE_Attempt', 'Active_Exploitation_Detected', 'Webshell_Detected',
            'PHP_File_In_Uploads', 'PHP_Files_In_Uploads_Pre_Hardening',
            'Core_File_Integrity_Failure', 'Stealth_Admin_Injected',
            'Unauthorized_Admin_Escalation', 'Exploit_Signature_Match', 'Admin_Brute_Force',
        ];
        static $warning_types = [
            'Suspicious_Request', 'Core_File_Missing', 'Htaccess_Hardening_Ineffective',
            'Vulnerable_Plugins_Detected', 'Autoupdate_Failure',
        ];

        foreach ($alerts as $alert) {
            $type = $alert['type'] ?? '';
            if (in_array($type, $critical_types, true))    $stats['critical']++;
            elseif (in_array($type, $warning_types, true)) $stats['warning']++;
            else                                           $stats['info']++;
        }

        return $stats;
    }

    /**
     * Returns an array of all installed plugins with their vulnerability status.
     * Sorted: vulnerable first, then unknown (non-semver), then safe.
     * Used by the Plugins and Overview tabs of the admin dashboard.
     */
    public function get_plugin_vulnerability_report(): array {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $installed = get_plugins();
        $vuln_data = $this->load_vuln_data();
        $active    = get_option('active_plugins', []);
        $report    = [];

        foreach ($installed as $plugin_file => $plugin_data) {
            $slug      = $this->resolve_plugin_slug($plugin_file, $plugin_data);
            $version   = $plugin_data['Version'];
            $is_active = in_array($plugin_file, $active, true);
            $status    = 'safe';
            $vuln_info = null;

            if ($this->is_semver($version)) {
                foreach ($vuln_data as $vuln) {
                    if ($vuln['slug'] !== $slug)                        continue;
                    if (!$this->is_version_vulnerable($version, $vuln)) continue;
                    $status    = 'vulnerable';
                    $vuln_info = $vuln;
                    break;
                }
            } else {
                $status = 'unknown';
            }

            $report[] = [
                'file'      => $plugin_file,
                'name'      => $plugin_data['Name'],
                'slug'      => $slug,
                'version'   => $version,
                'is_active' => $is_active,
                'author'    => strip_tags($plugin_data['Author'] ?? ''),
                'status'    => $status,
                'vuln'      => $vuln_info,
            ];
        }

        usort($report, static function (array $a, array $b): int {
            $order = ['vulnerable' => 0, 'unknown' => 1, 'safe' => 2];
            return ($order[$a['status']] ?? 2) - ($order[$b['status']] ?? 2);
        });

        return $report;
    }

    // =========================================================================
    // VULNERABILITY DATA HELPERS
    // =========================================================================

    /**
     * FP-5.4 Fix: Loads vuln data from VANDAM_COMMUNITY_VULN_DB (plugin-relative constant).
     * No hardcoded dev machine paths.
     */
    private function load_vuln_data(): array {
        if ($this->vuln_data !== null) return $this->vuln_data;

        $this->vuln_data = [];

        $local_path = dirname(rtrim(VANDAM_PLUGIN_DIR, '/')) . '/kinnector-protect-community/wordpress/vuln-plugins.json';
        if (file_exists($local_path)) {
            $parsed = json_decode((string) file_get_contents($local_path), true);
            if (!empty($parsed['vulnerabilities'])) {
                $this->vuln_data = $parsed['vulnerabilities'];
                return $this->vuln_data;
            }
        }

        if (file_exists(VANDAM_COMMUNITY_VULN_DB)) {
            $parsed = json_decode((string) file_get_contents(VANDAM_COMMUNITY_VULN_DB), true);
            if (!empty($parsed['vulnerabilities'])) {
                $this->vuln_data = $parsed['vulnerabilities'];
            }
        }

        return $this->vuln_data;
    }

    /**
     * Downloads fresh community vuln DB from GitHub and saves to data/ directory.
     * Called on activation and during daily cron.
     */
    public function refresh_community_vuln_db() {
        $local_path = dirname(rtrim(VANDAM_PLUGIN_DIR, '/')) . '/kinnector-protect-community/wordpress/vuln-plugins.json';
        if (file_exists($local_path)) {
            $body = file_get_contents($local_path);
            $parsed = json_decode($body, true);
            if (!empty($parsed['vulnerabilities'])) {
                if (!is_dir(VANDAM_DATA_DIR)) {
                    wp_mkdir_p(VANDAM_DATA_DIR);
                }
                file_put_contents(VANDAM_COMMUNITY_VULN_DB, $body);
                $this->vuln_data = null;
                return;
            }
        }

        $response = wp_remote_get(VANDAM_COMMUNITY_VULN_URL, ['timeout' => 10]);
        if (is_wp_error($response)) return;

        $body   = wp_remote_retrieve_body($response);
        $parsed = json_decode($body, true);
        if (empty($parsed['vulnerabilities'])) return;

        if (!is_dir(VANDAM_DATA_DIR)) {
            wp_mkdir_p(VANDAM_DATA_DIR);
        }
        file_put_contents(VANDAM_COMMUNITY_VULN_DB, $body);
        // Invalidate in-memory cache so next call gets fresh data
        $this->vuln_data = null;
    }

    /**
     * FP-5.1 Fix: Resolves plugin slug from directory name with Plugin URI fallback.
     */
    private function resolve_plugin_slug(string $plugin_file, array $plugin_data): string {
        $dir = dirname($plugin_file);
        if ($dir !== '.') return $dir;

        // Single-file plugin: derive slug from Plugin URI
        if (!empty($plugin_data['PluginURI'])) {
            return basename(rtrim($plugin_data['PluginURI'], '/'));
        }

        return basename($plugin_file, '.php');
    }

    /**
     * FP-5.2 Fix: Returns true only for semver-compatible version strings.
     * Rejects date-versioned (20260101), pre-release (1.0-RC1), and other non-standard formats.
     */
    private function is_semver(string $version): bool {
        return (bool) preg_match('/^\d{1,4}\.\d+(\.\d+)?$/', $version);
    }

    /**
     * Returns true if $version falls within a vulnerability's affected range.
     */
    private function is_version_vulnerable(string $version, array $vuln): bool {
        return version_compare($version, $vuln['vuln_start'] ?? '0', '>=')
            && version_compare($version, $vuln['vuln_end']   ?? '0', '<=');
    }

    // =========================================================================
    // PLUGIN INSTALL MONITORING
    // =========================================================================

    /**
     * Fires after any upgrader process completes (install, update, activate).
     * We only care about new plugin installations — not updates.
     */
    public function on_upgrader_process_complete($upgrader, array $hook_extra) {
        if (($hook_extra['action'] ?? '') !== 'install') return;
        if (($hook_extra['type']   ?? '') !== 'plugin')  return;

        $plugin_slug = $upgrader->result['destination_name'] ?? 'unknown';
        $plugin_name = $upgrader->new_plugin_data['Name']    ?? $plugin_slug;
        $plugin_ver  = $upgrader->new_plugin_data['Version'] ?? 'unknown';
        $installer   = is_user_logged_in() ? wp_get_current_user()->user_login : 'system';

        $this->log_security_event('Threat.Server.WordPressAnomaly', [
            'type'        => 'Plugin_Installed',
            'severity'    => 'info',
            'detail'      => sprintf('Plugin "%s" (v%s, slug: %s) installed by "%s".', $plugin_name, $plugin_ver, $plugin_slug, $installer),
            'plugin_slug' => $plugin_slug,
            'plugin_name' => $plugin_name,
            'version'     => $plugin_ver,
            'installer'   => $installer,
        ]);

        $this->send_webhook_notification('new_plugin_install', [
            'event'       => 'New Plugin Installed',
            'detail'      => sprintf('Plugin "%s" (v%s) was installed by "%s".', $plugin_name, $plugin_ver, $installer),
            'plugin_slug' => $plugin_slug,
            'plugin_name' => $plugin_name,
            'version'     => $plugin_ver,
            'installer'   => $installer,
            'ip'          => $_SERVER['REMOTE_ADDR'] ?? '',
            'site'        => get_site_url(),
        ], 'plugin_install_' . $plugin_slug . '_' . $plugin_ver);
    }

    // =========================================================================
    // LOGGING & RATE-LIMITED EMAIL ALERTS
    // =========================================================================

    public function log_security_event(string $event_type, array $details) {
        if (empty($details['alert_id'])) {
            $details['alert_id'] = 'local-' . uniqid() . '-' . rand(1000, 9999);
        }
        $details['type']      = $event_type;
        $details['timestamp'] = isset($details['timestamp']) ? $details['timestamp'] : time();

        if ($this->client->is_daemon_active()) {
            $this->client->send_daemon_event('alert', [
                'event_type' => $event_type,
                'details'    => $details,
                // Site attribution — vandamd can't infer this on its own for this
                // channel (unlike the low-level PHP RASP hooks, which already send
                // HTTP_HOST on every event). get_site_url()'s configured host, not
                // $_SERVER['HTTP_HOST'], since this can fire from cron/CLI contexts
                // with no current request, and matches this file's existing
                // convention (see the 'site' => get_site_url() webhook payload above).
                'domain'     => wp_parse_url(get_site_url(), PHP_URL_HOST),
            ]);
        }

        $alerts = get_option('vandam_local_alerts', []);
        
        // Deduplicate
        $exists = false;
        foreach ($alerts as $a) {
            if (isset($a['alert_id']) && $a['alert_id'] === $details['alert_id']) {
                $exists = true;
                break;
            }
        }
        if (!$exists) {
            $alerts[] = $details;
            if (count($alerts) > 100) array_shift($alerts);
            update_option('vandam_local_alerts', $alerts);
        }
    }

    /**
     * Fetches new alerts from the Vandam daemon and merges them into the local store.
     */
    public function sync_daemon_alerts() {
        if (!$this->client->is_daemon_active()) {
            return;
        }

        $daemon_alerts = $this->client->get_daemon_alerts();
        if (empty($daemon_alerts)) {
            return;
        }

        $local_alerts = get_option('vandam_local_alerts', []);
        $updated = false;

        // Build list of existing alert IDs for O(1) checks
        $existing_ids = [];
        foreach ($local_alerts as $la) {
            if (!empty($la['alert_id'])) {
                $existing_ids[$la['alert_id']] = true;
            }
        }

        foreach ($daemon_alerts as $da) {
            $aid = isset($da['alert_id']) ? $da['alert_id'] : '';
            if (empty($aid)) {
                continue;
            }

            // Skip if already in local alerts
            if (isset($existing_ids[$aid])) {
                continue;
            }

            // Convert to local format
            $local_alert = [
                'alert_id'  => $aid,
                'type'      => isset($da['threat_type']) ? $da['threat_type'] : 'Unknown',
                'detail'    => isset($da['remediation']['status']) ? $da['remediation']['status'] : '',
                'timestamp' => isset($da['timestamp']) ? strtotime($da['timestamp']) : time(),
                'severity'  => isset($da['severity']) ? strtolower($da['severity']) : 'info',
            ];

            // If it's a daemon-level process threat, we can enrich the detail with process name/cmdline
            if (!empty($da['process']['exec_path'])) {
                $local_alert['detail'] .= sprintf(
                    ' [Process: %s (PID %d), Cmd: %s]',
                    basename($da['process']['exec_path']),
                    $da['process']['pid'],
                    $da['process']['cmdline']
                );
            }

            $local_alerts[] = $local_alert;
            $existing_ids[$aid] = true;
            $updated = true;
        }

        if ($updated) {
            // Keep at most 100 alerts
            if (count($local_alerts) > 100) {
                $local_alerts = array_slice($local_alerts, -100);
            }
            update_option('vandam_local_alerts', $local_alerts);
        }
    }

    /**
     * FP-6.2 Fix: Rate-limited email alerting.
     * At most one email per $event_key per EMAIL_COOLDOWN seconds.
     */
    private function send_alert_email(string $subject, string $body, string $event_key) {
        $transient = 'vandam_email_' . md5($event_key);
        if (get_transient($transient)) return;

        wp_mail(get_option('admin_email'), $subject, $body);
        set_transient($transient, 1, self::EMAIL_COOLDOWN);
    }

    /**
     * Sends a structured JSON webhook notification to the configured URL.
     * Rate-limited: at most one delivery per $rate_key per WEBHOOK_COOLDOWN seconds.
     *
     * Payload envelope:
     *  {
     *    "source":    "vandam-wp",
     *    "site":      "https://example.com",
     *    "timestamp": 1720000000,
     *    "severity":  "<event>",
     *    "data":      { ...caller-supplied payload }
     *  }
     *
     * Compatible with Discord (embed via "content" field), Slack
     * ("text" field), and any generic webhook consumer.
     *
     * @param string $event    Short identifier, e.g. 'rce_attempt', 'new_admin'.
     * @param array  $payload  Arbitrary key-value context data.
     * @param string $rate_key Unique string for rate-limit deduplication.
     */
    private function send_webhook_notification(string $event, array $payload, string $rate_key) {
        $webhook_url = get_option('vandam_webhook_url', '');
        if (empty($webhook_url)) return;

        $transient = 'vandam_wh_' . md5($rate_key);
        if (get_transient($transient)) return;

        $severity_map = [
            'rce_attempt'         => 'critical',
            'possible_compromise' => 'critical',
            'possible_hijack'     => 'critical',
            'new_admin'           => 'warning',
            'admin_login'         => 'info',
            'new_plugin_install'  => 'info',
        ];

        $envelope = [
            'source'    => 'vandam-wp',
            'site'      => get_site_url(),
            'timestamp' => time(),
            'severity'  => $severity_map[$event] ?? 'info',
            'event'     => $event,
            'data'      => $payload,
        ];

        // Discord-compatible: wrap in a "content" field with a brief summary
        $discord_text = sprintf(
            "**[Vandam]** `%s` | **%s**\n%s\n*Site: %s — %s UTC*",
            strtoupper($severity_map[$event] ?? 'INFO'),
            $payload['event'] ?? $event,
            $payload['detail'] ?? '',
            get_site_url(),
            gmdate('Y-m-d H:i:s')
        );

        $body = wp_json_encode(array_merge($envelope, ['content' => $discord_text, 'text' => $discord_text]));

        wp_remote_post($webhook_url, [
            'headers'   => ['Content-Type' => 'application/json'],
            'body'      => $body,
            'timeout'   => 5,
            'blocking'  => false, // fire-and-forget, zero latency impact
            'sslverify' => true,
        ]);

        set_transient($transient, 1, self::WEBHOOK_COOLDOWN);
    }

    // Legacy stub — reserved for future SQL query vetting
    public function vet_database_query(string $query): string {
        return $query;
    }

    /**
     * Renders a premium, beautifully designed block page and exits.
     */
    private function render_block_page(string $reason) {
        status_header(403);
        $reference_id = 'WPW-' . strtoupper(substr(md5(time() . ($_SERVER['REMOTE_ADDR'] ?? '')), 0, 8));
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
        $time = gmdate('Y-m-d H:i:s') . ' UTC';
        ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Request Blocked | Vandam</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(17, 24, 39, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --primary-gradient: linear-gradient(135deg, #6366f1 0%, #a855f7 100%);
            --accent-color: #ef4444;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
            overflow-x: hidden;
            position: relative;
        }

        /* Abstract ambient background glow shapes */
        body::before {
            content: '';
            position: absolute;
            width: 300px;
            height: 300px;
            background: #4f46e5;
            filter: blur(120px);
            opacity: 0.15;
            top: 20%;
            left: 20%;
            pointer-events: none;
        }
        body::after {
            content: '';
            position: absolute;
            width: 300px;
            height: 300px;
            background: #9333ea;
            filter: blur(120px);
            opacity: 0.15;
            bottom: 20%;
            right: 20%;
            pointer-events: none;
        }

        .container {
            width: 100%;
            max-width: 580px;
            z-index: 10;
        }

        .card {
            background: var(--card-bg);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--border-color);
            border-radius: 24px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--primary-gradient);
        }

        .logo-wrap {
            margin-bottom: 32px;
        }

        .logo {
            font-size: 22px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            display: inline-block;
        }

        .logo small {
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: var(--text-secondary);
            -webkit-text-fill-color: var(--text-secondary);
            display: block;
            margin-top: 2px;
        }

        .status-icon {
            width: 72px;
            height: 72px;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 24px;
            color: var(--accent-color);
            position: relative;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% {
                box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4);
            }
            70% {
                box-shadow: 0 0 0 12px rgba(239, 68, 68, 0);
            }
            100% {
                box-shadow: 0 0 0 0 rgba(239, 68, 68, 0);
            }
        }

        .status-icon svg {
            width: 32px;
            height: 32px;
            stroke-width: 2;
        }

        h1 {
            font-size: 26px;
            font-weight: 800;
            color: var(--text-primary);
            margin-bottom: 12px;
            letter-spacing: -0.5px;
        }

        .subtitle {
            color: var(--text-secondary);
            font-size: 15px;
            line-height: 1.6;
            margin-bottom: 32px;
        }

        .details-box {
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 20px;
            text-align: left;
            margin-bottom: 24px;
        }

        .details-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            font-size: 13px;
        }

        .details-row:last-child {
            margin-bottom: 0;
        }

        .details-label {
            color: var(--text-secondary);
            font-weight: 500;
        }

        .details-value {
            color: var(--text-primary);
            font-weight: 600;
            font-family: monospace;
        }

        .footer-note {
            font-size: 12px;
            color: var(--text-secondary);
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="logo-wrap">
                <div class="logo">Protected with Vandam <small>by KINNECTOR</small></div>
            </div>

            <div class="status-icon">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
            </div>

            <h1>Request Blocked</h1>
            <p class="subtitle">This request was intercepted and blocked by the Vandam Security Engine due to detected threat behaviors.</p>

            <div class="details-box">
                <div class="details-row">
                    <span class="details-label">Reference ID</span>
                    <span class="details-value"><?php echo esc_html($reference_id); ?></span>
                </div>
                <div class="details-row">
                    <span class="details-label">Reason</span>
                    <span class="details-value"><?php echo esc_html($reason); ?></span>
                </div>
                <div class="details-row">
                    <span class="details-label">Client IP</span>
                    <span class="details-value"><?php echo esc_html($ip); ?></span>
                </div>
                <div class="details-row">
                    <span class="details-label">Timestamp</span>
                    <span class="details-value"><?php echo esc_html($time); ?></span>
                </div>
            </div>

            <p class="footer-note">If you believe this is a false positive, please contact the site administrator and provide the Reference ID listed above.</p>
        </div>
    </div>
</body>
</html>
        <?php
        exit;
    }
}

// Boot the singleton
Vandam_Helper::get_instance();
