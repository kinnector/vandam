<?php
/**
 * Admin Panel & Dashboard Interface for Vandam-WP
 * v2.0 — Full security management dashboard with multi-tab UI
 */

if (!defined('ABSPATH')) {
    exit;
}

class Vandam_Admin {

    private $client;
    private static $valid_tabs = ['overview', 'incidents', 'auth-history', 'plugins', 'settings'];

    public function __construct($client) {
        $this->client = $client;

        add_action('admin_menu',    [$this, 'register_admin_menu']);
        add_action('admin_init',    [$this, 'register_settings']);
        add_action('admin_notices', [$this, 'display_installation_warnings']);
        add_action('admin_head',    [$this, 'inject_admin_styles']);
    }

    // =========================================================================
    // MENU & SETTINGS REGISTRATION
    // =========================================================================

    public function register_admin_menu() {
        add_menu_page(
            'Vandam Security',
            'Vandam EDR',
            'manage_options',
            'vandam-security',
            [$this, 'render_admin_dashboard'],
            'dashicons-shield-alt',
            80
        );
    }

    public function register_settings() {
        register_setting('vandam_settings_group', 'vandam_license_key');
        register_setting('vandam_settings_group', 'vandam_autoupdate_vuln');
        register_setting('vandam_settings_group', 'vandam_approved_admins');
        register_setting('vandam_settings_group', 'vandam_webhook_url', [
            'sanitize_callback' => 'esc_url_raw',
        ]);

        if (!current_user_can('manage_options')) return;

        if (isset($_POST['vandam_run_scan']) && check_admin_referer('vandam_manual_scan_action', 'vandam_scan_nonce')) {
            Vandam_Helper::get_instance()->run_daily_security_scans();
            add_settings_error('vandam_messages', 'vandam_scan', 'Manual security audit completed successfully.', 'updated');
        }

        if (isset($_POST['vandam_clear_incidents']) && check_admin_referer('vandam_clear_incidents_action', 'vandam_clear_nonce')) {
            update_option('vandam_local_alerts', []);
            add_settings_error('vandam_messages', 'vandam_cleared', 'Incident history cleared.', 'updated');
        }

        if (isset($_POST['vandam_clear_auth_history']) && check_admin_referer('vandam_clear_auth_action', 'vandam_auth_nonce')) {
            update_option('vandam_admin_login_history', []);
            add_settings_error('vandam_messages', 'vandam_auth_cleared', 'Admin auth history cleared.', 'updated');
        }

        if (isset($_POST['vandam_update_admins']) && check_admin_referer('vandam_admin_list_action', 'vandam_admin_nonce')) {
            $raw = sanitize_text_field($_POST['approved_admin_list'] ?? '');
            $arr = array_values(array_filter(array_map('trim', explode(',', $raw))));
            update_option('vandam_approved_admins', $arr);
            add_settings_error('vandam_messages', 'vandam_admins', 'Administrator allowlist updated.', 'updated');
        }
    }

    public function display_installation_warnings() {
        if (!current_user_can('manage_options')) return;

        $screen = get_current_screen();
        if ($screen && $screen->id === 'toplevel_page_vandam-security') return;

        $daemon_active = $this->client->is_daemon_active();
        $is_vps        = file_exists('/run/systemd/resolve') || file_exists('/lib/systemd/systemd');

        if (!$daemon_active && $is_vps) {
            echo '<div class="notice notice-warning is-dismissible"><p>';
            echo '<strong>[Vandam EDR Notice]</strong> Your site is running on a VPS/Dedicated host, but the Vandam Kernel Daemon is not active. ';
            echo 'To unlock full eBPF/LSM protection, run: ';
            echo '<code>curl -sSL https://raw.githubusercontent.com/kinnector/kinnector-installer/main/install-vandam.sh | sudo bash</code>';
            echo '</p></div>';
        }
    }

    // =========================================================================
    // ADMIN STYLES (injected only on the Vandam page)
    // =========================================================================

    public function inject_admin_styles() {
        $screen = get_current_screen();
        if (!$screen || $screen->id !== 'toplevel_page_vandam-security') return;
        ?>
<style>
/* ── Vandam Dashboard Styles ─────────────────────────────────────────────── */
.wpw-wrap{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:1200px;margin:20px 20px 50px 0;color:#111827}
.wpw-header{background:linear-gradient(135deg,#1e1b4b 0%,#312e81 52%,#4338ca 100%);border-radius:12px;padding:24px 30px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}
.wpw-header h1{color:#fff;font-size:22px;font-weight:700;margin:0 0 4px}
.wpw-header p{color:#a5b4fc;font-size:13px;margin:0}
.wpw-hbadge{display:inline-flex;align-items:center;gap:6px;padding:5px 14px;border-radius:20px;font-size:12px;font-weight:600}
.wpw-hbadge-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
/* Tab nav */
.wpw-tabs{display:flex;gap:3px;background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:5px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.05);overflow-x:auto}
.wpw-tab{padding:9px 18px;border-radius:7px;font-size:13px;font-weight:600;color:#6b7280;text-decoration:none!important;white-space:nowrap;transition:all .14s;display:inline-block}
.wpw-tab:hover{color:#4f46e5;background:#eef2ff;text-decoration:none!important}
.wpw-tab.wpw-active{background:#4f46e5;color:#fff!important;text-decoration:none!important}
/* Grid layouts */
.wpw-grid-4{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:14px}
.wpw-grid-2{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}
.wpw-ov-main{display:grid;grid-template-columns:3fr 2fr;gap:14px}
/* Card */
.wpw-card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.wpw-card-label{font-size:11px;font-weight:700;color:#9ca3af;text-transform:uppercase;letter-spacing:.7px;margin-bottom:6px}
.wpw-stat{font-size:34px;font-weight:800;line-height:1;color:#111827}
.wpw-stat-sub{font-size:12px;color:#9ca3af;margin-top:4px}
.c-red .wpw-stat{color:#ef4444} .c-amber .wpw-stat{color:#f59e0b}
.c-blue .wpw-stat{color:#3b82f6} .c-green .wpw-stat{color:#10b981}
/* Section title */
.wpw-title{font-size:15px;font-weight:700;color:#111827;margin:0 0 14px;padding-bottom:10px;border-bottom:1px solid #f3f4f6}
.wpw-toolbar{display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:14px}
/* Table */
.wpw-table{width:100%;border-collapse:collapse;font-size:13px}
.wpw-table th{padding:9px 14px;text-align:left;font-size:11px;font-weight:700;color:#9ca3af;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid #f3f4f6;background:#f9fafb}
.wpw-table td{padding:11px 14px;border-bottom:1px solid #f3f4f6;color:#374151;vertical-align:middle}
.wpw-table tr:last-child td{border-bottom:none}
.wpw-table tr:hover td{background:#fafafa}
/* Pill badges */
.wpw-pill{display:inline-block;padding:2px 9px;border-radius:12px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.2px;line-height:1.6}
.p-crit{background:#fee2e2;color:#dc2626} .p-warn{background:#fef3c7;color:#d97706}
.p-info{background:#dbeafe;color:#1d4ed8} .p-ok{background:#d1fae5;color:#065f46}
.p-mute{background:#f3f4f6;color:#6b7280}
/* Buttons */
.wpw-btn{display:inline-flex;align-items:center;gap:5px;padding:8px 16px;border-radius:7px;font-size:13px;font-weight:600;cursor:pointer;border:none;text-decoration:none!important;line-height:1.3}
.wpw-btn-primary{background:#4f46e5;color:#fff!important} .wpw-btn-primary:hover{background:#4338ca}
.wpw-btn-danger{background:#fee2e2;color:#dc2626!important;border:1px solid #fca5a5} .wpw-btn-danger:hover{background:#fecaca}
.wpw-btn-ghost{background:#f3f4f6;color:#374151!important;border:1px solid #e5e7eb} .wpw-btn-ghost:hover{background:#e5e7eb}
/* Form controls */
.wpw-input{width:100%;padding:9px 12px;border:1px solid #d1d5db;border-radius:7px;font-size:13px;color:#111827;box-sizing:border-box}
.wpw-input:focus{outline:2px solid #4f46e5;border-color:#4f46e5}
.wpw-label{display:block;font-size:13px;font-weight:600;color:#374151;margin-bottom:5px}
.wpw-hint{font-size:12px;color:#9ca3af;margin:5px 0 0}
.wpw-fg{margin-bottom:20px}
/* Status row */
.wpw-sr{display:flex;justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid #f3f4f6;font-size:13px}
.wpw-sr:last-child{border-bottom:none}
/* Empty state */
.wpw-empty{text-align:center;padding:48px 20px;color:#9ca3af}
.wpw-empty-ico{font-size:40px;display:block;margin-bottom:10px}
/* Responsive */
@media(max-width:960px){.wpw-grid-4{grid-template-columns:repeat(2,1fr)}.wpw-ov-main,.wpw-grid-2{grid-template-columns:1fr}}
</style>
        <?php
    }

    // =========================================================================
    // MAIN RENDER DISPATCHER
    // =========================================================================

    public function render_admin_dashboard() {
        if (!current_user_can('manage_options')) {
            wp_die('Insufficient permissions.');
        }

        $daemon_active = $this->client->is_daemon_active();

        // Fetch/sync daemon alerts on dashboard render (rate limited to once every 10 seconds)
        if ($daemon_active) {
            $transient = 'vandam_alerts_sync_lock';
            if (!get_transient($transient)) {
                Vandam_Helper::get_instance()->sync_daemon_alerts();
                set_transient($transient, 1, 10);
            }
        }

        $active_tab = sanitize_key($_GET['tab'] ?? 'overview');
        if (!in_array($active_tab, self::$valid_tabs, true)) {
            $active_tab = 'overview';
        }

        $is_paid       = $this->client->is_paid_license();

        settings_errors('vandam_messages');

        echo '<div class="wpw-wrap">';
        $this->render_header($daemon_active, $is_paid);
        $this->render_tab_nav($active_tab);

        switch ($active_tab) {
            case 'overview':     $this->tab_overview($daemon_active, $is_paid);  break;
            case 'incidents':    $this->tab_incidents();                          break;
            case 'auth-history': $this->tab_auth_history();                      break;
            case 'plugins':      $this->tab_plugins();                           break;
            case 'settings':     $this->tab_settings($daemon_active, $is_paid);  break;
        }

        echo '</div>';
    }

    // =========================================================================
    // SHARED CHROME
    // =========================================================================

    private function render_header(bool $daemon_active, bool $is_paid) {
        $dot_col  = $daemon_active ? '#10b981' : '#f59e0b';
        $bg       = $daemon_active ? 'rgba(16,185,129,.15)' : 'rgba(245,158,11,.15)';
        $col      = $daemon_active ? '#6ee7b7' : '#fcd34d';
        $bdr      = $daemon_active ? 'rgba(16,185,129,.3)' : 'rgba(245,158,11,.3)';
        $mode     = $daemon_active ? 'Kernel EDR Mode' : 'User-Space Mode';
        ?>
        <div class="wpw-header">
            <div>
                <h1>⚔️ Vandam EDR Security</h1>
                <p>Application-level WordPress security engine — v<?php echo esc_html(VANDAM_VERSION); ?></p>
            </div>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
                <span class="wpw-hbadge" style="background:<?php echo $bg; ?>;color:<?php echo $col; ?>;border:1px solid <?php echo $bdr; ?>;">
                    <span class="wpw-hbadge-dot" style="background:<?php echo $dot_col; ?>;"></span>
                    <?php echo esc_html($mode); ?>
                </span>
                <?php if ($is_paid): ?>
                <span class="wpw-hbadge" style="background:rgba(99,102,241,.2);color:#a5b4fc;border:1px solid rgba(99,102,241,.35);">✦ Premium</span>
                <?php else: ?>
                <span class="wpw-hbadge" style="background:rgba(255,255,255,.08);color:#c7d2fe;border:1px solid rgba(255,255,255,.15);">Community</span>
                <?php endif; ?>
            </div>
        </div>
        <?php
    }

    private function render_tab_nav(string $active) {
        $base = admin_url('admin.php?page=vandam-security');
        $tabs = [
            'overview'     => '📊&nbsp; Overview',
            'incidents'    => '🚨&nbsp; Incidents',
            'auth-history' => '🔐&nbsp; Admin Auth',
            'plugins'      => '🧩&nbsp; Plugins',
            'settings'     => '⚙️&nbsp; Settings',
        ];
        echo '<div class="wpw-tabs">';
        foreach ($tabs as $key => $label) {
            $cls = 'wpw-tab' . ($active === $key ? ' wpw-active' : '');
            printf('<a href="%s" class="%s">%s</a>', esc_url($base . '&tab=' . $key), $cls, $label);
        }
        echo '</div>';
    }

    // =========================================================================
    // TAB: OVERVIEW
    // =========================================================================

    private function tab_overview(bool $daemon_active, bool $is_paid) {
        $helper   = Vandam_Helper::get_instance();
        $alerts   = get_option('vandam_local_alerts', []);
        $logins   = get_option('vandam_admin_login_history', []);
        $stats    = $helper->get_security_stats();
        $plugins  = $helper->get_plugin_vulnerability_report();
        $vuln_cnt = count(array_filter($plugins, fn($p) => $p['status'] === 'vulnerable'));
        ?>

        <!-- Stat cards -->
        <div class="wpw-grid-4">
            <div class="wpw-card c-red">
                <div class="wpw-card-label">Critical Threats</div>
                <div class="wpw-stat"><?php echo (int) $stats['critical']; ?></div>
                <div class="wpw-stat-sub">All-time incidents</div>
            </div>
            <div class="wpw-card c-amber">
                <div class="wpw-card-label">Warnings</div>
                <div class="wpw-stat"><?php echo (int) $stats['warning']; ?></div>
                <div class="wpw-stat-sub">Suspicious events</div>
            </div>
            <div class="wpw-card <?php echo $vuln_cnt > 0 ? 'c-red' : 'c-green'; ?>">
                <div class="wpw-card-label">Vulnerable Plugins</div>
                <div class="wpw-stat"><?php echo (int) $vuln_cnt; ?></div>
                <div class="wpw-stat-sub"><?php echo $vuln_cnt > 0 ? 'Require attention' : 'All plugins safe'; ?></div>
            </div>
            <div class="wpw-card c-blue">
                <div class="wpw-card-label">Admin Auth Events</div>
                <div class="wpw-stat"><?php echo count($logins); ?></div>
                <div class="wpw-stat-sub">Recorded login events</div>
            </div>
        </div>

        <div class="wpw-ov-main">
            <!-- Recent incidents -->
            <div class="wpw-card">
                <div class="wpw-title">Recent Security Incidents</div>
                <?php $recent = array_slice(array_reverse($alerts), 0, 8); ?>
                <?php if (empty($recent)): ?>
                    <div class="wpw-empty">
                        <span class="wpw-empty-ico">✅</span>
                        <strong>No incidents recorded</strong>
                        <p style="font-size:12px;margin:5px 0 0;">Your environment is clean.</p>
                    </div>
                <?php else: ?>
                    <div style="overflow-x:auto;">
                    <table class="wpw-table">
                        <thead><tr><th>Time</th><th>Type</th><th>Detail</th></tr></thead>
                        <tbody>
                        <?php foreach ($recent as $a): ?>
                        <tr>
                            <td style="white-space:nowrap;color:#9ca3af;font-size:11px;"><?php echo esc_html(date('m/d H:i', $a['timestamp'] ?? 0)); ?></td>
                            <td><?php echo $this->pill_for_type($a['type'] ?? 'Unknown'); ?></td>
                            <td style="font-size:12px;max-width:280px;"><?php
                                $d = $a['detail'] ?? '';
                                echo esc_html(strlen($d) > 85 ? substr($d, 0, 85) . '…' : $d);
                            ?></td>
                        </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                    </div>
                    <div style="margin-top:12px;">
                        <a href="<?php echo esc_url(admin_url('admin.php?page=vandam-security&tab=incidents')); ?>" class="wpw-btn wpw-btn-ghost" style="font-size:12px;">View All Incidents →</a>
                    </div>
                <?php endif; ?>
            </div>

            <!-- System status -->
            <div class="wpw-card">
                <div class="wpw-title">System Status</div>
                <?php
                $upls_ok   = file_exists(wp_upload_dir()['basedir'] . '/.htaccess');
                $vuln_ok   = file_exists(VANDAM_COMMUNITY_VULN_DB);
                $daily_ts  = wp_next_scheduled('vandam_daily_scan');
                $snap_ts   = wp_next_scheduled('vandam_filesystem_snapshot');
                $ae        = get_transient('vandam_active_exploits');
                $items = [
                    ['Enforcement Mode',       $daemon_active ? 'Kernel EDR (eBPF/LSM)' : 'User-Space (Shared Hosting)',                     true],
                    ['License',                $is_paid ? 'Premium Active' : 'Community Edition',                                           $is_paid],
                    ['Uploads Hardening',      $upls_ok ? 'Active (.htaccess)' : 'Not Applied',                                             $upls_ok],
                    ['Vulnerability Database', $vuln_ok ? 'Loaded (' . date('Y-m-d', (int) filemtime(VANDAM_COMMUNITY_VULN_DB)) . ')' : 'Not Downloaded', $vuln_ok],
                    ['Daily Scan Cron',        $daily_ts ? 'Scheduled (' . date('H:i', (int) $daily_ts) . ')' : 'Not Scheduled',           (bool) $daily_ts],
                    ['Filesystem Snapshot',    $snap_ts  ? 'Active (every 6h)' : 'Not Scheduled',                                          (bool) $snap_ts],
                    ['Active Exploit Watch',   $ae ? implode(', ', (array) $ae) : 'None tracked',                                          true],
                ];
                foreach ($items as [$lbl, $val, $ok]):
                ?>
                <div class="wpw-sr">
                    <span style="font-weight:600;color:#374151;font-size:12px;"><?php echo esc_html($lbl); ?></span>
                    <span style="font-size:12px;color:<?php echo $ok ? '#10b981' : '#ef4444'; ?>;">
                        <?php echo $ok ? '✓' : '✗'; ?> <?php echo esc_html($val); ?>
                    </span>
                </div>
                <?php endforeach; ?>

                <div style="margin-top:16px;">
                    <form method="post">
                        <?php wp_nonce_field('vandam_manual_scan_action', 'vandam_scan_nonce'); ?>
                        <button type="submit" name="vandam_run_scan" class="wpw-btn wpw-btn-primary" style="border:none;width:100%;justify-content:center;">⚡ Run Full Audit Now</button>
                    </form>
                </div>
            </div>
        </div>
        <?php
    }

    // =========================================================================
    // TAB: INCIDENTS
    // =========================================================================

    private function tab_incidents() {
        $alerts = array_reverse(get_option('vandam_local_alerts', []));
        $filter = sanitize_key($_GET['filter'] ?? '');
        $types  = array_unique(array_filter(array_column($alerts, 'type')));
        sort($types);

        if ($filter) {
            $alerts = array_values(array_filter($alerts, fn($a) => ($a['type'] ?? '') === $filter));
        }
        ?>
        <div class="wpw-card">
            <div class="wpw-toolbar">
                <div>
                    <div class="wpw-title" style="margin-bottom:2px;">Security Incident Log</div>
                    <p style="margin:0;font-size:12px;color:#9ca3af;">
                        <?php echo count($alerts); ?> event(s)
                        <?php if ($filter): ?> — filtered: <strong><?php echo esc_html(str_replace('_', ' ', $filter)); ?></strong><?php endif; ?>
                    </p>
                </div>
                <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
                    <form method="get" style="display:flex;gap:6px;align-items:center;">
                        <input type="hidden" name="page"   value="vandam-security" />
                        <input type="hidden" name="tab"    value="incidents" />
                        <select name="filter" class="wpw-input" style="width:auto;padding:7px 10px;" onchange="this.form.submit()">
                            <option value="">All Types</option>
                            <?php foreach ($types as $t): ?>
                            <option value="<?php echo esc_attr($t); ?>" <?php selected($filter, $t); ?>><?php echo esc_html(str_replace('_', ' ', $t)); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </form>
                    <form method="post">
                        <?php wp_nonce_field('vandam_clear_incidents_action', 'vandam_clear_nonce'); ?>
                        <button type="submit" name="vandam_clear_incidents" class="wpw-btn wpw-btn-danger"
                            onclick="return confirm('Clear all incident history? This cannot be undone.')">🗑 Clear All</button>
                    </form>
                </div>
            </div>

            <?php if (empty($alerts)): ?>
                <div class="wpw-empty"><span class="wpw-empty-ico">✅</span><strong>No incidents recorded</strong></div>
            <?php else: ?>
                <div style="overflow-x:auto;">
                <table class="wpw-table">
                    <thead><tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>Detail</th></tr></thead>
                    <tbody>
                    <?php foreach ($alerts as $a):
                        $type = $a['type'] ?? 'Unknown';
                        $sev  = $a['severity'] ?? $this->infer_severity($type);
                        $sc   = ['critical' => 'p-crit', 'warning' => 'p-warn', 'info' => 'p-info'][$sev] ?? 'p-mute';
                    ?>
                    <tr>
                        <td style="white-space:nowrap;font-size:12px;color:#9ca3af;"><?php echo esc_html(date('Y-m-d H:i:s', $a['timestamp'] ?? 0)); ?></td>
                        <td><?php echo $this->pill_for_type($type); ?></td>
                        <td><span class="wpw-pill <?php echo $sc; ?>"><?php echo esc_html(strtoupper($sev)); ?></span></td>
                        <td style="font-size:12px;max-width:440px;"><?php echo esc_html($a['detail'] ?? '—'); ?></td>
                    </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                </div>
            <?php endif; ?>
        </div>
        <?php
    }

    // =========================================================================
    // TAB: ADMIN AUTH HISTORY
    // =========================================================================

    private function tab_auth_history() {
        $history  = get_option('vandam_admin_login_history', []);
        $approved = get_option('vandam_approved_admins', []);

        // Counts for summary
        $successes = count(array_filter($history, fn($e) => empty($e['failed'])));
        $failures  = count($history) - $successes;
        ?>
        <div class="wpw-card">
            <div class="wpw-toolbar">
                <div>
                    <div class="wpw-title" style="margin-bottom:4px;">Administrator Auth History</div>
                    <div style="display:flex;gap:10px;flex-wrap:wrap;">
                        <span style="font-size:12px;color:#9ca3af;"><?php echo count($history); ?> total events</span>
                        <span class="wpw-pill p-ok" style="font-size:11px;"><?php echo $successes; ?> success</span>
                        <span class="wpw-pill p-crit" style="font-size:11px;"><?php echo $failures; ?> failed</span>
                    </div>
                </div>
                <form method="post">
                    <?php wp_nonce_field('vandam_clear_auth_action', 'vandam_auth_nonce'); ?>
                    <button type="submit" name="vandam_clear_auth_history" class="wpw-btn wpw-btn-danger"
                        onclick="return confirm('Clear all auth history?')">🗑 Clear History</button>
                </form>
            </div>

            <?php if (empty($history)): ?>
                <div class="wpw-empty">
                    <span class="wpw-empty-ico">🔐</span>
                    <strong>No admin logins recorded yet</strong>
                    <p style="font-size:12px;margin:5px 0 0;">Successful and failed admin login events will appear here once Vandam starts monitoring.</p>
                </div>
            <?php else: ?>
                <div style="overflow-x:auto;">
                <table class="wpw-table">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>User</th>
                            <th>Result</th>
                            <th>IP Address</th>
                            <th>User Agent</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($history as $entry):
                        $login       = $entry['user_login'] ?? '—';
                        $is_approved = in_array($login, $approved, true);
                        $is_failed   = !empty($entry['failed']);
                    ?>
                    <tr style="<?php echo $is_failed ? 'background:#fff8f8;' : ''; ?>">
                        <td style="white-space:nowrap;font-size:12px;color:#9ca3af;"><?php echo esc_html(date('Y-m-d H:i:s', $entry['timestamp'] ?? 0)); ?></td>
                        <td>
                            <strong><?php echo esc_html($login); ?></strong>
                            <?php if (!$is_approved): ?>
                            <span class="wpw-pill p-crit" style="margin-left:4px;font-size:10px;">⚠ Unapproved</span>
                            <?php endif; ?>
                            <?php if (!empty($entry['user_email'])): ?>
                            <br><span style="font-size:11px;color:#9ca3af;"><?php echo esc_html($entry['user_email']); ?></span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php echo $is_failed
                                ? '<span class="wpw-pill p-crit">Failed</span>'
                                : '<span class="wpw-pill p-ok">Success</span>'; ?>
                        </td>
                        <td style="font-family:monospace;font-size:12px;"><?php echo esc_html($entry['ip'] ?? '—'); ?></td>
                        <td style="font-size:11px;color:#9ca3af;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
                            title="<?php echo esc_attr($entry['user_agent'] ?? ''); ?>">
                            <?php echo esc_html(substr($entry['user_agent'] ?? '—', 0, 65)); ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                </div>
            <?php endif; ?>
        </div>
        <?php
    }

    // =========================================================================
    // TAB: PLUGINS
    // =========================================================================

    private function tab_plugins() {
        $helper  = Vandam_Helper::get_instance();
        $plugins = $helper->get_plugin_vulnerability_report();
        $vuln    = array_filter($plugins, fn($p) => $p['status'] === 'vulnerable');
        ?>

        <?php if (!empty($vuln)): ?>
        <div class="wpw-card" style="border-color:#fca5a5;background:#fff8f8;margin-bottom:14px;">
            <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;">
                <span style="font-size:28px;flex-shrink:0;">⚠️</span>
                <div style="flex:1;">
                    <strong style="color:#dc2626;font-size:14px;"><?php echo count($vuln); ?> vulnerable plugin(s) detected</strong>
                    <p style="margin:3px 0 0;font-size:12px;color:#ef4444;">These plugins have known CVEs and are active on this server. Update or deactivate them to eliminate the attack surface.</p>
                </div>
                <a href="<?php echo esc_url(admin_url('update-core.php')); ?>" class="wpw-btn wpw-btn-primary" style="flex-shrink:0;">Update All →</a>
            </div>
        </div>
        <?php endif; ?>

        <div class="wpw-card">
            <div class="wpw-toolbar">
                <div class="wpw-title" style="margin-bottom:0;">Installed Plugins — Security Status</div>
                <span style="font-size:12px;color:#9ca3af;"><?php echo count($plugins); ?> plugin(s) installed</span>
            </div>
            <div style="overflow-x:auto;">
            <table class="wpw-table">
                <thead>
                    <tr>
                        <th>Plugin</th>
                        <th>Version</th>
                        <th>Status</th>
                        <th>Security</th>
                        <th>CVE / Notes</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($plugins as $p):
                    if ($p['status'] === 'vulnerable') {
                        $sec_pill = '<span class="wpw-pill p-crit">⚠ Vulnerable</span>';
                    } elseif ($p['status'] === 'unknown') {
                        $sec_pill = '<span class="wpw-pill p-warn">? Non-SemVer</span>';
                    } else {
                        $sec_pill = '<span class="wpw-pill p-ok">✓ Safe</span>';
                    }
                    $active_lbl = $p['is_active']
                        ? '<span style="color:#10b981;font-weight:600;font-size:12px;">● Active</span>'
                        : '<span style="color:#9ca3af;font-size:12px;">○ Inactive</span>';
                ?>
                <tr>
                    <td>
                        <strong style="font-size:13px;"><?php echo esc_html($p['name']); ?></strong><br>
                        <span style="font-size:11px;color:#9ca3af;"><?php echo esc_html($p['slug']); ?></span>
                        <?php if ($p['author']): ?>
                        <br><span style="font-size:11px;color:#d1d5db;">by <?php echo esc_html($p['author']); ?></span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <code style="background:#f3f4f6;padding:2px 7px;border-radius:4px;font-size:12px;"><?php echo esc_html($p['version']); ?></code>
                        <?php if ($p['vuln'] && !empty($p['vuln']['patched_version'])): ?>
                        <br><span style="font-size:11px;color:#10b981;">→ v<?php echo esc_html($p['vuln']['patched_version']); ?> fixes this</span>
                        <?php endif; ?>
                    </td>
                    <td><?php echo $active_lbl; ?></td>
                    <td><?php echo $sec_pill; ?></td>
                    <td style="font-size:12px;max-width:240px;">
                        <?php if ($p['vuln']): ?>
                            <strong style="color:#dc2626;"><?php echo esc_html($p['vuln']['cve'] ?? 'CVE-Unknown'); ?></strong>
                            <?php if (!empty($p['vuln']['severity'])): ?>
                            <span class="wpw-pill p-crit" style="margin-left:4px;font-size:10px;"><?php echo esc_html($p['vuln']['severity']); ?></span>
                            <?php endif; ?>
                            <br>
                            <span style="color:#9ca3af;font-size:11px;">
                                <?php $desc = $p['vuln']['description'] ?? ''; echo esc_html(strlen($desc) > 70 ? substr($desc, 0, 70) . '…' : $desc); ?>
                            </span>
                        <?php elseif ($p['status'] === 'unknown'): ?>
                            <span style="color:#9ca3af;">Non-semver version — cannot check against vuln DB</span>
                        <?php else: ?>
                            <span style="color:#9ca3af;">No known vulnerabilities</span>
                        <?php endif; ?>
                    </td>
                    <td style="white-space:nowrap;">
                        <?php if ($p['status'] === 'vulnerable'): ?>
                        <a href="<?php echo esc_url(admin_url('update-core.php')); ?>" class="wpw-btn wpw-btn-primary" style="font-size:11px;padding:5px 12px;">Update</a>
                        <?php else: ?>
                        <a href="<?php echo esc_url(admin_url('plugins.php')); ?>" class="wpw-btn wpw-btn-ghost" style="font-size:11px;padding:5px 12px;">Manage</a>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            </div>
        </div>
        <?php
    }

    // =========================================================================
    // TAB: SETTINGS
    // =========================================================================

    private function tab_settings(bool $daemon_active, bool $is_paid) {
        $approved = get_option('vandam_approved_admins', []);
        ?>
        <div class="wpw-grid-2">

            <!-- Left column: Configuration -->
            <div class="wpw-card">
                <div class="wpw-title">Configuration</div>
                <form method="post" action="options.php">
                    <?php settings_fields('vandam_settings_group'); ?>

                    <div class="wpw-fg">
                        <label class="wpw-label" for="wpw_license">License Key</label>
                        <?php if ($daemon_active): ?>
                        <input type="text" id="wpw_license" name="vandam_license_key" class="wpw-input"
                               value="<?php echo esc_attr(get_option('vandam_license_key')); ?>"
                               placeholder="Leave empty for Community Edition" />
                        <?php else: ?>
                        <input type="text" class="wpw-input" disabled placeholder="Not available on shared hosting" style="opacity:.5;cursor:not-allowed;" />
                        <p class="wpw-hint" style="color:#ef4444;">Premium requires the Vandam Daemon (VPS or dedicated server).</p>
                        <?php endif; ?>
                    </div>

                    <div class="wpw-fg">
                        <label class="wpw-label" for="wpw_autoupdate">Auto-Update Vulnerable Plugins</label>
                        <select id="wpw_autoupdate" name="vandam_autoupdate_vuln" class="wpw-input" style="width:auto;">
                            <option value="1" <?php selected(get_option('vandam_autoupdate_vuln', '1'), '1'); ?>>Enabled — Critical severity only (Recommended)</option>
                            <option value="0" <?php selected(get_option('vandam_autoupdate_vuln'), '0'); ?>>Disabled — Alert only, no automatic updates</option>
                        </select>
                    </div>

                    <div class="wpw-fg">
                        <label class="wpw-label" for="wpw_webhook">Webhook URL</label>
                        <input type="url" id="wpw_webhook" name="vandam_webhook_url" class="wpw-input"
                               value="<?php echo esc_attr(get_option('vandam_webhook_url')); ?>"
                               placeholder="https://discord.com/api/webhooks/... or https://hooks.slack.com/..." />
                        <p class="wpw-hint">Notifies on: new plugin installs, admin logins, RCE attempts, brute-force attempts, compromises &amp; hijacks. Discord, Slack, and any generic JSON webhook are supported. Rate-limited: 1 notification / event / 15 min.</p>
                    </div>

                    <button type="submit" class="wpw-btn wpw-btn-primary" style="border:none;">💾 Save Settings</button>
                </form>
            </div>

            <!-- Right column: Allowlist + Tools + Premium -->
            <div style="display:flex;flex-direction:column;gap:14px;">

                <div class="wpw-card">
                    <div class="wpw-title">Approved Admin Allowlist</div>
                    <p style="font-size:13px;color:#6b7280;margin-bottom:14px;">Comma-separated administrator logins that are pre-approved. Any admin outside this list triggers an alert and webhook notification.</p>
                    <form method="post">
                        <?php wp_nonce_field('vandam_admin_list_action', 'vandam_admin_nonce'); ?>
                        <div class="wpw-fg" style="margin-bottom:12px;">
                            <textarea name="approved_admin_list" rows="3" class="wpw-input" style="resize:vertical;"
                                placeholder="admin, site_admin, dev_user"><?php echo esc_textarea(implode(', ', $approved)); ?></textarea>
                        </div>
                        <button type="submit" name="vandam_update_admins" class="wpw-btn wpw-btn-ghost" style="border:1px solid #e5e7eb;">Save Allowlist</button>
                    </form>
                </div>

                <div class="wpw-card">
                    <div class="wpw-title">Diagnostics &amp; Tools</div>
                    <p style="font-size:13px;color:#6b7280;margin-bottom:14px;">Manually trigger a full security audit: core file checksums, plugin vulnerability scan, and DB admin integrity check.</p>
                    <form method="post">
                        <?php wp_nonce_field('vandam_manual_scan_action', 'vandam_scan_nonce'); ?>
                        <button type="submit" name="vandam_run_scan" class="wpw-btn wpw-btn-primary" style="border:none;">⚡ Run Full Audit Now</button>
                    </form>
                </div>

                <?php if (!$is_paid): ?>
                <div class="wpw-card" style="background:linear-gradient(135deg,#1e1b4b 0%,#312e81 55%,#4c1d95 100%);border:none;color:#fff;">
                    <div style="font-size:20px;margin-bottom:10px;">✦ Upgrade to Premium</div>
                    <p style="color:#a5b4fc;font-size:13px;margin-bottom:10px;">Unlock private moderated exploit lists, advanced threat analytics, and priority support.</p>
                    <div style="background:rgba(255,255,255,.07);border-radius:7px;padding:9px 12px;font-size:12px;color:#c4b5fd;margin-bottom:16px;">
                        Requires Vandam Daemon on a VPS or dedicated server.
                    </div>
                    <a href="https://kinnector.com/vandam-premium" target="_blank" rel="noopener noreferrer"
                       class="wpw-btn" style="background:#6366f1;color:#fff!important;border:none;">Get Premium →</a>
                </div>
                <?php else: ?>
                <div class="wpw-card" style="background:linear-gradient(135deg,#0f172a,#1e1b4b);border:none;color:#fff;">
                    <div style="font-size:20px;margin-bottom:10px;">✦ Premium Active</div>
                    <p style="color:#a5b4fc;font-size:13px;margin-bottom:14px;">You have access to private exploit lists, advanced analytics, and priority support.</p>
                    <p style="font-size:12px;color:#6b7280;margin:0;">Key: <code style="color:#a5b4fc;"><?php echo esc_html(substr(get_option('vandam_license_key', ''), 0, 8)); ?>••••••••</code></p>
                </div>
                <?php endif; ?>

            </div>
        </div>
        <?php
    }

    // =========================================================================
    // RENDER HELPERS
    // =========================================================================

    private function pill_for_type(string $type): string {
        static $critical = [
            'RCE_Attempt', 'Active_Exploitation_Detected', 'Webshell_Detected',
            'PHP_File_In_Uploads', 'PHP_Files_In_Uploads_Pre_Hardening',
            'Core_File_Integrity_Failure', 'Stealth_Admin_Injected',
            'Unauthorized_Admin_Escalation', 'Exploit_Signature_Match', 'Admin_Brute_Force',
        ];
        static $warning = [
            'Suspicious_Request', 'Core_File_Missing', 'Htaccess_Hardening_Ineffective',
            'Vulnerable_Plugins_Detected', 'Autoupdate_Failure',
        ];
        static $info = ['Autoupdate_Success', 'Plugin_Installed'];

        if (in_array($type, $critical, true))     $cls = 'p-crit';
        elseif (in_array($type, $warning, true))  $cls = 'p-warn';
        elseif (in_array($type, $info, true))     $cls = 'p-info';
        else                                       $cls = 'p-mute';

        return '<span class="wpw-pill ' . $cls . '">' . esc_html(str_replace('_', ' ', $type)) . '</span>';
    }

    private function infer_severity(string $type): string {
        static $critical = [
            'RCE_Attempt', 'Active_Exploitation_Detected', 'Webshell_Detected',
            'PHP_File_In_Uploads', 'Core_File_Integrity_Failure', 'Stealth_Admin_Injected',
            'Unauthorized_Admin_Escalation', 'Exploit_Signature_Match', 'Admin_Brute_Force',
        ];
        static $warning = [
            'Suspicious_Request', 'Core_File_Missing', 'Htaccess_Hardening_Ineffective', 'Vulnerable_Plugins_Detected',
        ];
        if (in_array($type, $critical, true)) return 'critical';
        if (in_array($type, $warning,  true)) return 'warning';
        return 'info';
    }
}
