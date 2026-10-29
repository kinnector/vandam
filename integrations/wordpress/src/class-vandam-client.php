<?php
/**
 * UDS Client for Vandam EDR Socket
 * Handles all background API handshakes and telemetry transmission.
 */

if (!defined('ABSPATH')) {
    exit;
}

class Vandam_Client {
    private $socket_path = 'unix:///var/run/kinnector/vandam.sock';

    /**
     * FP-6.1 Fix: Checks daemon connectivity with a 60-second transient cache
     * so we don't incur a 1-second blocking socket timeout on every page load.
     */
    public function is_daemon_active() {
        $cached = get_transient('vandam_daemon_status');
        if ($cached !== false) {
            return (bool) $cached;
        }

        $result = $this->probe_daemon();
        // Cache for 60 seconds — daemon status doesn't change per-request
        set_transient('vandam_daemon_status', $result ? 1 : 0, 60);
        return $result;
    }

    /**
     * Performs the actual socket probe (only called when cache is cold).
     */
    private function probe_daemon() {
        $socket_file = str_replace('unix://', '', $this->socket_path);
        if (!file_exists($socket_file)) {
            return false;
        }

        $fp = @stream_socket_client($this->socket_path, $errno, $errstr, 1);
        if (!$fp) {
            return false;
        }

        $request = "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nConnection: Close\r\n\r\n";
        fwrite($fp, $request);
        $response = fgets($fp, 128);
        fclose($fp);

        return (strpos($response, '200 OK') !== false || strpos($response, 'HTTP/1.1') !== false);
    }

    /**
     * Sends custom event data to Vandam EDR daemon over UDS socket.
     */
    public function send_daemon_event($endpoint, $payload) {
        $fp = @stream_socket_client($this->socket_path, $errno, $errstr, 2);
        if (!$fp) {
            return false;
        }

        $json_payload = json_encode($payload);
        $request  = "POST /api/v1/event/{$endpoint} HTTP/1.1\r\n";
        $request .= "Host: localhost\r\n";
        $request .= "Content-Type: application/json\r\n";
        $request .= "Content-Length: " . strlen($json_payload) . "\r\n";
        $request .= "Connection: Close\r\n\r\n";
        $request .= $json_payload;

        fwrite($fp, $request);

        $response = '';
        while (!feof($fp)) {
            $response .= fgets($fp, 512);
        }
        fclose($fp);

        return (strpos($response, '200 OK') !== false || strpos($response, '201 Created') !== false);
    }

    /**
     * Checks if the current license is paid/premium.
     * On shared hosting (no daemon) always returns false.
     */
    public function is_paid_license() {
        $license_key = get_option('vandam_license_key', '');
        if (!empty($license_key)) {
            return true;
        }

        if ($this->is_daemon_active()) {
            $fp = @stream_socket_client($this->socket_path, $errno, $errstr, 1);
            if ($fp) {
                fwrite($fp, "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nConnection: Close\r\n\r\n");
                $response = '';
                while (!feof($fp)) {
                    $response .= fgets($fp, 512);
                }
                fclose($fp);

                if (strpos($response, '"tier":"paid"') !== false || strpos($response, '"status":"licensed"') !== false) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Fetches recent alerts from the Vandam daemon.
     */
    public function get_daemon_alerts() {
        if (!$this->is_daemon_active()) {
            return [];
        }

        $fp = @stream_socket_client($this->socket_path, $errno, $errstr, 2);
        if (!$fp) {
            return [];
        }

        $request = "GET /api/v1/alerts HTTP/1.1\r\nHost: localhost\r\nConnection: Close\r\n\r\n";
        fwrite($fp, $request);

        $response = '';
        while (!feof($fp)) {
            $response .= fgets($fp, 512);
        }
        fclose($fp);

        // Parse HTTP response and extract body
        $parts = explode("\r\n\r\n", $response, 2);
        if (count($parts) < 2) {
            return [];
        }

        $body = json_decode($parts[1], true);
        return isset($body['alerts']) ? $body['alerts'] : [];
    }
}
