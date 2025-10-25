<?php
/**
 * Plugin Name: PW User Geo
 * Description: Detects the visitor’s IP (proxy-aware) using a local MaxMind GeoLite2-Country.mmdb file. Caches results and exposes a shortcode/helper to display the country.
 * Version:     1.1.1
 * Author:      Yaniv Sasson
 * License:     GPL-2.0+
 * Text Domain: pw-user-geo
 */

if ( ! defined( 'ABSPATH' ) ) exit;

// Load Composer (for geoip2/geoip2) if present
if ( file_exists( __DIR__ . '/vendor/autoload.php' ) ) {
	require_once __DIR__ . '/vendor/autoload.php';
}

// Path to your .mmdb (can be filtered)
if ( ! defined( 'PW_USER_GEO_MAXMIND_DB' ) ) {
	define( 'PW_USER_GEO_MAXMIND_DB', __DIR__ . '/GeoLite2-Country.mmdb' );
}

final class PW_User_Geo {
	const TRANSIENT_PREFIX = 'pw_user_geo_';
	const VERSION          = '1.1.1';

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) self::$instance = new self();
		return self::$instance;
	}

	private function __construct() {
		add_shortcode( 'pw_user_geo', [ $this, 'shortcode' ] );

		// Helper function for theme or plugins
		if ( ! function_exists( 'pw_user_geo_get' ) ) {
			function pw_user_geo_get( $ip = null ) {
				$data = PW_User_Geo::instance()->get_location_data( $ip );

				// If there was an error or no country detected, return a readable fallback message.
				if ( ! empty( $data['error'] ) ) {
					return sprintf(
						__( 'Unable to detect location: %s', 'pw-user-geo' ),
						esc_html( $data['error'] )
					);
				}

				if ( empty( $data['country'] ) ) {
					return __( 'Unable to detect your location.', 'pw-user-geo' );
				}

				// Otherwise, return the normal array
				return $data;
			}
		}
	}

	/**
	 * Proxy/CDN-aware client IP detection.
	 */
	public function get_client_ip(): string {
		$keys = [
			'HTTP_CF_CONNECTING_IP',
			'HTTP_X_REAL_IP',
			'HTTP_X_FORWARDED_FOR',
			'HTTP_CLIENT_IP',
			'REMOTE_ADDR',
		];

		foreach ( $keys as $key ) {
			if ( empty( $_SERVER[ $key ] ) ) continue;
			$raw = $_SERVER[ $key ];

			if ( $key === 'HTTP_X_FORWARDED_FOR' ) {
				$list = array_map( 'trim', explode( ',', $raw ) );
				foreach ( $list as $candidate ) {
					if ( filter_var( $candidate, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
						return $candidate;
					}
				}
			} else {
				$ip = trim( is_array( $raw ) ? reset( $raw ) : $raw );
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) return $ip;
			}
		}
		return '0.0.0.0';
	}

	private function get_maxmind_db_path(): ?string {
		$path = apply_filters( 'pw_user_geo_maxmind_db_path', PW_USER_GEO_MAXMIND_DB );
		$path = is_string( $path ) ? $path : '';
		if ( $path && file_exists( $path ) && is_readable( $path ) ) return $path;
		return null;
	}

	/**
	 * Country-only lookup using local GeoLite2-Country.mmdb.
	 */
	public function get_location_data( $ip = null ): array {
		// Optional dev helper: force IP via ?pw_geo_ip=
		if ( isset($_GET['pw_geo_ip']) && filter_var($_GET['pw_geo_ip'], FILTER_VALIDATE_IP) ) {
			$ip = $_GET['pw_geo_ip'];
		}

		$ip = $ip ?: $this->get_client_ip();

		// Local/dev IPs
		if ( $ip === '127.0.0.1' || $ip === '::1' || $ip === '0.0.0.0' ) {
			return [
				'ip'           => $ip,
				'country'      => 'Local',
				'country_code' => '',
				'provider'     => 'local',
				'cached'       => true,
				'error'        => '',
			];
		}

		$key = self::TRANSIENT_PREFIX . md5( $ip );
		if ( isset($_GET['pw_geo_flush']) ) delete_transient($key);

		$cached = get_transient( $key );
		if ( is_array( $cached ) && ! empty( $cached['ip'] ) ) {
			$cached['cached'] = true;
			return $cached;
		}

		$data = [
			'ip'           => $ip,
			'country'      => '',
			'country_code' => '',
			'provider'     => 'maxmind-local',
			'cached'       => false,
			'error'        => '',
		];

		try {
			if ( ! class_exists('\GeoIp2\Database\Reader') ) {
				$data['error'] = 'GeoIP2 library not loaded (vendor/autoload.php missing?)';
				return $data;
			}

			$dbPath = $this->get_maxmind_db_path();
			if ( ! $dbPath ) {
				$data['error'] = 'GeoLite2-Country.mmdb not found or unreadable.';
				return $data;
			}

			$reader = new \GeoIp2\Database\Reader( $dbPath );
			$record = $reader->country( $ip );

			$data['country']      = sanitize_text_field( $record->country->name ?? '' );
			$data['country_code'] = sanitize_text_field( $record->country->isoCode ?? '' );

			$ttl = (int) apply_filters( 'pw_user_geo_cache_ttl', 12 * HOUR_IN_SECONDS );
			set_transient( $key, $data, $ttl );
			return $data;

		} catch ( \Throwable $e ) {
			$data['error'] = $e->getMessage();
			return $data;
		}
	}

	/**
	 * Shortcode: [pw_user_geo fields="country,country_code" wrapper="inline|list|none" show_labels="1|0" ip=""]
	 */
	public function shortcode( $atts = [] ): string {
		$atts = shortcode_atts( [
			'fields'      => 'country',
			'wrapper'     => 'inline', // inline|list|none
			'show_labels' => '1',
			'ip'          => '',
		], $atts, 'pw_user_geo' );

		$data       = $this->get_location_data( $atts['ip'] ?: null );
		$fields     = array_filter( array_map( 'trim', explode( ',', strtolower( $atts['fields'] ) ) ) );
		$show_labels = $atts['show_labels'] === '1';

		$labels = [
			'ip'           => __( 'IP', 'pw-user-geo' ),
			'country'      => __( 'Country', 'pw-user-geo' ),
			'country_code' => __( 'Country Code', 'pw-user-geo' ),
		];

		$items = [];
		foreach ( $fields as $f ) {
			if ( ! array_key_exists( $f, $data ) ) continue;
			$val = $data[ $f ];
			if ( $val === '' ) continue;
			$items[] = $show_labels
				? sprintf( '<span class="pw-user-geo__label">%s:</span> <span class="pw-user-geo__value">%s</span>', esc_html( $labels[ $f ] ?? ucfirst( $f ) ), esc_html( $val ) )
				: esc_html( $val );
		}

		if ( empty( $items ) ) {
			if ( ! empty( $data['error'] ) ) {
				return '<div class="pw-user-geo pw-user-geo--error">' . esc_html( $data['error'] ) . '</div>';
			}
			return '<div class="pw-user-geo pw-user-geo--empty">' . esc_html__( 'Location unavailable', 'pw-user-geo' ) . '</div>';
		}

		switch ( $atts['wrapper'] ) {
			case 'list':
				return '<ul class="pw-user-geo pw-user-geo--list"><li>' . implode( '</li><li>', $items ) . '</li></ul>';
			case 'none':
				return implode( ' ', $items );
			case 'inline':
			default:
				return '<span class="pw-user-geo pw-user-geo--inline">' . implode( ' · ', $items ) . '</span>';
		}
	}
}

// Include admin tools page
require_once __DIR__ . '/admin.php';

// Boot main class
PW_User_Geo::instance();

// Include redirect settings (textarea UI)
require_once __DIR__ . '/admin-redirects.php';

/* ===============================
   Cache-safe redirect via AJAX
   =============================== */

// 1) Helper to print inline script (theme or shortcode)
if ( ! function_exists( 'pw_user_geo_redirect_html' ) ) {
	function pw_user_geo_redirect_html(): string {
		$ajax = esc_url( admin_url( 'admin-ajax.php' ) );
		$inline = <<<JS
(function(){
  try{
    var uri  = location.pathname + location.search;
    var data = new URLSearchParams();
    data.append('action','pw_user_geo_redirect');
    data.append('uri', uri);
    data.append('host', location.host);
    // optional bypass via ?geo_noredirect=1 (sets cookie)
    if (/[?&]geo_noredirect=1(&|$)/.test(location.search)) {
      document.cookie='pw_geo_noredirect=1; max-age='+(30*24*3600)+'; path=/';
    }
    fetch('{$ajax}', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {'Content-Type':'application/x-www-form-urlencoded'},
      body: data.toString()
    }).then(function(r){ return r.json(); }).then(function(res){
      if(!res || !res.success || !res.data) return;
      if(res.data.redirect && res.data.url){
        if (res.data.url.replace(/\\/+$/,'') !== location.href.replace(/\\/+$/,'')) {
          location.replace(res.data.url);
        }
      }
    }).catch(function(){});
  }catch(e){}
})();
JS;
		return '<script>' . $inline . '</script>';
	}
}
add_shortcode( 'pw_user_geo_redirect', function(){ return pw_user_geo_redirect_html(); } );

// 2) AJAX endpoint (guests + logged-in)
if ( ! function_exists( 'pw_user_geo_normalize_uri' ) ) {
        /**
         * Ensure we only work with relative paths + optional query strings.
         */
        function pw_user_geo_normalize_uri( string $uri ): string {
                $uri   = preg_replace( '/[\x00-\x1F\x7F]/', '', $uri );
                $parts = wp_parse_url( $uri );

                if ( ! is_array( $parts ) ) {
                        return '/';
                }

                $path = $parts['path'] ?? '/';
                $path = $path === '' ? '/' : $path;
                if ( $path[0] !== '/' ) {
                        $path = '/' . ltrim( $path, '/' );
                }

                $query = isset( $parts['query'] ) && $parts['query'] !== ''
                        ? '?' . $parts['query']
                        : '';

                return $path . $query;
        }
}

if ( ! function_exists( 'pw_user_geo_normalize_host' ) ) {
        /**
         * Normalize host (optionally with port) from client-side value.
         */
        function pw_user_geo_normalize_host( string $host ): string {
                $host = preg_replace( '/[\x00-\x1F\x7F]/', '', $host );
                if ( $host === '' ) {
                        return '';
                }

                $parsed = wp_parse_url( '//' . ltrim( $host, '/' ) );
                if ( ! is_array( $parsed ) || empty( $parsed['host'] ) ) {
                        return '';
                }

                $clean = strtolower( preg_replace( '/[^a-z0-9\.-]/', '', $parsed['host'] ) );

                if ( ! empty( $parsed['port'] ) ) {
                        $port = (int) $parsed['port'];
                        if ( $port > 0 ) {
                                $clean .= ':' . $port;
                        }
                }

                return $clean;
        }
}
if ( ! function_exists( 'pw_user_geo_redirect_ajax' ) ) {
	function pw_user_geo_redirect_ajax() {
		// Ensure option keys and helpers exist
		if ( ! defined( 'PW_USER_GEO_REDIRECT_OPTION' ) ) define( 'PW_USER_GEO_REDIRECT_OPTION', 'pw_user_geo_redirects' );
		if ( ! function_exists( 'pw_user_geo_redirect_default_options' ) || ! function_exists( 'pw_user_geo_redirect_parse_mapping' ) ) {
			wp_send_json_success( [ 'redirect' => false, 'reason' => 'settings_missing' ] );
		}

		nocache_headers();

		$opt = wp_parse_args( get_option( PW_USER_GEO_REDIRECT_OPTION ), pw_user_geo_redirect_default_options() );

		// Respect settings
		if ( empty( $opt['enabled'] ) )                            wp_send_json_success( ['redirect'=>false,'reason'=>'disabled'] );
		if ( defined('REST_REQUEST') && REST_REQUEST )              wp_send_json_success( ['redirect'=>false,'reason'=>'rest'] );
		if ( wp_doing_cron() )                                     wp_send_json_success( ['redirect'=>false,'reason'=>'cron'] );
		if ( ! empty($opt['skip_logged_in']) && is_user_logged_in() ) wp_send_json_success( ['redirect'=>false,'reason'=>'logged_in'] );
		if ( ! empty($opt['skip_admins']) && current_user_can('manage_options') ) wp_send_json_success( ['redirect'=>false,'reason'=>'admin'] );
		if ( ! empty($opt['respect_bypass']) && ! empty($_COOKIE['pw_geo_noredirect']) ) wp_send_json_success( ['redirect'=>false,'reason'=>'bypass_cookie'] );

		$uri  = isset( $_POST['uri'] )
				? pw_user_geo_normalize_uri( (string) wp_unslash( $_POST['uri'] ) )
				: '/';
		$host = isset( $_POST['host'] )
				? pw_user_geo_normalize_host( (string) wp_unslash( $_POST['host'] ) )
				: '';

		if ( $host === '' ) {
				$server_host = isset( $_SERVER['HTTP_HOST'] )
						? pw_user_geo_normalize_host( (string) wp_unslash( $_SERVER['HTTP_HOST'] ) )
						: '';

				$host = $server_host;
		}

		if ( $host === '' ) {
				wp_send_json_success( [ 'redirect' => false, 'reason' => 'host_unknown' ] );
		}

		// Rules
		$map = pw_user_geo_redirect_parse_mapping( $opt['mapping_raw'] ?? '' );

		if ( empty( $map ) ) wp_send_json_success( ['redirect'=>false,'reason'=>'no_mapping'] );

		// Country
		$geo = pw_user_geo_get();
		if ( ! is_array( $geo ) ) wp_send_json_success( ['redirect'=>false,'reason'=>'geo_error'] );
		$cc = strtoupper( $geo['country_code'] ?? '' );

		$tpl = $map[ $cc ] ?? ( $map['*'] ?? '' );
		if ( ! $tpl ) wp_send_json_success( ['redirect'=>false,'reason'=>'no_rule'] );

		$target = str_replace( '{REQUEST_URI}', $uri ?: '/', $tpl );

		// Loop guard: identical URL -> no redirect
		if ( $host_known ) {
			$scheme       = is_ssl() ? 'https://' : 'http://';
			$current_full = $scheme . $host . $uri;
			if ( rtrim( $target, '/' ) === rtrim( $current_full, '/' ) ) {
					wp_send_json_success( ['redirect'=>false,'reason'=>'same_url'] );
			}
		}



		wp_send_json_success( [
			'redirect' => true,
			'url'      => $target,
			'reason'   => 'rule_match',
			'cc'       => $cc,
		] );
	}
}
add_action( 'wp_ajax_pw_user_geo_redirect',        'pw_user_geo_redirect_ajax' );
add_action( 'wp_ajax_nopriv_pw_user_geo_redirect', 'pw_user_geo_redirect_ajax' );

/**
 * ===============================
 * PW User Geo – Country display (cache-safe)
 * ===============================
 *
 * - pw_user_geo_country()         -> server-side value (not cache-safe)
 * - pw_user_geo_country_html()    -> placeholder + JS endpoint (cache-safe)
 * - [pw_user_country label="..."] -> shortcode (cache-safe)
 */

// 1) Raw value (use only on non-cached pages)
if ( ! function_exists( 'pw_user_geo_country' ) ) {
	function pw_user_geo_country(): string {
		$geo = pw_user_geo_get();
		return is_array($geo) ? (string)($geo['country'] ?? '') : '';
	}
}

// 2) Cache-safe HTML (placeholder + tiny JS endpoint)
if ( ! function_exists( 'pw_user_geo_country_html' ) ) {
	function pw_user_geo_country_html( $label = 'Loading…' ): string {
		$label = esc_html( $label );
		$src   = esc_url( admin_url( 'admin-ajax.php?action=pw_user_geo_js_country' ) );
		return '<span data-pw-geo-country>' . $label . '</span><script defer src="' . $src . '"></script>';
	}
}

// 3) Shortcode
add_shortcode('pw_user_country', function($atts){
	$atts = shortcode_atts(['label' => 'Detecting…'], $atts, 'pw_user_country');
	return pw_user_geo_country_html( $atts['label'] );
});

// 4) Tiny JS endpoint that prints the visitor’s country
add_action('wp_ajax_pw_user_geo_js_country',     'pw_user_geo_js_country');
add_action('wp_ajax_nopriv_pw_user_geo_js_country', 'pw_user_geo_js_country');

if ( ! function_exists('pw_user_geo_js_country') ) {
	function pw_user_geo_js_country() {
		// Return JS, not HTML
		nocache_headers();
		header('Content-Type: application/javascript; charset=utf-8');

		$geo = pw_user_geo_get();
		$country = '';
		$cc = '';
		if ( is_array($geo) ) {
			$country = (string) ($geo['country'] ?? '');
			$cc      = strtoupper( (string) ($geo['country_code'] ?? '') );
		}

		$country_js = wp_json_encode( $country );
		$cc_js      = wp_json_encode( $cc );

		echo "document.querySelectorAll('[data-pw-geo-country]').forEach(function(el){ el.textContent = {$country_js} || ''; if ({$cc_js}) el.setAttribute('data-pw-geo-cc', {$cc_js}); });";
		exit;
	}
}
