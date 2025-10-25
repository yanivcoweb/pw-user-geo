<?php
if ( ! defined( 'ABSPATH' ) ) exit;

define( 'PW_USER_GEO_REDIRECT_OPTION', 'pw_user_geo_redirects' );

/** Defaults (textarea-based) */
function pw_user_geo_redirect_default_options() {
	return [
		'enabled'        => 0,
		'skip_logged_in' => 1,
		'skip_admins'    => 1,
		'respect_bypass' => 1,
                'mapping_raw'    => "IL|https://he.webdevtest.co.il{REQUEST_URI}\nFR|https://fr.webdevtest.co.il{REQUEST_URI}\nES|https://es.webdevtest.co.il{REQUEST_URI}\nPT|https://pd.webdevtest.co.il{REQUEST_URI}\nDE|https://de.webdevtest.co.il{REQUEST_URI}\n*|https://webdevtest.co.il{REQUEST_URI}",
	];
}

/** Parse textarea rules → array('IL' => 'https://..{REQUEST_URI}', '*' => 'https://..') */
function pw_user_geo_redirect_parse_mapping( string $raw ) : array {
	$out = [];
	$lines = preg_split('/\r\n|\r|\n/', trim($raw));
	foreach ( $lines as $line ) {
		$line = trim($line);
		if ( $line === '' || $line[0] === '#' ) continue;

		$parts = array_map('trim', explode('|', $line, 2));
		if ( count($parts) !== 2 ) continue;

		$cc  = strtoupper( preg_replace('/[^A-Z\*]/', '', $parts[0]) );
		$url = trim($parts[1]);

		// Preserve {REQUEST_URI} while sanitizing URL
		$protected = str_replace('{REQUEST_URI}', '__PW_REQ_URI__', $url);
		$protected = esc_url_raw( $protected ); // keep only http(s)
		$url = str_replace('__PW_REQ_URI__','{REQUEST_URI}', $protected);

		// Must start with http(s)
		$test = str_replace('{REQUEST_URI}','/', $url);
		if ( ! $cc || ! $url || ! preg_match('#^https?://#i', $test) ) continue;

		$out[$cc] = $url;
	}
	return $out;
}

/** Settings registration */
add_action( 'admin_init', function () {
	register_setting(
		'pw_user_geo_redirects_group',
		PW_USER_GEO_REDIRECT_OPTION,
		[
			'type'    => 'array',
			'default' => pw_user_geo_redirect_default_options(),
			'sanitize_callback' => function( $input ) {
				$def = pw_user_geo_redirect_default_options();

				$out = [
					'enabled'        => empty($input['enabled']) ? 0 : 1,
					'skip_logged_in' => empty($input['skip_logged_in']) ? 0 : 1,
					'skip_admins'    => empty($input['skip_admins']) ? 0 : 1,
					'respect_bypass' => empty($input['respect_bypass']) ? 0 : 1,
					'mapping_raw'    => isset($input['mapping_raw']) ? (string)$input['mapping_raw'] : $def['mapping_raw'],
				];

				// If nothing valid was parsed, fall back to defaults
				$parsed = pw_user_geo_redirect_parse_mapping( $out['mapping_raw'] );
				if ( empty($parsed) ) $out['mapping_raw'] = $def['mapping_raw'];

				return $out;
			},
		]
	);
});

/** Admin page */
add_action( 'admin_menu', function () {
	add_options_page(
		__( 'PW User Geo Redirects', 'pw-user-geo' ),
		__( 'PW User Geo Redirects', 'pw-user-geo' ),
		'manage_options',
		'pw-user-geo-redirects',
		'pw_user_geo_redirects_render_page'
	);
});

function pw_user_geo_redirects_render_page() {
	if ( ! current_user_can( 'manage_options' ) ) return;
	$opt = wp_parse_args( get_option( PW_USER_GEO_REDIRECT_OPTION ), pw_user_geo_redirect_default_options() );
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'PW User Geo Redirects', 'pw-user-geo' ); ?></h1>
		<?php settings_errors(); ?>
		<form method="post" action="options.php">
			<?php settings_fields( 'pw_user_geo_redirects_group' ); ?>

			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Enable redirects', 'pw-user-geo' ); ?></th>
					<td>
						<label><input type="checkbox" name="<?php echo esc_attr( PW_USER_GEO_REDIRECT_OPTION ); ?>[enabled]" value="1" <?php checked( ! empty( $opt['enabled'] ) ); ?>>
							<?php esc_html_e( 'Turn on geolocation-based redirects', 'pw-user-geo' ); ?></label>
					</td>
				</tr>

				<tr>
					<th scope="row"><?php esc_html_e( 'Skip for logged-in users', 'pw-user-geo' ); ?></th>
					<td><label><input type="checkbox" name="<?php echo esc_attr( PW_USER_GEO_REDIRECT_OPTION ); ?>[skip_logged_in]" value="1" <?php checked( ! empty( $opt['skip_logged_in'] ) ); ?>> <?php esc_html_e( 'Do not redirect logged-in users', 'pw-user-geo' ); ?></label></td>
				</tr>

				<tr>
					<th scope="row"><?php esc_html_e( 'Skip for administrators', 'pw-user-geo' ); ?></th>
					<td><label><input type="checkbox" name="<?php echo esc_attr( PW_USER_GEO_REDIRECT_OPTION ); ?>[skip_admins]" value="1" <?php checked( ! empty( $opt['skip_admins'] ) ); ?>> <?php esc_html_e( 'Do not redirect admins', 'pw-user-geo' ); ?></label></td>
				</tr>

				<tr>
					<th scope="row"><?php esc_html_e( 'Bypass switch', 'pw-user-geo' ); ?></th>
					<td>
						<label><input type="checkbox" name="<?php echo esc_attr( PW_USER_GEO_REDIRECT_OPTION ); ?>[respect_bypass]" value="1" <?php checked( ! empty( $opt['respect_bypass'] ) ); ?>> <?php esc_html_e( 'Allow ?geo_noredirect=1 to set a no-redirect cookie', 'pw-user-geo' ); ?></label>
					</td>
				</tr>

				<tr>
					<th scope="row"><?php esc_html_e( 'Country → URL rules', 'pw-user-geo' ); ?></th>
					<td>
<textarea name="<?php echo esc_attr( PW_USER_GEO_REDIRECT_OPTION ); ?>[mapping_raw]" rows="8" cols="80" class="large-text code"><?php echo esc_textarea( $opt['mapping_raw'] ); ?></textarea>
						<p class="description">
							<?php esc_html_e( 'One rule per line. Format:', 'pw-user-geo' ); ?><br>
							<code>CC|https://example.com{REQUEST_URI}</code> &nbsp; <?php esc_html_e( '(Use * as fallback)', 'pw-user-geo' ); ?>
						</p>
					</td>
				</tr>
			</table>

			<?php submit_button(); ?>
		</form>
	</div>
	<?php
}
