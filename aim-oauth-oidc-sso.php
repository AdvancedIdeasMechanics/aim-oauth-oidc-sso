<?php
declare(strict_types=1);
/**
 * Plugin Name:       AIM OAuth 2.0 PKCE & OIDC SSO
 * Description:       OAuth 2.0 PKCE, OIDC SSO with flexible auth methods, 6-character random backdoor key, JWKS verification, Auto-Discovery, Tabbed Admin, Attribute Mapping, WooCommerce, and REST API Protection.
 * Version:           10.0.0
 * Author:            Advanced Ideas & Mechanics
 * Author URI:        https://advanced.im/products
 * License:           GPL v3 or later
 * License URI:       https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain:       aim-oauth-oidc-sso
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly
}

class AIM_OAuth_OIDC_SSO {

    private $group_general    = 'aim_oauth_group_general';
    private $group_endpoints  = 'aim_oauth_group_endpoints';
    private $group_attributes = 'aim_oauth_group_attributes';
    private $group_woo        = 'aim_oauth_group_woo';
    private $group_rest       = 'aim_oauth_group_rest';

    public function __construct() {
        // Init Session for PKCE & state storage
        add_action( 'init', array( $this, 'init_session' ) );

        // Admin Menu & Settings
        add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
        add_action( 'admin_init', array( $this, 'register_settings' ) );

        // Plugin Action Links on Plugins List Screen
        add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), array( $this, 'add_plugin_action_links' ) );

        // AJAX Handlers for Auto-Discovery & Key Regeneration
        add_action( 'wp_ajax_aim_oauth_sso_discover_endpoints', array( $this, 'ajax_discover_endpoints' ) );
        add_action( 'wp_ajax_aim_oauth_regenerate_backdoor', array( $this, 'ajax_regenerate_backdoor' ) );

        // Intercept Standard & WooCommerce Login Requests
        add_action( 'login_init', array( $this, 'intercept_login_page' ) );
        add_action( 'template_redirect', array( $this, 'intercept_woocommerce_account_page' ) );

        // Render SSO Button on standard wp-login.php when forced redirect is OFF
        add_action( 'login_form', array( $this, 'render_wplogin_sso_button' ) );

        // WooCommerce SSO Button Rendering
        add_action( 'woocommerce_login_form_end', array( $this, 'render_woocommerce_sso_button' ) );
        add_action( 'woocommerce_before_customer_login_form', array( $this, 'render_woocommerce_sso_button' ) );

        // Handle OAuth Callback
        add_action( 'init', array( $this, 'handle_oauth_callback' ) );

        // Handle Logout
        add_action( 'wp_logout', array( $this, 'handle_logout' ) );

        // REST API Protection Hooks
        add_filter( 'determine_current_user', array( $this, 'authenticate_rest_bearer_token' ), 20 );
        add_filter( 'rest_authentication_errors', array( $this, 'enforce_rest_api_protection' ) );
    }

    public function init_session() {
        if ( ! session_id() && ! headers_sent() ) {
            session_start();
        }
    }

    private function is_woocommerce_active() {
        return class_exists( 'WooCommerce' );
    }

    public static function generate_6char_random_key() {
        return wp_generate_password( 6, false, false );
    }

    /* ==========================================================================
       1. PLUGIN ACTION LINKS & UNINSTALL CLEANUP
       ========================================================================== */

    public function add_plugin_action_links( $links ) {
        $settings_link = '<a href="' . esc_url( admin_url( 'options-general.php?page=aim-oauth-oidc-sso' ) ) . '">' . __( 'Settings', 'aim-oauth-oidc-sso' ) . '</a>';
        array_unshift( $links, $settings_link );
        return $links;
    }

    public static function on_uninstall() {
        $options = array(
            'aim_oauth_auth_method',
            'aim_oauth_enable_redirect',
            'aim_oauth_client_id',
            'aim_oauth_client_secret',
            'aim_oauth_scopes',
            'aim_oauth_backdoor_key',
            'aim_oauth_discovery_url',
            'aim_oauth_authorize_url',
            'aim_oauth_token_url',
            'aim_oauth_userinfo_url',
            'aim_oauth_jwks_url',
            'aim_oauth_attr_email',
            'aim_oauth_attr_username',
            'aim_oauth_attr_first_name',
            'aim_oauth_attr_last_name',
            'aim_oauth_default_role',
            'aim_oauth_woo_redirect_account',
            'aim_oauth_rest_protection_mode',
        );

        foreach ( $options as $option ) {
            delete_option( $option );
        }

        global $wpdb;
        $wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_aim_oauth_jwks_%' OR option_name LIKE '_transient_timeout_aim_oauth_jwks_%'" );
    }

    /* ==========================================================================
       2. HELPER FUNCTIONS FOR CRYPTOGRAPHY & PKCE
       ========================================================================== */

    private function base64url_encode( $data ) {
        return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
    }

    private function base64url_decode( $data ) {
        return base64_decode( strtr( $data, '-_', '+/' ) . str_repeat( '=', ( 4 - strlen( $data ) % 4 ) % 4 ) );
    }

    private function generate_code_verifier() {
        return $this->base64url_encode( random_bytes( 64 ) );
    }

    private function generate_code_challenge( $verifier ) {
        $hash = hash( 'sha256', $verifier, true );
        return $this->base64url_encode( $hash );
    }

    private function jwk_to_pem( $n_b64, $e_b64 ) {
        $n = $this->base64url_decode( $n_b64 );
        $e = $this->base64url_decode( $e_b64 );

        $modulus  = pack( 'Ca*a*', 0x02, $this->asn1_length( strlen( $n ) ), $n );
        $exponent = pack( 'Ca*a*', 0x02, $this->asn1_length( strlen( $e ) ), $e );

        $sequence   = pack( 'Ca*a*', 0x30, $this->asn1_length( strlen( $modulus . $exponent ) ), $modulus . $exponent );
        $bit_string = pack( 'CCa*', 0x03, $this->asn1_length( strlen( $sequence ) + 1 ), "\x00" . $sequence );

        $rsa_oid = pack( 'H*', '300d06092a864886f70d0101010500' );
        $pub_key = pack( 'Ca*a*', 0x30, $this->asn1_length( strlen( $rsa_oid . $bit_string ) ), $rsa_oid . $bit_string );

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $pub_key ), 64, "\n" ) . "-----END PUBLIC KEY-----\n";
    }

    private function asn1_length( $len ) {
        if ( $len < 128 ) {
            return chr( $len );
        }
        $data = ltrim( pack( 'N', $len ), "\x00" );
        return chr( 0x80 | strlen( $data ) ) . $data;
    }

    private function verify_and_decode_id_token( $id_token, $jwks_url ) {
        $parts = explode( '.', $id_token );
        if ( count( $parts ) !== 3 ) {
            return false;
        }

        list( $header_b64, $payload_b64, $sig_b64 ) = $parts;

        $header  = json_decode( $this->base64url_decode( $header_b64 ), true );
        $payload = json_decode( $this->base64url_decode( $payload_b64 ), true );
        $sig     = $this->base64url_decode( $sig_b64 );

        if ( empty( $header['alg'] ) || empty( $header['kid'] ) || empty( $jwks_url ) ) {
            return $payload;
        }

        $cache_key = 'aim_oauth_jwks_' . md5( $jwks_url );
        $jwks_data = get_transient( $cache_key );

        if ( ! $jwks_data ) {
            $response = wp_remote_get( $jwks_url, array( 'timeout' => 10 ) );
            if ( ! is_wp_error( $response ) ) {
                $jwks_data = json_decode( wp_remote_retrieve_body( $response ), true );
                set_transient( $cache_key, $jwks_data, DAY_IN_SECONDS );
            }
        }

        if ( empty( $jwks_data['keys'] ) ) {
            return $payload;
        }

        $public_key_pem = null;
        foreach ( $jwks_data['keys'] as $key ) {
            if ( isset( $key['kid'] ) && $key['kid'] === $header['kid'] ) {
                if ( isset( $key['n'] ) && isset( $key['e'] ) ) {
                    $public_key_pem = $this->jwk_to_pem( $key['n'], $key['e'] );
                    break;
                }
            }
        }

        if ( $public_key_pem && $header['alg'] === 'RS256' ) {
            $data_to_verify = $header_b64 . '.' . $payload_b64;
            $verified       = openssl_verify( $data_to_verify, $sig, $public_key_pem, OPENSSL_ALGO_SHA256 );

            if ( $verified !== 1 ) {
                wp_die( 'Security check failed: Invalid ID Token signature.' );
            }
        }

        return $payload;
    }

    /* ==========================================================================
       3. AJAX HANDLERS
       ========================================================================== */

    public function ajax_discover_endpoints() {
        check_ajax_referer( 'aim_oauth_sso_discovery_nonce', 'security' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Unauthorized user.' );
        }

        $discovery_url = esc_url_raw( $_POST['discovery_url'] ?? '' );

        if ( empty( $discovery_url ) ) {
            wp_send_json_error( 'Please enter a valid Discovery URL or Base Issuer URI.' );
        }

        if ( strpos( $discovery_url, '.well-known/openid-configuration' ) === false ) {
            $discovery_url = rtrim( $discovery_url, '/' ) . '/.well-known/openid-configuration';
        }

        $response = wp_remote_get( $discovery_url, array( 'timeout' => 10 ) );

        if ( is_wp_error( $response ) ) {
            wp_send_json_error( 'Failed to fetch OIDC configuration: ' . $response->get_error_message() );
        }

        $data = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( empty( $data ) || ! is_array( $data ) ) {
            wp_send_json_error( 'Invalid JSON response received from Discovery endpoint.' );
        }

        $endpoints = array(
            'authorize_url' => $data['authorization_endpoint'] ?? '',
            'token_url'     => $data['token_endpoint'] ?? '',
            'userinfo_url'  => $data['userinfo_endpoint'] ?? '',
            'jwks_url'      => $data['jwks_uri'] ?? '',
        );

        if ( empty( $endpoints['authorize_url'] ) || empty( $endpoints['token_url'] ) ) {
            wp_send_json_error( 'Endpoints missing in Discovery document.' );
        }

        update_option( 'aim_oauth_authorize_url', sanitize_text_field( $endpoints['authorize_url'] ) );
        update_option( 'aim_oauth_token_url', sanitize_text_field( $endpoints['token_url'] ) );
        if ( ! empty( $endpoints['userinfo_url'] ) ) {
            update_option( 'aim_oauth_userinfo_url', sanitize_text_field( $endpoints['userinfo_url'] ) );
        }
        if ( ! empty( $endpoints['jwks_url'] ) ) {
            update_option( 'aim_oauth_jwks_url', sanitize_text_field( $endpoints['jwks_url'] ) );
        }

        wp_send_json_success( array(
            'message'   => 'Successfully fetched and auto-configured endpoints & JWKS URI!',
            'endpoints' => $endpoints,
        ));
    }

    public function ajax_regenerate_backdoor() {
        check_ajax_referer( 'aim_oauth_backdoor_nonce', 'security' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Unauthorized.' );
        }

        $new_key = self::generate_6char_random_key();
        update_option( 'aim_oauth_backdoor_key', $new_key );

        wp_send_json_success( array(
            'new_key' => $new_key,
            'url'     => site_url( '/wp-login.php?bypass_oauth=' . $new_key ),
        ));
    }

    /* ==========================================================================
       4. TABBED ADMIN SETTINGS PAGE
       ========================================================================== */

    public function add_admin_menu() {
        add_options_page(
            'AIM OAuth & OIDC SSO',
            'AIM OAuth SSO',
            'manage_options',
            'aim-oauth-oidc-sso',
            array( $this, 'render_settings_page' )
        );
    }

    public function register_settings() {
        // Tab 1: General
        register_setting( $this->group_general, 'aim_oauth_auth_method', array( 'default' => 'client_secret_pkce' ) );
        register_setting( $this->group_general, 'aim_oauth_enable_redirect' );
        register_setting( $this->group_general, 'aim_oauth_client_id' );
        register_setting( $this->group_general, 'aim_oauth_client_secret' );
        register_setting( $this->group_general, 'aim_oauth_scopes' );
        register_setting( $this->group_general, 'aim_oauth_backdoor_key' );

        if ( ! get_option( 'aim_oauth_backdoor_key' ) ) {
            add_option( 'aim_oauth_backdoor_key', self::generate_6char_random_key() );
        }

        // Tab 2: Endpoints
        register_setting( $this->group_endpoints, 'aim_oauth_discovery_url' );
        register_setting( $this->group_endpoints, 'aim_oauth_authorize_url' );
        register_setting( $this->group_endpoints, 'aim_oauth_token_url' );
        register_setting( $this->group_endpoints, 'aim_oauth_userinfo_url' );
        register_setting( $this->group_endpoints, 'aim_oauth_jwks_url' );

        // Tab 3: Attributes
        register_setting( $this->group_attributes, 'aim_oauth_attr_email', array( 'default' => 'email' ) );
        register_setting( $this->group_attributes, 'aim_oauth_attr_username', array( 'default' => 'preferred_username' ) );
        register_setting( $this->group_attributes, 'aim_oauth_attr_first_name', array( 'default' => 'given_name' ) );
        register_setting( $this->group_attributes, 'aim_oauth_attr_last_name', array( 'default' => 'family_name' ) );
        register_setting( $this->group_attributes, 'aim_oauth_default_role', array( 'default' => 'subscriber' ) );

        // Tab 4: WooCommerce
        register_setting( $this->group_woo, 'aim_oauth_woo_redirect_account' );

        // Tab 5: REST API Protection
        register_setting( $this->group_rest, 'aim_oauth_rest_protection_mode', array( 'default' => 'open' ) );
    }

    public function render_settings_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $active_tab   = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'general';
        $callback_url = site_url( '/?oauth_callback=1' );
        $backdoor_key = get_option( 'aim_oauth_backdoor_key', self::generate_6char_random_key() );
        $backdoor_url = site_url( '/wp-login.php?bypass_oauth=' . esc_attr( $backdoor_key ) );
        $auth_method  = get_option( 'aim_oauth_auth_method', 'client_secret_pkce' );
        $rest_mode    = get_option( 'aim_oauth_rest_protection_mode', 'open' );
        $woo_status   = $this->is_woocommerce_active() ? '<span style="color:green; font-weight:bold;">Detected & Active</span>' : '<span style="color:#666;">Not Active</span>';

        $current_option_group = $this->group_general;
        if ( $active_tab === 'endpoints' ) {
            $current_option_group = $this->group_endpoints;
        } elseif ( $active_tab === 'attributes' ) {
            $current_option_group = $this->group_attributes;
        } elseif ( $active_tab === 'woocommerce' ) {
            $current_option_group = $this->group_woo;
        } elseif ( $active_tab === 'rest_api' ) {
            $current_option_group = $this->group_rest;
        }

        $get_tab_url = function( $tab_name ) {
            return admin_url( 'options-general.php?page=aim-oauth-oidc-sso&tab=' . $tab_name );
        };
        ?>
        <div class="wrap">
            <h1>AIM OAuth 2.0 PKCE & OIDC Single Sign-On</h1>
            <p>Manage authentication workflows, identity provider endpoints, attribute claims, WooCommerce, and REST API Protection.</p>

            <h2 class="nav-tab-wrapper">
                <a href="<?php echo esc_url( $get_tab_url( 'general' ) ); ?>" class="nav-tab <?php echo $active_tab == 'general' ? 'nav-tab-active' : ''; ?>">General Settings</a>
                <a href="<?php echo esc_url( $get_tab_url( 'endpoints' ) ); ?>" class="nav-tab <?php echo $active_tab == 'endpoints' ? 'nav-tab-active' : ''; ?>">Endpoints & Auto-Discovery</a>
                <a href="<?php echo esc_url( $get_tab_url( 'attributes' ) ); ?>" class="nav-tab <?php echo $active_tab == 'attributes' ? 'nav-tab-active' : ''; ?>">Attribute & Role Mapping</a>
                <a href="<?php echo esc_url( $get_tab_url( 'woocommerce' ) ); ?>" class="nav-tab <?php echo $active_tab == 'woocommerce' ? 'nav-tab-active' : ''; ?>">WooCommerce</a>
                <a href="<?php echo esc_url( $get_tab_url( 'rest_api' ) ); ?>" class="nav-tab <?php echo $active_tab == 'rest_api' ? 'nav-tab-active' : ''; ?>">REST API Protection</a>
            </h2>

            <form method="post" action="options.php" style="margin-top: 20px;">
                <?php settings_fields( $current_option_group ); ?>

                <?php if ( $active_tab == 'general' ) : ?>
                    <table class="form-table">
                        <tr valign="top">
                            <th scope="row">Authentication Method</th>
                            <td>
                                <fieldset>
                                    <label><input type="radio" name="aim_oauth_auth_method" value="client_secret" <?php checked( 'client_secret', $auth_method ); ?> /> <strong>Client ID & Client Secret Only</strong> (Standard Confidential Client)</label><br />
                                    <label><input type="radio" name="aim_oauth_auth_method" value="pkce_only" <?php checked( 'pkce_only', $auth_method ); ?> /> <strong>Client ID & Code PKCE Only</strong> (Public Client / No Client Secret)</label><br />
                                    <label><input type="radio" name="aim_oauth_auth_method" value="client_secret_pkce" <?php checked( 'client_secret_pkce', $auth_method ); ?> /> <strong>Client ID + Client Secret + Code PKCE</strong> (Maximum Security / Recommended)</label>
                                </fieldset>
                            </td>
                        </tr>
                        <tr valign="top">
                            <th scope="row">Override WordPress Login Page</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="aim_oauth_enable_redirect" value="1" <?php checked( 1, get_option( 'aim_oauth_enable_redirect' ), true ); ?> />
                                    <strong>Enable Forced OAuth Redirect</strong>
                                </label>
                                <p class="description">When unchecked, an <strong>"SSO Sign In"</strong> link/button will be displayed on standard <code>wp-login.php</code> instead.</p>
                            </td>
                        </tr>
                        <tr valign="top">
                            <th scope="row">Client ID</th>
                            <td><input type="text" name="aim_oauth_client_id" value="<?php echo esc_attr( get_option( 'aim_oauth_client_id' ) ); ?>" class="regular-text" /></td>
                        </tr>
                        <tr valign="top">
                            <th scope="row">Client Secret</th>
                            <td>
                                <input type="password" name="aim_oauth_client_secret" value="<?php echo esc_attr( get_option( 'aim_oauth_client_secret' ) ); ?>" class="regular-text" />
                                <p class="description">Required for Client Secret auth methods. Leave blank if using Code PKCE Only.</p>
                            </td>
                        </tr>
                        <tr valign="top">
                            <th scope="row">OAuth / OIDC Scopes</th>
                            <td><input type="text" name="aim_oauth_scopes" value="<?php echo esc_attr( get_option( 'aim_oauth_scopes', 'openid profile email' ) ); ?>" class="regular-text" /></td>
                        </tr>
                        <tr valign="top">
                            <th scope="row">Emergency Backdoor Key</th>
                            <td>
                                <div style="display: flex; gap: 10px; align-items: center;">
                                    <input type="text" id="aim_oauth_backdoor_key" name="aim_oauth_backdoor_key" value="<?php echo esc_attr( $backdoor_key ); ?>" class="regular-text" maxlength="6" style="width: 120px; font-weight: bold; letter-spacing: 2px;" />
                                    <button type="button" id="btn_regen_backdoor" class="button button-secondary">Generate New 6-Char Key</button>
                                </div>
                                <p class="description">6-character random alphanumeric key used to bypass OAuth redirect.</p>
                            </td>
                        </tr>
                    </table>

                <?php elseif ( $active_tab == 'endpoints' ) : ?>
                    <div class="card" style="max-width: 800px; padding: 15px; margin-bottom: 20px; background: #fff; border: 1px solid #ccc;">
                        <h2>Auto-Discover Endpoints & JWKS</h2>
                        <p>Enter your OpenID Provider's Discovery URL or Base Issuer URI:</p>
                        <div style="display: flex; gap: 10px; align-items: center;">
                            <input type="url" id="aim_oauth_discovery_input" value="<?php echo esc_attr( get_option( 'aim_oauth_discovery_url', '' ) ); ?>" class="regular-text" placeholder="https://your-idp.com/.well-known/openid-configuration" />
                            <button type="button" id="btn_discover_oidc" class="button button-secondary">Fetch & Auto-Configure</button>
                        </div>
                        <p id="discovery_status" style="margin-top: 10px; font-weight: bold;"></p>
                    </div>

                    <input type="hidden" name="aim_oauth_discovery_url" id="aim_oauth_discovery_url_hidden" value="<?php echo esc_attr( get_option( 'aim_oauth_discovery_url', '' ) ); ?>" />

                    <table class="form-table">
                        <tr valign="top">
                            <th scope="row">Authorization Endpoint URL</th>
                            <td><input type="url" id="aim_oauth_authorize_url" name="aim_oauth_authorize_url" value="<?php echo esc_attr( get_option( 'aim_oauth_authorize_url' ) ); ?>" class="regular-text" /></td>
                        </tr>
                        <tr valign="top">
                            <th scope="row">Token Endpoint URL</th>
                            <td><input type="url" id="aim_oauth_token_url" name="aim_oauth_token_url" value="<?php echo esc_attr( get_option( 'aim_oauth_token_url' ) ); ?>" class="regular-text" /></td>
                        </tr>
                        <tr valign="top">
                            <th scope="row">UserInfo Endpoint URL</th>
                            <td><input type="url" id="aim_oauth_userinfo_url" name="aim_oauth_userinfo_url" value="<?php echo esc_attr( get_option( 'aim_oauth_userinfo_url' ) ); ?>" class="regular-text" /></td>
                        </tr>
                        <tr valign="top">
                            <th scope="row">JWKS URI (JSON Web Key Set)</th>
                            <td><input type="url" id="aim_oauth_jwks_url" name="aim_oauth_jwks_url" value="<?php echo esc_attr( get_option( 'aim_oauth_jwks_url' ) ); ?>" class="regular-text" /></td>
                        </tr>
                    </table>

                <?php elseif ( $active_tab == 'attributes' ) : ?>
                    <table class="form-table">
                        <tr valign="top">
                            <th scope="row">Email Attribute Claim</th>
                            <td><input type="text" name="aim_oauth_attr_email" value="<?php echo esc_attr( get_option( 'aim_oauth_attr_email', 'email' ) ); ?>" class="regular-text" /></td>
                        </tr>
                        <tr valign="top">
                            <th scope="row">Username Attribute Claim</th>
                            <td><input type="text" name="aim_oauth_attr_username" value="<?php echo esc_attr( get_option( 'aim_oauth_attr_username', 'preferred_username' ) ); ?>" class="regular-text" /></td>
                        </tr>
                        <tr valign="top">
                            <th scope="row">First Name Attribute Claim</th>
                            <td><input type="text" name="aim_oauth_attr_first_name" value="<?php echo esc_attr( get_option( 'aim_oauth_attr_first_name', 'given_name' ) ); ?>" class="regular-text" /></td>
                        </tr>
                        <tr valign="top">
                            <th scope="row">Last Name Attribute Claim</th>
                            <td><input type="text" name="aim_oauth_attr_last_name" value="<?php echo esc_attr( get_option( 'aim_oauth_attr_last_name', 'family_name' ) ); ?>" class="regular-text" /></td>
                        </tr>
                        <tr valign="top">
                            <th scope="row">Default Assigned Role</th>
                            <td>
                                <select name="aim_oauth_default_role">
                                    <?php wp_dropdown_roles( get_option( 'aim_oauth_default_role', 'subscriber' ) ); ?>
                                </select>
                            </td>
                        </tr>
                    </table>

                <?php elseif ( $active_tab == 'woocommerce' ) : ?>
                    <table class="form-table">
                        <tr valign="top">
                            <th scope="row">WooCommerce Integration Status</th>
                            <td><p><?php echo $woo_status; ?></p></td>
                        </tr>
                        <tr valign="top">
                            <th scope="row">Force Redirect WooCommerce /my-account/</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="aim_oauth_woo_redirect_account" value="1" <?php checked( 1, get_option( 'aim_oauth_woo_redirect_account' ), true ); ?> />
                                    <strong>Auto-redirect unauthenticated users on WooCommerce Account page to Identity Provider</strong>
                                </label>
                                <p class="description">If left unchecked, an "SSO Sign In" button will be displayed on WooCommerce login forms instead.</p>
                            </td>
                        </tr>
                    </table>

                <?php elseif ( $active_tab == 'rest_api' ) : ?>
                    <table class="form-table">
                        <tr valign="top">
                            <th scope="row">REST API Access Mode</th>
                            <td>
                                <select name="aim_oauth_rest_protection_mode" style="min-width: 350px;">
                                    <option value="open" <?php selected( 'open', $rest_mode ); ?>>Open REST API (WordPress Default)</option>
                                    <option value="blocked" <?php selected( 'blocked', $rest_mode ); ?>>Completely Blocked to Unauthenticated Visitors</option>
                                    <option value="idp_bearer" <?php selected( 'idp_bearer', $rest_mode ); ?>>Require Valid Identity Provider Bearer Token</option>
                                </select>
                                <p class="description" style="margin-top: 10px;">
                                    <strong>Open:</strong> Public endpoints remain readable by anonymous requests.<br />
                                    <strong>Completely Blocked:</strong> All <code>/wp-json/</code> endpoints return HTTP 401 Unauthorized for visitors without an active logged-in browser session.<br />
                                    <strong>Bearer Token:</strong> Inspects incoming <code>Authorization: Bearer &lt;access_token&gt;</code> HTTP headers and authenticates requests dynamically against your Identity Provider.
                                </p>
                            </td>
                        </tr>
                    </table>
                <?php endif; ?>

                <?php submit_button(); ?>
            </form>

            <hr />
            <h2>System Summary</h2>
            <table class="widefat fixed" style="max-width: 800px;">
                <tr>
                    <td><strong>Redirect / Callback URL:</strong></td>
                    <td><code><?php echo esc_url( $callback_url ); ?></code></td>
                </tr>
                <tr>
                    <td><strong>Emergency Admin Bypass URL:</strong></td>
                    <td><code id="display_backdoor_url"><a href="<?php echo esc_url( $backdoor_url ); ?>" target="_blank"><?php echo esc_url( $backdoor_url ); ?></a></code></td>
                </tr>
            </table>
        </div>

        <script type="text/javascript">
            jQuery(document).ready(function($) {
                $('#btn_discover_oidc').on('click', function(e) {
                    e.preventDefault();
                    var discoveryUrl = $('#aim_oauth_discovery_input').val();
                    var $status = $('#discovery_status');

                    if (!discoveryUrl) {
                        $status.css('color', 'red').text('Please enter a Discovery URL.');
                        return;
                    }

                    $status.css('color', '#666').text('Fetching OIDC configuration & JWKS URI...');

                    $.post(ajaxurl, {
                        action: 'aim_oauth_sso_discover_endpoints',
                        discovery_url: discoveryUrl,
                        security: '<?php echo wp_create_nonce( "aim_oauth_sso_discovery_nonce" ); ?>'
                    }, function(response) {
                        if (response.success) {
                            $status.css('color', 'green').text(response.data.message);
                            $('#aim_oauth_authorize_url').val(response.data.endpoints.authorize_url);
                            $('#aim_oauth_token_url').val(response.data.endpoints.token_url);
                            if (response.data.endpoints.userinfo_url) {
                                $('#aim_oauth_userinfo_url').val(response.data.endpoints.userinfo_url);
                            }
                            if (response.data.endpoints.jwks_url) {
                                $('#aim_oauth_jwks_url').val(response.data.endpoints.jwks_url);
                            }
                            $('#aim_oauth_discovery_url_hidden').val(discoveryUrl);
                        } else {
                            $status.css('color', 'red').text('Error: ' + response.data);
                        }
                    });
                });

                $('#btn_regen_backdoor').on('click', function(e) {
                    e.preventDefault();
                    $.post(ajaxurl, {
                        action: 'aim_oauth_regenerate_backdoor',
                        security: '<?php echo wp_create_nonce( "aim_oauth_backdoor_nonce" ); ?>'
                    }, function(response) {
                        if (response.success) {
                            $('#aim_oauth_backdoor_key').val(response.data.new_key);
                            $('#display_backdoor_url').html('<a href="' + response.data.url + '" target="_blank">' + response.data.url + '</a>');
                            alert('New 6-character emergency backdoor key generated!');
                        }
                    });
                });
            });
        </script>
        <?php
    }

    /* ==========================================================================
       5. INTERCEPT LOGIN & WOOCOMMERCE ACCOUNT PAGES
       ========================================================================== */

    public function intercept_login_page() {
        if ( isset( $_GET['action'] ) && $_GET['action'] === 'aim_sso_login' ) {
            $this->start_oauth_redirect();
        }

        if ( ! get_option( 'aim_oauth_enable_redirect' ) ) {
            return;
        }

        if ( isset( $_GET['action'] ) && $_GET['action'] === 'logout' ) {
            return;
        }

        $configured_backdoor = get_option( 'aim_oauth_backdoor_key' );
        if ( ! empty( $configured_backdoor ) && isset( $_GET['bypass_oauth'] ) && $_GET['bypass_oauth'] === $configured_backdoor ) {
            return;
        }

        $this->start_oauth_redirect();
    }

    public function intercept_woocommerce_account_page() {
        if ( ! $this->is_woocommerce_active() ) {
            return;
        }

        if ( is_account_page() && ! is_user_logged_in() && get_option( 'aim_oauth_woo_redirect_account' ) ) {
            $this->start_oauth_redirect( wc_get_page_permalink( 'myaccount' ) );
        }
    }

    private function start_oauth_redirect( $return_to = '' ) {
        $client_id     = get_option( 'aim_oauth_client_id' );
        $authorize_url = get_option( 'aim_oauth_authorize_url' );
        $auth_method   = get_option( 'aim_oauth_auth_method', 'client_secret_pkce' );

        if ( empty( $client_id ) || empty( $authorize_url ) ) {
            wp_die( 'OAuth SSO configuration is incomplete.' );
        }

        $redirect_uri = site_url( '/?oauth_callback=1' );
        $state        = wp_create_nonce( 'aim_oauth_oidc_state_nonce' );

        $_SESSION['aim_oauth_state']     = $state;
        $_SESSION['aim_oauth_return_to'] = ! empty( $return_to ) ? $return_to : ( $_GET['redirect_to'] ?? '' );

        $query_args = array(
            'response_type' => 'code',
            'client_id'     => $client_id,
            'redirect_uri'  => $redirect_uri,
            'scope'         => get_option( 'aim_oauth_scopes', 'openid profile email' ),
            'state'         => $state,
        );

        if ( in_array( $auth_method, array( 'pkce_only', 'client_secret_pkce' ), true ) ) {
            $verifier  = $this->generate_code_verifier();
            $challenge = $this->generate_code_challenge( $verifier );

            $_SESSION['aim_oauth_pkce_verifier'] = $verifier;

            $query_args['code_challenge']        = $challenge;
            $query_args['code_challenge_method'] = 'S256';
        }

        $auth_redirect = add_query_arg( $query_args, $authorize_url );
        wp_redirect( $auth_redirect );
        exit;
    }

    public function render_wplogin_sso_button() {
        if ( get_option( 'aim_oauth_enable_redirect' ) ) {
            return;
        }

        $sso_login_url = wp_login_url() . '?action=aim_sso_login';
        echo '<p style="margin-top: 15px; margin-bottom: 15px; text-align: center;">';
        echo '<a href="' . esc_url( $sso_login_url ) . '" class="button button-primary button-large" style="width: 100%; text-align: center; box-sizing: border-box; display: block; background: #007cba; border-color: #007cba; color: #fff; padding: 6px 12px; height: auto; font-size: 14px;">' . __( 'Sign in with Single Sign-On (SSO)', 'aim-oauth-oidc-sso' ) . '</a>';
        echo '</p>';
    }

    public function render_woocommerce_sso_button() {
        if ( is_user_logged_in() ) {
            return;
        }

        $sso_start_url = add_query_arg( array( 'start_sso' => '1' ), wc_get_page_permalink( 'myaccount' ) );
        if ( isset( $_GET['start_sso'] ) ) {
            $this->start_oauth_redirect( wc_get_page_permalink( 'myaccount' ) );
        }

        echo '<p class="form-row" style="margin-top: 15px; margin-bottom: 15px;">';
        echo '<a href="' . esc_url( $sso_start_url ) . '" class="buttonAlt button" style="width: 100%; text-align: center; display: block; background: #007cba; color: #fff; padding: 10px;">Sign in with SSO</a>';
        echo '</p>';
    }

    /* ==========================================================================
       6. HANDLE OAUTH CALLBACK & REDIRECT
       ========================================================================== */

    public function handle_oauth_callback() {
        if ( ! isset( $_GET['oauth_callback'] ) || ! isset( $_GET['code'] ) ) {
            return;
        }

        $saved_state = $_SESSION['aim_oauth_state'] ?? '';
        if ( ! isset( $_GET['state'] ) || empty( $saved_state ) || ! wp_verify_nonce( $_GET['state'], 'aim_oauth_oidc_state_nonce' ) ) {
            wp_die( 'Security check failed: State parameter mismatch or expired session.' );
        }

        unset( $_SESSION['aim_oauth_state'] );

        $code          = sanitize_text_field( $_GET['code'] );
        $client_id     = get_option( 'aim_oauth_client_id' );
        $client_secret = get_option( 'aim_oauth_client_secret' );
        $auth_method   = get_option( 'aim_oauth_auth_method', 'client_secret_pkce' );
        $token_url     = get_option( 'aim_oauth_token_url' );
        $userinfo_url  = get_option( 'aim_oauth_userinfo_url' );
        $jwks_url      = get_option( 'aim_oauth_jwks_url' );
        $redirect_uri  = site_url( '/?oauth_callback=1' );

        $body = array(
            'grant_type'   => 'authorization_code',
            'code'         => $code,
            'client_id'    => $client_id,
            'redirect_uri' => $redirect_uri,
        );

        if ( in_array( $auth_method, array( 'client_secret', 'client_secret_pkce' ), true ) && ! empty( $client_secret ) ) {
            $body['client_secret'] = $client_secret;
        }

        if ( in_array( $auth_method, array( 'pkce_only', 'client_secret_pkce' ), true ) && ! empty( $_SESSION['aim_oauth_pkce_verifier'] ) ) {
            $body['code_verifier'] = $_SESSION['aim_oauth_pkce_verifier'];
            unset( $_SESSION['aim_oauth_pkce_verifier'] );
        }

        $response = wp_remote_post( $token_url, array(
            'headers' => array( 'Accept' => 'application/json' ),
            'body'    => $body,
        ));

        if ( is_wp_error( $response ) ) {
            wp_die( 'OAuth Token Endpoint request error: ' . $response->get_error_message() );
        }

        $token_data   = json_decode( wp_remote_retrieve_body( $response ), true );
        $access_token = $token_data['access_token'] ?? null;
        $id_token     = $token_data['id_token'] ?? null;

        if ( ! $access_token && ! $id_token ) {
            wp_die( 'Authentication failed: No Access Token or ID Token returned from server.' );
        }

        $user_claims = array();

        if ( $id_token ) {
            $id_token_claims = $this->verify_and_decode_id_token( $id_token, $jwks_url );
            if ( is_array( $id_token_claims ) ) {
                $user_claims = array_merge( $user_claims, $id_token_claims );
            }
        }

        if ( ! empty( $userinfo_url ) && $access_token ) {
            $userinfo_response = wp_remote_get( $userinfo_url, array(
                'headers' => array(
                    'Authorization' => 'Bearer ' . $access_token,
                    'Accept'        => 'application/json',
                ),
            ));

            if ( ! is_wp_error( $userinfo_response ) ) {
                $userinfo_claims = json_decode( wp_remote_retrieve_body( $userinfo_response ), true );
                if ( is_array( $userinfo_claims ) ) {
                    $user_claims = array_merge( $user_claims, $userinfo_claims );
                }
            }
        }

        $this->authenticate_user( $user_claims );
    }

    /* ==========================================================================
       7. PROVISION & AUTHENTICATE USER
       ========================================================================== */

    private function authenticate_user( $claims ) {
        $email_key      = get_option( 'aim_oauth_attr_email', 'email' );
        $username_key   = get_option( 'aim_oauth_attr_username', 'preferred_username' );
        $first_name_key = get_option( 'aim_oauth_attr_first_name', 'given_name' );
        $last_name_key  = get_option( 'aim_oauth_attr_last_name', 'family_name' );
        $default_role   = get_option( 'aim_oauth_default_role', 'subscriber' );

        $email = isset( $claims[ $email_key ] ) ? sanitize_email( $claims[ $email_key ] ) : '';

        if ( empty( $email ) ) {
            wp_die( 'Authentication failed: Could not extract email.' );
        }

        $user = get_user_by( 'email', $email );

        if ( ! $user ) {
            $username = ! empty( $claims[ $username_key ] ) ? $claims[ $username_key ] : strstr( $email, '@', true );
            $username = sanitize_user( $username );

            $base_username = $username;
            $counter       = 1;
            while ( username_exists( $username ) ) {
                $username = $base_username . $counter;
                $counter++;
            }

            $random_password = wp_generate_password( 32, true, true );
            $user_id         = wp_create_user( $username, $random_password, $email );

            if ( is_wp_error( $user_id ) ) {
                wp_die( 'Failed to provision account: ' . $user_id->get_error_message() );
            }

            $user = get_user_by( 'id', $user_id );

            if ( $this->is_woocommerce_active() && $default_role === 'subscriber' ) {
                $user->set_role( 'customer' );
            } else {
                $user->set_role( $default_role );
            }

            wp_update_user( array(
                'ID'         => $user_id,
                'first_name' => sanitize_text_field( $claims[ $first_name_key ] ?? '' ),
                'last_name'  => sanitize_text_field( $claims[ $last_name_key ] ?? '' ),
            ));
        }

        if ( ob_get_level() ) {
            ob_end_clean();
        }

        wp_clear_auth_cookie();
        wp_set_current_user( $user->ID );
        wp_set_auth_cookie( $user->ID, true );
        do_action( 'wp_login', $user->user_login, $user );

        $return_to = $_SESSION['aim_oauth_return_to'] ?? '';
        unset( $_SESSION['aim_oauth_return_to'] );

        if ( ! empty( $return_to ) ) {
            wp_safe_redirect( esc_url_raw( $return_to ) );
        } elseif ( $this->is_woocommerce_active() && ! wp_is_maintenance_mode() ) {
            wp_safe_redirect( wc_get_page_permalink( 'myaccount' ) );
        } else {
            wp_safe_redirect( admin_url() );
        }
        exit;
    }

    public function handle_logout() {
        if ( wp_is_maintenance_mode() || ( $this->is_woocommerce_active() && ! is_account_page() ) ) {
            wp_redirect( wp_login_url() );
        } elseif ( $this->is_woocommerce_active() ) {
            wp_redirect( wc_get_page_permalink( 'myaccount' ) );
        } else {
            wp_redirect( home_url() );
        }
        exit;
    }

    /* ==========================================================================
       8. REST API PROTECTION ENGINE
       ========================================================================== */

    /**
     * Authenticates incoming REST requests via Identity Provider Bearer token
     */
    public function authenticate_rest_bearer_token( $user_id ) {
        if ( ! empty( $user_id ) ) {
            return $user_id; // Already authenticated
        }

        $mode = get_option( 'aim_oauth_rest_protection_mode', 'open' );
        if ( $mode !== 'idp_bearer' ) {
            return $user_id;
        }

        // Check for Bearer token in Authorization HTTP header
        $auth_header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        if ( empty( $auth_header ) || strpos( sanitize_text_field( $auth_header ), 'Bearer ' ) !== 0 ) {
            return $user_id;
        }

        $access_token = trim( substr( sanitize_text_field( $auth_header ), 7 ) );
        $userinfo_url = get_option( 'aim_oauth_userinfo_url' );

        if ( empty( $access_token ) || empty( $userinfo_url ) ) {
            return $user_id;
        }

        // Validate Bearer token with Identity Provider UserInfo Endpoint
        $response = wp_remote_get( $userinfo_url, array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $access_token,
                'Accept'        => 'application/json',
            ),
        ));

        if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 ) {
            $claims    = json_decode( wp_remote_retrieve_body( $response ), true );
            $email_key = get_option( 'aim_oauth_attr_email', 'email' );

            if ( ! empty( $claims[ $email_key ] ) ) {
                $user = get_user_by( 'email', sanitize_email( $claims[ $email_key ] ) );
                if ( $user ) {
                    return $user->ID; // Dynamically authenticates user for REST API scope
                }
            }
        }

        return $user_id;
    }

    /**
     * Enforces selected REST API protection mode
     */
    public function enforce_rest_api_protection( $result ) {
        if ( ! empty( $result ) ) {
            return $result;
        }

        $mode = get_option( 'aim_oauth_rest_protection_mode', 'open' );

        if ( $mode === 'open' ) {
            return $result;
        }

        // If user is authenticated via cookie, session, or Bearer token, allow request
        if ( is_user_logged_in() ) {
            return $result;
        }

        // Block unauthenticated REST API requests
        return new WP_Error(
            'rest_unauthorized',
            __( 'Access to WordPress REST API endpoints is restricted.', 'aim-oauth-oidc-sso' ),
            array( 'status' => 401 )
        );
    }
}

register_uninstall_hook( __FILE__, array( 'AIM_OAuth_OIDC_SSO', 'on_uninstall' ) );

new AIM_OAuth_OIDC_SSO();
