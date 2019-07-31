<?php
/**
 * OAuth API connector for wordpress
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @package wpoauth
 * @license GPLv2 or later
 * @author Uğur Biçer <uuur86@yandex.com>
 * @version 0.14
 */

namespace WPOauth;


abstract class OAuth {

	protected $api_id;

	protected $api_secret;

	protected $access_token;

	protected $settings_name;

	protected $oauth_url;

	protected $locate_domain;

	protected $return_url;

	protected $redirect_uri;

	protected $request_args;

	protected $token_args;

	protected $all_args;



	/**
	 * OAuth constructor.
	 *
	 * @param array $args
	 */
	public function __construct( $args ) {

		if( isset( $args[ 'return_url' ] ) ) {
			$this->return_url = $args[ 'return_url' ];
		}

		$this->settings_name	= $args[ 'settings_name' ];
		$this->oauth_url		= $args[ 'oauth_url' ];
		$this->locate_domain	= $args[ 'locate_domain' ];
		$this->api_secret		= $args[ 'client_secret' ];
		$this->api_id			= $args[ 'client_id' ];
		$this->request_args		= $args[ 'request_args' ];
		$this->token_args		= $args[ 'token_args' ];
		$this->redirect_uri		= urlencode( $this->oauth_callback_url() );

		$this->all_args = $args;
		$this->all_args[ 'redirect_uri' ] = $this->redirect_uri;
	}



	/**
	 * @param string $id
	 */
	public function set_id( $id ) {
		if( !empty( $id ) ) $this->api_id = $id;
	}



	/**
	 * @param string $secret
	 */
	public function set_secret( $secret ) {
		if( !empty( $secret ) ) $this->api_secret = $secret;
	}



	/**
	 * @param string $service
	 * @param array $args
	 * @param bool $post
	 *
	 * @return bool|object
	 */
	public function get_remote_api_data( $service, $args, $post = false ) {

		if( ( $url = $this->_generate_api_url( $service, $args ) ) !== false ) {

			if( $post !== false ) {
				$post_args = array(
					'method' => 'POST',
					'timeout' => '5',
					'body' => $args
				);
				$all_data = wp_remote_post( $url, $post_args );
			}
			else {
				$get_args = array(
					'method' => 'GET',
					'timeout' => '10'
				);
				$all_data = wp_remote_get( $url, $get_args );
			}

			$response_code = wp_remote_retrieve_response_code( $all_data );
			$response_code = intval( $response_code / 100 );

			if( $response_code == 2 ) {
				$call = wp_remote_retrieve_body( $all_data );

				return json_decode( $call );
			}
		}

		return false;
	}



	/**
	 * @param string $path
	 * @param array $args
	 *
	 * @return bool|string
	 */
	protected function _generate_api_url( $path, $args = array() ) {

		if( empty( $path ) ) return false;

		return add_query_arg( $args, $this->oauth_url . '/' .  trim( $path, '\\/' ) );
	}



	/**
	 * This method creates a form to send a authorization request WordPress admin-post
	 *
	 * @return bool|string
	 */
	public function authorize_link() {

		if( empty( $this->api_id ) || empty( $this->api_secret ) ) return false;

		$admin_post_url = admin_url( 'admin-post.php', 'https' );

		$html = '<form method="post" action="' . $admin_post_url . '">';
		$html .= '	<input type="hidden" name="action" value="' . $this->settings_name . '_authorize"/>';
		$html .= '	' . wp_nonce_field( $this->settings_name . '_authorize', $this->settings_name . '_authorize_nonce', true, false );
		$html .= '	<input type="submit" value="Authorize" name="' . $this->settings_name . '_authorize"/>';
		$html .= '</form>';

		return $html;
	}



	/**
	 * This method will redirect URI to particular OAuth dialog
	 */
	public function authorize_request() {

		if( !empty( $this->request_args[ 'url' ] ) ) $this->oauth_url = $this->request_args[ 'url' ];

		if( !empty( $_POST ) && wp_verify_nonce( $_POST[ $this->settings_name . '_authorize_nonce' ], $this->settings_name . '_authorize' ) ) {
			$get_args = [];

			$args = $this->_fill_args( $this->request_args[ 'data' ][ 'referenced' ] );
			$args += $this->request_args[ 'data' ][ 'manual' ];

			if( $this->request_args[ 'method' ] == 'GET' ) {
				$get_args = $args;
			}

			$dialog_url = $this->_generate_api_url( $this->request_args[ 'service_name' ], $get_args );

			header( "Location: " . $dialog_url );
		}
	}



	/**
	 * This method will send a request for giving a token then will redirect back to given URI
	 */
	public function authorize_request_callback() {
		$debug		= '';
		$send_post	= false;
		$return_url	= $this->return_url;

		if( !empty( $this->token_args[ 'url' ] ) ) {
			$this->oauth_url = $this->token_args[ 'url' ];
		}

		if( $this->token_args[ 'method' ] == 'POST' ) {
			$send_post = true;
		}

		$args = $this->_fill_args( $this->token_args[ 'data' ][ 'referenced' ] );

		if( isset( $this->token_args[ 'data' ][ 'manual' ] ) && is_array( $this->token_args[ 'data' ][ 'manual' ] ) ) {
			$args += $this->token_args[ 'data' ][ 'manual' ];
		}

		$response = $this->get_remote_api_data( $this->token_args[ 'service_name' ], $args, $send_post );

		if( isset( $response->error ) ) {
			$debug .= '<p> Error Message : ' . $response->error->message . ' URL : ' . $this->redirect_uri . '</p>';
		}
		else if( !empty( $response->access_token ) ) {
			$this->set_token( $response->access_token );
		}

		$return_url .= '&debug=' . $debug;

		header( "Location: " . $return_url );
	}



	/**
	 * @param string $name
	 * @param mixed $value
	 */
	public function set_option( $name, $value ) {

		if( $this->get_option( $name ) !== false ) update_option( $this->settings_name . '_' . $name, $value );
		else add_option( $this->settings_name . '_' . $name, $value );
	}



	/**
	 * @param string $name
	 *
	 * @return string|array
	 */
	public function get_option( $name ) {
		$option = get_option( $this->settings_name . '_' . $name, false );

		return $option;
	}



	/**
 	* If updated it returns true else returns false
 	*
 	* @return bool
 	*/
	public function check_token() {

		if( isset( $this->access_token ) ) {
			return true;
		}
		elseif( empty( $this->access_token ) ) {
			$this->access_token = $this->get_option( 'access_token', null );

			if( empty( $this->access_token ) ) return false;

			return true;
		}

		return false;
	}



	/**
 	* Get access token
 	*
 	* @return string|bool
 	*/
	public function get_token() {

		if( $this->check_token() ) {
	 		return $this->access_token;
		}

		return false;
	}



	/**
	* @param string $access_token
	*/
	public function set_token( $access_token ) {

		if( empty( $access_token ) ) return;

		$this->access_token = $access_token;
		$this->set_option( 'access_token', $this->access_token );
	}



	/**
 	* @param array $args
 	*
 	* @return array
 	*/
	protected function _fill_args( $args ) {
		$new_args = [];

		if( !is_array( $args ) ) return false;

		foreach( $args as $arg ) {

			if( isset( $this->all_args[ $arg ] ) ) {
				$new_args[ $arg ] = $this->all_args[ $arg ];
			}
			elseif( $arg == 'code' && isset( $_GET[ 'code' ] ) ) {
				$new_args[ 'code' ] = $_GET[ 'code' ];
			}
		}

		return $new_args;
	}



	/**
	 * This function returns to the callback url
	 *
	 * @return string
	 */
	public function oauth_callback_url() {
		$callback_name	= $this->settings_name . '_authorize_callback';
		$callback_args	= [ 'action' => $callback_name ];
		$redirect_uri	= add_query_arg( $callback_args, admin_url( 'admin-post.php', 'https' ) );

		return $redirect_uri;
	}



	/**
	 * This function references callback function to the admin post
	 */
	public function callback_init() {
		global $pagenow;

		if( $pagenow === 'admin-post.php' && is_ssl() ) {
			add_action( 'admin_post_' . $this->settings_name . '_authorize', array( $this, 'authorize_request' ) );
			add_action( 'admin_post_' . $this->settings_name . '_authorize_callback', array( $this, 'authorize_request_callback' ) );
		}
	}


	/**
	 * Checks whether the auth process has occurred.
	 *
	 * @return bool
	 */
	public function authorize_control() {

		if( $this->get_token() !== false ) {
			return true;
		}

		return false;
	}
}
