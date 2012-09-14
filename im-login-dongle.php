<?php

	/* 
		Plugin Name: IM Login Dongle
		Plugin URI: http://wpplugz.is-leet.com
		Description: A simple wordpress plugin that adds two way authentication via selected instant messenger.
		Version: 0.5
		Author: Bostjan Cigan
		Author URI: http://bostjan.gets-it.net
		License: GPL v2
	*/
	
	include_once('functions.php');
	
	// First we register all the functions, actions, hooks ...
	register_activation_hook(__FILE__, 'im_login_dongle_install');
	add_action('auth_redirect', 'check_dongle_login'); // Actions for checking if user is logged in
	add_action('wp_logout', 'im_login_dongle_clear'); // Adding action to logout (clearing cookies etc.)
	add_action('init', 'im_login_dongle_install'); // For ugprade purposes, upgrade the DB if not yet updated
	
	$plugin_options = get_option('im_login_dongle_settings');
	if($plugin_options['plugin_activated']) {
		add_action('show_user_profile', 'im_login_dongle_edit_fields'); // Add actions for editing the Google Talk ID in users profile
		add_action('edit_user_profile', 'im_login_dongle_edit_fields');
		add_action('personal_options_update', 'im_login_dongle_profile_fields'); // Show the fields in users profile
		add_action('edit_user_profile_update', 'im_login_dongle_profile_fields');
	}
	
	add_action('admin_menu', 'im_dongle_login_menu_create'); // Register the administration menu

	function im_dongle_login_menu_create() {
		add_menu_page('IM Login Dongle Settings', 'IM Login Dongle', 'administrator', 'im-login-dongle-main', 'im_login_dongle_settings_about', plugin_dir_url(__FILE__).'images/padlock.png');
		add_submenu_page('im-login-dongle-main', 'General settings', 'General settings', 'administrator', 'im-login-dongle-general', 'im_login_dongle_general_settings');
		add_submenu_page('im-login-dongle-main', 'Google Talk Bot', 'Google Talk Bot', 'administrator', 'im-login-dongle-gbot', 'im_login_dongle_gbot_settings');
		add_submenu_page('im-login-dongle-main', 'ICQ Bot', 'ICQ Bot', 'administrator', 'im-login-dongle-icqbot', 'im_login_dongle_icqbot_settings');
		add_submenu_page('im-login-dongle-main', 'Reset keys', 'Reset keys', 'administrator', 'im-login-dongle-codes', 'im_login_dongle_codes_settings');
		add_submenu_page('im-login-dongle-main', 'Data liberation', 'Data liberation', 'administrator', 'im-login-dongle-data-liberation', 'im_login_dongle_data_liberation_settings');
	}

	function im_login_dongle_install() {
		
		$plugin_options = get_option('im_login_dongle_settings');
		if(isset($plugin_options['version'])) {
			if($plugin_options['version'] == "0.1") {
				$plugin_options['version'] = "0.3";
				$plugin_options['session_time'] = 60;
				$plugin_options['show_message'] = false;
				update_option('im_login_dongle_settings', $plugin_options);
			}
		}
		else {
			$plugin_options = array(
				'custom_im_msg' => '',
				'version' => '0.3', // Plugin version
				'plugin_activated' => false, // Is plugin activated?
				'encryption_salt' => random_string(60), // The encryption salt string
				'code_length' => 6, // How long is the dongle code that is sent
				'session_time' => 60, // Session time validity in minutes
				'show_message' => false,
				'im_bots' => array( // Because of future versions, a multiple array
					'gtalk' => array(
						'im_bot_username' => '',
						'im_bot_domain' => '',
						'activated' => false,
						'im_bot_password' => ''
					),
					'icq' => array(
						'im_bot_username' => '',
						'im_bot_domain' => '',
						'activated' => false,
						'im_bot_password' => ''
					)
				),
				'disable_code' => array(
					'code1' => random_string(15),
					'code2' => random_string(15),
					'code3' => random_string(15),
					'code4' => random_string(15)
				)
			);		

			add_option('im_login_dongle_settings', $plugin_options);

		}
		
	}
	
	// Clear the dongle cookie, delete the dongle id from the database
	function im_login_dongle_clear() {
		global $current_user;
		get_currentuserinfo();
		$cookie = $_COOKIE['dongle_login_id'];
		$dongle_data = get_user_meta($current_user->ID, 'im_login_dongle_data', true);
		if(is_array($dongle_data)) {
			unset($dongle_data[$cookie]);
			update_user_meta($current_user->ID, 'im_login_dongle_data', $dongle_data);			
		}
		setcookie("dongle_login_id", "", time()-3600*24, "/");
		wp_redirect(home_url('/wp-login.php'), 301);
	}

	// Check if user has authorized with dongle
	function check_dongle_login() {
		
		global $current_user;
		get_currentuserinfo();
		
		$plugin_options = get_option('im_login_dongle_settings');
		$user_dongle_settings = get_user_meta($current_user->ID, 'im_login_dongle_settings', true);
		$ip = getenv("REMOTE_ADDR");		

		$dongle_status = $user_dongle_settings['im_login_dongle_state'];
		
		// Check if user has the dongle login disabled, return true if disabled (login success)
		if($dongle_status == "disabled" || $dongle_status == "" || !$plugin_options['plugin_activated'] || !$plugin_options['im_bots'][$user_dongle_settings['im_login_dongle_type']]['activated']) { 
			return true; 
		}
		else {
			$value = $_COOKIE['dongle_login_id'];
			if(!isset($value)) {
				$dongle_code = random_string($plugin_options['code_length']); // Generate the dongle code that we will be using for the login
				$dongle_id = insert_dongle_code($current_user->ID, $dongle_code);
				$im_id = $user_dongle_settings['im_login_dongle_id']; // Get the IM of the current user
				$send_msg = send_dongle_message($current_user->ID, $im_id, $dongle_code, $user_dongle_settings['im_login_dongle_type']); // Send the dongle code to the user
				if(!$send_msg) {
					if(is_admin()) {
						$redirect_url = plugin_dir_url(__FILE__).'shutdown.php?error';
						wp_redirect($redirect_url, 301);						
					}
					else {
						$redirect_url = plugin_dir_url(__FILE__).'disable.php?error';
						wp_redirect($redirect_url, 301);						
					}
				}
				else {
					$dongle_id_encrypted = encrypt($dongle_id, $plugin_options['encryption_salt']);
					$redirect_url = plugin_dir_url(__FILE__).'cookie.php?dongle_id='.urlencode(htmlspecialchars($dongle_id_encrypted)).'&set=true';
					wp_redirect($redirect_url, 301);
				}
			}
			else if(isset($value)) {
				$dongle_data = get_user_meta($current_user->ID, 'im_login_dongle_data', true);
				$cur_data = $dongle_data[$_COOKIE['dongle_login_id']];
				if($cur_data == NULL) {
					im_login_dongle_clear();
				}
				else if($cur_data['authenticated'] == true && $cur_data['ip'] == $ip) {
					if(time() - $cur_data['timestamp'] < $plugin_options['session_time'] * 60) {
						return true;	
					}
					else {
						im_login_dongle_clear();
					}
				}
				else {
					im_login_dongle_clear();
				}
			}
			else {
				im_login_dongle_clear();
			}
		}
		
	}
		
	function send_dongle_message($user_id, $email, $code, $type) {

		$plugin_options = get_option('im_login_dongle_settings');
		$ip = getenv("REMOTE_ADDR");
		$connection_success = true;
				
		if($type == "gtalk") {

			require_once 'XMPPHP/XMPP.php';
			
			$message = "WP Login code \n\n".$code."\n \n"."This code was requested from ".$ip." and is valid for the next 30 seconds.".$plugin_options['custom_im_msg'];
			
			if($plugin_options['show_message']) {
				$message = $message."\n\n.: Powered by IM Login Dongle. (http://wpplugz.is-leet.com) :.";	
			}

			
			$conn = new XMPPHP_XMPP('talk.google.com', 
										5222, 
										$plugin_options['im_bots']['gtalk']['im_bot_username'], 
										decrypt($plugin_options['im_bots']['gtalk']['im_bot_password'], $plugin_options['encryption_salt']), 
										'xmpphp', 
										$plugin_options['im_bots']['gtalk']['im_bot_domain'], 
										$printlog=false, 
										$loglevel=XMPPHP_Log::LEVEL_INFO);

			$conn->useEncryption(true);
			
			try {
			    $conn->connect();
			    $conn->processUntil('session_start');
	    		$conn->presence();
			    $conn->message($email, $message);
			    $conn->disconnect();
			} catch(XMPPHP_Exception $e) {
				$connection_success = false;
			}
			
		}
		else if($type == "icq") {
		
			require_once 'ICQ/WebIcqLite.class.php';
			
			$message = "WP Login code \n\n".$code."\n \n"."This code was requested from ".$ip." and is valid for the next 30 seconds.".$plugin_options['custom_im_msg'];
			
			if($plugin_options['show_message']) {
				$message = $message."\n\n.: Powered by IM Login Dongle :.";	
			}
			
			$icq = new WebIcqLite();
			$icq_pass = decrypt($plugin_options['im_bots']['icq']['im_bot_password'], $plugin_options['encryption_salt']);
			$icq->connect($plugin_options['im_bots']['icq']['im_bot_username'], $icq_pass);
			$send_msg = $icq->send_message($email, $message);
			if(!$send_msg) {
				$connection_success = false;
			}
			$icq->disconnect();
			
		}
		
		return $connection_success;
		
	}

	// Generate a valid 30 second dongle code and insert it into the DB
	function insert_dongle_code($user_id, $dongle_code) {
		
		$dongle_unique_id = random_string(30);
		$dongle_data = get_user_meta($user_id, 'im_login_dongle_data', true);
		$ip = getenv("REMOTE_ADDR");
		
		$dongle_login = array(
			'user_id' => $user_id,
			'timestamp' => time(),
			'authenticated' => false,
			'ip' => $ip,
			'code' => $dongle_code,
			'dongle_used' => false
		);
		
		$dongle_data[$dongle_unique_id] = $dongle_login;
		
		update_user_meta($user_id, 'im_login_dongle_data', $dongle_data);
	
		return $dongle_unique_id;
	
	}

	function im_login_dongle_edit_fields($user) { 

		$dongle_settings = get_the_author_meta('im_login_dongle_settings', $user->ID);
?>
		<h3>IM Login Dongle</h3>
		<table class="form-table">
			<tr>
				<th scope="row"><label for="im_login_dongle_enabled">Activate dongle</label></th>

				<td>
<?php
		if(isset($dongle_settings)) {
			if($dongle_settings['im_login_dongle_state'] == "enabled") {
				
?>
					<input name="im_login_dongle_enabled" id="im_login_dongle_enabled" type="checkbox" checked="checked" />
<?php
        	}
            else {
?>
					<input name="im_login_dongle_enabled" id="im_login_dongle_enabled" type="checkbox" />
<?php
            }
        }
        else {
?>
					<input name="im_login_dongle_enabled" id="im_login_dongle_enabled" type="checkbox" />
<?php
        }

?>
					<br />
                    <span class="description">Enable or disable two step verification.</span>
				</td>
			</tr>		
			<tr>
				<th scope="row"><label for="im_login_dongle_type">IM type</label></th>
				<td>
					<select name="im_login_dongle_type" id="im_login_dongle_type">
						<option value="gtalk" <?php if($dongle_settings['im_login_dongle_type'] == "gtalk") { ?> selected="selected" <?php } ?>>Google Talk</option>
                        <option value="icq" <?php if($dongle_settings['im_login_dongle_type'] == "icq") { ?> selected="selected" <?php } ?>>ICQ</option>
					</select>
                    <br />
					<span class="description">Select your IM.</span>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="im_login_dongle_id">Instant messenger ID</label></th>
				<td>
					<input type="text" name="im_login_dongle_id" id="im_login_dongle_id" value="<?php echo esc_attr($dongle_settings['im_login_dongle_id']); ?>" class="regular-text" /><br />
					<span class="description">Please enter your IM ID (Google Talk example: someone@gmail.com, ICQ example: 123456789).</span>
				</td>
			</tr>      
			<tr>
				<th scope="row"><label for="im_login_dongle_resend">Resend friend request</label></th>
				<td>
					<input name="im_login_dongle_resend" id="im_login_dongle_resend" type="checkbox" />
					<br />
                    <span class="description">If you haven't received your friend request from the bot, mark this field to resend it.</span>
				</td>
			</tr>		
			<tr>
				<th scope="row"><label for="im_login_dongle_regenerate">Regenerate disable codes</label></th>
				<td>
					<input name="im_login_dongle_regenerate" id="im_login_dongle_regenerate" type="checkbox" />
					<br />
                    <span class="description">Mark this to generate or regenerate the login dongle disable codes (in case anything goes wrong).</span>
				</td>
			</tr>		
			<tr>
				<th scope="row"><label for="im_login_dongle_codes">Disable codes</label></th>
				<td>
<?php 

					if(isset($dongle_settings['reset_keys'])) { 
						echo esc_attr($dongle_settings['reset_keys']['key1']);
						echo " - ";
						echo esc_attr($dongle_settings['reset_keys']['key2']); 
						echo " - ";
						echo esc_attr($dongle_settings['reset_keys']['key3']);
						echo " - ";
						echo esc_attr($dongle_settings['reset_keys']['key4']); 
					} else { 
?> 
						Mark the "Regenerate disable codes" checkbox to generate your disable codes. 
<?php 
					} 
?>
					<br />
                    <span class="description">The disable codes for the dongle login (you can use these to disable the dongle im login).</span>
				</td>
			</tr>		
		</table>
        
<?php 

	}

	// Update profile fields (google talk id and enabled/disabled two step authentication)
	function im_login_dongle_profile_fields($user_id) {

		require_once 'XMPPHP/XMPP.php';

		$im_id = $_POST['im_login_dongle_id'];
		$dongle_type = $_POST['im_login_dongle_type'];
		$dongle_settings = get_user_meta($user_id, 'im_login_dongle_settings', true);
		$connection_success = true;
		$resend_request = false;
		$reset_keys = false;
		
		if(isset($_POST['im_login_dongle_resend'])) {
			$resend_request = true;	
		}
		if(isset($_POST['im_login_dongle_regenerate'])) {
			$reset_keys = true;	
		}
		
		if(!is_array($dongle_settings)) {
			$dongle_settings = array();	
		}
		
		$im_dongle_settings = get_option('im_login_dongle_settings');
		$request_sent = $dongle_settings['request_sent'];
		
		if (!current_user_can('edit_user', $user_id))
			return false;
			
		if($reset_keys) {
			$dongle_settings['reset_keys']['key1'] = random_string(15);	
			$dongle_settings['reset_keys']['key2'] = random_string(15);	
			$dongle_settings['reset_keys']['key3'] = random_string(15);	
			$dongle_settings['reset_keys']['key4'] = random_string(15);	
		}

		if(isset($im_id) && strlen($im_id) > 0) {
			if(($dongle_type == "gtalk")) {
				if(!$request_sent || $resend_request) {
					$conn = new XMPPHP_XMPP('talk.google.com', 
												5222, 
												$im_dongle_settings['im_bots']['gtalk']['im_bot_username'], 
												decrypt($plugin_options['im_bots']['gtalk']['im_bot_password'], $plugin_options['encryption_salt']), 
												'xmpphp', 
												$im_dongle_settings['im_bots']['gtalk']['im_bot_domain'], 
												$printlog=false, 
												$loglevel=XMPPHP_Log::LEVEL_INFO);
			
					try {
						$conn->useEncryption(true);
    					$conn->connect();
				    	$conn->processUntil('session_start');
			    		$conn->presence();
						$conn->addRosterContact($im_id, '');
						$conn->subscribe($im_id);
	    				$conn->disconnect();
					} catch(XMPPHP_Exception $e) {
					    $connection_success = false;
					}
				
					$dongle_settings['request_sent'] = true;

				}
				
			}
		}

		$dongle_settings['im_login_dongle_id'] = $im_id;
		$dongle_settings['im_login_dongle_type'] = $dongle_type;
		$dongle_enabled = $_POST['im_login_dongle_enabled'];
		if(isset($dongle_enabled) && isset($im_id) && strlen($im_id) > 0) {
			$dongle_settings['im_login_dongle_state'] = "enabled";
		}
		else {
			$dongle_settings['im_login_dongle_state'] = "disabled";			
		}
		
		update_user_meta($user_id, 'im_login_dongle_settings', $dongle_settings);
		
		return $connection_success;
		
	}

	// The plugin admin page
	function im_login_dongle_general_settings() {
		
		$message = "";
		
		$plugin_settings = get_option('im_login_dongle_settings');
		
		if(isset($_POST['settings-submit'])) {
			$msg = html_entity_decode($_POST['custom_msg']);
			$code_len = intval($_POST['code_length']);
			$status = $_POST['dongle_status'];
			$session_time = $_POST['session_time'];
			$msg_show = $_POST['show_message'];

			if(isset($status)) { 
				$status = true; 
			} else { 
				$status = false; 
			}
			
			if(isset($msg_show)) {
				$msg_show = true;	
			}
			else {
				$msg_show = false;	
			}

			$plugin_settings['code_length'] = $code_len;
			$plugin_settings['custom_im_msg'] = $msg;
			$plugin_settings['plugin_activated'] = $status;
			$plugin_settings['session_time'] = $session_time;
			$plugin_settings['show_message'] = $msg_show;
			
			update_option('im_login_dongle_settings', $plugin_settings);
			$message = "General settings were successfully updated.";
			
		}
					
		
?>
		<div id="icon-options-general" class="icon32"></div><h2>IM Login Dongle General Settings</h2>
<?php

		if(strlen($message) > 0) {
		
?>

			<div id="message" class="updated">
				<p><strong><?php echo $message; ?></strong></p>
			</div>

<?php
			
		}

?>
        
                <form method="post" action="">
				<table class="form-table">
					<tr>
						<th scope="row"><img src="<?php echo plugin_dir_url(__FILE__).'images/settings.png'; ?>" height="96px" width="96px" /></th>
						<td>
							<p>You can edit the general plugin settings here.</p>
			                <p>Once you've added an IM bot account, please mark the dongle status checkbox and click update.</p>
			                <p>Before activating, make sure you write down the disable codes that are available in the "Reset keys" section.</p>
                    	</td>
					</tr>		
					<tr>
						<th scope="row"><label for="code_length">Code length</label></th>
						<td>
							<input name="code_length" id="code_length" type="text" value="<?php echo esc_attr($plugin_settings['code_length']); ?>" />
							<br />
            				<span class="description">The length of the code that will be sent to users.</span>
						</td>
					</tr>		
					<tr>
						<th scope="row"><label for="session_time">Session expiration time</label></th>
						<td>
							<input name="session_time" id="session_time" type="text" value="<?php echo esc_attr($plugin_settings['session_time']); ?>" />
							<br />
            				<span class="description">Session expiration time in minutes (default is 60 minutes).</span>
						</td>
					</tr>		
					<tr>
						<th scope="row"><label for="custom_msg">IM custom message</label></th>
						<td>
							<textarea rows="3" cols="80" name="custom_msg" id="custom_msg" ><?php echo esc_attr($plugin_settings['custom_im_msg']); ?></textarea>
							<br />
            				<span class="description">A custom note that will be sent with the dongle key.</span>
						</td>
					</tr>		
					<tr>
						<th scope="row"><label for="show_message">Powered by message</label></th>
						<td>
							<input type="checkbox" name="show_message" id="show_message" value="true" <?php if($plugin_settings['show_message']) { ?>checked="checked"<?php } ?> />
							<br />
            				<span class="description">Enable or disable the "Powered by" message. If removed, please consider a donation.</span>
						</td>
					</tr>		
					<tr>
						<th scope="row"><label for="dongle_status">Dongle status</label></th>
						<td>
							<input type="checkbox" name="dongle_status" id="dongle_status" value="true" <?php if($plugin_settings['plugin_activated']) { ?>checked="checked"<?php } ?> />
							<br />
            				<span class="description">Enable or disable the dongle login. Only enable it when you are sure that one of your IM account bots is working.</span>
						</td>
					</tr>		
				</table>					
				<p><input type="submit" name="settings-submit" class="button-primary" value="<?php esc_attr_e('Update options') ?>" /></p>
				</form>
            
<?php

	}
	
	// The plugin admin page
	function im_login_dongle_gbot_settings() {
		
		$message = "";
		
		$plugin_settings = get_option('im_login_dongle_settings');
		
		if(isset($_POST['gtalk-submit'])) {
		
			$id = $_POST['google_talk_id'];
			$pass = $_POST['google_talk_pass'];
			$pass_cmp = $_POST['google_talk_pass_conf'];
			$domain = $_POST['google_talk_domain'];
			$status = $_POST['google_talk_status'];

			if(isset($status)) { 
				$status = true; 
			} else { 
				$status = false; 
			}

			if(isset($pass) && isset($pass_cmp) && strlen($pass) > 0 && strlen($pass_cmp) > 0) {
				if(strcmp($pass, $pass_cmp) == 0) {
					$pass = encrypt($pass, $plugin_settings['encryption_salt']);
					$plugin_settings['im_bots']['gtalk']['im_bot_password'] = $pass;
				}
				else {
					$message = "Passwords for Google Talk Bot account did not match.";	
				}
			}
			
			if(isset($id)) {
				$plugin_settings['im_bots']['gtalk']['im_bot_username'] = $id;	
			}
			if(isset($domain)) {
				$plugin_settings['im_bots']['gtalk']['im_bot_domain'] = $domain;	
			}
			
			$plugin_settings['im_bots']['gtalk']['activated'] = $status;
			
			update_option('im_login_dongle_settings', $plugin_settings);
			$message = $message." Google Talk Bot settings were successfully saved.";			
			
		}

		
?>
		<div id="icon-options-general" class="icon32"></div><h2>IM Login Dongle Google Bot Settings</h2>
<?php

		if(strlen($message) > 0) {
		
?>

			<div id="message" class="updated">
				<p><strong><?php echo $message; ?></strong></p>
			</div>

<?php
			
		}

?>
        
                <form method="post" action="">
				<table class="form-table">
					<tr>
						<th scope="row"><img src="<?php echo plugin_dir_url(__FILE__).'images/gtalk.png'; ?>" height="96px" width="96px" /></th>
						<td>
							<p>You can configure your Google Talk account here. This account will be used to send out invites and dongle codes to other users.</p>
			                <p>We recommend you create a separate account on Google <a href="https://accounts.google.com/SignUp?service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&ltmpl=default&hl=en">here</a>.</p>
			                <p>When you've created your account, enter the login data bellow. Mark the dongle status checkbox when your account is registered.</p>
                    	</td>
					</tr>		
					<tr>
						<th scope="row"><label for="google_talk_id">Account ID</label></th>
						<td>
							<input name="google_talk_id" id="google_talk_id" type="text" value="<?php echo esc_attr($plugin_settings['im_bots']['gtalk']['im_bot_username']); ?>" />
							<br />
            				<span class="description">The Google Talk account ID (gmail).</span>
						</td>
					</tr>		
					<tr>
						<th scope="row"><label for="google_talk_pass">Password and confirmation</label></th>
						<td>
							<input name="google_talk_pass" id="google_talk_pass" type="password" /><br />
							<input name="google_talk_pass_conf" id="google_talk_pass_conf" type="password" /><br />
            				<span class="description">Account password.</span>
						</td>
					</tr>		
					<tr>
						<th scope="row"><label for="google_talk_domain">Domain</label></th>
						<td>
							<input name="google_talk_domain" id="google_talk_domain" type="text" value="<?php echo esc_attr($plugin_settings['im_bots']['gtalk']['im_bot_domain']); ?>" />
                            <br />
            				<span class="description">The domain (default is gmail.com).</span>
						</td>
					</tr>		
					<tr>
						<th scope="row"><label for="google_talk_status">Dongle status</label></th>
						<td>
							<input type="checkbox" id="google_talk_status" id="google_talk_status" name="google_talk_status" value="true" 
							<?php if($plugin_settings['im_bots']['gtalk']['activated']) { ?>checked="checked"<?php } ?> />
							<br />
            				<span class="description">Enable or disable the selected account.</span>
						</td>
					</tr>		
				</table>					
				<p><input type="submit" name="gtalk-submit" class="button-primary" value="<?php esc_attr_e('Update Google Talk options') ?>" /></p>
				</form>

<?

	}
			
	// The plugin admin page
	function im_login_dongle_codes_settings() {
		
		$message = "";
		
		$plugin_settings = get_option('im_login_dongle_settings');
		
		if(isset($_POST['reset-codes'])) {
		
			$plugin_settings['disable_code']['code1'] = random_string(15);
			$plugin_settings['disable_code']['code2'] = random_string(15);
			$plugin_settings['disable_code']['code3'] = random_string(15);
			$plugin_settings['disable_code']['code4'] = random_string(15);
			
			update_option('im_login_dongle_settings', $plugin_settings);
			$message = "Reset keys were successfully regenerated.";

		}
		
?>
		<div id="icon-options-general" class="icon32"></div><h2>IM Login Dongle Reset keys</h2>
<?php

		if(strlen($message) > 0) {
		
?>

			<div id="message" class="updated">
				<p><strong><?php echo $message; ?></strong></p>
			</div>

<?php
			
		}

?>
        
        
        
                <form method="post" action="">
				<table class="form-table">
                	<tr>
                    	<th scope="row"><img src="<?php echo plugin_dir_url(__FILE__).'images/keys.png'; ?>" height="96px" width="96px" /></th>
                    	<td>
							<p>If by any chance one of the IM systems fails, you will need a backup login. Entering these codes will disable the IM Login Dongle for all the users, so store them in a safe place.</p> <p>To access the deactivation menu, you login normally and click on "Disable IM Login for all users".</p> <p>This only works for administrators.</p>                        	
                        </td>
                    </tr>
					<tr>
						<th scope="row">Keys</th>
						<td>
							<?php echo esc_attr($plugin_settings['disable_code']['code1']); ?> - <?php echo esc_attr($plugin_settings['disable_code']['code2']); ?> - <?php echo esc_attr($plugin_settings['disable_code']['code3']); ?> - <?php echo esc_attr($plugin_settings['disable_code']['code4']); ?>
						</td>
					</tr>		
				</table>					
				<p><input type="submit" name="reset-codes" class="button-primary" value="<?php esc_attr_e('Generate new codes') ?>" /></p>
				</form>

<?

	}
			
?>

<?php
	
	// The plugin admin page
	function im_login_dongle_settings_about() {
		
?>

				<div id="icon-options-general" class="icon32"></div><h2>IM Login Dongle About</h2>
					<table class="form-table">
					<tr>
						<th scope="row"><img src="<?php echo plugin_dir_url(__FILE__).'images/about.png'; ?>" height="96px" width="96px" /></th>
						<td>
							<p>This plugin was created by <a href="http://wpplugz.is-leet.com">wpPlugz</a>.</p>
			                <p>Please leave the "Powered by" message in the IMs intact. If you change it anyway, than please consider a donation.</p>
			                <p>This plugin uses the following libraries:</p>
                            <ul>
                            	<li>&middot; <a href="http://code.google.com/p/xmpphp/">XMPPHP</a> by Nathanael C. Fritz,</li>
                            	<li>&middot; <a href="http://wip.asminog.com/projects/icq/WebIcqLite.class.phps">WebICQLite</a> by Sergey Akudovich.</li>
                            </ul>
                            <p>It also uses the following icon sets:</p>
                            <ul>
                            	<li>&middot; <a href="http://www.smashingmagazine.com/2008/08/27/on-stage-a-free-icon-set">On Stage</a>,</li>
                                <li>&middot; <a href="http://www.iconspedia.com/pack/simply-google-1-37/">Simply Google</a>,</li>
                                <li>&middot; ICQ icon by <a href="http://www.iconfinder.com/icondetails/1413/128/flower_icq_icon">David Vignoni</a>.</li>
                            </ul>
			                <p>Any bugs, request and reports can be sent on the official plugin page on Wordpress.</p>						
                    	</td>
					</tr>		
				</table>
			</div>

<?

	}
			
?>
    		
<?php
	
	// The plugin admin page
	function im_login_dongle_data_liberation_settings() {
		
		$message = "";
		
		$plugin_settings = get_option('im_login_dongle_settings');
		
		if(isset($_POST['clear-all-data'])) {
			$reset = $_POST['clear_reset'];
			$sessions = $_POST['clear_sessions'];
			if(isset($reset)) {
				$blogusers = get_users();
				foreach($blogusers as $user) {
					delete_user_meta($user->ID, 'im_login_dongle_settings');	
					delete_user_meta($user->ID, 'im_login_dongle_data');	
				}			
				$message = "All user data was deleted from the database.";		
			}
			if(isset($sessions)) {
				$blogusers = get_users();
				foreach($blogusers as $user) {
					delete_user_meta($user->ID, 'im_login_dongle_data');	
				}			
				$message = "All sessions were deleted from the database.";					
			}
		}
		
?>
		<div id="icon-options-general" class="icon32"></div><h2>IM Login Dongle Data Management</h2>
<?php

		if(strlen($message) > 0) {
		
?>

			<div id="message" class="updated">
				<p><strong><?php echo $message; ?></strong></p>
			</div>

<?php
			
		}

?>
        
                <form method="post" action="">
				<table class="form-table">
					<tr>
						<th scope="row"><img src="<?php echo plugin_dir_url(__FILE__).'images/data.png'; ?>" height="96px" width="96px" /></th>
						<td>
							<p>You can clear all IM Login Dongle data from the database here.</p>
			                <p>By marking the "Clear all dongle data" checkbox you delete all the data associated with IM Login Dongle from the Wordpress database.</p>
			                <p>You can also clear all current sessions by marking the "Clear sessions" checkbox.</p>
                    	</td>
					</tr>		
					<tr>
						<th scope="row"><label for="clear_sessions">Clear sessions</label></th>
						<td>
							<input type="checkbox" id="clear_sessions" name="clear_sessions" />
							<br />
            				<span class="description">Mark this to clear all dongle sessions from the database.</span>
						</td>
					</tr>		
					<tr>
						<th scope="row"><label for="clear_reset">Clear all dongle data</label></th>
						<td>
							<input type="checkbox" id="clear_reset" name="clear_reset" />
							<br />
            				<span class="description">Mark this to clear all dongle sessions and dongle data in the database. This action is <strong><font color="#FF0000">UNDOABLE!</font></strong></span>
						</td>
					</tr>		
				</table>					
				<p><input type="submit" name="clear-all-data" class="button-primary" value="<?php esc_attr_e('Delete data') ?>" /></p>
				</form>

<?

	}

	// The plugin admin page
	function im_login_dongle_icqbot_settings() {
		
		$message = "";
		
		$plugin_settings = get_option('im_login_dongle_settings');
		
		if(isset($_POST['icq-submit'])) {
		
			$id = $_POST['icq_id'];
			$pass = $_POST['icq_pass'];
			$pass_cmp = $_POST['icq_pass_conf'];
			$status = $_POST['icq_status'];

			if(isset($status)) { 
				$status = true; 
			} else { 
				$status = false; 
			}

			if(isset($pass) && isset($pass_cmp) && strlen($pass) > 0 && strlen($pass_cmp) > 0) {
				if(strcmp($pass, $pass_cmp) == 0) {
					$pass = encrypt($pass, $plugin_settings['encryption_salt']);
					$plugin_settings['im_bots']['icq']['im_bot_password'] = $pass;
				}
				else {
					$message = "Passwords for ICQ Bot account did not match.";	
				}
			}
			
			if(isset($id)) {
				$plugin_settings['im_bots']['icq']['im_bot_username'] = $id;	
			}
			if(isset($domain)) {
				$plugin_settings['im_bots']['icq']['im_bot_domain'] = $domain;	
			}
			
			$plugin_settings['im_bots']['icq']['activated'] = $status;
			
			update_option('im_login_dongle_settings', $plugin_settings);
			$message = $message." ICQ Bot settings were successfully saved.";			
			
		}

		
?>
		<div id="icon-options-general" class="icon32"></div><h2>IM Login Dongle ICQ Bot Settings</h2>
<?php

		if(strlen($message) > 0) {
		
?>

			<div id="message" class="updated">
				<p><strong><?php echo $message; ?></strong></p>
			</div>

<?php
			
		}

?>
        
                <form method="post" action="">
				<table class="form-table">
					<tr>
						<th scope="row"><img src="<?php echo plugin_dir_url(__FILE__).'images/icq.png'; ?>" height="96px" width="96px" /></th>
						<td>
                            <?php //<p>Please note that ICQ support is currently in an <strong><font color="#FF0000">experimental</font></strong> stage, so do write down your reset keys before continuing.</p> ?>
							<p>You can configure your ICQ account here. This account will be used to send out invites and dongle codes to other users.</p>
			                <p>We recommend you create a separate account on ICQ <a href="http://www.icq.com/join/en">here</a>.</p>
			                <p>When you've created your account, enter the login data bellow. Mark the dongle status checkbox when your account is registered.</p>
                    	</td>
					</tr>		
					<tr>
						<th scope="row"><label for="icq_id">Account ID</label></th>
						<td>
							<input name="icq_id" id="icq_id" type="text" value="<?php echo esc_attr($plugin_settings['im_bots']['icq']['im_bot_username']); ?>" />
							<br />
            				<span class="description">The ICQ account ID (not your mail address, number example: 123456789).</span>
						</td>
					</tr>		
					<tr>
						<th scope="row"><label for="icq_pass">Password and confirmation</label></th>
						<td>
							<input name="icq_pass" id="icq_pass" type="password" /><br />
							<input name="icq_pass_conf" id="icq_pass_conf" type="password" /><br />
            				<span class="description">Account password.</span>
						</td>
					</tr>		
					<tr>
						<th scope="row"><label for="icq_status">Dongle status</label></th>
						<td>
							<input type="checkbox" id="icq_status" id="icq_status" name="icq_status" value="true" 
							<?php if($plugin_settings['im_bots']['icq']['activated']) { ?>checked="checked"<?php } ?> />
							<br />
            				<span class="description">Enable or disable the selected account.</span>
						</td>
					</tr>		
				</table>					
				<p><input type="submit" name="icq-submit" class="button-primary" value="<?php esc_attr_e('Update ICQ options') ?>" /></p>
				</form>

<?

	}
			
