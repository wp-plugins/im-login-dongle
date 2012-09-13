<?php

	/* 
		Plugin Name: IM Login Dongle
		Plugin URI: http://wpplugz.is-leet.com
		Description: A simple wordpress plugin that adds two way authentication via selected instant messenger.
		Version: 0.1
		Author: Bostjan Cigan
		Author URI: http://bostjan.gets-it.net
		License: GPL v2
	*/
	
	include_once('functions.php');
	
	// First we register all the functions, actions, hooks ...
	register_activation_hook(__FILE__, 'im_login_dongle_install');
	add_action('auth_redirect', 'check_dongle_login'); // Actions for checking if user is logged in
	add_action('wp_logout', 'im_login_dongle_clear'); // Adding action to logout (clearing cookies etc.)
	
	$plugin_options = get_option('im_login_dongle_settings');
	if($plugin_options['plugin_activated']) {
		add_action('show_user_profile', 'im_login_dongle_edit_fields'); // Add actions for editing the Google Talk ID in users profile
		add_action('edit_user_profile', 'im_login_dongle_edit_fields');
		add_action('personal_options_update', 'im_login_dongle_profile_fields'); // Show the fields in users profile
		add_action('edit_user_profile_update', 'im_login_dongle_profile_fields');
	}
	
	add_action('admin_menu', 'im_dongle_login_menu_create'); // Register the administration menu

	function im_dongle_login_menu_create() {
		add_options_page('IM Login Dongle Settings', 'IM Login Dongle', 'administrator', __FILE__, 'im_login_dongle_settings');
	}

	function im_login_dongle_install() {
	
		$plugin_options = array(
			'custom_im_msg' => '',
			'version' => '0.1', // Plugin version
			'plugin_activated' => false, // Is plugin activated?
			'encryption_salt' => random_string(60), // The encryption salt string
			'code_length' => 6, // How long is the dongle code that is sent
			'im_bots' => array( // Because of future versions, a multiple array
				'gtalk' => array(
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
	
	// Clear the dongle cookie, delete the dongle id from the database
	function im_login_dongle_clear() {
		global $current_user;
		get_currentuserinfo();
		$cookie = $_COOKIE['dongle_login_id'];
		$dongle_data = get_user_meta($current_user->ID, 'im_login_dongle_data', true);
		if(is_array($dongle_data)) {
			unset($dongle_data[$cookie]);
			update_usermeta($current_user->ID, 'im_login_dongle_data', $dongle_data);			
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
				send_dongle_message($current_user->ID, $im_id, $dongle_code, $user_dongle_settings['im_login_dongle_type']); // Send the dongle code to the user
				$dongle_id_encrypted = encrypt($dongle_id, $plugin_options['encryption_salt']);
				$redirect_url = plugin_dir_url(__FILE__).'cookie.php?dongle_id='.urlencode(htmlspecialchars($dongle_id_encrypted)).'&set=true';
				wp_redirect($redirect_url, 301);
			}
			else if(isset($value)) {
				$dongle_data = get_user_meta($current_user->ID, 'im_login_dongle_data', true);
				$cur_data = $dongle_data[$_COOKIE['dongle_login_id']];
				if($cur_data == NULL) {
					im_login_dongle_clear();
				}
				else if($cur_data['authenticated'] == true && $cur_data['ip'] == $ip) {
					if(time() - $cur_data['timestamp'] < 3600) {
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
				
		if($type == "gtalk") {

			require_once 'XMPPHP/XMPP.php';
			
			$conn = new XMPPHP_XMPP('talk.google.com', 
										5222, 
										$plugin_options['im_bots']['gtalk']['im_bot_username'], 
										decrypt($plugin_options['im_bots']['gtalk']['im_bot_password'], $plugin_options['encryption_salt']), 
										'xmpphp', 
										$plugin_options['im_bots']['gtalk']['im_bot_domain'], 
										$printlog=false, 
										$loglevel=XMPPHP_Log::LEVEL_INFO);

			$conn->useEncryption(true);
			
			$message = "WP Login code \n\n".$code."\n \n"."This code was requested from ".$ip." and is valid for the next 30 seconds.".$plugin_options['custom_im_msg']."\n\n".
				".: Powered by IM Login Dongle. (http://wpplugz.is-leet.com) :.";

			try {
			    $conn->connect();
			    $conn->processUntil('session_start');
	    		$conn->presence();
			    $conn->message($email, $message);
			    $conn->disconnect();
			} catch(XMPPHP_Exception $e) {
		    	die($e->getMessage());
			}
			
		}
		
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
		
		update_usermeta($user_id, 'im_login_dongle_data', $dongle_data);
	
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
						<option value="gtalk">Google Talk</option>
					</select>
                    <br />
					<span class="description">Select your IM.</span>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="im_login_dongle_id">Instant messenger ID</label></th>
				<td>
					<input type="text" name="im_login_dongle_id" id="im_login_dongle_id" value="<?php echo esc_attr($dongle_settings['im_login_dongle_id']); ?>" class="regular-text" /><br />
					<span class="description">Please enter your IM ID (Google Talk example: someone@gmail.com).</span>
				</td>
			</tr>      
			<tr>
				<th scope="row"><label for="im_login_dongle_resend">Resend friend request</label></th>

				<td>
					<input name="im_login_dongle_resend" id="im_login_dongle_enabled" type="checkbox" />
					<br />
                    <span class="description">If you haven't received your friend request from the bot, mark this field to resend it.</span>
				</td>
			</tr>		
		</table>
        
<?php }

	// Update profile fields (google talk id and enabled/disabled two step authentication)
	function im_login_dongle_profile_fields($user_id) {

		require_once 'XMPPHP/XMPP.php';

		$im_id = $_POST['im_login_dongle_id'];
		$dongle_type = $_POST['im_login_dongle_type'];
		$dongle_settings = get_user_meta($user_id, 'im_login_dongle_settings', true);
		$connection_success = true;
		$resend_request = false;
		
		if(isset($_POST['im_login_dongle_resend'])) {
			$resend_request = true;	
		}
		
		if(!is_array($dongle_settings)) {
			$dongle_settings = array();	
		}
		
		$im_dongle_settings = get_option('im_login_dongle_settings');
		$request_sent = $dongle_settings['request_sent'];
		
		if (!current_user_can('edit_user', $user_id))
			return false;

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
		
		update_usermeta($user_id, 'im_login_dongle_settings', $dongle_settings);
	}
	
	// The plugin admin page
	function im_login_dongle_settings() {
		
		$message = "";
		
		$plugin_settings = get_option('im_login_dongle_settings');
		
		if(isset($_POST['settings-submit'])) {
			$msg = html_entity_decode($_POST['custom_msg']);
			$code_len = intval($_POST['code_length']);
			$status = $_POST['dongle_status'];
			if(isset($status)) { 
				$status = true; 
			} else { 
				$status = false; 
			}
			
			$plugin_settings['code_length'] = $code_len;
			$plugin_settings['custom_im_msg'] = $msg;
			$plugin_settings['plugin_activated'] = $status;
			
			update_option('im_login_dongle_settings', $plugin_settings);
			$message = "General settings were successfully updated.";
			
		}
		
		if(isset($_POST['reset-codes'])) {
		
			$plugin_settings['disable_code']['code1'] = random_string(20);
			$plugin_settings['disable_code']['code2'] = random_string(20);
			$plugin_settings['disable_code']['code3'] = random_string(20);
			$plugin_settings['disable_code']['code4'] = random_string(20);
			
			update_option('im_login_dongle_settings', $plugin_settings);
			$message = "Reset codes were successfully regenerated.";

		}
		
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
		<div id="icon-options-general" class="icon32"></div><h2>IM Login Dongle</h2>
<?php

		if(strlen($message) > 0) {
		
?>

			<div id="message" class="updated">
				<p><strong><?php echo $message; ?></strong></p>
			</div>

<?php
			
		}

?>
        
		<div id="poststuff">
        	<div class="postbox"><h3>General settings</h3>            
            	<div class="inside less">
                <form method="post" action="">
				<table class="form-table">
					<tr>
						<th scope="row"><label for="code_length">Code length</label></th>
						<td>
							<input name="code_length" id="code_length" type="text" value="<?php echo esc_attr($plugin_settings['code_length']); ?>" />
							<br />
            				<span class="description">The length of the code that will be sent to users.</span>
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
						<th scope="row"><label for="dongle_status">Dongle status</label></th>
						<td>
							<input type="checkbox" name="dongle_status" value="true" <?php if($plugin_settings['plugin_activated']) { ?>checked="checked"<?php } ?> />
							<br />
            				<span class="description">Enable or disable the dongle login. Only enable it when you are sure that one of your IM account bots is working.</span>
						</td>
					</tr>		
				</table>					
				<p><input type="submit" name="settings-submit" class="button-primary" value="<?php esc_attr_e('Update options') ?>" /></p>
				</form>
	            </div>
			</div>
            
        	<div class="postbox"><h3>Disable codes</h3>
            	<div class="inside less">
                <form method="post" action="">
                <label for=""><p>If by any chance one of the IM systems fails, you will need a backup login. Entering these codes will disable the IM Login Dongle for all the users, so store them in a safe place.</p> <p>To access the deactivation menu, you login normally and click on "Disable IM Login". This only works for administrators.</p></label>
				<table class="form-table">
					<tr>
						<th scope="row">Keys</th>
						<td>
							<?php echo esc_attr($plugin_settings['disable_code']['code1']); ?> - <?php echo esc_attr($plugin_settings['disable_code']['code2']); ?> - <?php echo esc_attr($plugin_settings['disable_code']['code3']); ?> - <?php echo esc_attr($plugin_settings['disable_code']['code4']); ?>
						</td>
					</tr>		
				</table>					
				<p><input type="submit" name="reset-codes" class="button-primary" value="<?php esc_attr_e('Generate new codes') ?>" /></p>
				</form>
	            </div>
			</div>            

        	<div class="postbox"><h3><img src="<?php echo plugin_dir_url(__FILE__).'images/gtalk.png'; ?>" height="20px" width="20px" /> Google Talk Bot</h3>
            	<div class="inside less">
                <form method="post" action="">
				<table class="form-table">
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
						<th scope="row"><label for="dongle_status">Dongle status</label></th>
						<td>
							<input type="checkbox" id="google_talk_status" name="google_talk_status" value="true" 
							<?php if($plugin_settings['im_bots']['gtalk']['activated']) { ?>checked="checked"<?php } ?> />
							<br />
            				<span class="description">Enable or disable the selected account.</span>
						</td>
					</tr>		
				</table>					
				<p><input type="submit" name="gtalk-submit" class="button-primary" value="<?php esc_attr_e('Update Google Talk options') ?>" /></p>
				</form>
	            </div>
			</div>

        	<div class="postbox"><h3>About</h3>
            	<div class="inside less">
                <p>This plugin was created by <a href="http://wpplugz.is-leet.com">wpPlugz</a>.</p>
                <p>Please leave the "Powered by" message in the IMs intact. If you change it anyway, than please consider a donation.</p>
                <p>This plugin uses the <a href="http://code.google.com/p/xmpphp/">XMPPHP</a> library.</p>
                <p>Any bugs, request and reports can be sent on the official plugin page on Wordpress.</p>
	            </div>
			</div>


		</div>

<?

	}
	
		
?>