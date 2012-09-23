<?php

	require_once('class.GoogleTalkBot.php');
	require_once('class.WLMBot.php');
	require_once('class.ICQBot.php');
	
	function encrypt($text, $salt) { 
    	return trim(base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $salt, $text, MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND))));
	} 

	function decrypt($text, $salt) { 
	    return trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $salt, base64_decode($text), MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND)));
	}
	
	function is_user_logged_in_im_login_dongle($user_id, $id) {

		$agent = $_SERVER['HTTP_USER_AGENT'];
		$ip = $_SERVER['REMOTE_ADDR'];
		$options = get_option('im_login_dongle_settings');

		$dongle_data = get_user_meta($user_id, 'im_login_dongle_data', true);
		if(!is_array($dongle_data)) {
			return false;
		}

		$dongle_id = $dongle_data[$id]['dongle_id'];
		$unhashed_string = $agent.$ip.$dongle_id;

		$cmp_string = hash("sha512", $unhashed_string);
		if(isset($dongle_data[$id])) {
			if($dongle_data[$id]['authenticated']) {
				if(strcmp($cmp_string, $id) == 0) {
					if(time() - $dongle_data[$id]['timestamp'] < $options['session_time'] * 60) {
						return true;	
					}
				}
			}
		}
		
		return false;
			
	}
	
	// Check if dongle id is valid, id is valid for login if 30 seconds haven't passed yet
	function check_id_validity($user_id, $cur_data, $code, $id) {

		$agent = $_SERVER['HTTP_USER_AGENT'];
		$ip = $_SERVER['REMOTE_ADDR'];

		$dongle_data = get_user_meta($user_id, 'im_login_dongle_data', true);
		
		if($cur_data['dongle_used']) { return false; }
		if(time() - $cur_data['timestamp'] < 30) {
			if($code == $cur_data['code']) {
				$cmp_string = hash("sha512", $agent.$ip.$cur_data['dongle_id']);
				if(strcmp($cmp_string, $id) == 0) {
					return true;	
				}
			}
			return false;
		}
		return false;

	}
	
	// Generate a random string	
	function random_string($length) {
	    
		$characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    	$string = '';
    	for($i=0; $i<$length; $i++) {
	        $string .= $characters[mt_rand(0, strlen($characters)-1)];
    	}
    
		return $string;

	}

	// Check if exec function is available
	function is_exec_available() {

	    if($safe_mode = ini_get('safe_mode') && strtolower($safe_mode) != 'off') {
    	    return false;
		}

	    if(in_array('exec', array_map('trim', explode(',', ini_get('disable_functions'))))) {
			return false;
		}

	    return true;

	}

	// Check if certain PID is running
	function isPIDRunning($pid) {
		if($pid == NULL) return false;
		$result = exec(sprintf("ps %s", $pid));
		if(strpos($result, $pid) !== false) {
			return true;
		}
		return false;
	}
			
	// Generate a valid 30 second dongle code and insert it into the DB
	function insert_dongle_code($user_id, $dongle_code) {
		
		$agent = $_SERVER['HTTP_USER_AGENT'];
		$ip = $_SERVER['REMOTE_ADDR'];
		$dongle_id = random_string(60);

		$dongle_string = $agent.$ip.$dongle_id;

		$dongle_unique_id = hash("sha512", $dongle_string);

		$dongle_data = get_user_meta($user_id, 'im_login_dongle_data', true);
		
		if(!is_array($dongle_data)) {
			$dongle_data = array();	
		}
		
		$dongle_login = array(
			'user_id' => $user_id,
			'dongle_id' => $dongle_id,
			'timestamp' => time(),
			'authenticated' => false,
			'ip' => $ip,
			'code' => $dongle_code,
			'dongle_used' => false,
			'agent' => $agent
		);
		
		$dongle_data[$dongle_unique_id] = $dongle_login;
		
		update_user_meta($user_id, 'im_login_dongle_data', $dongle_data);
	
		return $dongle_unique_id;
	
	}

	/**
	* Returns true if at least one of the bot accounts is active
	*
	* @param array $settings
	*/
	function is_any_bot_account_active($settings) {
		
		$active = false;
		foreach($settings['im_bots'] as $account => $data) {
			if($data['activated']) $active = true; 
			if($active) break;
		}
		
		return $active;
		
	}

	/**
	* Returns string of login options in auth.php
	*
	* @param int $user_id
	*/
	function get_available_accounts($user_id) {

		$settings = get_option('im_login_dongle_settings');
		$dongle_data = get_user_meta($user_id, 'im_login_dongle_settings', true);

		$string = "";

		foreach($settings['im_bots'] as $account => $data) {
			if($data['activated']) {
				if($dongle_data['im_accounts'][$account]['active']) {
					$link = plugin_dir_url(__FILE__).'auth.php?type='.$account;
					$image = plugin_dir_url(__FILE__).'images/'.$account.'.png';
					$string = $string.' <a href="'.$link.'"><img src="'.$image.'" height="64px" width="64px" /></a>';
				}
			}
		}
		
		return $string;	
		
	}
	
	// Check if any of the bot accounts is currently active for the user
	function check_if_any_bot_for_user_active($user_id) {
		
		$settings = get_option('im_login_dongle_settings');
		$dongle_data = get_user_meta($user_id, 'im_login_dongle_settings', true);

		foreach($settings['im_bots'] as $account => $data) {
			if($data['activated']) {
				if($dongle_data['im_accounts'][$account]['active']) {
					return true;
				}
			}
		}
		
		return false;
		
	}
	
	
?>