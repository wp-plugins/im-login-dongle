<?php

	$path = dirname(dirname(dirname(dirname (__FILE__))));
	require($path.'/wp-load.php');
	include_once('functions.php');

	if(is_user_logged_in()) {

		$dongle_id = $_GET['dongle_id'];
		$set = $_GET['set'];
		$plugin_options = get_option('im_login_dongle_settings');
	
		if(isset($dongle_id) && isset($set)) {
			$tmp_dongle = htmlentities($dongle_id);
			$dongle_id_decrypted = decrypt($tmp_dongle, $plugin_options['encryption_salt']);
			$redirect_url = plugin_dir_url(__FILE__).'auth.php?id='.$dongle_id_decrypted;
			header("Location: $redirect_url");
			setcookie("dongle_login_id", $dongle_id_decrypted, time()+($plugin_options['session_time']*60), "/");
		    exit();
		}
		else {
			wp_redirect(home_url('/wp-login.php'), 301);
			exit();
		}
		
	}

?>