<?php

	$path = dirname(dirname(dirname(dirname (__FILE__))));
	require($path.'/wp-load.php');

	if(is_user_logged_in() && current_user_can('manage_options')) {

		if(isset($_POST['submitted'])) {
			$code1 = $_POST['code1'];
			$code2 = $_POST['code2'];
			$code3 = $_POST['code3'];
			$code4 = $_POST['code4'];
			
			$redirect_url = home_url('/wp-login.php');
			
			if(isset($code1) && isset($code2) && isset($code3) && isset($code4)) {
				$plugin_options = get_option('im_login_dongle_settings');
				$codes = $plugin_options['disable_code'];
				if($codes['code1'] == $code1 && $codes['code2'] == $code2 && $codes['code3'] == $code3 && $codes['code4'] == $code4) {
					$plugin_options['plugin_activated'] = false;
					update_option('im_login_dongle_settings', $plugin_options);
					wp_redirect(get_admin_url(), 301);
				}
				else {
					wp_redirect($redirect_url, 301);	
				}
			}
			else {
					wp_redirect($redirect_url, 301);				
			}
				
		}

?>


			<!DOCTYPE html>
			<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">  
			<link rel='stylesheet' id='wp-admin-css' href='<?php echo admin_url('css/wp-admin.css?ver=20111208'); ?>' type='text/css' media='all' />
			<link rel='stylesheet' id='colors-fresh-css'  href='<?php echo admin_url('css/colors-fresh.css?ver=20111206');  ?>' type='text/css' media='all' />
			<head><title>IM Login Dongle disable</title></head>
			<body class="login">
			<div id='login'>
			<a href="http://wpplugz.is-leet.net"><img src="images/logo.png" style="display: block; overflow: hidden; padding-bottom: 15px; padding-left:30px; align:center;" /></a>


			<form id="login_form" name="loginform"  action="" method="post">
			<label for="user_login">To disable the IM Login dongle for all users, please enter the four keys that were given to you.<br /><br /></label>
			<label for="code1">Key 1<input class="input" type="text" name="code1" id="code1" /></label><br />
            <label for="code2">Key 2<input class="input" type="text" name="code2" id="code2" /></label><br />
            <label for="code3">Key 3<input class="input" type="text" name="code3" id="code3" /></label><br />
            <label for="code4">Key 4<input class="input" type="text" name="code4" id="code4" /></label><br />
            <input type="hidden" value="submitted" name="submitted" />
			<p class="submit"><input type="submit" name="submit" tabindex="100" id="wp-submit" class="button-primary" value="Disable" tabindex="100" /></p>
            <label for='cancel'><a href='<?php echo wp_logout_url(); ?>'>Cancel</a></label><br />
			</form>
			</div>
			</body>

<?php

	}
	
	else {
		$redirect_url = site_url('/wp-login.php');
		wp_redirect($redirect_url, 301);
	}

?>