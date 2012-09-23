<?php

	$path = dirname(dirname(dirname(dirname(__FILE__))));
	require_once($path.'/wp-load.php');
	include_once('functions.php');

	if(is_user_logged_in()) {


		global $current_user;
		get_currentuserinfo();

		if(is_user_logged_in_im_login_dongle($current_user->ID, $_COOKIE['dongle_login_id'])) {
			wp_redirect(get_admin_url(), 301);
			exit;
		}

		if(isset($_POST['submitted'])) {
			$code = $_POST['code'];
			if(isset($code)) {
			
				$dongle_data = get_user_meta($current_user->ID, 'im_login_dongle_data', true);
				$cookie_id = $_COOKIE['dongle_login_id'];
				$cur_data = $dongle_data[$cookie_id];

				$check_validity = check_id_validity($current_user->ID, $cur_data, $code, $cookie_id);

				if($check_validity) {
					$cur_data['authenticated'] = true;
					$cur_data['dongle_used'] = true;
					$dongle_data[$cookie_id] = $cur_data;
					update_user_meta($current_user->ID, 'im_login_dongle_data', $dongle_data);
					wp_redirect(get_admin_url(), 301);				
				}
				else {
					unset($dongle_data[$cookie_id]);
					update_usermeta($current_user->ID, 'im_login_dongle_data', $dongle_data);				
					$redirect = home_url('/wp-login.php');
					setcookie("dongle_login_id", "", time()-3600*24, "/");			
					wp_logout();
					wp_redirect($redirect, 301);
				}
			}
		}

		$id = $_GET['id'];
		if(isset($id)) {
		
?>


			<!DOCTYPE html>
			<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">  
			<link rel='stylesheet' id='wp-admin-css' href='<?php echo admin_url('css/wp-admin.css?ver=3.4.2'); ?>' type='text/css' media='all' />
			<link rel='stylesheet' id='colors-fresh-css'  href='<?php echo admin_url('css/colors-fresh.css?ver=3.4.2');  ?>' type='text/css' media='all' />
			<head><title>Login authorization</title></head>
			<body class="login">
			<div id='login'>
			<a href="http://wpplugz.is-leet.com"><img src="images/logo.png" style="display: block; overflow: hidden; padding-bottom: 15px; padding-left:30px; align:center;" /></a>


			<form id="login_form" name="loginform"  action="" method="post">
			<label for="user_login"><p>Please enter the authentication code that was sent to you. If you did not receive your code yet, maybe use <a href="<?php echo plugin_dir_url(__FILE__).'auth.php'; ?>">another method</a>?</p><br /><input class="input" type="text" name="code" />
            <input type="hidden" value="submitted" name="submitted" />
			<p class="submit"><input type="submit" name="submit" tabindex="100" id="wp-submit" class="button-primary" value="Authorize" tabindex="100" /></p>
			<label for='cancel'><a href='<?php echo wp_logout_url(); ?>'>Cancel</a></label><br />
<?php 		if(current_user_can('manage_options')) {
	
?>				
			<br /><br /><label for='shutdown'><a href='<?php echo plugin_dir_url(__FILE__).'disable.php'; ?>'>Disable IM login?</a></label>
			<br /><br /><label for='shutdown'><a href='<?php echo plugin_dir_url(__FILE__).'shutdown.php'; ?>'>Disable IM login for all users?</a></label>

<?php			
			}
			else {
?>
			<br /><br /><label for='shutdown'><a href='<?php echo plugin_dir_url(__FILE__).'disable.php'; ?>'>Disable IM login?</a></label>
<?php
			}		
?>
			<br /><br />
			</form><br />
            <meta http-equiv="refresh" content="30;URL='<?php echo wp_logout_url(); ?>'">
			</div>
			</body>

<?php

		}
	
		else {
			$redirect_url = site_url('/wp-login.php');
			wp_redirect($redirect_url, 301);
		}

	}

?>