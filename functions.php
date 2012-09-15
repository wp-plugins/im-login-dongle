<?php

	function encrypt($text, $salt) { 
    	return trim(base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $salt, $text, MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND))));
	} 

	function decrypt($text, $salt) { 
	    return trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $salt, base64_decode($text), MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND)));
	}
	
	function check_id_validity($cmp_id, $id, $timestamp, $cmp_ip, $ip, $cmp_code, $code, $dongle_used) {
		if($dongle_used) { return false; }
		if($cmp_id == $id && $cmp_ip == $ip && $cmp_code == $code) {
			if(time() - $timestamp > 30) {
				return false;	
			}
			else {
				return true;	
			}
		}
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


?>