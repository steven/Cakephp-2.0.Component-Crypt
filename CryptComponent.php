<?php
/**
 * --- Crypt Component ---
 * Github: https://github.com/steven/Cakephp-2.0.Component-Crypt
 * For encrypting and decrypting a string, URL friendly
 *
 * @author Steven Thompson <steven@fantasmagorical.co.uk>
 */
 
class CryptComponent extends Component{
	
	var $key;
	var $name = 'Crypt';
		
	// Retrieve the Security salt from the config and cut to 20 characters
	function __construct(){
		$this->key = substr(Configure::read('Security.salt'),0,20);
	}
	
	function _safe_b64encode($string) {
		$data = base64_encode($string);
		$data = str_replace(array('+','/','='),array('-','_',''),$data);
		return $data;
	}

  function _safe_b64decode($string) {
		$data = str_replace(array('-','_'),array('+','/'),$string);
		$mod4 = strlen($data) % 4;
		if ($mod4) {
				$data .= substr('====', $mod4);
		}
		return base64_decode($data);
	}
	
	// Encrypt the string
	function encrypt($value){ 
		if(!$value){return false;}
		$text = $value;
		$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
		$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
		$crypttext = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $this->key, $text, MCRYPT_MODE_ECB, $iv);
		return trim($this->_safe_b64encode($crypttext));
	}
	
	// Decrypt the string
	function decrypt($value){
		if(!$value){return false;}
		$crypttext = $this->_safe_b64decode($value); 
		$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
		$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
		$decrypttext = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $this->key, $crypttext, MCRYPT_MODE_ECB, $iv);
		return trim($decrypttext);
	}
} 