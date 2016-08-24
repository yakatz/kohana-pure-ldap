<?php defined('SYSPATH') or die('No direct access allowed.');

/**
 * Kohana-Pure-LDAP User Model
 *
 * @package    kohana-pure-ldap
 * @author     Stephen Eisenhauer
 * @copyright  (c) 2011 Stephen Eisenhauer
 * @license    New BSD License
 */
class Model_LDAP_User extends Model
{
	// Properties
	public $username = '';

	// This is needed for additional LDAP operations
	private $secure_handler;
	public $encrypted_password = '';

	public $attributes = array();
	public $roles = array();

	public function __construct()
	{
		 $this->secure_handler = new SecureHandler();
	}

	public function store_password($password)
	{
		$this->encrypted_password = base64_encode($this->secure_handler->encrypt($password));
	}

    public function get_password()
    {
        return $this->secure_handler->decrypt(base64_decode($this->encrypted_password));
    }
}


class SecureHandler
{
    /**
     * Constructor
     */
    public function __construct()
    {
        if (! extension_loaded('openssl')) {
            throw new \RuntimeException(sprintf(
                "You need the OpenSSL extension to use %s",
                __CLASS__
            ));
        }
        if (! extension_loaded('mbstring')) {
            throw new \RuntimeException(sprintf(
                "You need the Multibytes extension to use %s",
                __CLASS__
            ));
        }
    }

	private function create_iv($length){
		if (function_exists('random_bytes')) {
			return bin2hex(random_bytes($length));
		}
		if (function_exists('mcrypt_create_iv')) {
			return bin2hex(mcrypt_create_iv($length, MCRYPT_DEV_URANDOM));
		} 
		if (function_exists('openssl_random_pseudo_bytes')) {
			return bin2hex(openssl_random_pseudo_bytes($length));
		}
		throw new Exception("No crypto function available");
	}
    /**
     * Encrypt and authenticate
     *
     * @param string $data
     * @param string $key
     * @return string
     */
    public function encrypt($data)
    {
    	$key = $this->getKey('KEY_' . session_name());

        $iv = create_iv(16); // AES block size in CBC mode
        // Encryption
        $ciphertext = openssl_encrypt(
            $data,
            'AES-256-CBC',
            mb_substr($key, 0, 32, '8bit'),
            OPENSSL_RAW_DATA,
            $iv
        );
        // Authentication
        $hmac = hash_hmac(
            'SHA256',
            $iv . $ciphertext,
            mb_substr($key, 32, null, '8bit'),
            true
        );
        return $hmac . $iv . $ciphertext;
    }
    /**
     * Authenticate and decrypt
     *
     * @param string $data
     * @param string $key
     * @return string
     */
    public function decrypt($data)
    {
		$key = $this->getKey('KEY_' . session_name());

        $hmac       = mb_substr($data, 0, 32, '8bit');
        $iv         = mb_substr($data, 32, 16, '8bit');
        $ciphertext = mb_substr($data, 48, null, '8bit');
        // Authentication
        $hmacNew = hash_hmac(
            'SHA256',
            $iv . $ciphertext,
            mb_substr($key, 32, null, '8bit'),
            true
        );
        if (! $this->hash_equals($hmac, $hmacNew)) {
            throw new \RuntimeException('Authentication failed');
        }
        // Decrypt
        return openssl_decrypt(
            $ciphertext,
            'AES-256-CBC',
            mb_substr($key, 0, 32, '8bit'),
            OPENSSL_RAW_DATA,
            $iv
        );
    }
    /**
     * Get the encryption and authentication keys from cookie
     *
     * @param string $name
     * @return string
     */
    public function getKey($name)
    {
        if (empty($_SESSION[$name])) {
            $key = create_iv(64); // 32 for encryption and 32 for authentication
            $_SESSION[$name] = base64_encode($key);
        } else {
            $key = base64_decode($_SESSION[$name]);
        }
        return $key;
    }
    /**
     * Hash equals function for PHP 5.5+
     *
     * @param string $expected
     * @param string $actual
     * @return bool
     */
    public function hash_equals($expected, $actual)
    {
        $expected     = (string) $expected;
        $actual       = (string) $actual;
        if (function_exists('hash_equals')) {
            return hash_equals($expected, $actual);
        }
        $lenExpected  = mb_strlen($expected, '8bit');
        $lenActual    = mb_strlen($actual, '8bit');
        $len          = min($lenExpected, $lenActual);
        $result = 0;
        for ($i = 0; $i < $len; $i++) {
            $result |= ord($expected[$i]) ^ ord($actual[$i]);
        }
        $result |= $lenExpected ^ $lenActual;
        return ($result === 0);
    }
}