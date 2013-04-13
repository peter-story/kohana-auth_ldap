<?php defined('SYSPATH') or die('No direct access allowed.');

class Kohana_Auth_LDAP extends Auth {
    protected $_link;

    protected $_key  = 'example_secret_key';

    public function __construct($config = array()) {
        if (is_object($config)) {
            $config = $config->as_array();
        }

        $config = array_merge(
            Kohana::config('auth')->as_array(),
            Kohana::config('ldap')->as_array(),
            $config
        );

        parent::__construct($config);

        $this->_link   = ldap_connect($this->_config['host'], $this->_config['port']);
    }

    function password($username) {}

    function check_password($password) {}

    function login($username, $password, $remember = FALSE) {
        foreach ($this->_config['email_domains'] as $domain) {
            $username = trim(str_replace($domain, '', $username));
        }

        $success = $this->_login($username, trim($password), $remember);

        $this->close_link();

        return $success;
    }

    protected function _login($username, $password, $remember) {
        if ( ! $username || ! $password || ! $this->bind($username, $password))
            return FALSE;

        $result = $this->search($username);

        if ( ! $result || ($result['count'] !== 1))
            return FALSE;

        $result[0]['password'][0] = $this->encrypt($password);

        $user   = new LDAP_User($result[0]);

        if ($remember) {
            Cookie::set($this->_config['cookie_key'], json_encode($user->get_values()), $this->_config['lifetime']);
        }

        $this->complete_login($user);

        return TRUE;
    }

    protected function encrypt($string) {
        return base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5($this->_key), $string, MCRYPT_MODE_CBC, md5(md5($this->_key))));
    }

    protected function decrypt($encrypted) {
        return rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5($this->_key), base64_decode($encrypted), MCRYPT_MODE_CBC, md5(md5($this->_key))), "\0");
    }

    public function logout($destroy = FALSE, $logout_all = FALSE) {
        Cookie::delete($this->_config['cookie_key']);

        return parent::logout($destroy);
    }

    function bind($username, $password, $decrypt_password = FALSE) {
        if ($decrypt_password) {
            $password = $this->decrypt($password);
        }

        return @ldap_bind($this->_link, "{$this->_config['domain']}\\$username", $password);
    }

    function get_a_user($username) {
        $result = $this->search($username);

        if ( ! $result || ($result['count'] !== 1))
            return FALSE;

        $user   = new LDAP_User($result[0]);

        return $user;
    }

    function get_all_users() {
        $results = $this->search();

        $users   = array();

        if ($results && $results['count']) {
            foreach ($results as $key => $val) {
                if ( ! is_numeric($key))
                    continue;

                $user = new LDAP_User($val);

                $users[$this->_get_user_index($user)] = $user;
            }
        }

        ksort($users);

        return $users;
    }

    protected function _get_user_index($user) {
        // override this as you see fit
        return NULL;
    }

    protected function search($username = NULL) {
        $filter = $username ? str_replace(':user', $username, $this->_config['user_filter']) : $this->_config['allactive'];

        $result = @ldap_search(
            $this->_link,
            $this->_config['base_dn'],
            $filter,
            array_values($this->_config['attributes']),
            NULL,
            NULL,
            5
        );

        if ( ! $result)
            return FALSE;

        return @ldap_get_entries($this->_link, $result);
    }

    // This function retrieves and returns CN from given DN
    function get_user($default = NULL) {
        $user = parent::get_user($default);

        if ($user === $default) {
            // check for "remembered" login
            if (($user = $this->auto_login()) === FALSE)
                return $default;
        }

        return $user;
    }

    function auto_login() {
        $user_vals = Cookie::get($this->_config['cookie_key']);

        if (empty($user_vals))
            return $user_vals;

        return new LDAP_User($user_vals);
    }

    function authorize($access_rules) {
        $user = $this->get_user();

        if ( ! $user)
            return FALSE;

        // the user's role cannot be smaller than the access_rule role, assuming that the two are named with the same prefix and only the number at the end differentiates them 
        if ( ! empty($access_rules['role']) && ($access_rules['role'] > $user->role))
            return FALSE;

        return $this->check_departments($user, Arr::get($access_rules, 'departments', array()));
    }

    function check_departments($user, array $departments) {
        // if no groups are required, then it passes
        if (empty($departments))
            return TRUE;

        if ( ! in_array('development', $departments)) {
            $departments[] = 'development';
        }

        return in_array($user->department, $departments);
    }

    protected function get_auth_group($level) {
        return 'CN='.$this->_config['auth_level_prefix'].$this->get_role_level($level).','.$this->_config['auth_group'];
    }

    protected function get_role_level($role) {
        return str_replace($this->_config['auth_level_prefix'], '', $role);
    }

    function edit_role($user, $level) {
        $success     = TRUE;

        if ($user->role) {
            if ($user->role == $level)
                return TRUE;

            $success = $this->del_role($user);

            if ( ! $success) {
                $success = ldap_error($this->_link);
            }
        }

        if ( ! $level || ! $success)
            return $success;

        if (@ldap_mod_add($this->_link, $this->get_auth_group($level), array('member' => $user->dn())))
            return TRUE;

        return ldap_error($this->_link);
    }

    function del_role($user) {
        return @ldap_mod_del($this->_link, $this->get_auth_group($user->role), array('member' => $user->dn()));
    }

    function close_link() {
        return @ldap_close($this->_link);
    }
}