<?php defined('SYSPATH') or die('No direct access allowed.');

class Kohana_LDAP_User {
    protected $_dn;

    protected $_object              = array(
        'id'          => '',
        'has_access'  => FALSE,
        'has_manager' => FALSE,
        'role'        => '',
        'department'  => '',
        'groups'      => array()
    );

    protected $_config              = array();

    public function __construct($user) {
        $this->_config = Kohana::config('ldap')->as_array();

        if (is_string($user)) {
            $this->_object = json_decode($user, TRUE);
        } else {
            $this->_dn = $user['dn'];

            foreach (Arr::get($this->_config, 'attributes') as $key => $val) {
                if (in_array($val, array('memberof', 'department')))
                    continue;

                $idx = is_numeric($key) ? $val : $key;

                $this->_object[$idx] = Arr::path($user, $val.'.0');
            }

            $this->_object['has_access'] = (boolean) Arr::path($user, 'department.0');

            $access = array('department' => array(Arr::path($user, 'department.0')));

            if ( ! empty($user['memberof'])) {
                foreach ($user['memberof'] as $member) {
                    if (is_string($member)) {
                        $type = 'role';

                        if ($this->is_group($member)) {
                            $type = 'groups';
                        } elseif ( ! $this->is_role($member))
                            continue;

                        $access[$type][] = $this->get_cn($member);
                    }
                }
            }

            if ( ! empty($access)) {
                foreach ($access as $type => $members) {
                    foreach ($members as $member) {
                        $group = preg_replace(array('/\W+/', '/_+/', '/^_+/', '/_+$/'), array('_', '_', '', ''), trim(strtolower($member)));

                        if ($group) {
                            if ($type == 'groups') {
                                $this->_object[$type][$group] = $group;
                            } elseif ( ! Arr::path($this->_object, 'access.'.$type) || (($type == 'role') && ($group > Arr::path($this->_object, 'access.'.$type)))) {
                                if ($type == 'role') {
                                    $this->_object['has_manager'] = $group >= $this->_config['manager_level'];
                                }

                                $this->_object[$type]         = $group;
                            }
                        }
                    }
                }
            }

            $this->_object['id'] = $this->user_name;
        }
    }

    function dn() {
        return $this->_dn;
    }

    public function __get($name) {
        return $this->_object[$name];
    }

    public function get_values() {
        return $this->_object;
    }

    protected function get_cn($dn) {
        preg_match('/[^,]*/', $dn, $matches, PREG_OFFSET_CAPTURE, 3);

        return Arr::path($matches, '0.0', '');
    }

    protected function is_group($dn) {
        return stripos($dn, $this->_config['user_groups']) !== FALSE;
    }

    protected function is_role($dn) {
        return stripos($dn, $this->_config['auth_group']) !== FALSE;
    }
}