<?php defined('SYSPATH') or die('No direct script access.');

/**
 * LDAP config
 */
return array (
    'cookie_key'        => 'auth_auto_login',
    'host'              => 'localhost',
    'port'              => 389,
    'domain'            => 'localhost',
    'email_domains'     => array(), // '@example.com'
    'base_dn'           => 'OU=Departments,DC=localhost',
    'auth_group'        => 'OU=AuthGroup,OU=Departments,DC=localhost',
    'auth_level_prefix' => 'level_',
    'manager_level'     => 'level_2',
    'auth_filter'       => '(&(objectClass=*)(sn=*)(ou=ProgramAuth))',
    'user_groups'       => 'OU=user groups',
    'user_filter'       => '(&(objectClass=*)(sn=*)(department=*)(sAMAccountName=:user))',
    'allactive'         => '(&(objectClass=*)(sn=*)(department=*))',
    'attributes'        => array(
        // leave blank to get all attributes, or specify desired attributes for greater efficiency
    ),
);