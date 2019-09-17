<?php
/**
 * Ldap_Service class used for Active Directory authentication
 * 
 * @author  Christian Ward (christian.a.ward@gmail.com)
 */
class Ldap_Service {
	  
  /**
   * The CI superclass
   * @var object
   */
	public $CI;
  
  /**
   * Array containing default class instance 
   * configuration values. Should be loaded from a CI 
   * config file named '/application/config/ldap.php'.
   * @var array
   */
  private $ldap_config = array(
    'ldap_port' => null,
    'ldap_dn' => null,
    'ldap_rdn_pfx' => null,
    'ad_domain' => null,
    'ad_dc_list' => null,
    'ad_group_map' => null
  );
  
  /**
   * The LDAP connection TCP port 
   * @var int
   */
  private $ldap_port;
  
  /**
   * The LDAP base DN (Distinguished Name) 
   * (e.g. 'DC=name,DC=name,DC=name').
   * @var string
   */
  private $ldap_dn;
  
  /**
   * The RDN (Relative Distinguished Name) prefix to 
   * combine with the username used for AD authentication.
   * Must be formatted for AD (e.g. 'DOMAIN'."\\").
   * @var string
   */
  private $ldap_rdn_pfx;
  
  /**
   * The Active Directory domain name in dot notation 
   * (e.g. 'domain.com');
   * @var string
   */
  private $ad_domain;
  
  /**
   * Assoc array containing IP/hostname values.
   * Must be an assoc array. IP must be the key, 
   * and hostname must be the value 
   * (e.g. '0.0.0.0' => 'hostname').
   * @var array
   */
  private $ad_dc_list;
  
  /**
   * Assoc array containing local/AD group name mapping values.
   * Must be an assoc array. The local role_id must be the key, 
   * and the AD group name must be the value 
   * (e.g. 11 => 'Technicians').
   * @var array
   */
  private $ad_group_map;
  
  /**
   * Placeholder for the hostname (or ip address) of the 
   * connected AD domain controller.
   * @var string
   */
  private $domain_controller;
  
  /**
   * The LDAP connection resource object created 
   * by ldap_connect().
   * @var resource|bool
   */
  private $ldap_connection;
  
  /**
   * The LDAP search result identifier resource 
   * object created by ldap_search().
   * @var resource|bool
   */
  private $ldap_result;
  
  /**
   * Array containing search result data returned 
   * by ldap_get_entries().
   * @var array|bool
   */
  private $ldap_entries;
  
  /**
   * Array containing IP addresses for AD domain 
   * controllers.
   * by ldap_get_entries().
   * @var array
   */
  private $host_list = array();
  
	public function __construct($ldap_port = 3268, $ldap_dn = '', $ldap_rdn_pfx = '', $ad_domain = '', $ad_dc_list = array(), $ad_group_map = array()) {
		$this->CI =& get_instance();
    $this->ldap_config = !empty($this->CI->config->item('ldap')) ? $this->CI->config->item('ldap') : $this->ldap_config;
    $this->ldap_port = !empty($ldap_port) ? $ldap_port : $this->ldap_config['ldap_port'];
    $this->ldap_dn = !empty($ldap_dn) ? $ldap_dn : $this->ldap_config['ldap_dn'];
    $this->ldap_rdn_pfx = !empty($ldap_rdn_pfx) ? $ldap_rdn_pfx : $this->ldap_config['ldap_rdn_pfx'];
    $this->ad_domain = !empty($ad_domain) ? $ad_domain : $this->ldap_config['ad_domain'];
    $this->ad_dc_list = !empty($ad_dc_list) ? $ad_dc_list : $this->ldap_config['ad_dc_list'];
    $this->ad_group_map = !empty($ad_group_map) ? $ad_group_map : $this->ldap_config['ad_group_map'];
    if (empty($this->ldap_dn) || empty($this->ldap_rdn_pfx) || empty($this->ad_domain) || empty($this->ad_dc_list)) {
      throw new Exception("Error: LDAP Service failed to initialize. Missing required parameters.");
    }
	}

  public function authenticate($username, $password) {
    $data = array();
    $this->connect()
      ->bind($this->ldap_rdn_pfx.$username, $password)
      ->search('(sAMAccountName='.$username.')', array('memberof','extensionattribute1','cn','displayname','mail'))
      ->sort_result("sn")
      ->get_entries()
      ->close();
    if (!empty($this->ldap_entries)) {
      $role_ids = array();
      foreach($this->ldap_entries[0]['memberof'] as $groups) {
        foreach ($this->ad_group_map as $k => $v) {
          if (stripos($groups, $v)) $role_ids[] = $k;
        }
      }
      $data['user_id'] = $this->ldap_entries[0]['extensionattribute1'][0];
      $data['role_id'] = !empty($role_ids) ? max($role_ids) : 0;
      $data['username'] = $this->ldap_entries[0]['cn'][0];
      $data['full_name'] = $this->ldap_entries[0]['displayname'][0];
      $data['email'] = $this->ldap_entries[0]['mail'][0];
    }
    return json_decode(json_encode($data));
  }
  
  public function query($username, $password, $filter, $attr = array(), $sort = null, $as_object = false) {
    $this->connect()
      ->bind($this->ldap_rdn_pfx.$username, $password)
      ->search($filter, $attr)
      ->sort_result($sort)
      ->get_entries()
      ->close();
    return ($as_object) ? json_decode(json_encode($this->ldap_entries)) : $this->ldap_entries;
  }

  protected function connect() {
    if (empty($this->host_list)) $this->host_list = array_keys($this->ad_dc_list);
    // Randomize the order of the list to promote load balancing.
    shuffle($this->host_list);
    foreach ($this->host_list as $host_ip) {
      if ($this->ping($host_ip)) {
        $this->domain_controller = $this->ad_dc_list[$host_ip];
        break;
      }
    }
    if (!empty($this->domain_controller)) {
      if ($this->ldap_port) $this->ldap_connection = @ldap_connect($this->domain_controller, $this->ldap_port);
      else $this->ldap_connection = @ldap_connect($this->domain_controller);
      ldap_set_option($this->ldap_connection, LDAP_OPT_PROTOCOL_VERSION, 3);
      ldap_set_option($this->ldap_connection, LDAP_OPT_REFERRALS, 0);
    }
    else {
      throw new Exception("Error: LDAP Service failed to locate a directory server.");
      exit;
    }
    return $this;
  }

  protected function bind($rdn, $password) {
    if ($this->ldap_connection && !@ldap_bind($this->ldap_connection, $rdn, $password)) {
      throw new Exception("Error: LDAP Service failed to connect and bind to the directory server.");
      exit;
    }
    return $this;
  }
  
  protected function search($filter, $attr = array()) {
    if ($this->ldap_connection) $this->ldap_result = @ldap_search($this->ldap_connection, $this->ldap_dn, $filter, $attr);
    if (!$this->ldap_result) {
      throw new Exception("Error: LDAP Service failed to create the search query.");
      exit;
    }
    return $this;
  }
  
  protected function sort_result($filter) {
    if ($this->ldap_connection && $this->ldap_result && !@ldap_sort($this->ldap_connection, $this->ldap_result, $filter)) {
      throw new Exception("Error: LDAP Service failed to sort the search result.");
      exit;
    }
    return $this;
  }
  
  protected function get_entries() {
    if ($this->ldap_connection && $this->ldap_result) $this->ldap_entries = @ldap_get_entries($this->ldap_connection, $this->ldap_result);
    if (!$this->ldap_entries) {
      throw new Exception("Error: LDAP Service failed to return a search result.");
      exit;
    }
    return $this;
  }
  
  protected function unbind() {
    if ($this->ldap_connection && !@ldap_unbind($this->ldap_connection)) {
      throw new Exception("Error: LDAP Service failed to unbind and close the connection to the directory server.");
      exit;
    }
    return $this;
  }

  protected function close() {
    return $this->unbind();
  }
  
  private function ping($host, $port = 389, $timeout = 1) {
    $op = @fsockopen($host, $port, $errno, $errstr, $timeout);
    if (!$op) return false; //DC is N/A
    else {
      fclose($op); // Explicitly close the open socket connection!
      return true; // DC is up & running, we can safely connect with ldap_connect().
    }
  }
  
  
  
}

/* End of file Ldap_Service.php */
