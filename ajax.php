<?php
/**
 * AJAX call handler for ACL plugin
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Andreas Gohr <andi@splitbrain.org>
 */

//fix for Opera XMLHttpRequests
if(!count($_POST) && $HTTP_RAW_POST_DATA){
  parse_str($HTTP_RAW_POST_DATA, $_POST);
}

if(!defined('DOKU_INC')) define('DOKU_INC',dirname(__FILE__).'/../../../');
require_once(DOKU_INC.'inc/init.php');
//close session
session_write_close();

//if(!auth_isadmin()) die('for admins only');
if(!checkSecurityToken()) die('CRSF Attack');

$ID    = getID();

$acl = plugin_load('admin','autlogin');
$acl->handle();
$ajax = $_REQUEST['ajax'];
header('Content-Type: text/html; charset=utf-8');

if($ajax == 'tree'){
    global $conf;
    global $ID;

    $dir = $conf['datadir'];
    $ns  = $_REQUEST['ns'];
    if($ns == '*'){
        $ns ='';
    }
    $ns  = cleanID($ns);
    $lvl = count(explode(':',$ns));
    $ns  = utf8_encodeFN(str_replace(':','/',$ns));

    $data = $acl->_get_tree($ns,$ns);

    foreach($data as $item){
        $item['level'] = $lvl+1;
        echo $acl->_html_li_acl($item);
        echo '<div class="li">';
        echo $acl->_html_list_acl($item);
        echo '</div>';
        echo '</li>';
    }
}

