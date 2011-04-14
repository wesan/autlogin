<?php

/**
 * Dokuwiki Action Plugin: automatic login
 * 
 * @author Ondrej Machac <omachac@seznam.cz>
 */
 

if(!defined('DOKU_INC')) die();
if(!defined('DOKU_PLUGIN')) define('DOKU_PLUGIN',DOKU_INC.'lib/plugins/');
require_once(DOKU_PLUGIN.'action.php');

class action_plugin_autlogin extends DokuWiki_Action_Plugin {
    
    var $acl = array();
    var $passw = "autlogin";

/**
   * return some info
   */
  function getInfo(){
    return array(
      'author' => 'Ondrej Machac',
      'email'  => 'omachac@seznam.cz',
      'date'   => '2011-02-17',
      'name'   => 'Automatic login',
      'desc'   => 'Automatic login for host, who meets some criterion of performance.',
      'url'    => 'http://cloud.github.com/downloads/wesan/autlogin.tgz',
    );
  }
  
  
    function register(&$controller) {
    $controller->register_hook(
      'TPL_METAHEADER_OUTPUT', 'BEFORE', $this, 'get_searchq'
    );
  
   	$controller->register_hook
      ('TPL_ACT_RENDER', 'AFTER', $this, display_banner, array()); 
  }
  
   //if is login host a moderator display new button
    function display_banner(&$event, $param) {
    if($this->_ismoderator()) {
        echo '<br><br>';
        echo '<HR size=1 width="100%" align="center">';
        echo '<form action="'.wl().'" method="post" accept-charset="utf-8"><div class="no">'.NL;
        echo '<input type="submit" value="'.$this->getLang('moderator').'" name="moderat" class="button" />';  
        echo '<input type="hidden" name="id" value="'.hsc($ID).'" />'.NL;
        echo '<input type="hidden" name="do" value="admin" />'.NL;
        echo '<input type="hidden" name="page" value="autlogin" />'.NL;
        echo '<input type="hidden" name="sectok" value="'.getSecurityToken().'" />'.NL;  
        echo '</div></form>'.NL;
    
    
    }
    
    
    }
    /**                   
   * Handle the event
   */ 
  function get_searchq(&$event, $param) {
        
        global $ID;
        global $BName, $Version, $Platform; //browser, OS
        global $entry_page; //entry page
        global $ACTUAL_ACL; //actual ACL with alias
        global $user_ip;
        global $auth;
        global $ACT;
        global $conf;


    
      
          if(empty($_SERVER['REMOTE_USER']))      // if isn't somebody login continue
          {
           
            $user_ip = $_SERVER['REMOTE_ADDR'];  //host's IP
            
            if(!empty($_SERVER['HTTP_REFERER']))   //if exist entry page
            $entry_page = $_SERVER['HTTP_REFERER']; //load
            
            $user_agent=$_SERVER[HTTP_USER_AGENT];
            $this->detect_browser($user_agent);     //load browser and OS
            
            $ACTUAL_ACL = file(DOKU_PLUGIN.'/autlogin/settings/transl.php');
            
           // $this->get_perm(); //load actual rules from transl.php
            
            $best = $this->find_best();   //find best rule for host
              
            if($best != -1) //some rule is accepting, log in like $best
             {
                $best = auth_nameencode($best,true);
                $info = $auth->getUserData($best);
               if($info === false){
                     $exist = false;
               }else{
                    $groups = $info['grps'];
                    $exist = true;
               } 
               if($exist){
                   auth_login($best,$passw,false,false);
                   if(auth_aclcheck($ID,$best,$groups) == AUTH_NONE)
                      $ACT = 'denied';
                   echo '<br><h3>'.$this->getLang('refresh_page').'</h3><br>'.NL;
                }
             }
            else //if no rule is right, write hosts info to file visit.php
             {
                  $this->write_to_visit(); 
             }
          
          }
            
  }
  
  //find best rule for actual host
  function find_best()
   {
   
        global $ID;
        global $BName, $Version, $Platform; //browser, OS
        global $entry_page; //entry page
        global $ACTUAL_ACL; //actual ACL with alias
        global $user_ip;
   

      $ip=0;
      $is=0;
      $max = 0;
      $best = -1;
      $this->get_perm(); //load actual rules from transl.php
      
      if(empty($this->acl)) // no rule is set
       return -1;
      
      foreach($this->acl as $stranka => $n1)
      {
       //if($ID != $stranka) //only for rights ID's::!!!!!!!
       if(!$this->_is_page($ID,$stranka))
         continue;
       foreach ($n1 as $kriterium => $n2) 
         foreach ($n2 as $alias => $cislo)
          {
          $numb=0;
          $count = 0;
          $rules = preg_split('/,/',$kriterium);
          foreach($rules as $asd)
           $numb++;  //number of item in criteria          
          if($numb == 0)
           $numb=1;
           
          if(!empty($user_ip))
           {
             if(preg_match("~$user_ip~",$kriterium)){ //search if is user IP in criterium
              $count++;
              $ip = 1;
             }
           }
          if(!empty($BName))
           {
             if(preg_match("~$BName~",$kriterium))
              $count++;
           } 
          if(!empty($Version))
           {
             if(preg_match("~$Version~",$kriterium))
              $count++;
           }
          if(!empty($Platform))
           {
             if(preg_match("~$Platform~",$kriterium))
              $count++;
           }  
         if(!empty($entry_page))
           {
           $line = preg_split('/,/',$kriterium);
           foreach($line as $match)
             if((SubStr($match,0,3)) == 'EP='){
               $match = SubStr($match,3,(strlen($match)));
               $match = trim($match); 
               $entry_page = trim($entry_page);
               if($entry_page == $match)
                 $count++;
             }
           } 
 
          if(($count == $numb)) //all criteria are right?
           {           
           if($ip != 1 && $is == 1 )//if is set ip and same criteria set new $best
            $ip = 0;
           else{
            $is = 1;
            $max = $count;
            $best = $alias;
            $ip=0;
           }
           $numb=0;      
       }
      }
     }

     return $best;
   } 
    
   
   
   function write_to_visit()
    {
        global $ID;
        global $BName, $Version, $Platform; //browser, OS
        global $entry_page; //entry page
        global $ACTUAL_ACL; //actual ACL with alias
        global $user_ip;
        

        if(($BName != 'Unknown') && ($Version != 'Unknown') && ($Platform != 'Unknown')) //neznamy navstevnik
            {
              $visit = file_get_contents(DOKU_PLUGIN.'/autlogin/settings/visit.php');
              
                  $datum = StrFTime("%d/%m/%Y-%H:%M:%S", Time());
                  //$line.=$datum." ".$ID;
                  $line = $ID;
                  if(!empty($user_ip))
                   $line.=" IP=".$user_ip.",";
                  if(!empty($BName) && ($BName != 'Unknown'))
                    $line.="WB=".$BName.",";
                  if(!empty($Version) && ($Version != 'Unknown'))
                    $line.="VER=".$Version.","; 
                  if(!empty($entry_page))
                    $line.="EP=".$entry_page.",";
                  if(!empty($Platform) && ($Platform != 'Unknown'))
                    $line.="OS=".$Platform;
                         
                  if(($this->_exist($line)) == 1){ //exist the same host?
                   $visit.="\n".$datum." ".$line."\n";                   
                   io_saveFile(DOKU_PLUGIN.'/autlogin/settings/visit.php', $visit);
                  }
              
             
            }  
   }
      
      
  // is exist host whit the same criteria and same $ID return -1
  // else return 1   
  function _exist($line)
   {
    $line = trim($line);
    $file_line = file(DOKU_PLUGIN.'/autlogin/settings/visit.php');   
       foreach($file_line as $lines)
       {    
           $users = preg_split('/\s+/',$lines);
           $users[2] = rawurldecode($users[2]);
           $match =$users[1]." ".$users[2];

           $match = trim($match);
           if($line == $match){
             return -1;
             }
       } 

     return 1;
   }
  
  
  //is $id and $stranka the same, or is $id in $stranka's namespace
 function _is_page($ID,$stranka)
  {
     if($ID == $stranka) return true;
  
      $ids   = preg_split('/:/',$ID);
      $pages   = preg_split('/:/',$stranka);
      $count = count($ids);
      if($count>0) for($i=0; $i<$count; $i++){
         if($ids[$i] != $pages[$i]){
           if($pages[$i] == '*')
            return true;
           else return false;   
         }
       }
    return true;
      
  }  
  
  //load actual setttings store in transl.php
  function get_perm()
  {
     global $ACTUAL_ACL;
     
     if($ACTUAL_ACL){
        foreach($ACTUAL_ACL as $line){
            $line = trim(preg_replace('/#.*$/','',$line)); //ignore comments
            if(!$line) continue;

            $acl = preg_split('/\s+/',$line);
            //0 is pege, 1 kriterium, 2 alias, 3 is acl

            $acl[1] = rawurldecode($acl[1]);
            $acl_config[$acl[0]][$acl[1]][$acl[2]] = $acl[3];
        }
        $this->acl = $acl_config;
     }
}
  
  //is login user a moderator?
  function _ismoderator(){
    global $auth;
    
    $user = $_SERVER['REMOTE_USER'];
    $user = auth_nameencode($user);
        $info = $auth->getUserData($user);
        if($info === false){
                $exist = false;
            }else{
                $groups = $info['grps'];
                $exist = true;
            }
        if($exist == true){
         foreach($groups as $lines)
          if($lines == 'moderator')
           return 1;
        }
   
   
    return 0;
   }
  
  
  
  //function for find browser, his version and OS
      
  function detect_browser($user_agent) 
  { 
    global $BName, $Version, $Platform; 
 

 
      //--- Browser, Robot, crawler, spider & Download Managers ---
          if(preg_match("~(Offline Explorer)/([0-9]{1}.[0-9]{1})~",$user_agent,$match)) 
        { 
        	$BName = "Offline_Explorer"; $Version=$match[2]; 
        } 
        if(preg_match("~WebCopier v ([0-9]{1}.[0-9]{1}.{0,1}[0-9]{0,1})~",$user_agent,$match)) 
        { 
        	$BName = "WebCopier"; $Version=$match[2]; 
        } 
        elseif(preg_match("~(Web Downloader)/([0-9]{1}.[0-9]{1})~",$user_agent,$match)) 
        { 
        	$BName = "Web_Downloader"; $Version=$match[2]; 
        } 
        elseif(preg_match("~(Mass Downloader)/([0-9]{1}.[0-9]{1})~",$user_agent,$match)) 
        { 
        	$BName = "Mass_Downloader"; $Version=$match[2]; 
        } 
        elseif(preg_match("(Ask Jeeves/Teoma)",$user_agent)) 
        { 
        	$BName = 'Search_Bot_Ask_Jeeves/Teoma'; 
        } 
        elseif(preg_match("(Googlebot)",$user_agent)) 
        { 
        	$BName = 'Search_Bot_Googlebot'; 
        } 
        elseif(preg_match("(nuhk)",$user_agent)) 
        { 
      	$BName = 'Search_Bot_NUHK'; 
      } 
      elseif(preg_match("(Openbot)",$user_agent)) 
      { 
      	$BName = 'Search_Bot_Openbot'; 
      } 
      elseif(preg_match("(Slurp)",$user_agent)) 
      { 
      	$BName = 'Search_Bot_Slurp'; 
      } 
      elseif(preg_match("(ia_archiver)",$user_agent)) 
      { 
      	$BName = 'Search_Bot_ia_archiver'; 
      } 
      elseif(preg_match("(MSNBot)",$user_agent)) 
      { 
      	$BName = 'Search_Bot_MSNBot'; 
      } 
      elseif(preg_match("(Yammybot)",$user_agent)) 
      { 
      	$BName = 'Search_Bot_Yammybot'; 
      } 
      elseif(preg_match("~(Opera Mini)/([0-9]{1,2}.[0-9]{1,2})~",$user_agent,$match)) 
      { 
      	$BName = "Opera_Mini"; $Version=$match[2]; 
      } 
      elseif(preg_match("~(opera) ([0-9]{1,2}.[0-9]{1,3}){0,1}~",$user_agent,$match) 
      	|| preg_match("~(opera/)([0-9]{1,2}.[0-9]{1,3}){0,1}~",$user_agent,$match)) 
      { 
      	$BName = "Opera"; $Version=$match[2]; 
      	
      	if ($Version == '9.80'){
      		preg_match("~([0-9]{1,2}.[0-9]{1,3}){0,1}$~",$user_agent,$match);
      		$Version=$match[1];
    	}
    	
    } 
    elseif( preg_match("~(NetCaptor) ([0-9]{1,2}.[0-9]{1,3}.[0-9]{1,3})~",$user_agent,$match) 
    	|| preg_match("~(NetCaptor) ([0-9]{1,2}.[0-9]{1,3})~",$user_agent,$match)) 
    { 
    	$BName = "NetCaptor"; $Version=$match[2]; 
    } 
    elseif(preg_match("(amaya)",$user_agent,$match)) 
    { 
    	$BName = "Amaya"; $Version="Unknown"; 
    } 
    elseif(preg_match("~(Camino)/([0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2})~",$user_agent,$match)) 
    { 
    	$BName = "Camino"; $Version=$match[2];
    } 
    elseif(preg_match("~(Epiphany)/([0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2})~",$user_agent,$match)
    	|| preg_match("~(Epiphany)/([0-9]{1,2}.[0-9]{1,2})~",$user_agent,$match)) 
    { 
    	$BName = "Epiphany"; $Version=$match[2];
    } 
    elseif(preg_match("~(Flock)/([0-9]{1,2}.[0-9]{1,2}.{0,1}[0-9]{0,3}.{0,1}[0-9]{0,3})~",$user_agent,$match)) 
    { 
    	$BName = "Flock"; $Version=$match[2]; 
    } 
    elseif(preg_match("~(Galeon)/([0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2})~",$user_agent,$match)) 
    { 
    	$BName = "Galeon"; $Version=$match[2]; 
    } 
    elseif(preg_match("~(Chimera)/([0-9]{1,2}.[0-9]{1,2})~",$user_agent,$match)) 
    { 
    	$BName = "Chimera"; $Version=$match[2];
    } 
    elseif(preg_match("~(Chrome)/([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})~",$user_agent,$match)) 
    { 
    	$BName = "Chrome"; $Version=$match[2];
    } 
    elseif(preg_match("(icab)",$user_agent,$match)) 
    { 
    	$BName = "iCab"; $Version="Unknown"; 
    } 
    elseif(preg_match("~(K-Meleon)/([0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2})~",$user_agent,$match)) 
    { 
    	$BName = "K-Meleon"; $Version=$match[2]; 
    } 
    elseif(preg_match("~(konqueror)/([0-9]{1,2}.[0-9]{1,3})~",$user_agent,$match)) 
    { 
    	$BName = "Konqueror"; $Version=$match[2]; 
    } 
    elseif(preg_match("~(Lunascape) ([0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2})~",$user_agent,$match)) 
    { 
    	$BName = "Lunascape"; $Version=$match[2]; 
    } 
    elseif(preg_match("~(links) / ([0-9]{1,2}.[0-9]{1,3})~",$user_agent,$match)) 
    { 
    	$BName = "Links"; $Version=$match[2]; 
    } 
    elseif(preg_match("(lotus)",$user_agent,$match)) 
    { 
    	$BName = "Lotus "; $Version="Unknown"; 
    } 
    elseif(preg_match("~(lynx)/([0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2})~",$user_agent,$match)) 
    { 
    	$BName = "Lynx"; $Version=$match[2]; 
    } 
    elseif(preg_match("(Maxthon)",$user_agent,$match)) 
    { 
    	$BName = "Maxthon"; $Version="Unknown"; 
    } 
    elseif(preg_match("(mosaic)",$user_agent,$match)) 
    { 
    	$BName = "Mosaic "; $Version="Unknown"; 
    } 
    elseif( preg_match("~(Safari)/([0-9]{1,3})~",$user_agent,$match) ) 
    { 
    	$BName = "Safari";
    	if ( preg_match("~(Version)/([0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2})~",$user_agent,$match)
    	|| preg_match("~(Version)/([0-9]{1,2}.[0-9]{1,2})~",$user_agent,$match)
    	) $Version=$match[2]; 
    } 
    elseif(preg_match("~(SeaMonkey)/([0-9]{1,2}.[0-9]{1,2}.{0,1}[0-9]{0,3}.{0,1}[0-9]{0,3})~",$user_agent,$match)) 
    { 
    	$BName = "SeaMonkey"; $Version=$match[2]; 
    } 
    elseif(preg_match("~(Sleipnir)/([0-9]{1,2}.[0-9]{1,2}.{0,1}[0-9]{0,3}.{0,1}[0-9]{0,3})~",$user_agent,$match)) 
    { 
    	$BName = "Sleipnir"; $Version=$match[2]; 
    } 
    elseif(preg_match("~(Songbird)/([0-9]{1,2}.[0-9]{1,2})~",$user_agent,$match)) 
    { 
    	$BName = "Songbird"; $Version=$match[2]; 
    } 
    elseif(preg_match("~(Sylera)/([0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2})~",$user_agent,$match)) 
    { 
    	$BName = "Sylera"; $Version=$match[2]; 
    } 
    elseif(preg_match("~(Firefox)/([0-9]{1,2}.[0-9]{1,2}.{0,1}[0-9]{0,3}.{0,1}[0-9]{0,3})~",$user_agent,$match)) 
    { 
    	$BName = "Firefox"; $Version=$match[2]; 
    } 
    elseif((preg_match("~MSIE 7.0~",$user_agent,$match)) 
     && (preg_match("~(Trident/4.0)~",$user_agent,$match))) 
    { 
    	$BName = "MSIE"; $Version= 8.0 ; 
    } 
    elseif(preg_match("~(MSIE) ([0-9]{1,2}.[0-9]{1,3})~",$user_agent,$match)) 
    { 
    	$BName = "MSIE"; $Version=$match[2]; 
    } 
    elseif(preg_match("~(netscape6)/(6.[0-9]{1,3})~",$user_agent,$match)) 
    { 
    	$BName = "Netscape"; $Version=$match[2]; 
    } 
    elseif(preg_match("~(netscape)/(7.[0-9]{1,2})~",$user_agent,$match)) 
    { 
    	$BName = "Netscape"; $Version=$match[2]; 
    } 
    elseif(preg_match("~(Gecko)/([0-9]{1,8})~",$user_agent,$match)) 
    { 
    	$BName = "Mozilla"; 
    	$Version=$match[2]; 
    	if (preg_match("(rv):([0-9]{1,2}.[0-9]{1,3}.[0-9]{1,3})",$user_agent,$match))
    	{
    		$Version=$match[2];
    	};
    	if (preg_match("(rv):([0-9]{1,2}.[0-9]{1,3})",$user_agent,$match))
    	{
    		$Version=$match[2];
    	};
    } 
    elseif(preg_match("~mozilla/5~",$user_agent)) 
    { 
    	$BName = "Netscape"; $Version="Unknown"; 
    } 
    elseif(preg_match("~(mozilla)/([0-9]{1,2}.[0-9]{1,3})~",$user_agent,$match)) 
    { 
    	$BName = "Netscape "; $Version=$match[2]; 
    } 
    elseif(preg_match("~w3m~",$user_agent)) 
    { 
    	$BName = "W3M"; $Version="Unknown"; 
    } 
    else{$BName = "Unknown"; $Version="Unknown";} 
     
    //--- Detekce SystĂŠmu ------------------------------------------------
    if((preg_match("~Windows XP~",$user_agent)) 
      || (preg_match("(Windows NT 5.1)",$user_agent,$match))) 
    { 
    	$Platform = "Windows_XP"; 
    } 
    elseif(preg_match("win16",$user_agent)) 
    { 
    	$Platform = "Windows_3.11"; 
    } 
    elseif((preg_match("(Windows 2000)",$user_agent,$match)) 
    	|| (preg_match("(Windows NT 5.0)",$user_agent,$match))) 
    { 
    	$Platform = "Windows_2000";
    } 
    elseif(preg_match("(Windows NT 5.2)|(windows 2003)",$user_agent)) 
    { 
    	$Platform = "Windows_Server_2003"; 
    } 
    elseif(preg_match("(Windows NT 6.0)|(Windows Vista)",$user_agent)) 
    { 
    	$Platform = "Windows_Vista"; 
    } 
    elseif((preg_match("(Windows NT 7.0)",$user_agent)) 
        || (preg_match("(Windows NT 6.1)",$user_agent,$match))) 
    { 
    	$Platform = "Windows_7"; 
    } 
    elseif(preg_match("Windows.ME",$user_agent)) 
    { 
    	$Platform = "Windows_ME"; 
    } 
    elseif(preg_match("windows.ce",$user_agent)) 
    { 
    	$Platform = "Windows_CE"; 
    } 
    elseif(preg_match("win32",$user_agent)) 
    { 
    	$Platform = "Windows"; 
    } 
    elseif((preg_match("(win)([0-9]{4})",$user_agent,$match)) 
    	|| (preg_match("(windows) ([0-9]{4})",$user_agent,$match))) 
    { 
    	$Platform = "Windows $match[2]";
    } 
    elseif((preg_match("(win)([0-9]{2})",$user_agent,$match)) 
    	|| (preg_match("(windows) ([0-9]{2})",$user_agent,$match))) 
    { 
    	$Platform = "Windows $match[2]"; 
    } 
    elseif(preg_match("(winnt)([0-9]{1,2}.[0-9]{1,2}){0,1}",$user_agent,$match)) 
    { 
    	$Platform = "Windows_NT $match[2]"; 
    } 
    elseif(preg_match("(windows nt)( ){0,1}([0-9]{1,2}.[0-9]{1,2}){0,1}",$user_agent,$match)) 
    { 
    	$Platform = "Windows_NT $match[3]"; 
    } 
    elseif(preg_match("(sunos) ([0-9]{1,2}.[0-9]{1,2}){0,1}",$user_agent,$match)) 
    { 
    	$Platform = "SunOS $match[2]"; 
    } 
    elseif(preg_match("(beos) r([0-9]{1,2}.[0-9]{1,2}){0,1}",$user_agent,$match)) 
    { 
    	$Platform = "BeOS $match[2]"; 
    } 
    elseif(preg_match("(CentOS)/([0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2})",$user_agent)) 
    { 
    	$Platform = "CentOS"; 
    } 
    elseif(preg_match("freebsd",$user_agent)) 
    { 
    	$Platform = "FreeBSD"; 
    } 
    elseif(preg_match("(Fedora)/([0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2})",$user_agent,$match)) 
    { 
    	$Platform = "Fedora $match[2]"; 
    } 
    elseif(preg_match("hp-ux",$user_agent)) 
    { 
    	$Platform = "HP-Unix"; 
    } 
    elseif(preg_match("(iPhone OS)",$user_agent)) 
    { 
    	$Platform = "iPhone_OS"; 
    } 
    elseif(preg_match("irix",$user_agent)) 
    { 
    	$Platform = "IRIX"; 
    } 
    elseif(preg_match("netbsd",$user_agent)) 
    { 
    	$Platform = "NetBSD"; 
    } 
    elseif(preg_match("(Mandriva)/([0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2})",$user_agent)) 
    { 
    	$Platform = "Mandriva"; 
    } 
    elseif(preg_match("openbsd",$user_agent)) 
    { 
    	$Platform = "OpenBSD"; 
    } 
    elseif(preg_match("osf",$user_agent)) 
    { 
    	$Platform = "OSF"; 
    } 
    elseif(preg_match("os/2",$user_agent)) 
    { 
    	$Platform = "OS/2"; 
    } 
    elseif(preg_match("plan9",$user_agent)) 
    { 
    	$Platform = "Plan9"; 
    } 
    elseif(preg_match("(Red Hat)/([0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2})",$user_agent,$match)) 
    { 
    	$Platform = "Red_Hat"; 
    } 
    elseif(preg_match("(SUSE)/([0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2})",$user_agent)) 
    { 
    	$Platform = "SUSE_Linux"; 
    } 
    elseif(preg_match("sunos",$user_agent)) 
    { 
    	$Platform = "SunOS"; 
    } 
    elseif(preg_match("symbian",$user_agent)) 
    { 
    	$Platform = "Symbian_OS"; 
    } 
    elseif(preg_match("ubuntu",$user_agent)) 
    { 
    	$Platform = "Ubuntu_Linux"; 
    } 
    elseif(preg_match("(debian)",$user_agent)) 
    { 
    	$Platform = "Debian_Linux"; 
    } 
    elseif(preg_match("unix",$user_agent)) 
    { 
    	$Platform = "Unix"; 
    } 
    elseif(preg_match("linux",$user_agent)) 
    { 
    	$Platform = "Linux"; 
    } 
    elseif(preg_match("(Mac_PowerPC)|(Mac_PPC)|(Macintosh)|(Mac_68000)|(Mac OS X)",$user_agent)) 
    { 
    	$Platform = "Mac_OS"; 
    } 
    else 
    {
      $Platform = "Unknown";
    } 
    
    }
}
 ?>