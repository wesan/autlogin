<?php
/**
 * Automatic login - interface for admins
 *
 * @author Ondrej Machac <omachac@seznam.cz>
 */



if(!defined('DOKU_INC')) die();

if(!defined('DOKU_PLUGIN')) define('DOKU_PLUGIN',DOKU_INC.'lib/plugins/');
require_once(DOKU_PLUGIN.'admin.php');

/**
 * All DokuWiki plugins to extend the admin function
 * need to inherit from this class
 */
class admin_plugin_autlogin extends DokuWiki_Admin_Plugin {


   var $visitors = null; //from visit.php
   var $acl = null; //from transl.php
   var $rule = null; //from acl.auth.php
   var $kolo;
   var $ns;
   var $current_item = null;
   var $passw = "autlogin";
/**
   * return some info
   */
  function getInfo()
   {
    return array(
      'author' => 'Ondrej Machac',
      'email'  => 'omachac@seznam.cz',
      'date'   => '2011-03-01',
      'name'   => 'Automatic login',
      'desc'   => 'Automatic login for host, who meets some criterion of performance.',
      'url'    => 'http://cloud.github.com/downloads/wesan/autlogin.tgz',
    );
   }
  
    /**
     * return prompt for admin menu
     */
    function getMenuText($language) 
     {
         return 'Automatic login';
     }

    /**
     * return sort order for position in admin menu
     */
    function getMenuSort() 
     {
        return 140;
     }
     
    function forAdminOnly() {
          return false;
      }


  /**
     * handle user request
     *
     * Initializes internal vars and handles modifications

     */

   function handle() 
    {
    global $auth;
    global $username;


// namespace given?
        if($_REQUEST['ns'] == '*'){
            $this->ns = '*';
        }else{
            $this->ns = cleanID($_REQUEST['ns']);
        }

        if ($_REQUEST['current_ns']) {
            $this->current_item = array('id' => cleanID($_REQUEST['current_ns']), 'type' => 'd');
        } elseif ($_REQUEST['current_id']) {
            $this->current_item = array('id' => cleanID($_REQUEST['current_id']), 'type' => 'f');
        } elseif ($this->ns) {
            $this->current_item = array('id' => $this->ns, 'type' => 'd');
        } else {
            $this->current_item = array('id' => $ID, 'type' => 'f');
        }


     if(isset($_REQUEST['cmd']) && checkSecurityToken()){
       
        if(isset($_REQUEST['cmd']['visit'])) //if some host from visit.php was chosen 
         {
           $who = $_REQUEST['select_visit']; //who host was chosen
           
           if(isset($_REQUEST['radioselect']))  //finds out perm
           {
              $perm = $_REQUEST['radioselect'];
              $coun = 0;
               if(isset($_REQUEST['check1'])){  //finds out criteria  
                 $coun++;
                 $IP = $_REQUEST['check1'];            
               }
               if(isset($_REQUEST['check2'])) {
                 $coun++;  
                 $WB = $_REQUEST['check2']; 
                 }                 
               if(isset($_REQUEST['check3'])) {
                  $coun++;                
                 $VERSION = $_REQUEST['check3'];
                 }                  
               if(isset($_REQUEST['check4']))   {
                 $coun++;
                 $EP = $_REQUEST['check4'];   
                 }               
               if(isset($_REQUEST['check5'])) {
                 $coun++;  
                 $OS = $_REQUEST['check5'];   
                 }
               if(!empty($_REQUEST['username'])){  
                 $username=$_REQUEST['username'];
                
              }     
                 
               if($coun != 0) // only if some item in criterai was chosen   
               $this->_save_user($who, $perm, $IP, $WB, $VERSION, $EP, $OS);
               
           } 
         }
         
       $r=0; 
      if(isset($_REQUEST['cmd']['update'])) //if some rule was update
      {
       if(isset($_REQUEST['del'])){
        foreach((array)$_REQUEST['del'] as $stranka1 => $n1)
           foreach($n1 as $alias1){
          // remove all rules marked for deletion
           $this->del_acl($alias1,$stranka1);//delete rule from acl.auth.php
         }
       

        $this->get_perm(); //read transl.php
        $this->_actaulize(); //actualize it
        $this->get_perm();  //read actual transl.php  
             //check if was change some number of perm
       }
       
       $this->get_acl(); //read acl.auth.php
       $AUTH_ACL = file(DOKU_CONF.'acl.auth.php'); 
       foreach($AUTH_ACL as $line){
             if($line{0} == '#'){
                 $lines[] = $line;
             }else{
                 break;
             }      
       } 
      $save = join('\n',$lines);
      if(!empty($this->rule))  
       {     
       foreach($this->rule as $page => $n1)
         foreach ($n1 as $alias => $cislo) 
            {
               $visit = substr($alias,0,1);
               if($visit != '@'){ //only users, not groups
               $perm = $_REQUEST[$alias.$page];
               $user = auth_nameencode($alias);
               $info = $auth->getUserData($user);
               if($info === false){
                     $exist = false;
               }else{
                    $groups = $info['grps'];
                    $exist = true;
            } 
               if((auth_aclcheck($page,$alias,$groups)) != $perm){//if number was change
                  $this->del_acl($alias,$page);//delete rule from acl.auth.php
                  $this->add_acl($page,$alias,$perm);//add rule whit new number perm
              } 
           }
           }
       }
      
       
     }
     
      if(isset($_REQUEST['cmd']['manual'])) //if some host was add manually  
       {
          $line=array();
          $flag = 0;
          $counter = 0;
          $perm = $_REQUEST['manualmanual'];

          if(!empty($_REQUEST['id']))
           $stranka = $_REQUEST['id'];
          elseif(!empty($_REQUEST['ns']))
           $stranka = $_REQUEST['ns'].":*";
         
          if($stranka == "*:*")
           $stranka = "*";
      //choose a page and perm is more then EDIT? max right is EDIT
           if(substr($stranka,strlen($stranka)-1,1) != '*' && $perm > AUTH_EDIT)
            $perm = AUTH_EDIT;
          //save criterions
          if(!empty($_REQUEST['ip_address'])){ 
              if($this->control_ip($_REQUEST['ip_address']) == 1){   
                 $lines[]="IP=".$_REQUEST['ip_address'];
                 $counter++;
              }
              else $flag=1;
          }
          if(!empty($_REQUEST['browser'])){ 
          
                 $lines[]="WB=".$_REQUEST['browser'];
                 $counter++;
              }
          
          if(!empty($_REQUEST['version'])){ 
                 $lines[]="VER=".$_REQUEST['version'];
                 $counter++;
             }

          if(!empty($_REQUEST['e_page'])){ 
              if($this->control_page($_REQUEST['e_page'])){
                 $lines[]="EP=".$_REQUEST['e_page'];
                 $counter++;
             }
              else $flag=1;
          }
          if(!empty($_REQUEST['os'])){  
                 $lines[]="OS=".$_REQUEST['os'];
                 $counter++;
              }
              
          if(!empty($_REQUEST['username'])){  
                 $username=$_REQUEST['username'];
                
              }    
           
          

          if($flag == 0 && $counter > 0){
              $line = join(',',$lines);
              $this->save($stranka, $line, $perm);//save user
          }            
           
       }
      
      
     if(isset($_REQUEST['cmd']['moderator'])) //set moderator
      {
         $same = false;
         $save='';
         $user=$_REQUEST['select_user'];
         if(!empty($_REQUEST['id']))
           $page = $_REQUEST['id'];
          elseif(!empty($_REQUEST['ns']))
           $page = $_REQUEST['ns'].":*";
         if($page == "*:*")
           $page = "*";
           
         $moderators = file(DOKU_PLUGIN.'/autlogin/settings/moderators.php');
         
         foreach($moderators as $line){
            $unit = preg_split('/\s+/',$line); 
            if($unit[0]==$user && $unit[1]==$page)
              $same = true;   //already exist
          }
         if($same == false){ //only if dont exist the same line
            $moderators = file_get_contents(DOKU_PLUGIN.'/autlogin/settings/moderators.php');
            $save = "$user\t$page\n";
            $moderators.= $save;
            io_saveFile(DOKU_PLUGIN.'/autlogin/settings/moderators.php', $moderators);    
            $this->add_group($user); //add group 'moderator' to $user
         }
      }
      
      
       if(isset($_REQUEST['cmd']['update_mod'])) //if some moderators was update
        {
         if(isset($_REQUEST['del_m'])){
         
          foreach((array)$_REQUEST['del_m'] as $stranka1 => $n1)
             foreach($n1 as $alias1){
            // remove all rules marked for deletion
                $acl_config = file(DOKU_PLUGIN.'/autlogin/settings/moderators.php');
                $acl_user = auth_nameencode($alias1,true);
        
                $acl_pattern = '^'.$acl_user.'\s+'.preg_quote($stranka1,'/').'*$';
        
                // save all non!-matching
                $new_config = preg_grep("/$acl_pattern/", $acl_config, PREG_GREP_INVERT);
        
                io_saveFile(DOKU_PLUGIN.'/autlogin/settings/moderators.php', join('',$new_config));  
                
                $acl_config= file_get_contents(DOKU_PLUGIN.'/autlogin/settings/moderators.php');
                $pozice = StrPos($acl_config, $alias1);
                if($pozice === false)//no moderator rule set
                 $this->del_group($alias1); //remove group moderator
              }
            }
       
       
         }
         
        if(isset($_REQUEST['cmd']['set_mod'])) //set rights
         {   
              $page = $_REQUEST['select_mod_page'];
              $alias =$_REQUEST['select_user'];
              $perm = $_REQUEST['manualmanual'];  
              $number = -1;      
              $save='';
                    
              if(substr($page,strlen($page)-1,1) != '*' && $perm > AUTH_EDIT)
               $perm = AUTH_EDIT;    
 
              $this->get_perm(); //read transl.php
              //exist the same rule?
              if(!empty($this->acl))  
               {     
               foreach($this->acl as $stranka => $n1)
                 foreach ($n1 as $kriterium => $n2) 
                  foreach ($n2 as $jmeno => $cislo) 
                  {
                  
                    if($stranka == $page && $alias == $jmeno){ //actualize number
                      $save.= "$stranka\t$kriterium\t$jmeno\t$perm\n";
                      $number = 0;
                    }
                    else
                      $save.= "$stranka\t$kriterium\t$jmeno\t$cislo\n";
                  }
               
               }  
             io_saveFile(DOKU_PLUGIN.'/autlogin/settings/transl.php',$save);
             
             if ($number == 0){ //same rule only different perm number
                 $this->del_acl($alias,$page);//delete rule from acl.auth.php
                 $this->add_acl($page,$alias,$perm);//add rule whit new number perm
             }
             elseif($number == -1)//new rule
                 $visit = $this->_find_visit($alias);
                 if(!$visit)
                  $noexist = 1;
                 $new = "$page\t$visit\t$alias\t$perm\n";
                 $ACTUAL_ACL = file_get_contents(DOKU_PLUGIN.'/autlogin/settings/transl.php');
                 $ACTUAL_ACL.= $new;
                 io_saveFile(DOKU_PLUGIN.'/autlogin/settings/transl.php',$ACTUAL_ACL); 
                 $this->add_acl($page,$alias,$perm);//add rule whit new number perm
        
        if($noexist){//add new rule for user, who is not a member of autlogin group
           $this->del_acl($alias,$page);//delete rule from acl.auth.php
           $this->add_acl($page,$alias,$perm);//add rule whit new number perm
        
        }
        
        
        }
           

         
     }
    
    
     $this->get_visit();
     $this->get_perm(); //read transl.php
     $this->_actaulize(); //actualize it
     $this->get_perm();  //read actual transl.php
     $this->clear_users();//remove all users, who are registered in users.auth.php but are not use in transl.php
 
 }
   
   function html()
    {
    global $ID;
    global $conf;
    global $USERINFO;

 
              echo '<div id="auth_manager">'.NL;  // 1

              
       if(auth_isadmin())  {

 
              echo '<h1>'.$this->getLang('admin_auth').'</h1>'.NL;
              echo '<a name="ZALOZKY">'.$this->getLang('select_page').'</a>';
              echo '<br>';              
              echo '<div id="acl__tree">'.NL; 
              $this->_html_explorer();
              echo '</div>';
              echo '<fieldset style="width: 100%; text-align: left">';
              echo '<legend>'.$this->getLang('from_visit').'</legend>';
              
              echo '<div id="auth1__detail">'.NL;
              $this->_select();
              echo '</div>'.NL;
              echo '</fieldset>';
              echo '<br><br>';
              echo '<fieldset style="width: 100%; text-align: left">';
              echo '<legend>'.$this->getLang('from_manual').'</legend>';   

              echo '<div id="auth2__detail">'.NL;
              $this->_manual_acl();
              echo '</div>'.NL;
              echo '</fieldset>';
    
              echo '<br><br>';
              echo '<fieldset style="width: 100%; text-align: left">';
              echo '<legend>'.$this->getLang('from_table').'</legend>';
              echo '<div id="auth__table">'.NL;

              $data = $this->_get_all_pages();
              $count = count($data);
              
              if($count>0) for($i=0; $i<$count; $i++){
              $pages[]=$data[$i]['id'];
              }
              $this->_table($pages); 
              echo '</div>'.NL;
              echo '</fieldset>';   
              
              echo '<br><br>';
              echo '<fieldset style="width: 100%; text-align: left">';
              echo '<legend>'.$this->getLang('from_manage').'</legend>';
              echo '<div id="auth3__detail">'.NL;
              $this->_manage();
              echo '</div>'.NL; 
              
              echo '<br><br>';
              $this->_table_moderator(); 
              echo '</fieldset>';   
                            
      }
       if(auth_ismanager()){
              echo '<h1>'.$this->getLang('moderator_auth').'</h1>'.NL;
              echo '<fieldset style="width: 100%; text-align: left"">';
              echo '<legend>'.$this->getLang('mod_menu').'</legend>';
              $this->_set_moderator(); 
              echo '</fieldset>';
              
 
              echo '<br><br>';
              echo '<fieldset style="width: 100%; text-align: left">';
              echo '<legend>'.$this->getLang('mod_table').'</legend>';
              echo '<div id="mod__set">'.NL;
              $user = $_SERVER['REMOTE_USER'];
              $data = $this->_get_pages($user); 
              $datas= $this->_parse_ns($data);
              $this->_table($datas); 
              echo '</div>'.NL;
              echo '</fieldset>';
       }
       if(auth_isadmin())  {
              echo '<div class="footnotes"><div class="fn">'.NL;
              echo '<sup><a id="fn__1" class="fn_bot" name="fn__1" href="#fnt__1">1)</a></sup>'.NL;
              echo $this->getLang('p_include');
              echo '</div>';
              echo '<div class="fn">'.NL;              
              echo '<sup><a id="fn__2" class="fn_bot" name="fn__2" href="#fnt__2">2)</a></sup>'.NL;
              echo $this->getLang('max_right');
              echo '</div></div>';

      }
              echo '</div>'.NL; // 1

    }
   
  
  
    /**
     * Print a visitor's selector 
     */
 function _select()
   {
        global $ID;
        

      echo '<form action="'.wl().'" method="post" accept-charset="utf-8"><div class="no">'.NL;
      echo '<div id="auth__select">';      
      echo '<select name="select_visit" class="edit">'.NL; 
     
        foreach($this->visitors as $datum => $n1)
          foreach($n1 as $stranka => $kriteria)
          {
               $kriteria = rawurldecode($kriteria);
               echo '  <option value="'.$datum.'">'.$datum." &lt ".$stranka." &gt  ".$kriteria.'</option>'.NL;
          }
       
        echo '</select>'.NL;
        echo '<br><br>';        
        //enter alias
        echo $this->getLang('username').'<sup><a id="fnt__1" class="fn_top" name="fnt__1" href="#fn__1">1)</a></sup>';                
        echo '<input type="text" name="username" size="20"></input>&nbsp;';
        echo '<br><br>';
         
        echo $this->_kriterium();
        echo '<br><br>';
        echo $this->getLang('right');
        echo $this->_radio('','radio','select');
        echo '<br><br>';       
        echo '<input type="submit" value="'.$this->getLang('btn_select').'" name="cmd[visit]" class="button" />';  
        echo '</div>'.NL;
        
        echo '<input type="hidden" name="ns" value="'.hsc($this->ns).'" />'.NL;
        echo '<input type="hidden" name="id" value="'.hsc($ID).'" />'.NL;
        echo '<input type="hidden" name="do" value="admin" />'.NL;
        echo '<input type="hidden" name="page" value="autlogin" />'.NL;
        echo '<input type="hidden" name="sectok" value="'.getSecurityToken().'" />'.NL;      
         echo '</div></form>'.NL;
        
   }   
  
  
  //its possible set rights manually
  function _manual_acl()
   {
        global $ID;
        global $conf;
        
        echo '<form action="'.wl().'" method="post" accept-charset="utf-8"><div class="no">'.NL;
        echo '<div id="auth__manual">';
        
        //enter alias
        echo $this->getLang('username').'<sup><a id="fnt__1" class="fn_top" name="fnt__1" href="#fn__1">1)</a></sup>';                 
        echo '<input type="text" name="username" size="20"></input>&nbsp;';
 
        echo '<a href="#ZALOZKY">'.$this->getLang('help_page').'</a>';
 
        //enter IP adress    
        echo '<br><br>';
        echo $this->getLang('set_ip');
        echo '<input type="text" name="ip_address" size="20"></input>&nbsp;';
                
        // display select for choose web browsers (from browsers.php)
        $webs = $this->load_browser(); 
        echo $this->getLang('set_browser');        
        echo '<select name="browser" class="edit">'.NL;
        echo '  <option value=""></option>'.NL; //empty row        
        $count = count($webs); 
        if($count>0) for($i=0; $i<$count; $i++){
         echo '  <option value="'.$webs[$i].'">'.$webs[$i].'</option>'.NL;
         }
        echo '</select>'.NL;
        
        //enter verion
        echo $this->getLang('set_version');                
        echo '<input type="text" name="version" size="20"></input>&nbsp;';
        echo '<br><br>';        
        echo $this->getLang('set_page');        
        echo '<input type="text" name="e_page" size="30"></input>&nbsp;';    
     
        
        //select for choose the operation system (from systems.php)
        $systems = $this->load_system(); 
        echo $this->getLang('set_os');        
        echo '<select name="os" class="edit">'.NL;
        echo '  <option value=""></option>'.NL;      //first empty row  
        $count = count($systems); 
        if($count>0) for($i=0; $i<$count; $i++){
         echo '  <option value="'.$systems[$i].'">'.$systems[$i].'</option>'.NL;
         }
        echo '</select>'.NL;  
        
        echo '<br><br>';
        echo $this->getLang('right').'<sup><a id="fnt__2" class="fn_top" name="fnt__2" href="#fn__2">2)</a></sup>';
        echo $this->_radio('','manual','manual'); //number of permission
        echo '<br><br>';
        echo '</div>'.NL;
        echo '<input type="submit" value="'.$this->getLang('btn_select').'" name="cmd[manual]" class="button" />';
        echo '<input type="hidden" name="ns" value="'.hsc($this->ns).'" />'.NL;
        echo '<input type="hidden" name="id" value="'.hsc($ID).'" />'.NL;
        echo '<input type="hidden" name="do" value="admin" />'.NL;
        echo '<input type="hidden" name="page" value="autlogin" />'.NL;
        echo '<input type="hidden" name="sectok" value="'.getSecurityToken().'" />'.NL;      
        
        echo '</div></form>'.NL;   
   }
   
  
  
  //this function write to table exist rules
  function _table($data)
   {
   
        global $ID;
        
        $this->get_perm();
        $this->_actaulize(); //actualize it
        $this->get_perm();  //read actual transl.php
        
        echo '<form action="'.wl().'" method="post" accept-charset="utf-8"><div class="no">'.NL;
        echo '<input type="hidden" name="ns" value="'.hsc($this->ns).'" />'.NL;
        echo '<input type="hidden" name="id" value="'.$ID.'" />'.NL;
        echo '<input type="hidden" name="do" value="admin" />'.NL;
        echo '<input type="hidden" name="page" value="autlogin" />'.NL;
        echo '<input type="hidden" name="sectok" value="'.getSecurityToken().'" />'.NL;   
        echo '<table class="inline">';
        echo '<tr>';
        echo '<th>'.$this->getLang('where').'</th>';
        echo '<th>'.$this->getLang('who').'</th>';
        echo '<th>'.$this->getLang('kriteria').'</th>';
        echo '<th>'.$this->getLang('perm').'</th>';
        echo '<th>'.$this->getLang('delete').'</th>';
        echo '</tr>';
        $this->get_acl();
         if(!empty($this->rule))
         {
          foreach($this->rule as $stranka => $n1)
            foreach ($n1 as $alias => $cislo) 
            if(substr($alias,0,1) != "@"){

            {
             if(in_array($stranka,$data)){
              $kriterium = $this->_find_visit($alias);
               $kriterium = rawurldecode($kriterium);
                echo '<tr>';
                echo '<td>';
                echo '<span class="aclns">'.$stranka.'</span>';
                echo '</td>';
                echo '<td>';
                echo '<span class="aclns">'.$alias.'</span>';
                echo '</td>';
                echo '<td>';
                if($kriterium)
                echo '<span class="aclns">'.$kriterium.'</span>';
                else
                echo '<span class="aclns">'.$this->getLang('novisit').'</span>';
                echo '</td>';               
                echo '<td>';
                echo $this->_radio($cislo,$alias,$stranka);
                echo '</td>';

                echo '<td align="center">';
                echo '<input type="checkbox" name="del['.$stranka.'][]" value="'.$alias.'" />';
                echo '</td>';
                echo '</tr>';
                
            }
           } 
          }}

        echo '<tr>';
        echo '<th align="right" colspan="4">';
        echo '<input type="submit" value="'.$this->getLang('update').'" name="cmd[update]" class="button" />';
        echo '</th>';
        echo '</tr>';
        echo '</table>';
        echo '</div></form>'.NL;   
   
   }
   
   //print moderators
   function _table_moderator()
    {
        global $ID;
        
        
        echo '<form action="'.wl().'" method="post" accept-charset="utf-8"><div class="no">'.NL;
        echo '<input type="hidden" name="ns" value="'.hsc($this->ns).'" />'.NL;
        echo '<input type="hidden" name="id" value="'.$ID.'" />'.NL;
        echo '<input type="hidden" name="do" value="admin" />'.NL;
        echo '<input type="hidden" name="page" value="autlogin" />'.NL;
        echo '<input type="hidden" name="sectok" value="'.getSecurityToken().'" />'.NL;   
        echo '<table class="inline">';
        echo '<tr>';
        echo '<th>'.$this->getLang('where').'</th>';
        echo '<th>'.$this->getLang('who_m').'</th>';
        echo '<th>'.$this->getLang('delete').'</th>';
        echo '</tr>';
         $actual_moderator = file(DOKU_PLUGIN.'/autlogin/settings/moderators.php');
        foreach($actual_moderator as $line)
         {
             $user = preg_split('/\s+/',$line);
             $stranka = $user[1];
             $alias = $user[0];
            
                echo '<tr>';
                echo '<td>';
                echo '<span class="aclns">'.$stranka.'</span>';
                echo '</td>';
                echo '<td>';
                echo '<span class="aclns">'.$alias.'</span>';
                echo '</td>';

                echo '<td align="center">';
                echo '<input type="checkbox" name="del_m['.$stranka.'][]" value="'.$alias.'" />';
                echo '</td>';
                echo '</tr>';
            }
          

        echo '<tr>';
        echo '<th align="right" colspan="4">';
        echo '<input type="submit" value="'.$this->getLang('update').'" name="cmd[update_mod]" class="button" />';
        echo '</th>';
        echo '</tr>';
        echo '</table>';
        echo '</div></form>'.NL;      
    
    }
   
   //set moderators
   function _manage()
    {
      global $ID;
        
        echo '<form action="'.wl().'" method="post" accept-charset="utf-8"><div class="no">'.NL;

        $user = $this->get_users(); //load all users and display them
        $count = count($user);
        echo $this->getLang('s_user');
        echo '<select name="select_user" class="edit">'.NL;
        if($count>0) for($i=0; $i<$count; $i++){
         echo '  <option value="'.$user[$i].'">'.$user[$i].'</option>'.NL;
         }
        echo '</select>'.NL;
        
        echo '<a href="#ZALOZKY">'.$this->getLang('help_page').'</a>&nbsp;';

        echo '<input type="submit" value="'.$this->getLang('btn_select').'" name="cmd[moderator]" class="button" />';   
        echo '<input type="hidden" name="ns" value="'.hsc($this->ns).'" />'.NL;
        echo '<input type="hidden" name="id" value="'.hsc($ID).'" />'.NL;
        echo '<input type="hidden" name="do" value="admin" />'.NL;
        echo '<input type="hidden" name="page" value="autlogin" />'.NL;
        echo '<input type="hidden" name="sectok" value="'.getSecurityToken().'" />'.NL;
        echo '</div></form>'.NL;
  }
  
  
  //print set rights, bud only for some page
  function _set_moderator()
   {

        echo '<form action="'.wl().'" method="post" accept-charset="utf-8"><div class="no">'.NL;
        echo '<div id="auth__set_mod">';
        $user = $_SERVER['REMOTE_USER'];
        $data = $this->_get_pages($user);

        
        $pages=$this->_parse_ns($data);


        $count = count($pages);           

        echo $this->getLang('s_page');
        echo '<select name="select_mod_page" class="edit">'.NL;
        if($count>0) for($i=0; $i<$count; $i++){
         echo '  <option value="'.$pages[$i].'">'.$pages[$i].'</option>'.NL;
         }
        echo '</select>'.NL;
   
        $user = $this->get_users(); //load all users and display them
        $count = count($user);
        echo $this->getLang('mod_user');
        echo '<select name="select_user" class="edit">'.NL;
        if($count>0) for($i=0; $i<$count; $i++){
         echo '  <option value="'.$user[$i].'">'.$user[$i].'</option>'.NL;
         }
        echo '</select>'.NL;
        
        echo $this->getLang('right').'<sup><a id="fnt__2" class="fn_top" name="fnt__2" href="#fn__2">2)</a></sup>';
        echo $this->_radio('','manual','manual'); //number of permission
        

        echo '<input type="submit" value="'.$this->getLang('btn_select').'" name="cmd[set_mod]" class="button" />';   
        echo '</div>'.NL;   
        echo '<input type="hidden" name="ns" value="'.hsc($this->ns).'" />'.NL;  
        echo '<input type="hidden" name="id" value="'.$ID.'" />'.NL;
        echo '<input type="hidden" name="do" value="admin" />'.NL;
        echo '<input type="hidden" name="page" value="autlogin" />'.NL;
        echo '<input type="hidden" name="sectok" value="'.getSecurityToken().'" />'.NL;      
        echo '</div></form>'.NL;  
   }
  
  
  
   
   function _radio($cislo,$jmeno,$stranka)
    {
     
     static $label = 0; //number labels
     $ret = '';
        foreach(array(AUTH_NONE,AUTH_READ,AUTH_EDIT,AUTH_CREATE,AUTH_UPLOAD,AUTH_DELETE) as $perm){
            $label += 1;

            //general checkbox attributes
            $atts = array( 'type'  => 'radio',
                           'id'    => 'pbox'.$label,
                           'name'  => $jmeno.$stranka,
                           'value' => $perm );
    
            if($cislo == $perm) $atts['checked']  = 'checked';
            if((substr($stranka,strlen($stranka)-1,1) != '*' && $perm > AUTH_EDIT) || ($stranka == 'select' && $perm > AUTH_EDIT))
             $atts['disabled'] = 'disabled';
            if($stranka == 'manual')
             unset($atts['disabled']);
            //build code
            $ret .= '<label for="pbox'.$label.'" title="'.$this->getLang('acl_perm'.$perm).'">';
            $ret .= '<input '.html_attbuild($atts).' />&nbsp;';
            $ret .= $this->getLang('acl_perm'.$perm);
            $ret .= '</label>'.NL;
        }    
        return $ret;
    }
    
    
    
   
  function _kriterium()
   {
   
   static $label = 0; //number labels
     $ret = '';
      foreach(array(IP, BROWSER, VERSION, ENTRY_PAGE, OS) as $type){
            $label += 1;
      
            //general checkbox attributes
            $atts = array( 'type'  => 'checkbox',
                           'id'    => 'chbox'.$label,
                           'name'  => 'check'.$label,
                           'value' => $type );
           
            if($cislo == $type) $atts['checked']  = 'checked';
            //build code
            $ret .= '<label for="chbox'.$label.'" title="'.$this->getLang($type).'">';
            $ret .= '<input '.html_attbuild($atts).' />&nbsp;';
            $ret .= $this->getLang($type);
            $ret .= '</label>'.NL;
        }  
       return $ret;  
   
   }
   
   
   
   
 /* 
 $who .... what host will by save
 $perm ... number of permission
 $ip ... ip address
 $wb ... web browser
 $version .. version of wb
 $ep ... entry page
 $os ... operating system
 */   
   
  function _save_user($who, $perm, $IP, $WB, $VERSION, $EP, $OS)
    {
     
     
      $this->get_visit();
      
      //now find the right host
      foreach($this->visitors as $datum => $n1)
       foreach($n1 as $page1 => $criteria)
        {
         if ($who == $datum)
          {
           $kriterium = $criteria;
           $stranka = $page1;
          }  
        }
        
        $rules = preg_split('/,/',$kriterium);
          
        if(isset($IP)) //if is set IP addres
         {
           foreach($rules as $now)  //parse concrete ip
            if(preg_match("(IP=)",$now))
              {
              $concr_ip = $now ;    //save concrete ip
              }
         }
         
         
         if(isset($WB))
          {
            foreach($rules as $now)
             if(preg_match("(WB=)",$now))
              {
              $concr_wb = $now;    //save concrete WB
              }
          } 
          
        if(isset($VERSION)) //if is set IP addres
         {
           foreach($rules as $now)
             if(preg_match("(VER=)",$now))
              {
              $concr_ver = $now;    //save concrete WB
              }
         }
         
        if(isset($EP))
          {
            foreach($rules as $now)
             if(preg_match("(EP=)",$now))
              {
              $concr_ep = $now ;    //save concrete WB
              }
          }
          
         if(isset($OS))
          {
            foreach($rules as $now)
             if(preg_match("(OS=)",$now))
              {
              $concr_os = $now;    //save concrete WB
              }
          }
          
          if(!empty($concr_ip))
           $visit.=$concr_ip.",";
          if(!empty($concr_wb))
           $visit.=$concr_wb.",";
          if(!empty($concr_ver))
           $visit.=$concr_ver.","; 
          if(!empty($concr_ep))
           $visit.=$concr_ep.",";
          if(!empty($concr_os))
           $visit.=$concr_os;
          if(empty($concr_os))
           $visit = substr($visit,0,(strlen($visit)-1)); //erase last ","
           
           
          $this->save($stranka,$visit,$perm);
       
           
          

    }
    
  // $stranka = name of page
  // $visit = criteria
  // $perm = number of permission 
 function save($stranka,$visit,$perm)
  {  
     global $auth;
     global $username;
     $already = false; //same criteria, but other page
     $same = false;  //the same rule yet exist

   //already exist same page whit same criteria ??
         $this->get_perm(); //read transl.php
         if(!empty($this->acl)) 
         { 
            foreach($this->acl as $page => $n1)
              foreach ($n1 as $kriterium => $n2) 
               foreach ($n2 as $alias => $cislo)
                 {

                  if(($page == $stranka) && ($kriterium == $visit))  
                  {
                   $same = true;   // already exist?
             
                  }
                  // same sriteria but for different page
                  elseif(($kriterium == $visit) && ($page != $stranka ))
                  {

                   $already = true;
                   $concr_alias = $alias;
                  }
                 } 
    
          }
 

          //new user
          if(($already == false) && ($same == false)) 
           {
             if(isset($username)){
              $crit=$this->_find_visit($username);
              if($crit)
                $username.="2"; 
             }
              
             if(!isset($username)) 
               $concr_alias = $this->rand_alias();
             else
               $concr_alias = $username;
              
             $name = 'plugin autlogin';
             $email = $concr_alias.'@false.cz';
             $grps[] = 'autlogin';
             if (!$auth->canDo('addUser')) return false;
             $auth->triggerUserMod('create', array($concr_alias,$passw,$name,$email,$grps));//cretae new user
          
           }
           
          //if exist the same criteria, but for other page, save as the same alias           
         if($same == false)
           { 
             $save='';
             $save = "$stranka\t$visit\t$concr_alias\t$perm\n";
             $ACTUAL_ACL = file_get_contents(DOKU_PLUGIN.'/autlogin/settings/transl.php');
             $ACTUAL_ACL.= $save;
             io_saveFile(DOKU_PLUGIN.'/autlogin/settings/transl.php',$ACTUAL_ACL); 
             $this->add_acl($stranka,$concr_alias,$perm);
           }
  
  }   
    
    /* 
 ********************************
 *********************************
 *********************************
 */


 //load info from visit.php  
  function get_visit()
   {   
   
   
    $ACT_VISIT = file(DOKU_PLUGIN.'/autlogin/settings/visit.php');
    foreach($ACT_VISIT as $line){
            $line = trim(preg_replace('/#.*$/','',$line)); //ignore comments
            if(!$line) continue;

            $acl = preg_split('/\s+/',$line);
            //0 is page, 1 kriterium, 2 alias, 3 is acl

            //$acl[2] = rawurldecode($acl[2]);
            $acl_config[$acl[0]][$acl[1]] = $acl[2];
        }
        $this->visitors = $acl_config;
    
   
   }
 

     //load actual setttings store in transl.php
  function get_acl()
  {
     $ACTUAL_ACL = file(DOKU_CONF.'acl.auth.php');
     
     
        foreach($ACTUAL_ACL as $line){
            $line = trim(preg_replace('/#.*$/','',$line)); //ignore comments
            if(!$line) continue;

            $acl = preg_split('/\s+/',$line);
            //0 is page, 1 criteria, 2 alias, 3 is acl

            //$acl[1] = rawurldecode($acl[1]);
            $acl_config[$acl[0]][$acl[1]] = $acl[2];
        }
        $this->rule = $acl_config;
 }

 
     //load actual setttings store in transl.php
  function get_perm()
  {
     $ACTUAL_ACL = file(DOKU_PLUGIN.'/autlogin/settings/transl.php');
     
     
        foreach($ACTUAL_ACL as $line){
            $line = trim(preg_replace('/#.*$/','',$line)); //ignore comments
            if(!$line) continue;

            $acl = preg_split('/\s+/',$line);
            //0 is page, 1 criteria, 2 alias, 3 is acl

            //$acl[1] = rawurldecode($acl[1]);
            $acl_config[$acl[0]][$acl[1]][$acl[2]] = $acl[3];
        }
        $this->acl = $acl_config;
 }
 
 

/*This function actualize file transl.php
**if some change was made in acl plugin
**this change must write it to transl.php
*/
 function _actaulize()
  {
      global $conf;
      
         $users = $this->get_users_autlogin();
         
        $data = $this->_get_all_pages();
         $count = count($data);
         if($count>0) for($i=0; $i<$count; $i++){
            $pages[]=$data[$i]['id'];
            }

       $AUTH_ACL = file(DOKU_CONF.'acl.auth.php');

       if($users && $pages){
       foreach($users as $user)
        foreach($pages as $page)
          {
              $matches = preg_grep('/^'.preg_quote($page,'/').'\s+('.$user.')\s+/'.$ci,$AUTH_ACL);
              
              if(count($matches)){
                 foreach($matches as $match){

                     $match = preg_replace('/#.*$/','',$match); //ignore comments
                     $acll   = preg_split('/\s+/',$match);
                     
                     $perm = $acll[2];
                     
                 }
                 if($perm > -1){
                 $visit= $this->_find_visit($user);
                     //we had a match - return it
                $save.= "$page\t$visit\t$user\t$perm\n";
                 }
               }
          
          }

    io_saveFile(DOKU_PLUGIN.'/autlogin/settings/transl.php',$save);  
     }
  }
  
 
 //return all pages and namespaces
 function _get_all_pages()
  {
   global $conf;
        $data = array();
 
           $dir = '';
         $media = array();
         $opts['skipacl'] = 0; // no ACL skipping
         search($data, $conf['datadir'], 'search_allpages', $opts, $dir);
         search($media, $conf['datadir'], 'search_namespaces', $opts, $dir);
         $count = count($media);
         if($count>0) for($i=0; $i<$count; $i++)
            $media[$i]['id']=$media[$i]['id'].":*"; 
         $media[$i+1]['id']="*";
         $data = array_merge($data,$media);
         return $data;
  }
  
  //remove all users, who are registered in users.auth.php but are not use in transl.php
  // and are in authlogin group 
  function clear_users()
   {
   $user_config=array();
   
    $actual_users = file(DOKU_CONF.'users.auth.php');
      
       foreach($actual_users as $line){
            $line = trim(preg_replace('/#.*$/','',$line)); //ignore comments
            if(!$line) continue;

            $user = preg_split('/:/',$line);
            //0 is user, 1 psswr, 2 real name, 3 email, 4 are groups
           
      //store all users when one of group is authlogin 
            $user2 = preg_split('/,/',$user[4]);    
            foreach($user2 as $group)
            if($group == 'autlogin')
            {
              $user_config[] = $user[0];
            }
        }
    
        $this->get_perm;    
         if(!empty($this->acl))  
          { 
           foreach($this->acl as $page => $n1)
            foreach ($n1 as $kriterium => $n2) 
              foreach ($n2 as $alias => $cislo)
               {
               //erase all hosts who are use in transl.php
               if(in_array($alias, $user_config)){  
               
                $count = count($user_config);
                if($count>0) 
                
                for($i=0; $i<$count; $i++){   
                 if($user_config[$i] == $alias)
                  $user_config[$i]= '';
                }  
                  
               }
              }
          }
    //now are in $user_config store all host who ar not active
          
       $new_user = ''; 
         $actual_users = file(DOKU_CONF.'users.auth.php');   
       foreach($actual_users as $line)
       {    
            if(($pozice = SubStr($line,0,1)) == '#')
              $new_user.=$line;
              
            $line = trim(preg_replace('/#.*$/','',$line)); //ignore comments
            if(!$line) continue;

            $user = preg_split('/:/',$line);
            //0 is user, 1 psswr, 2 real name, 3 email, 4 are groups
            if(!in_array($user[0],$user_config))
             $new_user.=$line."\n";
       } 
       //clear not exist moderators
      $new_moderator = ''; 
      $actual_moderator = file(DOKU_PLUGIN.'/autlogin/settings/moderators.php');
      foreach($actual_moderator as $line)
        {
             $user  = preg_split('/\s+/',$line);
             if(!in_array($user[0],$user_config))
               $new_moderator.=$line;
        }
       
      io_saveFile(DOKU_PLUGIN.'/autlogin/settings/moderators.php',$new_moderator);
      io_saveFile(DOKU_CONF.'users.auth.php',$new_user);       
      
          
   }

//add moderator group to user $moderator
 function add_group($moderator)
  {
  
  $flag = 0;
  $actual_users = file(DOKU_CONF.'users.auth.php');   
       foreach($actual_users as $line)
       {    
            if(($pozice = SubStr($line,0,1)) == '#')
              $new_user.=$line;
              
            $line = trim(preg_replace('/#.*$/','',$line)); //ignore comments
            if(!$line) continue;

            $user = preg_split('/:/',$line);
            //0 is user, 1 psswr, 2 real name, 3 email, 4 are groups
            if(($user[0] != $moderator))
             $new_user.=$line."\n";
            else
             {
              $grps = preg_split('/,/',$user[4]);
              foreach($grps as $group)
                if($group == 'moderator')
                 $flag = 1;
              
              if($flag == 0)   
                 $user[4].=',moderator';
              $line=$user[0].":".$user[1].":".$user[2].":".$user[3].":".$user[4];
              $new_user.=$line."\n";
             }
       } 
           io_saveFile(DOKU_CONF.'users.auth.php',$new_user);   
          
   }
   
   
 //delete moderator group  
  function del_group($moderator)
   {
    $flag = 0;
   $actual_users = file(DOKU_CONF.'users.auth.php');   
       foreach($actual_users as $line)
       {    
            if(($pozice = SubStr($line,0,1)) == '#')
              $new_user.=$line;
              
            $line = trim(preg_replace('/#.*$/','',$line)); //ignore comments
            if(!$line) continue;

            $user = preg_split('/:/',$line);
            //0 is user, 1 psswr, 2 real name, 3 email, 4 are groups
            if(($user[0] != $moderator))
             $new_user.=$line."\n";
            else
             {
              $grps = preg_split('/,/',$user[4]);
              foreach($grps as $group)
               {
                $save.=$group;
                if($group != 'moderator'){
                 $groups[]=$group;
                 $flag = 1;
                }
               }

              if($flag == 1)
              $user[4] = join(',',$groups);
              $line=$user[0].":".$user[1].":".$user[2].":".$user[3].":".$user[4];
              $new_user.=$line."\n";
             }
       } 
           io_saveFile(DOKU_CONF.'users.auth.php',$new_user);  
   
   }
  

 // delete user
 function del_acl($acl_user,$acl_scope)
  {
        $acl_config = file(DOKU_CONF.'acl.auth.php');
        $acl_user = auth_nameencode($acl_user,true);

        $acl_pattern = '^'.preg_quote($acl_scope,'/').'\s+'.$acl_user.'\s+[0-8].*$';

        // save all non!-matching
        $new_config = preg_grep("/$acl_pattern/", $acl_config, PREG_GREP_INVERT);

        return io_saveFile(DOKU_CONF.'acl.auth.php', join('',$new_config));  
  
  }
  
  //add new user to acl.auth.php 
  function add_acl($stranka,$concr_alias,$perm)
   {
  
       $acl_config = file_get_contents(DOKU_CONF.'acl.auth.php');
       $save = "$stranka\t$concr_alias\t$perm\n";
       $acl_config.= $save;
       io_saveFile(DOKU_CONF.'acl.auth.php', $acl_config); 
 
 
   }
 
 //return criterias what are $user
 function _find_visit($user)
  {
      $data = 0;
      $this->get_perm();
        
      if(!empty($this->acl))  
      { 
       foreach($this->acl as $page => $n1)
        foreach ($n1 as $kriterium => $n2) 
          foreach ($n2 as $alias => $cislo)
           {
            if($user == trim($alias))
             $data = $kriterium;
           }
       }    
     return $data;
  }
 
 
   
   //load pages who are set on moderators.php and moderator is $user
 function _get_pages($user)
    {
      $ACTUAL_MOD = file(DOKU_PLUGIN.'/autlogin/settings/moderators.php');
     
        foreach($ACTUAL_MOD as $line){

            $mod = preg_split('/\s+/',$line);
            //0 is name, 1 page
            if($mod[0] == $user)
              $data[] = $mod[1];
        }
        if(empty ($data))
         $data[]='';
         
      return $data;
    }
   
   
   //load all users
  function get_users()
   {
        global $conf;
   
         $AUTH_ACL = file(DOKU_CONF.'users.auth.php'); 
         foreach($AUTH_ACL as $line){
                  $line = trim(preg_replace('/#.*$/','',$line)); //ignore comments
                  if(!$line) continue;
      
                  $acl = preg_split('/:/',$line);
                  //0 is username, 1 passw, 2 name,...
      
                  // store non-special users and groups for later selection dialog
                  $ug = $acl[0];
                  $cast_textu = SubStr($ug, 0, 1);
                  if($cast_textu != '@')
                  $usersgroups[] = $ug;
              }
        $result = count($usersgroups);      
        if($result > 0)
        $usersgroups = array_unique($usersgroups);              
    return $usersgroups;
   } 
   
   
  //load users who group is autlogin   
 function get_users_autlogin()
   {
        global $conf;
        global $auth; 
        
   
         $AUTH_ACL = file(DOKU_CONF.'users.auth.php'); 
         foreach($AUTH_ACL as $line){
                  $line = trim(preg_replace('/#.*$/','',$line)); //ignore comments
                  if(!$line) continue;
      
                  $acl = preg_split('/:/',$line);
                  //0 is username, 1 passw, 2 name,...
      
                 $user = auth_nameencode($acl[0]);
                  $info = $auth->getUserData($user);
                  if($info === false){
                          $exist = false;
                      }else{
                         $groups = $info['grps'];
                          $exist = true;
                      }
                  if($exist){
                     foreach($groups as $group)
                     if($group == 'autlogin')
                     {
      
                          // store non-special users and groups for later selection dialog
                          $ug = $acl[0];
                          $cast_textu = SubStr($ug, 0, 1);
                          if($cast_textu != '@')
                          $usersgroups[] = $ug;
                    }
                    }
              }
        $result = count($usersgroups);      
        if($result > 0)
        $usersgroups = array_unique($usersgroups);              
        return $usersgroups;
   } 
   
   
   
  // exist ip? 
  function control_ip($ip)
   {
   $regular = '/^0*([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\.0*([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\.0*([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\.0*([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])$/';
   
   if(preg_match($regular,$ip)) //IPv4
    return 1;
   else {
      $IPV6_REGEX = '/^\s*((([0-9A-Fa-f]{1,4}:){7}(([0-9A-Fa-f]{1,4})|:))|(([0-9A-Fa-f]{1,4}:){6}(:|((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})|(:[0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){0,1}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){0,2}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){0,3}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:)(:[0-9A-Fa-f]{1,4}){0,4}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(:(:[0-9A-Fa-f]{1,4}){0,5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})))(%.+)?\s*$/';
     if(preg_match($IPV6_REGEX,$ip)) //IPv6
       return 1;
       }
   
    return -1;
   } 
  
 //is entry page ok?  
  function control_page($url)
   {
    return (preg_match('$(http|https|ftp)\://([a-zA-Z0-9\.\-]+(\:[a-zA-Z0-9\.&%\$\ -]+)*@)?((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]) \.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25 [0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5] |2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|([a-zA-Z0-9\-]+\ .)*[a-zA-Z0-9\-]+\.[a-zA-Z]{2,4})(\:[0-9]+)?(/[^/][a-zA-Z0-9\.\,\?\'\\ /\+&%\$#\=~_\-@]*)*$', $url));

   } 
   

 //load all possible browsers from browsers.php  
 function load_browser()
  {
     $file = file(DOKU_PLUGIN.'/autlogin/settings/browsers.php');
     foreach($file as $line){
        $line = trim($line);
        $data[] = $line;
        }
       
    return $data;  
  } 
   
 //load all possible OS from systems.php
 function load_system()
  {
     $file = file(DOKU_PLUGIN.'/autlogin/settings/systems.php');
     foreach($file as $line){
        $line = trim($line);
        $data[] = $line;
        }
       
    return $data;  
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
 
 
 //this parse namaspaces and return all namespaces and pages who are in this namespaces
 function _parse_ns($data)
 {
       global $conf;
       
        $pages = array();
        $count = count($data);
        if($count>0) 
        for($i=0; $i<$count; $i++){

         if($data[$i] == '*'){

           $page = $this->_get_all_pages(); 
           $counta = count($page);
           if($counta>0) for($a=0; $a<$counta; $a++)
             $pages[]=$page[$a]['id'];
            
          
         }
              
         elseif(substr($data[$i],strlen($data[$i])-1,1)== '*'){
           $dir = substr($data[$i],0,(strlen($data[$i])-2)); //erase last ":*"
           $flag=$flag+1;
           //$dir = $data[$i];
           //$dir = '';
           $dir  = utf8_encodeFN(str_replace(':','/',$dir));
           $media = array();
           $datas = array();
           $opts['skipacl'] = 0; // no ACL skipping
           search($datas, $conf['datadir'], 'search_allpages', $opts, $dir);
           search($media, $conf['datadir'], 'search_namespaces', $opts, $dir);
           
           $countq = count($media);
           if($countq>0) for($q=0; $q<$countq; $q++)
              $pages[]=$media[$q]['id'].":*"; 
           //$datas = array_merge($datas,$media);
           $countr = count($datas);
           if($countr>0) for($e=0; $e<$countr; $e++)
              $pages[]=$datas[$e]['id'];
            
 
           unset($datas);
           unset($media);
          }
         
         else{
          $flag=$flag+1;
          $pages[]=$data[$i];
          }

       }
        $pages = array_merge($pages,$data);
        $pages = array_unique($pages);
        usort($pages,array($this,'_tree_sort'));
        
  return $pages;
 }  
   
   
 //return random alias
 function rand_alias()
  {
      $letter = 'abcdefghijklmnopqrstuvwxyz'; // possible letters
    
       $str = ''; // initialization string 
    
       $letter_num = 8; // the alias will have eight letter
    
       SRand((double)MicroTime()*1e6); // random generator
    
    
    
      for($i=0;$i<$letter_num;$i++):
    
        $rand = Rand(0, StrLen($letter)-1); //we select random position
    
        $str .= SubStr($letter, $rand, 1); // add char to $rand position
    
      endfor;
      
      return "host".$str;
  
  }

 /**
     * returns array with set options for building links
     *
     * @author Andreas Gohr <andi@splitbrain.org>
     */
    function _get_opts($addopts=null){
        global $ID;
        $opts = array(
                    'do'=>'admin',
                    'page'=>'autlogin',
                );
        if($this->ns) $opts['ns'] = $this->ns;

        if(is_null($addopts)) return $opts;
        return array_merge($opts, $addopts);
    }


    /**
     * Display a tree menu to select a page or namespace
     *
     * @author Andreas Gohr <andi@splitbrain.org>
     */
    function _html_explorer(){
        global $conf;
        global $ID;
        global $lang;

        $dir = $conf['datadir'];
        $ns  = $this->ns;
        if(empty($ns)){
            $ns = dirname(str_replace(':','/',$ID));
            if($ns == '.') $ns ='';
        }elseif($ns == '*'){
            $ns ='';
        }
        $ns  = utf8_encodeFN(str_replace(':','/',$ns));

        $data = $this->_get_tree($ns);

        // wrap a list with the root level around the other namespaces
        $item = array( 'level' => 0, 'id' => '*', 'type' => 'd',
                   'open' =>'true', 'label' => '['.$lang['mediaroot'].']');

        echo '<ul class="acltree">';
        echo $this->_html_li_acl($item);
        echo '<div class="li">';
        echo $this->_html_list_acl($item);
        echo '</div>';
        echo html_buildlist($data,'acl',
                            array($this,'_html_list_acl'),
                            array($this,'_html_li_acl'));
        echo '</li>';
        echo '</ul>';

    }

    /**
     * get a combined list of media and page files
     *
     * @param string $folder an already converted filesystem folder of the current namespace
     * @param string $limit  limit the search to this folder
     */
    function _get_tree($folder,$limit=''){
        global $conf;

        // read tree structure from pages and media
        $data = array();
        search($data,$conf['datadir'],'search_index',array('ns' => $folder),$limit);
        $media = array();
        search($media,$conf['mediadir'],'search_index',array('ns' => $folder, 'nofiles' => true),$limit);
        $data = array_merge($data,$media);
        unset($media);

        // combine by sorting and removing duplicates
        usort($data,array($this,'_tree_sort'));
        $count = count($data);
        if($count>0) for($i=1; $i<$count; $i++){
            if($data[$i-1]['id'] == $data[$i]['id'] && $data[$i-1]['type'] == $data[$i]['type']) unset($data[$i]);
        }
        return $data;
    }

    /**
     * usort callback
     *
     * Sorts the combined trees of media and page files
     */
    function _tree_sort($a,$b){
        // handle the trivial cases first
        if ($a['id'] == '') return -1;
        if ($b['id'] == '') return 1;
        // split up the id into parts
        $a_ids = explode(':', $a['id']);
        $b_ids = explode(':', $b['id']);
        // now loop through the parts
        while (count($a_ids) && count($b_ids)) {
            // compare each level from upper to lower
            // until a non-equal component is found
            $cur_result = strcmp(array_shift($a_ids), array_shift($b_ids));
            if ($cur_result) {
                // if one of the components is the last component and is a file
                // and the other one is either of a deeper level or a directory,
                // the file has to come after the deeper level or directory
                if (empty($a_ids) && $a['type'] == 'f' && (count($b_ids) || $b['type'] == 'd')) return 1;
                if (empty($b_ids) && $b['type'] == 'f' && (count($a_ids) || $a['type'] == 'd')) return -1;
                return $cur_result;
            }
        }
        // The two ids seem to be equal. One of them might however refer
        // to a page, one to a namespace, the namespace needs to be first.
        if (empty($a_ids) && empty($b_ids)) {
            if ($a['type'] == $b['type']) return 0;
            if ($a['type'] == 'f') return 1;
            return -1;
        }
        // Now the empty part is either a page in the parent namespace
        // that obviously needs to be after the namespace
        // Or it is the namespace that contains the other part and should be
        // before that other part.
        if (empty($a_ids)) return ($a['type'] == 'd') ? -1 : 1;
        if (empty($b_ids)) return ($b['type'] == 'd') ? 1 : -1;
    }
    
    
    /**
     * Item formatter for the tree view
     *
     * User function for html_buildlist()
     *
     * @author Andreas Gohr <andi@splitbrain.org>
     */
    function _html_list_acl($item){
        global $ID;
        $ret = '';
        // what to display
        if($item['label']){
            $base = $item['label'];
        }else{
            $base = ':'.$item['id'];
            $base = substr($base,strrpos($base,':')+1);
        }

        // highlight?
        if( ($item['type']== $this->current_item['type'] && $item['id'] == $this->current_item['id'])) 
            $cl = ' cur';

        // namespace or page?
        if($item['type']=='d'){
            if($item['open']){
                $img   = DOKU_BASE.'lib/images/minus.gif';
                $alt   = '&minus;';
            }else{
                $img   = DOKU_BASE.'lib/images/plus.gif';
                $alt   = '+';
            }
            $ret .= '<img src="'.$img.'" alt="'.$alt.'" />';
            $ret .= '<a href="'.wl('',$this->_get_opts(array('ns'=>$item['id'],'sectok'=>getSecurityToken()))).'" class="idx_dir'.$cl.'">';
            $ret .= $base;
            $ret .= '</a>';
        }else{
            $ret .= '<a href="'.wl('',$this->_get_opts(array('id'=>$item['id'],'ns'=>'','sectok'=>getSecurityToken()))).'" class="wikilink1'.$cl.'">';
            $ret .= noNS($item['id']);
            $ret .= '</a>';
        }
        return $ret;
    }


    function _html_li_acl($item){
            return '<li class="level'.$item['level'].'">';
    }

}
