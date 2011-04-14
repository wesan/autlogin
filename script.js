acl = {
    init: function(){
        this.ctl = $('auth_manager');
        if(!this.ctl) return;

        addEvent($('acl__tree'),'click',acl.treehandler);
    },


    /**
     * parse URL attributes into a associative array
     *
     * @todo put into global script lib?
     */
    parseatt: function(str){
        if(str[0] == '?') str = str.substr(1);
        var attributes = {};
        var all = str.split('&');
        for(var i=0; i<all.length; i++){
            var att = all[i].split('=');
            attributes[att[0]] = decodeURIComponent(att[1]);
        }
        return attributes;
    },

    /**
     * htmlspecialchars equivalent
     *
     * @todo put in gloabl scripts lib?
     */
    hsc: function(str) {
        str = str.replace(/&/g,"&amp;");
        str = str.replace(/\"/g,"&quot;");
        str = str.replace(/\'/g,"&#039;");
        str = str.replace(/</g,"&lt;");
        str = str.replace(/>/g,"&gt;");
        return str;
    },


    /**
     * Open or close a subtree using AJAX
     *
     * @author Andreas Gohr <andi@splitbrain.org>
     */
    treetoggle: function(clicky){
        var listitem = clicky.parentNode.parentNode;

        // if already open, close by removing the sublist
        var sublists = listitem.getElementsByTagName('ul');
        if(sublists.length){
            listitem.removeChild(sublists[0]);
            clicky.src = DOKU_BASE+'lib/images/plus.gif';
            clicky.alt = '+';
            return false;
        }

        // get the enclosed link (is always the first one)
        var link = listitem.getElementsByTagName('a')[0];

        // prepare an AJAX call to fetch the subtree
        var ajax = new sack(DOKU_BASE + 'lib/plugins/autlogin/ajax.php');
        ajax.AjaxFailedAlert = '';
        ajax.encodeURIString = false;
        if(ajax.failed) return true;

        //prepare the new ul
        var ul = document.createElement('ul');
        listitem.appendChild(ul);
        ajax.elementObj = ul;
        ajax.setVar('ajax', 'tree');
        var frm = $('auth1__detail').getElementsByTagName('form')[0];
        ajax.setVar('current_ns', encodeURIComponent(frm.elements['ns'].value));
        ajax.setVar('current_id', encodeURIComponent(frm.elements['id'].value));     
        ajax.runAJAX(link.search.substr(1));
        clicky.src = DOKU_BASE+'lib/images/minus.gif';
        return false;
    },

    /**
     * Handles all clicks in the tree, dispatching the right action based on the
     * clicked element
     */
    treehandler: function(e){
        if(e.target.src){ // is it an image?
            acl.treetoggle(e.target);
        } else if(e.target.href){ // is it a link?
            // remove highlighting
            var obj = getElementsByClass('cur',$('acl__tree'),'a');
            for(var i=0; i<obj.length; i++){
                obj[i].className = obj[i].className.replace(/ cur/,'');
            }

            // add new highlighting
            e.target.className += ' cur';

            // set new page to detail form
            var frm = $('auth1__detail').getElementsByTagName('form')[0];
            if(e.target.className.search(/wikilink1/) > -1){
                frm.elements['ns'].value = '';
                frm.elements['id'].value = acl.hsc(acl.parseatt(e.target.search)['id']);
            }else if(e.target.className.search(/idx_dir/) > -1){
                frm.elements['ns'].value = acl.hsc(acl.parseatt(e.target.search)['ns']);
                frm.elements['id'].value = '';
            }
            var frm2 = $('auth2__detail').getElementsByTagName('form')[0];
            if(e.target.className.search(/wikilink1/) > -1){
                frm2.elements['ns'].value = '';
                frm2.elements['id'].value = acl.hsc(acl.parseatt(e.target.search)['id']);
            }else if(e.target.className.search(/idx_dir/) > -1){
                frm2.elements['ns'].value = acl.hsc(acl.parseatt(e.target.search)['ns']);
                frm2.elements['id'].value = '';
            } 
             var frm3 = $('auth3__detail').getElementsByTagName('form')[0];
            if(e.target.className.search(/wikilink1/) > -1){
                frm3.elements['ns'].value = '';
                frm3.elements['id'].value = acl.hsc(acl.parseatt(e.target.search)['id']);
            }else if(e.target.className.search(/idx_dir/) > -1){
                frm3.elements['ns'].value = acl.hsc(acl.parseatt(e.target.search)['ns']);
                frm3.elements['id'].value = '';
            }            
                   
    
        }

        e.stopPropagation();
        e.preventDefault();
        return false;
    }

};

addInitEvent(acl.init);
