/*
 * Parameter component for cryptanalysis input
 * @author Xiao Xin <xin.xiao@hotmail.com>
 * Date: 05-04-17
 */

var param_app = new Vue({
  el: '#param',
  data: {
    p: '',
    k: ''
  },
  methods: {
    parseText: function(){
      var r = parseInt(this.p);
      return (r >= 0 && r < 16) ? r : NaN;
    },

    parseKey: function(){
      var p = this.k.split(' ');
      var r = [];
      for(var i = 0; i < p.length; i++){
        if(p[i]){
          var x = parseInt(p[i]);
          if(isNaN(x) || x < 0 || x > 15)
            return null;
          r.push(x);
        }
      }
      if(r.length == 0 || r.length > 7)
        return null;
      return r;
    },

    parseAndEncrypt: function(){
      stage_app.s = 0;
      if(!this.p || !this.k)
        return 'None';
      var p = this.parseText();
      var k = this.parseKey();
      if(isNaN(p) || k == null)
        return 'None';
      return encrypt(p, k);
    },

    canGenerate: function(){
      if(!this.p || !this.k)
        return false;
      if(isNaN(this.parseText()) || this.parseKey() == null)
        return false;
      return true;
    },
    
    analyze: function(){
      var p = this.parseText();
      var k = this.parseKey();
      A.initialize(p, k);
      A.generate();
      stage_app.s++;
    }
  }
})
