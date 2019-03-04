/*
 * Differential Cryptanalysis Simulation
 * 
 * @author Xiao Xin <xin.xiao@hotmail.com>
 * Date: 05-04-17
 */

/*
 * Functionality extension
 */

/*
 * Array.prototype.rand 
 * Get an item from a random index
 * in the array
 */
Array.prototype.rand = function(){
  var p = Math.floor(Math.random() * this.length);
  return this[p];  
};

/*
 * Array.prototype.contains
 * Check if a item is in the array
 */
Array.prototype.contains = function(e){
  return this.indexOf(e) != -1;
};

/*
 * Static Variable 
 */

// SBOX - Substitution Network
var SBOX = [3, 14, 1, 10, 
            4, 9, 5, 6, 
            8, 11, 15, 2, 
            13, 12, 0, 7];

// DIFFERENTIAL - Differential connected network
var DIFFERENTIAL = {}
for(var i = 0; i < 16; i++){
  for(var j = 0; j < i; j++){
    var s = i ^ j;
    var e = SBOX[i] ^ SBOX[j];
    if(!(s in DIFFERENTIAL))
      DIFFERENTIAL[s] = [e];
    else if (!DIFFERENTIAL[s].contains(e))
      DIFFERENTIAL[s].push(e);
  }
}

/*
 * Static methods
 */ 

/*
 * encrypt
 * Encrypt a 4-bit message using given key chain
 */
function encrypt(p, k){
  for(var i = 0; i < k.length - 1; i++)
    p = SBOX[p ^ k[i]];
  return p ^ k[k.length - 1];
}

/*
 * norm
 * Generate all cipher generated using given key
 */
function norm(k){
  var r = [];
  for(var i = 0; i < 16; i++)
    r.push(encrypt(i, k));
  return r;
}

/*
 * differential
 * Generte all differential change possibilitis 
 * at given encryption depth
 */
function differential(r, l, t, d){
  if(l.length == d){
    if(l[d - 1] == t)
      r.push(l);
  }else{
    var c = DIFFERENTIAL[l[l.length - 1]];
    c.forEach(n=>differential(r, l.concat(n), t, d));
  }
}

/*
 * test
 * Test if a given key aligns with given norm
 */
function test(k, N){
  return N.every((n, i) => n == encrypt(i, k));
}

/*
 * key
 * Check if the key can be recovered based on 
 * a given differential change line
 */
function key(p, c, i, l, r, N){
  if(i + 1 == l.length){
    r.push(c ^ p);
    if(test(r, N))
      return true;
    r.pop();
    return false;
  }
  
  var pp = p ^ l[i];
  for(var x = 0; x < 16; x++){
    var np = SBOX[p ^ x];
    var npp = SBOX[pp ^ x];
    if((np ^ npp) == l[i + 1]){
      r.push(x);
      var t = key(np, c, i + 1, l, r, N);
      if(t) 
        return true;
      r.pop();
    }
  }
  return false;
}

/*
 * Model for differential crypanalysis
 */
class Analysis{
  /*
   * initialize
   * Initialize package with given plaintext and key
   */
  initialize(p, k){
    if(!this.p || this.p != p || !this.k || this.k != k){
      this.p = p;
      this.k = k;
      this.c = encrypt(p, k);
      this.N = norm(k);
      this.r = [];
      for(var i = 1; i < 16; i++)
        differential(this.r, 
                    [i], 
                     this.c ^ encrypt(this.p ^ i, this.k),
                     this.k.length);
      this.gp = this.r.length;
    }
  }

  /*
   * generate
   * Crack the cipher using a differential connection,
   * and generate the each stage of the analysis
   */
  generate(){
    this.crack();
    this.stage();
  }

  /*
   * crack
   * Find and store a differential connection that will
   * recover the key
   */
  crack(){
    this.dc = null;
    while(!this.dc){
      var l = this.r.rand();
      if(key(this.p, this.c, 0, l, [], this.N))
        this.dc = l;
    }
  }

  /*
   * stage
   * Show how differential pair changes at each stage 
   * of the analysis
   */
  stage(){
    var kt = 1;
    var c = this.p;
    var cc = c ^ this.dc[0];
    var r = [[[c], [cc]]];

    for(var i = 1; i < this.dc.length; i++){
      var j = 2 * (i - 1);
      var cl = r[j][0];
      var ccl = r[j][1];
      
      var cxor = [];
      var ccxor = [];
      var cxorSBOX = [];
      var ccxorSBOX = [];

      for(var k = 0; k < cl.length; k++){
        var c = cl[k];
        var cc = ccl[k];

        for(var d = 0; d < 16; d++){
          var nc = SBOX[c ^ d];
          var ncc = SBOX[cc ^ d];
          if((nc ^ ncc) == this.dc[i] && !cxor.contains(c ^ d)){
            cxor.push(c ^ d);
            ccxor.push(cc ^ d);
            cxorSBOX.push(nc);
            ccxorSBOX.push(ncc);
          };
        }
      }
      kt *= cxor.length;
      r.push([cxor, ccxor]);
      r.push([cxorSBOX, ccxorSBOX]);
    }
    kt *= r[r.length - 1][0].length;
    r.push([[this.c], [this.c ^ this.dc[this.dc.length - 1]]]);
    this.kt = kt;
    this.sp = r;
  }
}
