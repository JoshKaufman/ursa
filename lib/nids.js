var nids = [];

function addNid(nid, ln, sn) {
  nids.push({ nid: nid, sn: sn, ln: ln });
}

addNid(0, "md4", "MD4");
addNid(1, "md5", "MD5");
addNid(2, "ripemd160", "RIPEMD160");
addNid(3, "sha", "SHA");
addNid(4, "sha1", "SHA1");
addNid(5, "sha224", "SHA224");
addNid(6, "sha256", "SHA256");
addNid(7, "sha384", "SHA384");
addNid(8, "sha512", "SHA512");
addNid(9, "rmd160", "rmd160");

module.exports.byNid = nids.reduce(function(acc, cur) {
  acc[cur.nid] = cur;
  return acc;
}, {});
module.exports.bySN = nids.reduce(function(acc, cur) {
  acc[cur.sn] = cur;
  return acc;
}, {});
module.exports.byLN = nids.reduce(function(acc, cur) {
  acc[cur.ln] = cur;
  return acc;
}, {});
