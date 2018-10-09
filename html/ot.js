'use strict';
(generator => {
  if (typeof exports === 'object') {
    generator(exports, true)
  } else {
    const exports = {}
    window.ot = generator(exports, false)
  }
})((exports, isNodeJs) => {
  exports.enc = (pub, pos, N, M) => {
    /*
      |c2| = 2|c1|
    */
    if (M == 0 || M > N) {
      M = Math.floor(Math.sqrt(N * 2))
    }
    const q = Math.floor(pos / M)
    const r = pos - q * M
    const ct2vN = Math.ceil(N / M)
    console.log(`N=${N}, M=${M}, ct2vN=${ct2vN}, q=${q}, r=${r}`)

    const ct1v = [String(M)]
    for (let i = 0; i < M; i++) {
      ct1v.push(pub.encG1(i == r).serializeToHexStr())
    }
    const ct2v = [String(ct2vN)]
    for (let i = 0; i < ct2vN; i++) {
      ct2v.push(pub.encG2(i == q).serializeToHexStr())
    }
    return { 'ret':[ct1v, ct2v] }
  }
  exports.dec = (she, sec, json) => {
    const ctStr = json['ret']
    const ct = she.deserializeHexStrToCipherTextGT(ctStr)
    return sec.dec(ct)
  }
  return exports
})

