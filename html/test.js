'use strict'
const she = require('./she.js')
const assert = require('assert')
const fetch = require('node-fetch')
const ot = require('./ot.js')
const { performance } = require('perf_hooks')

function bench (label, count, func) {
  const start = performance.now()
  for (let i = 0; i < count; i++) {
    func()
  }
  const end = performance.now()
  const t = (end - start) / count
  const roundTime = (Math.round(t * 1000)) / 1000
  console.log(label + ' ' + roundTime)
}

she.init()
  .then(() => {
    try {
      const sec = new she.SecretKey()
      sec.setByCSPRNG()
      const pub = sec.getPublicKey()
      const ppub = new she.PrecomputedPublicKey()
      ppub.init(pub)
      const N = 1000000
      const M = 0
      const pos = 999999
      const expect = 5
      bench('enc', 2, () => { ot.enc(ppub, 0, N, M) })
      const json = ot.enc(ppub, pos, N, M)
      const begin = performance.now()
      fetch('https://herumi.com:50002/cgi-bin/ot.cgi', {
        method: 'POST',
        headers: {
          "Content-Type": "application/json; charset=utf-8",
        },
        body: JSON.stringify(json)
      }).then(res => res.json())
      .then(json => {
        console.log(`send/recive ${Math.round((performance.now() - begin) * 1000) / 1000}msec`)
        const v = ot.dec(she, sec, json)
        console.log(`v=${v}`)
        assert.equal(v, expect)
      })
      .catch(err => console.error(err))
    } catch (e) {
      console.log(`TEST FAIL ${e}`)
      assert(false)
    }
  })

