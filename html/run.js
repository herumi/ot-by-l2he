function getValue (name) {
  const e = document.getElementsByName(name)
console.log(`getValue ${e} ${e.length}`)
  return e.length > 0 ? e[0].value : 0
}
function getText (name) {
  const e = document.getElementsByName(name)
console.log(`getText ${e} ${e.length}`)
  return e.length > 0 ? e[0].innerText : ''
}
function setText (name, val) {
  const e = document.getElementsByName(name)
console.log(`setText ${e} ${e.length}`)
  if (e.length > 0) e[0].innerText = val
}
const URL = '../cgi-bin/ot.cgi'

const loadScript = (url, callback) => {
  const script = document.createElement('script')
  script.type = 'text/javascript'
  script.src = url
  if (script.readyState) {
    script.onreadystatechange = () => {
      if (script.readyState === 'loaded' || script.readyState === 'complete') {
        script.onreadystatechange = null
        callback()
      }
    }
  } else {
    script.onload = () => callback()
  }
  document.getElementsByTagName('head')[0].appendChild(script)
}

let sec = null
let pub = null
let ppub = null
let prevTime = 0
const getPassedTime = () => {
  const t = Date.now()
  const ret = t - prevTime
  prevTime = t
  return ret
}

loadScript('./she_c.js', () => {
  she.init(she.BN254, 128).then(() => {
    sec = new she.SecretKey()
    sec.setByCSPRNG()
//    sec.deserializeHexStr("673406c280f5475db8f7b9dec0fc662bedb4e6a536ef8d628e71e898b632911ba90e0ffe43fe224263f690b61692dca96b941846b375e58046f01974782fc509");
    pub = sec.getPublicKey()
    ppub = new she.PrecomputedPublicKey()
    ppub.init(pub)
    setText('status', 'ok')
  })
})

const onClickOT = () => {
  const pos = getValue('pos') | 0
  const N = getValue('N') | 0
  console.log(`pos=${pos}, N=${N}, pos >= N : ${pos >= N}`)
  if (pos >= N || pos < 0 || N <= 0) {
    alert(`err ${pos} >= ${N}`)
    return
  }
  const M = getValue('M') | 0
  prevTime = Date.now()
  const v = ot.enc(ppub, pos, N, M)
  setText('status', 'sending...')
  const time = getPassedTime()
  setText('encTime', time)
  console.log(`sending...${time}`)
  sendOT(v)
}

const sendOT = (data) => {
  fetch(URL, {
    method: 'POST',
    headers: {
      "Content-Type": "application/json; charset=utf-8",
    },
    body: JSON.stringify(data),
  }).then(res => res.json())
    .then(json => {
      const time = getPassedTime()
      setText('recvTime', time)
      console.log(`received ${time}`)
      setText('status', 'received')
      const v = ot.dec(she, sec, json)
      console.log(`dec=${v}`)
      setText('ret', v)
    })
    .catch(err => console.error(err))
}
