import strutils

import ../ed25519 as ed25519

let ourKeyPair    = createKeypair(seed())
let theirKeyPair  = createKeypair(seed())
let msg = "test"

let sig = msg.sign(ourKeyPair)

doAssert(msg.verify(sig, ourKeyPair.publicKey))
doAssert(not msg.verify(sig, theirKeyPair.publicKey))

let ourShared   = keyExchange(theirKeyPair.publicKey, ourKeyPair.privateKey)
let theirShared = keyExchange(ourKeyPair.publicKey, theirKeyPair.privateKey)

doAssert(ourShared == theirShared)

let newKeyPair = ourKeyPair.addScalar(seed())

doAssert(newKeyPair != ourKeyPair)
