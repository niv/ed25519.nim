{.compile: "ed25519/src/add_scalar.c".}
{.compile: "ed25519/src/fe.c".}
{.compile: "ed25519/src/ge.c".}
{.compile: "ed25519/src/key_exchange.c".}
{.compile: "ed25519/src/keypair.c".}
{.compile: "ed25519/src/sc.c".}
{.compile: "ed25519/src/seed.c".}
{.compile: "ed25519/src/sha512.c".}
{.compile: "ed25519/src/sign.c".}
{.compile: "ed25519/src/verify.c".}

type
  Seed* = array[32, byte]
  PublicKey* = array[32, byte]
  PrivateKey* = array[64, byte]
  Signature* = array[64, byte]
  Scalar* = array[32, byte]
  SharedSecret* = array[32, byte]
  KeyPair* = tuple[publicKey: PublicKey, privateKey: PrivateKey]

proc lib_ed25519_create_seed(seed: Seed): int {.importc: "ed25519_create_seed".}

proc lib_ed25519_create_keypair(publicKey: PublicKey, privateKey: PrivateKey,
  seed: Seed): void {.importc: "ed25519_create_keypair".}

proc lib_ed25519_sign(signature: Signature, message: cstring, messageLen: cuint,
  publicKey: PublicKey, privateKey: PrivateKey): void {.importc: "ed25519_sign".}

proc lib_ed25519_verify(signature: Signature, message: cstring, messageLen: cuint,
  publicKey: PublicKey): cint {.importc: "ed25519_verify".}

proc lib_ed25519_add_scalar(publicKey: PublicKey, privateKey: PrivateKey,
  scalar: Scalar): void {.importc: "ed25519_add_scalar".}

proc lib_ed25519_key_exchange(sharedSecret: SharedSecret, publicKey: PublicKey,
  privateKey: PrivateKey): void {.importc: "ed25519_key_exchange".}

## Braindead-easy sign/verify for arbitary binary data with ed25519.
##
## Backed by: https://github.com/orlp/ed25519
##
## Crypto code shipped directly inside package.


proc seed*(): Seed =
  ## Creates a 32 byte random seed for key generation.

  var seed: Seed # array[32, char] # newString(32)
  if lib_ed25519_create_seed(seed) != 0:
    raise newException(ValueError, "ed25519_create_seed failed")
  # assert(seed.len == 32)

  result = seed

proc createKeypair*(seed: Seed): KeyPair =
  ## Creates a new key pair from the given seed.

  # var sd = if seed == "": ed25519_seed() else: seed
  var pu: PublicKey
  var pr: PrivateKey
  lib_ed25519_create_keypair(pu, pr, seed)
  result = (pu, pr)

proc sign*(message: string, keyPair: KeyPair): Signature =
  ## Creates a signature of the given message using `keyPair`.

  var sig: Signature
  lib_ed25519_sign(sig, message, message.len.cuint, keyPair.publicKey, keyPair.privateKey)
  result = sig

proc verify*(message: string, signature: Signature, publicKey: PublicKey): bool =
  ## Verifies the signature on the given message using `publicKey`.

  result = lib_ed25519_verify(signature, message, message.len.cuint, publicKey) == 1

proc addScalar*(keyPair: KeyPair, scalar: Scalar): KeyPair =
  ## Adds `scalar` to the given key pair where scalar is a 32 byte buffer (possibly
  ## generated with `ed25519_create_seed`), generating a new key pair. You can
  ## calculate the public key sum without knowing the private key and vice versa by
  ## passing in `NULL` for the key you don't know. This is useful for enforcing
  ## randomness on a key pair by a third party while only knowing the public key,
  ## among other things.  Warning: the last bit of the scalar is ignored - if
  ## comparing scalars make sure to clear it with `scalar[31] &= 127`.

  var keyPair2 = keyPair
  lib_ed25519_add_scalar(keyPair2.publicKey, keyPair2.privateKey, scalar)
  result = keyPair2

proc keyExchange*(publicKey: PublicKey, privateKey: PrivateKey): SharedSecret =
  ##  Performs a key exchange on the given public key and private key, producing a
  ## shared secret.
  ## It is recommended to hash the shared secret before using it.
  ##
  ## Hint: Put in the other's person public key:
  ## The magic here is that ed25519_keyExchange(publicKey, otherPersonPrivateKey)
  ## would result in the same shared_secret.

  var sh: SharedSecret
  lib_ed25519_key_exchange(sh, publicKey, privateKey)
  result = sh
