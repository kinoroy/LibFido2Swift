LibFido2Swift is a Swift package wrapper around the [libfido2 C library](https://github.com/Yubico/libfido2)

Currently only getting an assertion is implemented (used for logging in in a WebAuthn flow)

Example Use:

````swift
// Base64Url encoded challenge string
let challengeUrl = "ZWxpZmtqa2dzYWxoamoycGlqb3Jsc2VmZGRzZGZkc2ZkZGEyZTM"
// Relying party ID
let rpId = "example.com"
// A list of valid credentials to use (provided by the relying party)
let validCreds = ["ZHNmbGRrc2pma2xhanNlbGZhZWtmamVzbGZlYWZhZWY="]

let fido2 = FIDO2()
let response = try fido2.respondToChallenge(args: ChallengeArgs(rpId: rpId,
                                                                validCredentials:
                                                                validCreds,
                                                                devPin: "123456", // The device PIN 
                                                                challenge: FIDO2.base64urlToBase64(base64url: challengeUrl),
                                                                origin: "https://example.com"))
````

This package bundles binary frameworks for libfido2, libcbor, and libcrypto. The licences for these are located with the respective library binary files in the Frameworks folder 
