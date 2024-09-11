//
//  main.swift
//  Fido2Test
//
//  Created by Kino on 2024-09-10.
//

import Foundation
import SwiftCBOR
import CryptoKit

/**
 {"type":"webauthn.get","challenge":"zL3uHOdD1YSKI8yOFisymxRoj0PXxRKhzDHLBmPr_LQ","origin":"https://idmsa.apple.com","topOrigin":"https://appleid.apple.com","crossOrigin":true}
 */
struct ClientData: Encodable {
    let type: String = "webauthn.get"
    let challenge: String
    let origin: String = "https://idmsa.apple.com"
    let topOrigin: String = "https://appleid.apple.com"
    let crossOrigin: Bool = true
}
let fa = fido_assert_new()
let rpId = "apple.com"
let devPin = "173431"
fido_assert_set_rp(fa, rpId)

let validCredentials = ["TLwzMtgEyHX3wtjXSoJ8E3xF2seBVmp7V3ZarHE+0nVVn8HpekJJi9IVWeesYEdx", "SbK5sfVp+o6SV6EnXLgVn2KFx//StQki9ir9PKeOuFk4OTePRV5xLx/1EdlXW+xM"]

let challenge = "KibX0JBC2w+npGzmNMnKy29KXGtPD7Drey0GHmmkBvc"
let clientDataInput = ClientData(challenge: challenge)
let clientDataBase64Encoded = (try JSONEncoder().encode(clientDataInput)).base64EncodedString()
fido_assert_set_clientdata(fa, clientDataBase64Encoded, clientDataBase64Encoded.lengthOfBytes(using: .utf8))
for cred in validCredentials {
    let credD = Data(base64Encoded: cred)!
    credD.withUnsafeBytes { (u8Ptr: UnsafePointer<UInt8>) in
        let rawPtr = UnsafeRawPointer(u8Ptr)
        fido_assert_allow_cred(fa, rawPtr, credD.count)
    }
}
//fido_assert_set_clientdata_hash(fa, challenge, challenge.count)
/*
var info = fido_dev_info_new(1)
var foundDevices: Int = 0
fido_dev_info_manifest(info, 1, &foundDevices)

print(info)
print(foundDevices)

let path = fido_dev_info_path(info)

print(String(cString: path!))*/
let dev = fido_dev_new()

fido_dev_open(dev, "ioreg://4295070154")

let rk = fido_credman_rk_new() // Resident credentials array
guard fido_credman_get_dev_rk(dev, rpId, rk, devPin) == FIDO_OK else {
    assertionFailure()
    exit(1)
}
var matchingCredId: String?
let rkCount = fido_credman_rk_count(rk)
for i in 0..<rkCount {
    let cred = fido_credman_rk(rk, i)
    let idPtr = fido_cred_id_ptr(cred)
    let idLen = fido_cred_id_len(cred)
    let idData = Data(bytes: idPtr!, count: idLen)
    let idBase64 = idData.base64EncodedString()
    print("Found ID: \(idBase64)")
    if validCredentials.contains(idBase64) {
        matchingCredId = idBase64
    }
}

guard let matchingCredId else {
    // The device has no valid credentials, we cannot continue
    assertionFailure()
    exit(1)
}


let assertResult = fido_dev_get_assert(dev, fa, devPin)
print("assertResult \(assertResult)")
guard assertResult == FIDO_OK else {
    assertionFailure()
    exit(1)
}

// Get the authData String
let authDataPtr = fido_assert_authdata_raw_ptr(fa, 0)
let authDataLen = fido_assert_authdata_len(fa, 0)
let authData = Data(bytes: authDataPtr!, count: 37)
let authDataBase64Str = authData.base64EncodedString()
print("auth data:")
print(authDataBase64Str)

let signatureDataPtr = fido_assert_sig_ptr(fa, 0)
let signatureLength = fido_assert_sig_len(fa, 0)
let signatureData = Data(bytes: signatureDataPtr!, count: signatureLength)
let signatureDataBase64Str = signatureData.base64EncodedString()
print("signature:")
print(signatureDataBase64Str)

let userHandlePtr = fido_assert_user_id_ptr(fa, 0)
let userHandleLen = fido_assert_user_id_len(fa, 0)
let userHandleData = Data(bytes: userHandlePtr!, count: userHandleLen)
let userHandleBase64Str = userHandleData.base64EncodedString()
print("user handle:")
print(userHandleBase64Str)

let devList = fido_dev_info_new(64)
var nDevs: Int = 0
let manifestResult = fido_dev_info_manifest(devList, 64, &nDevs)
guard manifestResult == FIDO_OK else {
    assertionFailure()
    exit(1)
}
for i in 0..<nDevs {
    let devPtr = fido_dev_info_ptr(devList, i)
}

struct ChallengeResponse: Encodable {
    let challenge: String
    let clientData: String
    let signatureData: String
    let authenticatorData: String
    let userHandle: String
    let credentialID: String
    let rpId: String
}

let response = ChallengeResponse(challenge: challenge, clientData: clientDataBase64Encoded, signatureData: signatureDataBase64Str, authenticatorData: authDataBase64Str, userHandle: userHandleBase64Str, credentialID: matchingCredId, rpId: rpId)
let responseData = try JSONEncoder().encode(response)
let responseJsonStr = String(data: responseData, encoding: .utf8)
print(responseJsonStr!)
/**
 {
    "challenge": "zL3uHOdD1YSKI8yOFisymxRoj0PXxRKhzDHLBmPr/LQ",
    "clientData": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiekwzdUhPZEQxWVNLSTh5T0Zpc3lteFJvajBQWHhSS2h6REhMQm1Qcl9MUSIsIm9yaWdpbiI6Imh0dHBzOi8vaWRtc2EuYXBwbGUuY29tIiwidG9wT3JpZ2luIjoiaHR0cHM6Ly9hcHBsZWlkLmFwcGxlLmNvbSIsImNyb3NzT3JpZ2luIjp0cnVlfQ==",
    "signatureData": "MEUCIQCh50DDYT+O8c1RO4kAyf2UammQTDNbh1iOtSN6HYJyKwIgDUMWTCpKWFmDcjlDYHk8fKhvKk0qVk0yxSC1PoMD0bQ=",
    "authenticatorData": "ImXLzD7yQQbJ4O3b0E88yg0DIl2j/MqOLYb3o5SvkoMFAAAABQ==",
    "userHandle": "QUY3NGdSTnMwWEFJSnFyMUlHcy95WDMvcUxVOFh5Sm9tTC9Ndk5VY3QxQT0",
    "credentialID": "SbK5sfVp+o6SV6EnXLgVn2KFx//StQki9ir9PKeOuFk4OTePRV5xLx/1EdlXW+xM",
    "rpId": "apple.com"
 }
 */

/**
 {
    "signatureData": "MEYCIQCrs5eStUAhzLvxi47RwMfu+VqcRT+U+tuCqOhRKkQlXgIhANZ+8ibgy27YyZWGZRsPJq/oTDdn8Eu9bMfB4KO0T6bz",
    "authenticatorData": "ImXLzD7yQQbJ4O3b0E88yg0DIl2j/MqOLYb3o5SvkoMFAAAA9Q==",
    "rpId": "apple.com",
    "userHandle": "QUY3NGdSTnMwWEFJSnFyMUlHcy95WDMvcUxVOFh5Sm9tTC9Ndk5VY3QxQT0=",
    "clientData": "eyJvcmlnaW4iOiJodHRwczpcL1wvaWRtc2EuYXBwbGUuY29tIiwiY3Jvc3NPcmlnaW4iOnRydWUsImNoYWxsZW5nZSI6Iml2VjVEZW4xVFFKaXJiNGFpMXNyUXpoVWRuZWJYS1p5UHI2MVFEUWZadmsiLCJ0b3BPcmlnaW4iOiJodHRwczpcL1wvYXBwbGVpZC5hcHBsZS5jb20iLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0=",
    "challenge": "ivV5Den1TQJirb4ai1srQzhUdnebXKZyPr61QDQfZvk",
    "credentialID": "TLwzMtgEyHX3wtjXSoJ8E3xF2seBVmp7V3ZarHE+0nVVn8HpekJJi9IVWeesYEdx"
 }
 */
