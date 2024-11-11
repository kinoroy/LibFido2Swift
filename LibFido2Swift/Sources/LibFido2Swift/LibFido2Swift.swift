// The Swift Programming Language
// https://docs.swift.org/swift-book
import libfido2
import Foundation
import CryptoKit

public struct ChallengeResponse: Encodable {
    public let challenge: String
    public let clientData: String
    public let signatureData: String
    public let authenticatorData: String
    public let userHandle: String
    public let credentialID: String
    public let rpId: String
}
public struct ChallengeArgs {
    public let rpId: String
    public let validCredentials: [String]
    public let devPin: String?
    public let challenge: String
    public let origin: String
    
    public init(rpId: String, validCredentials: [String], devPin: String?, challenge: String, origin: String) {
        self.rpId = rpId
        self.validCredentials = validCredentials
        self.devPin = devPin
        self.challenge = challenge
        self.origin = origin
    }
}

public enum FIDO2Error: Error {
    // Input Errors
    /// When there was an error decoding the valid credentials array, are these base64 encoded strings?
    case inputErrorInvalidCredentialsArray
    /// When there was no connected device discovered
    case noDeviceFound
    /// When the connected device does not have FIDO2 functionality
    case notFido2Device
    /// Where the connected device has no valid credentials
    case errorNoValidCredentials
    /// When the assertation request timed out
    case assertionRequestTimedOut
    /// When the user cancels the request
    case canceledByUser
    /// When there was an internal error
    case internalError
    /// When there was an internal error interacting with libfido2, the associated value is the error code returned from libfido2
    case libfido2ErrorInternal(Int32)
}

public class FIDO2 {
    private struct ClientData {
        let type: String = "webauthn.get"
        let challenge: String
        let origin: String
        let crossOrigin: Bool = true
        
        var json: String {
    """
    {"type":"\(type)","challenge":"\(challenge)","origin":"\(origin)","crossOrigin":\(crossOrigin)}
    """
        }
    }
    private var fidoDev: OpaquePointer?
    
    public init() {}
    
    public func hasDeviceAttached() -> Bool {
        do {
            let _ = try findFirstDevicePath()
            return true
        } catch {
            return false
        }
    }
    
    public func deviceHasPin() throws -> Bool {
        let devPath = try findFirstDevicePath()
        
        var dev = fido_dev_new()
        defer { fido_dev_free(&dev) }
        
        let openResult = fido_dev_open(dev, devPath)
        guard openResult == FIDO_OK else {
            throw FIDO2Error.internalError
        }
        defer { fido_dev_close(dev) }
        
        return fido_dev_has_pin(dev)
    }
    
    /// Responds to the given WebAuthn challenge
    /// Note that this is a **blocking** method if the challenge requires user verification (don't call it on the main thread!)
    /// (The method blocks waiting for the user to touch the security device)
    /// You can call this from a Task or background thread and use the `cancel()` method from the main or other thread to cancel the pending user verification
    /// - Parameter args: The required input arguments to form an assertation
    /// - Returns: The output which can form an assertion 
    public func respondToChallenge(args: ChallengeArgs) throws -> ChallengeResponse {
        var fa = fido_assert_new()
        defer { fido_assert_free(&fa) }
        let rpId = args.rpId
        let devPin = args.devPin
        fido_assert_set_rp(fa, rpId)

        let challenge = args.challenge
        let clientDataInput = ClientData(challenge: FIDO2.base64ToBase64url(base64: challenge), origin: args.origin)
        let clientDataJsonData = Data(clientDataInput.json.utf8)
        let clientDataBase64Encoded = (clientDataJsonData).base64EncodedString()
        
        let clientDataHash = [UInt8](SHA256.hash(data: clientDataJsonData))
        fido_assert_set_clientdata_hash(fa, clientDataHash, clientDataHash.count)
        
        let validCredentials = args.validCredentials
        try setValidCredentials(validCredentials, forAssertion: fa)

        let devPath = try findFirstDevicePath()
        
        var dev = fido_dev_new()
        // Set a reference to the device, so any pending action can be canceled from another thread with the cancel() method
        self.fidoDev = dev
        defer { fido_dev_free(&dev) }
        
        let openResult = fido_dev_open(dev, devPath)
        guard openResult == FIDO_OK else {
            throw FIDO2Error.internalError
        }
        defer { fido_dev_close(dev) }
        
        guard fido_dev_is_fido2(dev) else {
            throw FIDO2Error.notFido2Device
        }

        try makeAssertion(using: dev, fidoAssertion: fa, devicePin: devPin)

        let authDataBase64Str = try getAuthData(fidoAssertion: fa)
        let credentialId = try getCredentialIdUsed(fidoAssertion: fa)
        let signatureDataBase64Str = try getSignatureData(fidoAssertion: fa)
        let userHandleBase64Str = try getUserData(fidoAssertion: fa)


        let response = ChallengeResponse(challenge: challenge,
                                         clientData: clientDataBase64Encoded,
                                         signatureData: signatureDataBase64Str,
                                         authenticatorData: authDataBase64Str,
                                         userHandle: userHandleBase64Str,
                                         credentialID: credentialId,
                                         rpId: rpId)
        return response
    }
    
    private func setValidCredentials(_ validCredentials: [String], forAssertion fa: OpaquePointer?) throws {
        for cred in validCredentials {
            guard let credD = Data(base64Encoded: cred) else {
                throw FIDO2Error.inputErrorInvalidCredentialsArray
            }
            let ptr = credD.withUnsafeBytes { rawPtr in
                return rawPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
            }
            fido_assert_allow_cred(fa, ptr, credD.count)
        }
    }
    
    private func findFirstDevicePath() throws -> String {
        var devList = fido_dev_info_new(64)
        defer { fido_dev_info_free(&devList, 64) }
        
        var nDevs: Int = 0
        let manifestResult = fido_dev_info_manifest(devList, 64, &nDevs)
        guard manifestResult == FIDO_OK else {
            throw FIDO2Error.libfido2ErrorInternal(manifestResult)
        }
        
        guard nDevs > 0 else {
            throw FIDO2Error.noDeviceFound
        }

        // Just use the first found device
        guard let devInfo = fido_dev_info_ptr(devList, 0) else {
            // We know there's at least 1 device from the above check
            // So this would be an unknown error
            throw FIDO2Error.internalError
        }
        guard let devPath = fido_dev_info_path(devInfo) else {
            throw FIDO2Error.internalError
        }
        
        // Copy the String so that it is not deallocated when devList is freed
        return String(cString: devPath)
    }
    
    private func makeAssertion(using device: OpaquePointer?, fidoAssertion: OpaquePointer?, devicePin: String?) throws {
        let assertResult = fido_dev_get_assert(device, fidoAssertion, devicePin)
        guard assertResult == FIDO_OK else {
            if assertResult == FIDO_ERR_ACTION_TIMEOUT {
                throw FIDO2Error.assertionRequestTimedOut
            }
            if assertResult == FIDO_ERR_KEEPALIVE_CANCEL {
                throw FIDO2Error.canceledByUser
            }
            throw FIDO2Error.libfido2ErrorInternal(assertResult)
        }
    }
    
    private func getAuthData(fidoAssertion fa: OpaquePointer?) throws -> String {
        // Get the authData String
        guard let authDataPtr = fido_assert_authdata_raw_ptr(fa, 0) else {
            throw FIDO2Error.internalError
        }
        let authDataLen = fido_assert_authdata_len(fa, 0)
        let authData = Data(bytes: authDataPtr, count: 37)
        let authDataBase64Str = authData.base64EncodedString()
        return authDataBase64Str
    }
    
    private func getCredentialIdUsed(fidoAssertion fa: OpaquePointer?) throws -> String {
        guard let credentialIdPtr = fido_assert_id_ptr(fa, 0) else {
            throw FIDO2Error.internalError
        }
        let credIdLen = fido_assert_id_len(fa, 0)
        let credIdData = Data(bytes: credentialIdPtr, count: credIdLen)
        let credIdBase64Str = credIdData.base64EncodedString()
        return credIdBase64Str
    }
    
    private func getSignatureData(fidoAssertion fa: OpaquePointer?) throws -> String {
        guard let signatureDataPtr = fido_assert_sig_ptr(fa, 0) else {
            throw FIDO2Error.internalError
        }
        let signatureLength = fido_assert_sig_len(fa, 0)
        let signatureData = Data(bytes: signatureDataPtr, count: signatureLength)
        let signatureDataBase64Str = signatureData.base64EncodedString()
        return signatureDataBase64Str
    }

    private func getUserData(fidoAssertion fa: OpaquePointer?) throws -> String {
        guard let userHandlePtr = fido_assert_user_id_ptr(fa, 0) else {
            throw FIDO2Error.internalError
        }
        let userHandleLen = fido_assert_user_id_len(fa, 0)
        let userHandleData = Data(bytes: userHandlePtr, count: userHandleLen)
        guard let userHandleBase64Str = String(data: userHandleData, encoding: .utf8) else {
            throw FIDO2Error.internalError
        }
        return userHandleBase64Str
    }
    
    public func cancel() {
        if let fidoDev {
            fido_dev_cancel(fidoDev)
        }
    }
    
    public static func base64urlToBase64(base64url: String) -> String {
        var base64 = base64url
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        if base64.count % 4 != 0 {
            base64.append(String(repeating: "=", count: 4 - base64.count % 4))
        }
        return base64
    }

    public static func base64ToBase64url(base64: String) -> String {
        let base64url = base64
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return base64url
    }
}
