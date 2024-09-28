//
//  ContentView.swift
//  LibFido2App
//
//  Created by Kino on 2024-09-27.
//

import SwiftUI
import LibFido2Swift

struct ContentView: View {
    @AppStorage("challengeUrl") var challengeUrl = ""
    @AppStorage("rpId") var rpId = ""
    @AppStorage("validCreds") var validCreds = ""
    @AppStorage("origin") var origin = ""
    @AppStorage("devicePin") var devicePin = ""
    @State var responseJson = ""
    var body: some View {
        VStack {
            VStack {
                TextField("Challenge URL", text: $challengeUrl)
                TextField("Relying Party ID", text: $rpId)
                TextField("Valid Credentials (comma separated)", text: $validCreds)
                TextField("Origin", text: $origin)
                TextField("Device Pin", text: $devicePin)
                Button("FIDO") {
                    do {
                        try fido()
                    } catch {
                        print(error)
                    }
                }
            }
            VStack {
                Text("Response:")
                Text(responseJson)
                    .textSelection(.enabled)
                    .padding()
                    .background(.white)
                    .opacity(responseJson.isEmpty ? 0 : 1)
            }
        }
        .padding()
    }
    
    func fido() throws {
        let fido2 = FIDO2()
        let validCredsArray = validCreds.split(separator: ",").map { String($0) }
        let response = try fido2.respondToChallenge(args: ChallengeArgs(rpId: rpId,
                                                                        validCredentials: validCredsArray,
                                                                        devPin: devicePin, // The device PIN
                                                                        challenge: FIDO2.base64urlToBase64(base64url: challengeUrl),
                                                                        origin: origin))
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        responseJson = String(data: try encoder.encode(response), encoding: .utf8)!
    }
}

#Preview {
    ContentView()
}
