import Foundation
import Security

guard CommandLine.arguments.count == 3,
      ["trusted", "absent", "untrusted"].contains(CommandLine.arguments[2]) else { exit(2) }
let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
guard let certificate = SecCertificateCreateWithData(nil, data as CFData) else { exit(2) }
let expected = CommandLine.arguments[2] == "trusted"
var settings: CFArray?
let status = SecTrustSettingsCopyTrustSettings(certificate, .admin, &settings)
let denied = (settings as? [[String: Any]]).map { entries in
    entries.count == 1 && (entries[0][kSecTrustSettingsResult as String] as? NSNumber)?.uint32Value == SecTrustSettingsResult.deny.rawValue
} ?? false
let valid = expected ? status == errSecSuccess : status == errSecItemNotFound ||
    (CommandLine.arguments[2] == "untrusted" && status == errSecSuccess && denied)
guard valid else {
    fputs("Unexpected trust settings status: \(status)\n", stderr)
    exit(1)
}
var trust: SecTrust?
guard SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
      let trust = trust else { exit(1) }
guard SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess else { exit(1) }
var error: CFError?
let accepted = SecTrustEvaluateWithError(trust, &error)
guard accepted == expected else {
    fputs("Unexpected certificate acceptance: \(accepted), \(String(describing: error))\n", stderr)
    exit(1)
}
print("Verified trust settings and certificate acceptance: \(CommandLine.arguments[2])")
