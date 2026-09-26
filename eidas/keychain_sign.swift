// Signs a digest with a smart-card key via macOS CryptoTokenKit (keychain). The PIN is asked by macOS.
// Usage: keychain_sign list                        -> "<cert-sha1> <name>" per smart-card identity
//        keychain_sign cert <sha1>                 -> certificate DER on stdout
//        keychain_sign sign <sha1> <sha256|sha384|sha512>   (digest on stdin, signature on stdout;
//                                                   ECDSA signatures are DER-encoded)
import CryptoKit
import Foundation
import Security

struct Identity {
    let sha1: String
    let name: String
    let identity: SecIdentity
    let der: Data
}

func identities() -> [Identity] {
    let query: [String: Any] = [
        kSecClass as String: kSecClassIdentity,
        kSecAttrAccessGroup as String: kSecAttrAccessGroupToken,
        kSecMatchLimit as String: kSecMatchLimitAll,
        kSecReturnRef as String: true,
    ]
    var out: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess, let items = out as? [SecIdentity] else {
        return []
    }
    return items.compactMap { identity in
        var cert: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &cert) == errSecSuccess, let cert else { return nil }
        let der = SecCertificateCopyData(cert) as Data
        let sha1 = Insecure.SHA1.hash(data: der).map { String(format: "%02x", $0) }.joined()
        let name = SecCertificateCopySubjectSummary(cert) as String? ?? "?"
        return Identity(sha1: sha1, name: name, identity: identity, der: der)
    }
}

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write((msg + "\n").data(using: .utf8)!)
    exit(1)
}

func find(_ sha1: String) -> Identity {
    guard let found = identities().first(where: { $0.sha1 == sha1.lowercased() }) else {
        fail("no smart-card identity with certificate SHA-1 \(sha1) - is the card inserted?")
    }
    return found
}

let args = Array(CommandLine.arguments.dropFirst())
switch (args.first, args.count) {
case ("list", 1):
    for id in identities() { print(id.sha1, id.name) }
case ("cert", 2):
    FileHandle.standardOutput.write(find(args[1]).der)
case ("sign", 3):
    var key: SecKey?
    guard SecIdentityCopyPrivateKey(find(args[1]).identity, &key) == errSecSuccess, let key else {
        fail("cannot access private key")
    }
    let keyType = (SecKeyCopyAttributes(key) as? [String: Any])?[kSecAttrKeyType as String] as? String
    let isEC = keyType == (kSecAttrKeyTypeECSECPrimeRandom as String)
    let algorithms: [String: (SecKeyAlgorithm, SecKeyAlgorithm)] = [
        "sha256": (.rsaSignatureDigestPKCS1v15SHA256, .ecdsaSignatureDigestX962SHA256),
        "sha384": (.rsaSignatureDigestPKCS1v15SHA384, .ecdsaSignatureDigestX962SHA384),
        "sha512": (.rsaSignatureDigestPKCS1v15SHA512, .ecdsaSignatureDigestX962SHA512),
    ]
    guard let pair = algorithms[args[2]] else { fail("unsupported digest \(args[2])") }
    let digest = FileHandle.standardInput.readDataToEndOfFile()
    var error: Unmanaged<CFError>?
    guard let sig = SecKeyCreateSignature(key, isEC ? pair.1 : pair.0, digest as CFData, &error) else {
        fail("signing failed: \(error!.takeRetainedValue())")
    }
    FileHandle.standardOutput.write(sig as Data)
default:
    fail("usage: keychain_sign list | cert <sha1> | sign <sha1> <sha256|sha384|sha512>")
}
