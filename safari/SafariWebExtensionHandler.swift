// VaultOS's Safari app extension. Safari hands it each native message from the VaultOS web
// extension packaged with it (no other extension can reach it), and it relays the message to
// the app through vaultos-browser, the helper Chromium browsers start, run from this bundle
// under this extension's sandbox, which allows only the VaultOS data folder and the owner's
// socket in it. It keeps nothing between messages.
import Foundation
import SafariServices

/// The origin vaultos-browser reports for Safari (`native_host::SAFARI_ORIGIN`).
private let origin = "safari-web-extension://org.vaultos.preview.safari/"
private let maxReply = 64 * 1024 * 1024

final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let message = item?.userInfo?[SFExtensionMessageKey]
        // A pairing waits for the human, so the relay runs off Safari's thread.
        DispatchQueue.global(qos: .userInitiated).async {
            let response = NSExtensionItem()
            response.userInfo = [SFExtensionMessageKey: relay(message)]
            context.completeRequest(returningItems: [response], completionHandler: nil)
        }
    }
}

private func failure(_ text: String) -> [String: Any] {
    ["ok": false, "code": "no_host", "error": text]
}

/// The VaultOS data folder in the real home folder; inside the sandbox HOME is the
/// extension's container.
private func dataDir() -> String? {
    guard let entry = getpwuid(getuid()), let home = entry.pointee.pw_dir else { return nil }
    return String(cString: home) + "/Library/Application Support/VaultOS-Preview"
}

private func relay(_ message: Any?) -> [String: Any] {
    guard let message, JSONSerialization.isValidJSONObject(message),
          let body = try? JSONSerialization.data(withJSONObject: message)
    else { return failure("Expected a JSON object") }
    guard let dir = dataDir() else { return failure("VaultOS cannot find your home folder.") }
    let helper = Process()
    helper.executableURL = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/vaultos-browser")
    helper.arguments = [origin]
    helper.environment = ["VAULTOS_DATA_DIR": dir]
    let input = Pipe(), output = Pipe()
    helper.standardInput = input
    helper.standardOutput = output
    helper.standardError = FileHandle.nullDevice
    do {
        try helper.run()
    } catch {
        return failure("The VaultOS browser helper could not start. Reinstall VaultOS.")
    }
    // Native messaging framing: a 32-bit length in native byte order, then the JSON.
    var length = UInt32(body.count)
    var frame = Data(bytes: &length, count: 4)
    frame.append(body)
    try? input.fileHandleForWriting.write(contentsOf: frame)
    try? input.fileHandleForWriting.close()
    let reply = output.fileHandleForReading.readDataToEndOfFile()
    helper.waitUntilExit()
    guard reply.count >= 4 else { return failure("VaultOS did not answer. Open the VaultOS app.") }
    let size = reply.prefix(4).withUnsafeBytes { Int($0.loadUnaligned(as: UInt32.self)) }
    guard size <= maxReply, size <= reply.count - 4,
          let object = try? JSONSerialization.jsonObject(with: reply.subdata(in: 4..<(4 + size))),
          let answer = object as? [String: Any]
    else { return failure("VaultOS sent an answer this extension could not read.") }
    return answer
}
