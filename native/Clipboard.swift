import AppKit

// Writes a copied secret so clipboard managers and Universal Clipboard leave it alone:
// org.nspasteboard.ConcealedType and TransientType (https://nspasteboard.org) ask history
// tools not to record it, and currentHostOnly keeps it off other devices. The value arrives
// on stdin, never in process arguments.
struct Request: Decodable { let action: String; let text: String?; let changeCount: Int?; let pasteboard: String? }
let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")
func reply(_ result: [String: Any]) {
    FileHandle.standardOutput.write(try! JSONSerialization.data(withJSONObject: result))
}
let data = FileHandle.standardInput.readDataToEndOfFile()
guard data.count <= 1_048_576, let request = try? JSONDecoder().decode(Request.self, from: data) else { exit(2) }
var board = NSPasteboard.general
#if VAULTOS_TEST
// Tests use a private named pasteboard and never touch the human's clipboard.
guard let name = request.pasteboard, name.hasPrefix("org.vaultos.preview.test."), name.count < 128 else { exit(2) }
board = NSPasteboard(name: NSPasteboard.Name(name))
#endif
switch request.action {
case "write":
    guard let text = request.text else { exit(2) }
    // One item carrying all three types, written with writeObjects: declareTypes would clear
    // the pasteboard again and drop the currentHostOnly option set just before it.
    let item = NSPasteboardItem()
    guard item.setString(text, forType: .string),
          item.setData(Data(), forType: concealed),
          item.setData(Data(), forType: transient) else { exit(3) }
    board.prepareForNewContents(with: .currentHostOnly)
    guard board.writeObjects([item]) else { exit(3) }
    reply(["changeCount": board.changeCount])
case "clear":
    // Clears only if nothing was copied since our write, so a later copy by the human survives.
    guard let expected = request.changeCount else { exit(2) }
    let unchanged = board.changeCount == expected
    if unchanged { board.clearContents() }
    reply(["cleared": unchanged])
#if VAULTOS_TEST
case "inspect":
    reply(["types": (board.types ?? []).map { $0.rawValue }, "text": board.string(forType: .string) ?? NSNull(), "changeCount": board.changeCount])
case "release":
    board.releaseGlobally()
    reply([:])
#endif
default:
    exit(2)
}
