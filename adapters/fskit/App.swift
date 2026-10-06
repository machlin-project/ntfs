// Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
import AppKit
import FSKit
import SwiftUI

private enum Layout {
    static let spacing: CGFloat = 16
    static let iconSize: CGFloat = 44
    static let padding: CGFloat = 32
    static let width: CGFloat = 620
    static let height: CGFloat = 660
}

@MainActor
private final class ImageMount: ObservableObject {
    @Published var busy = false
    @Published var mountURL: URL?
    @Published var status = "Choose an image you own to mount it for editing."

    func chooseImage() {
        guard !busy, mountURL == nil else { return }
        guard #available(macOS 27.0, *) else {
            status = "Image editing requires macOS 27."
            return
        }
        busy = true
        let panel = NSOpenPanel()
        panel.title = "Choose an NTFS image"
        panel.message = "Select an offline NTFS partition image you own. Keep an independent backup."
        panel.prompt = "Mount for editing"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.resolvesAliases = false
        guard panel.runModal() == .OK, let url = panel.url else {
            busy = false
            return
        }
        Task { await mountImage(url) }
    }

    @available(macOS 27.0, *)
    private func mountImage(_ url: URL) async {
        defer { busy = false }
        status = "Mounting \(url.lastPathComponent)…"
        do {
            let mounted = try await ImageOperations.mountSelectedImage(url)
            mountURL = mounted
            status = "Mounted at \(mounted.path)."
        } catch {
            status = "Could not mount the image: \(error.localizedDescription)"
        }
    }

    func unmountImage() {
        guard !busy, let url = mountURL else { return }
        busy = true
        status = "Unmounting the image…"
        // An ordinary unmount must drain the extension's writes; never force it.
        FileManager.default.unmountVolume(at: url, options: []) { error in
            Task { @MainActor in
                if let error {
                    self.status = "Could not unmount the image: \(error.localizedDescription)"
                } else {
                    self.mountURL = nil
                    self.status = "Image unmounted. You can choose it again."
                }
                self.busy = false
            }
        }
    }
}

struct NTFSApp: App {
    @StateObject private var imageMount = ImageMount()

    var body: some Scene {
        WindowGroup("Machlin NTFS") {
            VStack(alignment: .leading, spacing: Layout.spacing) {
                Image(systemName: "externaldrive.badge.checkmark")
                    .font(.system(size: Layout.iconSize)).foregroundStyle(.blue)
                Text("Machlin NTFS").font(.largeTitle.bold())
                Text("Data extraction and image editing preview").font(.title3)
                Text("Enable the NTFS filesystem extension in System Settings on your dedicated test Mac before mounting a test volume.")
                Divider()
                Label("Extract supported contents, or edit existing initialized file ranges in an NTFS image on macOS 27.", systemImage: "externaldrive")
                Label("Choose extraction or image editing explicitly. Image editing is restricted to the image owner's native account; Windows permissions are not applied.", systemImage: "info.circle")
                if #available(macOS 27.0, *) {
                    HStack {
                        Button("Edit an NTFS image…") { imageMount.chooseImage() }
                            .disabled(imageMount.busy || imageMount.mountURL != nil)
                        if let url = imageMount.mountURL {
                            Button("Show in Finder") { NSWorkspace.shared.open(url) }
                            Button("Unmount") { imageMount.unmountImage() }
                                .disabled(imageMount.busy)
                        }
                        Button("Extension settings") {
                            _ = FSClient.shared.openFileSystemExtensionsSettings()
                        }
                    }
                    Text(imageMount.status).font(.callout)
                        .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                } else {
                    Text("Image editing requires macOS 27.").font(.callout)
                }
                Text("Not qualified for production use. Keep an independent backup of test data.")
                    .font(.callout).foregroundStyle(.secondary)
                Spacer()
                Text("© 2026 Dmitri Arekhta. All rights reserved.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(Layout.padding).frame(width: Layout.width, height: Layout.height)
        }
        .windowResizability(.contentSize)
    }
}

@main
@MainActor
enum NTFSProgram {
    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        if arguments.contains("--image-command") {
            ImageOperations.runCommands(arguments)
        }
        NTFSApp.main()
    }
}
