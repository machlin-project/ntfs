// Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
import AppKit
import Darwin
import FSKit

private enum ImageControlError: LocalizedError {
    case usage, missingImage, staleBookmark, scopeRefused, changedImage, busy
    case ambiguousMount, invalidMount, unavailableRuntime, unavailableSDK, invalidCatalog

    var errorDescription: String? {
        switch self {
        case .usage: return "Usage: Machlin NTFS --image-command status|import FILE_NAME|mount IMAGE_ID|unmount IMAGE_ID|unmount-path MOUNT_PATH"
        case .missingImage: return "Choose this image in the app before using its saved identifier."
        case .staleBookmark: return "The saved permission is stale. Choose the image again."
        case .scopeRefused: return "macOS did not restore access to the selected image."
        case .changedImage: return "The selected image's identity or ownership changed."
        case .busy: return "Another image command is in progress."
        case .ambiguousMount: return "The image does not have exactly one matching NTFS mount."
        case .invalidMount: return "The reported mount is outside the managed volume directory."
        case .unavailableRuntime: return "Image editing requires macOS 27."
        case .unavailableSDK: return "Image editing is unavailable in this build. Rebuild with a macOS 27 or newer SDK."
        case .invalidCatalog: return "The saved image catalog is invalid."
        }
    }
}

private struct ImageIdentity: Codable, Equatable {
    let device: Int32
    let inode: UInt64
    let bytes: Int64
    let owner: UInt32
    let group: UInt32

    init(url: URL) throws {
        var information = stat()
        let result = url.withUnsafeFileSystemRepresentation { path in
            path.map { lstat($0, &information) } ?? -1
        }
        guard result == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        guard UInt32(information.st_mode) & UInt32(S_IFMT) == UInt32(S_IFREG),
              information.st_nlink == 1, information.st_size > 0,
              getuid() == geteuid(), information.st_uid == getuid() else {
            throw ImageControlError.changedImage
        }
        device = information.st_dev
        inode = information.st_ino
        bytes = information.st_size
        owner = information.st_uid
        group = information.st_gid
    }
}

private struct SavedImage: Codable {
    let id: String
    let sourceURL: String
    let name: String
    let identity: ImageIdentity
    let bookmark: Data

    func resolve() throws -> URL {
        var stale = false
        let url = try URL(resolvingBookmarkData: bookmark,
                          options: [.withSecurityScope, .withoutUI, .withoutMounting],
                          relativeTo: nil, bookmarkDataIsStale: &stale)
        guard !stale else { throw ImageControlError.staleBookmark }
        guard url.isFileURL, url.absoluteString == sourceURL else {
            throw ImageControlError.changedImage
        }
        return url
    }
}

private final class ImageCatalog {
    private static let maximumImages = 64
    private static let maximumBytes = 1024 * 1024
    private let file: URL
    let inbox: URL
    private var descriptor: Int32 = -1

    init() throws {
        let support = try FileManager.default.url(for: .applicationSupportDirectory,
            in: .userDomainMask, appropriateFor: nil, create: true)
        let directory = support.appendingPathComponent("SavedImages", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        file = directory.appendingPathComponent("images.json")
        inbox = directory.appendingPathComponent("Inbox", isDirectory: true)
        try FileManager.default.createDirectory(at: inbox, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let lock = directory.appendingPathComponent("commands.lock")
        let fd = lock.withUnsafeFileSystemRepresentation { path in
            path.map { Darwin.open($0, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600) } ?? -1
        }
        guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            Darwin.close(fd)
            throw ImageControlError.busy
        }
        descriptor = fd
    }

    deinit { close() }

    func close() {
        if descriptor >= 0 {
            flock(descriptor, LOCK_UN)
            Darwin.close(descriptor)
            descriptor = -1
        }
    }

    func images() throws -> [SavedImage] {
        guard FileManager.default.fileExists(atPath: file.path) else { return [] }
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        guard let bytes = attributes[.size] as? NSNumber,
              bytes.int64Value > 0, bytes.int64Value <= Self.maximumBytes else {
            throw ImageControlError.invalidCatalog
        }
        let images = try JSONDecoder().decode([SavedImage].self, from: Data(contentsOf: file))
        guard images.count <= Self.maximumImages,
              Set(images.map(\.id)).count == images.count,
              images.allSatisfy({ UUID(uuidString: $0.id) != nil }) else {
            throw ImageControlError.invalidCatalog
        }
        return images
    }

    func image(id: String) throws -> SavedImage {
        guard let image = try images().first(where: { $0.id == id }) else {
            throw ImageControlError.missingImage
        }
        return image
    }

    @discardableResult
    func remember(url: URL) throws -> SavedImage {
        let identity = try ImageIdentity(url: url)
        let bookmark = try url.bookmarkData(options: .withSecurityScope,
            includingResourceValuesForKeys: nil, relativeTo: nil)
        var saved = try images()
        let previous = saved.firstIndex(where: { $0.identity == identity })
        let image = SavedImage(id: previous.map { saved[$0].id } ?? UUID().uuidString,
            sourceURL: url.absoluteString, name: url.lastPathComponent,
            identity: identity, bookmark: bookmark)
        let resolved = try image.resolve()
        guard resolved.startAccessingSecurityScopedResource() else {
            throw ImageControlError.scopeRefused
        }
        defer { resolved.stopAccessingSecurityScopedResource() }
        guard try ImageIdentity(url: resolved) == identity else { throw ImageControlError.changedImage }
        if let previous { saved[previous] = image } else { saved.append(image) }
        guard saved.count <= Self.maximumImages else { throw ImageControlError.invalidCatalog }
        let data = try JSONEncoder().encode(saved)
        guard data.count <= Self.maximumBytes else { throw ImageControlError.invalidCatalog }
        try data.write(to: file, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        return image
    }
}

private struct ImageNativeMount {
    let source: String
    let path: String
    let owner: UInt32
    let readOnly: Bool

    var report: [String: Any] {
        ["path": path, "sourceURL": source, "mountOwnerUserID": owner, "readOnly": readOnly]
    }

    private static func string<T>(_ field: T) -> String {
        withUnsafeBytes(of: field) { bytes in
            String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
        }
    }

    static func all() throws -> [ImageNativeMount] {
        var table: UnsafeMutablePointer<statfs>?
        let count = getmntinfo(&table, MNT_NOWAIT)
        guard count > 0, let table else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        return (0..<Int(count)).compactMap { index in
            let entry = table[index]
            guard string(entry.f_fstypename) == "machlinntfs" else { return nil }
            return ImageNativeMount(source: string(entry.f_mntfromname),
                path: string(entry.f_mntonname), owner: entry.f_owner,
                readOnly: entry.f_flags & UInt32(MNT_RDONLY) != 0)
        }
    }
}

@MainActor
enum ImageOperations {
    private static let moduleID = "org.machlin.ntfs.filesystem"

    static var imageEditingAvailable: Bool {
        guard NTFSAppBuiltWithModernFSKit() else { return false }
        if #available(macOS 27.0, *) { return true }
        return false
    }

    static var imageEditingUnavailableReason: String {
        if !NTFSAppBuiltWithModernFSKit() {
            return ImageControlError.unavailableSDK.localizedDescription
        }
        return ImageControlError.unavailableRuntime.localizedDescription
    }

    static func requireImageEditing() throws {
        guard NTFSAppBuiltWithModernFSKit() else { throw ImageControlError.unavailableSDK }
        guard #available(macOS 27.0, *) else { throw ImageControlError.unavailableRuntime }
    }

    static func mountSelectedImage(_ url: URL) async throws -> URL {
        try requireImageEditing()
        guard url.isFileURL, url.startAccessingSecurityScopedResource() else {
            throw ImageControlError.scopeRefused
        }
        defer { url.stopAccessingSecurityScopedResource() }
        let catalog = try ImageCatalog()
        defer { catalog.close() }
        try catalog.remember(url: url)
        return try await mountScopedImage(url)
    }

    private static func mountScopedImage(_ url: URL) async throws -> URL {
        try requireImageEditing()
        let mounts = try ImageNativeMount.all()
        guard !mounts.contains(where: { $0.source == url.absoluteString }) else {
            throw ImageControlError.ambiguousMount
        }
        let resource = FSPathURLResource(url: url, writable: true)
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<URL, Error>) in
            NTFSAppMountImageResource(resource, moduleID) { mounted, error in
                if let error { continuation.resume(throwing: error) }
                else if let mounted { continuation.resume(returning: mounted) }
                else { continuation.resume(throwing: ImageControlError.invalidMount) }
            }
        }
    }

    static func unmount(_ url: URL) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            FileManager.default.unmountVolume(at: url, options: []) { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            }
        }
    }

    private static func unmountOwned(_ mount: ImageNativeMount, backingOwner: UInt32) async throws -> URL {
        let url = URL(fileURLWithPath: mount.path, isDirectory: true)
        guard getuid() == geteuid(), backingOwner == getuid(),
              url.path.hasPrefix("/Volumes/"), url.standardizedFileURL.path == url.path else {
            throw ImageControlError.invalidMount
        }
        try await unmount(url)
        return url
    }

    static func command(_ arguments: [String]) async throws -> [String: Any] {
        guard arguments.first == "--image-command", arguments.count >= 2 else {
            throw ImageControlError.usage
        }
        let action = arguments[1]
        guard (action == "status" && arguments.count == 2) ||
              ((action == "import" || action == "mount" || action == "unmount" || action == "unmount-path") && arguments.count == 3) else {
            throw ImageControlError.usage
        }
        if action == "import" {
            let name = arguments[2]
            guard !name.isEmpty, name != ".", name != "..", !name.contains("/"),
                  !name.utf8.contains(0), name.utf8.count <= 255 else { throw ImageControlError.usage }
        } else if action == "unmount-path" {
            let path = arguments[2]
            let url = URL(fileURLWithPath: path, isDirectory: true)
            guard path.hasPrefix("/Volumes/"), !path.utf8.contains(0),
                  url.path == path, url.standardizedFileURL.path == path else {
                throw ImageControlError.usage
            }
        } else if arguments.count == 3, UUID(uuidString: arguments[2]) == nil {
            throw ImageControlError.usage
        }
        // Refuse unavailable mounts before creating the catalog, restoring
        // permission, or touching an image. Other commands retain their scope.
        if action == "mount" { try requireImageEditing() }
        let catalog = try ImageCatalog()
        defer { catalog.close() }
        let mounts = try ImageNativeMount.all()
        var report: [String: Any] = ["result": "PASS", "command": action,
            "realUserID": getuid(), "effectiveUserID": geteuid(),
            "bundleVersion": Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") ?? "unknown"]
        if action == "status" {
            let runtimeSupported: Bool
            if #available(macOS 27.0, *) { runtimeSupported = true }
            else { runtimeSupported = false }
            report["imageEditing"] = ["buildSDKSupported": NTFSAppBuiltWithModernFSKit(),
                "runtimeSupported": runtimeSupported, "available": imageEditingAvailable]
            let modules = try await FSClient.shared.installedExtensions
            report["modules"] = modules.filter { $0.bundleIdentifier == moduleID }.map {
                ["bundleIdentifier": $0.bundleIdentifier, "enabled": $0.isEnabled]
            }
            report["images"] = try catalog.images().map { image in
                ["id": image.id, "name": image.name, "sourceURL": image.sourceURL,
                 "backingOwnerUserID": image.identity.owner,
                 "mounts": mounts.filter { $0.source == image.sourceURL }.map(\.report)] as [String: Any]
            }
            report["inboxPath"] = catalog.inbox.path
            report["mounts"] = mounts.map(\.report)
            return report
        }
        if action == "unmount-path" {
            // This also permits an ordinary teardown of an image mounted by an
            // earlier app version, which did not save its picker permission.
            let matches = mounts.filter { $0.path == arguments[2] }
            guard matches.count == 1 else { throw ImageControlError.ambiguousMount }
            let saved = try catalog.images().filter { $0.sourceURL == matches[0].source }
            let owner: UInt32
            if saved.count == 1 {
                owner = saved[0].identity.owner
            } else {
                guard saved.isEmpty, let source = URL(string: matches[0].source),
                      source.isFileURL else { throw ImageControlError.ambiguousMount }
                owner = try ImageIdentity(url: source).owner
            }
            report["mountURL"] = try await unmountOwned(matches[0], backingOwner: owner).path
            return report
        }
        if action == "import" {
            // Automation supplies generated images only in the app's own inbox.
            // External images require the ordinary picker permission. The
            // catalog creates and positively restores a real scoped bookmark.
            let image = try catalog.remember(url: catalog.inbox.appendingPathComponent(arguments[2]))
            report["imageID"] = image.id
            report["sourceURL"] = image.sourceURL
            return report
        }
        let image = try catalog.image(id: arguments[2])
        report["imageID"] = image.id
        if action == "unmount" {
            let matches = mounts.filter { $0.source == image.sourceURL }
            guard matches.count == 1 else { throw ImageControlError.ambiguousMount }
            report["mountURL"] = try await unmountOwned(matches[0], backingOwner: image.identity.owner).path
            return report
        }
        let url = try image.resolve()
        guard url.startAccessingSecurityScopedResource() else { throw ImageControlError.scopeRefused }
        defer { url.stopAccessingSecurityScopedResource() }
        guard try ImageIdentity(url: url) == image.identity else { throw ImageControlError.changedImage }
        let mounted = try await mountScopedImage(url)
        report["mountURL"] = mounted.path
        return report
    }

    static func runCommands(_ arguments: [String]) -> Never {
        NSApplication.shared.setActivationPolicy(.prohibited)
        Task { @MainActor in
            let report: [String: Any]
            let exitCode: Int32
            do {
                report = try await command(arguments)
                exitCode = EXIT_SUCCESS
            } catch {
                let native = error as NSError
                report = ["result": "FAIL", "error": error.localizedDescription,
                    "errorDomain": native.domain, "errorCode": native.code]
                exitCode = EXIT_FAILURE
            }
            do {
                var data = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
                data.append(0x0a)
                try FileHandle.standardOutput.write(contentsOf: data)
            } catch {
                Darwin.exit(EXIT_FAILURE)
            }
            Darwin.exit(exitCode)
        }
        NSApplication.shared.run()
        Darwin.exit(EXIT_FAILURE)
    }
}
