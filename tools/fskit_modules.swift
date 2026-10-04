// Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
// Read-only native discovery; registration and enablement remain OS operations.
import Darwin
import Foundation
import FSKit

private enum QueryPolicy {
    static let timeoutSeconds: TimeInterval = 15
    static let filesystemBundleIdentifier = "org.machlin.ntfs.filesystem"
}

private func fail(_ error: NSError) -> Never {
    let message = "FSKit discovery failed: \(error.domain) \(error.code)\n"
    FileHandle.standardError.write(Data(message.utf8))
    exit(EXIT_FAILURE)
}

guard CommandLine.arguments.count == 1 else {
    FileHandle.standardError.write(Data("Usage: ntfs-fskit-modules\n".utf8))
    exit(EXIT_FAILURE)
}

// FSClient completion needs the main run loop to remain available. A missing
// callback is a failed query, never an empty or enabled module observation.
DispatchQueue.global().asyncAfter(deadline: .now() + QueryPolicy.timeoutSeconds) {
    fail(NSError(domain: NSPOSIXErrorDomain, code: Int(ETIMEDOUT)))
}
FSClient.shared.fetchInstalledExtensions { modules, error in
    if let error { fail(error as NSError) }
    guard let modules else {
        fail(NSError(domain: NSPOSIXErrorDomain, code: Int(EIO)))
    }
    let selected = modules.filter {
        $0.bundleIdentifier == QueryPolicy.filesystemBundleIdentifier
    }.sorted {
        $0.url.path < $1.url.path
    }.map {
        ["bundleIdentifier": $0.bundleIdentifier,
         "enabled": $0.isEnabled,
         "path": $0.url.path] as [String: Any]
    }
    do {
        let output = try JSONSerialization.data(withJSONObject: selected,
                                               options: [.sortedKeys])
        FileHandle.standardOutput.write(output)
        FileHandle.standardOutput.write(Data("\n".utf8))
    } catch {
        fail(error as NSError)
    }
    exit(EXIT_SUCCESS)
}
dispatchMain()
