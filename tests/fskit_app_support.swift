// Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
import Darwin
import Foundation
import FSKit

@main
@MainActor
enum AppSupportTests {
    private static var checks = 0

    private static func require(_ condition: Bool, _ message: String) throws {
        guard condition else {
            throw NSError(domain: "NTFSAppSupportTests", code: 1,
                userInfo: [NSLocalizedDescriptionKey: message])
        }
        checks += 1
    }

    private static func refused(_ operation: () async throws -> Void, reason: String) async throws {
        var refusal: Error?
        do { try await operation() }
        catch { refusal = error }
        try require(refusal?.localizedDescription == reason, "Expected unavailable refusal: \(reason)")
    }

    static func main() async throws {
        try require(CommandLine.arguments.count == 2, "Expected actual SDK capability argument")
        let expectedSDK = CommandLine.arguments[1] == "modern"
        let builtWithModernSDK = NTFSAppBuiltWithModernFSKit()
        let runtimeSupported: Bool
        if #available(macOS 27.0, *) { runtimeSupported = true }
        else { runtimeSupported = false }
        try require(builtWithModernSDK == expectedSDK, "SDK capability must match selected SDK")
        try require(ImageOperations.imageEditingAvailable == (expectedSDK && runtimeSupported),
            "Image editing requires both SDK and runtime support")

        if ImageOperations.imageEditingAvailable {
            try ImageOperations.requireImageEditing()
            checks += 1
        } else {
            let reason = builtWithModernSDK ? "Image editing requires macOS 27." :
                "Image editing is unavailable in this build. Rebuild with a macOS 27 or newer SDK."
            try require(ImageOperations.imageEditingUnavailableReason == reason,
                "Unavailable reason must identify the SDK or runtime blocker")
            try require(!NTFSAppOpenFileSystemExtensionsSettings(),
                "Unavailable settings bridge must refuse without opening Settings")

            // Creating a resource value does not grant scope or mount it. This
            // branch only runs when the bridge has no available native route.
            let url = URL(fileURLWithPath: "/machlin-ntfs-unavailable-test-does-not-exist.ntfs")
            let resource = FSPathURLResource(url: url, writable: true)
            var callbacks = 0
            var nativeMount: URL?
            var nativeError: Error?
            NTFSAppMountImageResource(resource, "org.machlin.ntfs.filesystem") { mount, error in
                callbacks += 1
                nativeMount = mount
                nativeError = error
            }
            try require(callbacks == 1 && nativeMount == nil,
                "Unavailable bridge must complete exactly once without a mount")
            try require((nativeError as NSError?)?.domain == NSPOSIXErrorDomain &&
                (nativeError as NSError?)?.code == Int(ENOTSUP),
                "Unavailable bridge must report ENOTSUP")
            try await refused({ try ImageOperations.requireImageEditing() }, reason: reason)
            try await refused({ _ = try await ImageOperations.mountSelectedImage(url) }, reason: reason)
            try await refused({
                _ = try await ImageOperations.command([
                    "--image-command", "mount", "00000000-0000-0000-0000-000000000000"])
            }, reason: reason)
        }

        var invalidCommand: Error?
        do { _ = try await ImageOperations.command(["--image-command", "mount", "invalid-id"]) }
        catch { invalidCommand = error }
        try require(invalidCommand?.localizedDescription.hasPrefix("Usage:") == true,
            "Malformed commands must retain usage validation before availability checks")

        let report: [String: Any] = ["result": "PASS", "checks": checks,
            "buildSDKSupported": builtWithModernSDK, "runtimeSupported": runtimeSupported,
            "imageEditingAvailable": ImageOperations.imageEditingAvailable,
            "unavailableRefusalTests": ImageOperations.imageEditingAvailable ? "SKIP" : "PASS",
            "nativeMountAndSettingsExecution": "UNEXECUTED",
            "scope": "Real SDK bridge and Swift refusal checks; no app launch, registration, installation, or mount"]
        var data = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
        data.append(0x0a)
        try FileHandle.standardOutput.write(contentsOf: data)
    }
}
