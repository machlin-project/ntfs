// Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
import SwiftUI

@main
struct NTFSApp: App {
    var body: some Scene {
        WindowGroup("Machlin NTFS") {
            VStack(alignment: .leading, spacing: 20) {
                Image(systemName: "externaldrive.badge.checkmark")
                    .font(.system(size: 44)).foregroundStyle(.blue)
                Text("Machlin NTFS").font(.largeTitle.bold())
                Text("Read-only developer preview").font(.title3)
                Text("This app contains the NTFS filesystem extension. Enable it in System Settings on your dedicated test Mac before mounting a test volume.")
                Divider()
                Label("Reading preserves the original disk contents.", systemImage: "lock.shield")
                Label("Writes and Windows permission translation are not available in this preview.", systemImage: "info.circle")
                Text("Not qualified for production use. Keep an independent backup of test data.")
                    .font(.callout).foregroundStyle(.secondary)
                Spacer()
                Text("© 2026 Dmitri Arekhta. All rights reserved.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(32).frame(width: 530, height: 450)
        }
        .windowResizability(.contentSize)
    }
}
