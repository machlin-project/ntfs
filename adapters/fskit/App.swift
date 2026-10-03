// Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
import SwiftUI

private enum Layout {
    static let spacing: CGFloat = 20
    static let iconSize: CGFloat = 44
    static let padding: CGFloat = 32
    static let width: CGFloat = 530
    static let height: CGFloat = 450
}

@main
struct NTFSApp: App {
    var body: some Scene {
        WindowGroup("Machlin NTFS") {
            VStack(alignment: .leading, spacing: Layout.spacing) {
                Image(systemName: "externaldrive.badge.checkmark")
                    .font(.system(size: Layout.iconSize)).foregroundStyle(.blue)
                Text("Machlin NTFS").font(.largeTitle.bold())
                Text("Read-only data extraction preview").font(.title3)
                Text("This app contains the NTFS filesystem extension. Enable it in System Settings on your dedicated test Mac before mounting a test volume.")
                Divider()
                Label("Reading preserves the original disk contents.", systemImage: "lock.shield")
                Label("Windows permissions are not enforced. Mounting requires an explicit choice of extraction mode.", systemImage: "info.circle")
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
