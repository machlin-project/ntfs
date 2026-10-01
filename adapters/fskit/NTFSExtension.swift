// Copyright (c) 2026 Dmitri Arekhta. All rights reserved.
import ExtensionFoundation
import FSKit

@main
struct NTFSExtension: UnaryFileSystemExtension {
    var fileSystem: FSUnaryFileSystem & FSUnaryFileSystemOperations {
        NTFSFileSystem()
    }
}
