/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import <FSKit/FSKit.h>

NS_ASSUME_NONNULL_BEGIN

/* Runtime availability cannot make declarations appear in an older SDK. */
BOOL NTFSAppBuiltWithModernFSKit(void);
BOOL NTFSAppOpenFileSystemExtensionsSettings(void);
void NTFSAppMountImageResource(FSPathURLResource *resource, NSString *bundleID,
    void (^completionHandler)(NSURL *_Nullable mountPath, NSError *_Nullable error));

NS_ASSUME_NONNULL_END
