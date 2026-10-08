/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSAppSupport.h"
#include <errno.h>

BOOL
NTFSAppBuiltWithModernFSKit(void)
{
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
	return YES;
#else
	return NO;
#endif
}

BOOL
NTFSAppOpenFileSystemExtensionsSettings(void)
{
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
	if (@available(macOS 27.0, *)) {
		return [FSClient.sharedInstance openFileSystemExtensionsSettings];
	}
#endif
	return NO;
}

void
NTFSAppMountImageResource(FSPathURLResource *resource, NSString *bundleID,
    void (^completionHandler)(NSURL *_Nullable mountPath, NSError *_Nullable error))
{
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
	if (@available(macOS 27.0, *)) {
		[FSClient.sharedInstance mountSingleVolumeForResource:resource
						   bundleID:bundleID
						    options:@[ @"-o", @"rw,owners,ntfs-access=image-edit" ]
						  completionHandler:completionHandler];
		return;
	}
#else
	(void)resource;
	(void)bundleID;
#endif
	completionHandler(nil, [NSError errorWithDomain:NSPOSIXErrorDomain code:ENOTSUP
	    userInfo:@{NSLocalizedDescriptionKey: @"Image editing requires a macOS 27 SDK build and macOS 27."}]);
}
