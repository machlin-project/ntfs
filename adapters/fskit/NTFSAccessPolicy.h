/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSResource.h"

typedef NS_ENUM(NSUInteger, NTFSNativeAccessMode) {
	NTFSNativeAccessUnselected,
	NTFSNativeAccessExtraction
};

enum {
	/* Bound trusted task configuration independently of disk geometry. */
	NTFS_FSKIT_OPTION_LIMIT = 128
};

/* A caller must explicitly select extraction at load or activation. This
 * deliberately bypasses Windows discretionary policy, never maps an NTFS SID
 * to a native principal, and does not authorize an individual operation. */
FOUNDATION_EXPORT NSString *const NTFSExtractionAccessOption;

enum ntfs_result ntfs_native_access_mode(NSArray<NSString *> *, NTFSNativeAccessMode *);
