/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSResource.h"

typedef NS_ENUM(NSUInteger, NTFSNativeAccessMode) {
	NTFSNativeAccessUnselected,
	NTFSNativeAccessExtraction,
	NTFSNativeAccessImageEditing
};

enum {
	/* Bound trusted task configuration independently of disk geometry. */
	NTFS_FSKIT_OPTION_LIMIT = 128
};

/* Select native access explicitly. Neither mode maps a Windows principal.
 * Extraction has no mutation capability; image editing additionally requires
 * an authorized offline-image owner and authenticated per-operation access. */
FOUNDATION_EXPORT NSString *const NTFSExtractionAccessOption;
FOUNDATION_EXPORT NSString *const NTFSImageEditingAccessOption;

enum ntfs_result ntfs_native_access_mode(NSArray<NSString *> *, NTFSNativeAccessMode *);
/* Validate every image-mode option before resource acquisition or recovery.
 * Unsupported native roots, forced checker loads and unknown policy refuse. */
enum ntfs_result ntfs_native_image_options(NSArray<NSString *> *);
