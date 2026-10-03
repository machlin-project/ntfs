/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSAccessPolicy.h"
#include <limits.h>

NSString *const NTFSExtractionAccessOption = @"ntfs-access=extract";
static NSString *const accessOptionName = @"ntfs-access";
static NSString *const accessOptionPrefix = @"ntfs-access=";

enum ntfs_result
ntfs_native_access_mode(NSArray<NSString *> *options, NTFSNativeAccessMode *out)
{
	NSString *option, *part;
	NTFSNativeAccessMode selected = NTFSNativeAccessUnselected;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	*out = NTFSNativeAccessUnselected;
	if (options != nil && ![options isKindOfClass:NSArray.class]) {
		return NTFS_INVALID;
	}
	if (options.count > NTFS_FSKIT_OPTION_LIMIT) {
		return NTFS_RANGE;
	}
	for (option in options) {
		if (![option isKindOfClass:NSString.class] || option.length > PATH_MAX) {
			return NTFS_INVALID;
		}
		for (part in [option componentsSeparatedByString:@","]) {
			if ([part isEqualToString:accessOptionName] ||
			    [part isEqualToString:accessOptionPrefix]) {
				return NTFS_INVALID;
			}
			if (![part hasPrefix:accessOptionPrefix]) {
				continue;
			}
			if (selected != NTFSNativeAccessUnselected) {
				return NTFS_INVALID;
			}
			if (![part isEqualToString:NTFSExtractionAccessOption]) {
				return NTFS_UNSUPPORTED;
			}
			selected = NTFSNativeAccessExtraction;
		}
	}
	*out = selected;
	return NTFS_OK;
}
