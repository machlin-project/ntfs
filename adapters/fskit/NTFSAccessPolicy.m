/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSAccessPolicy.h"
#include <limits.h>

NSString *const NTFSExtractionAccessOption = @"ntfs-access=extract";
NSString *const NTFSImageEditingAccessOption = @"ntfs-access=image-edit";
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
			if ([part isEqualToString:NTFSExtractionAccessOption]) {
				selected = NTFSNativeAccessExtraction;
			} else if ([part isEqualToString:NTFSImageEditingAccessOption]) {
				selected = NTFSNativeAccessImageEditing;
			} else {
				return NTFS_UNSUPPORTED;
			}
		}
	}
	*out = selected;
	return NTFS_OK;
}

enum ntfs_result
ntfs_native_image_options(NSArray<NSString *> *options)
{
	NTFSNativeAccessMode selected;
	NSString *option, *part;
	NSUInteger index;
	enum ntfs_result result;

	result = ntfs_native_access_mode(options, &selected);
	if (result != NTFS_OK) {
		return result;
	}
	if (selected != NTFSNativeAccessUnselected && selected != NTFSNativeAccessImageEditing) {
		return NTFS_INVALID;
	}
	for (index = 0; index < options.count; index++) {
		option = options[index];
		if ([option isEqualToString:@"-o"]) {
			if (index + 1 == options.count || [options[index + 1] hasPrefix:@"-"]) {
				return NTFS_INVALID;
			}
			continue;
		}
		for (part in [option componentsSeparatedByString:@","]) {
			if ([part isEqualToString:NTFSImageEditingAccessOption] ||
			    [part isEqualToString:@"ro"] || [part isEqualToString:@"rw"] ||
			    [part isEqualToString:@"rdonly"] || [part isEqualToString:@"owners"] ||
			    [part isEqualToString:@"noowners"] ||
			    [part isEqualToString:@"nobrowse"] || [part isEqualToString:@"nodev"] ||
			    [part isEqualToString:@"nosuid"] || [part isEqualToString:@"noexec"] ||
			    [part isEqualToString:@"sync"] || [part isEqualToString:@"async"]) {
				continue;
			}
			return NTFS_UNSUPPORTED;
		}
	}
	return NTFS_OK;
}
