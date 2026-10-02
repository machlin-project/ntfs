/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSNames.h"

enum {
	NTFS_FSKIT_LINK_TARGET_BYTES = PATH_MAX - 1,
	/* A minimum-size component and separator consume two native path bytes. */
	NTFS_FSKIT_LINK_COMPONENT_LIMIT = PATH_MAX / 2,
	/* Trusted mount configuration stays small independently of media size. */
	NTFS_FSKIT_WINDOWS_ROOT_LIMIT = 64,
	NTFS_FSKIT_OPTION_LIMIT = 128
};

/* Configuration binds Windows root aliases to this mounted owner, never to a
 * guessed drive letter or host path. Other volumes and UNC/device realms remain
 * explicit UNSUPPORTED operations. Recreate an owner to change its bindings. */
@interface NTFSLinkPolicy : NSObject
@property(readonly) uint64_t volumeSerial;
@property(readonly, copy) NSArray<NSString *> *windowsRoots;
- (instancetype)initWithVolumeSerial:(uint64_t)serial windowsRoots:(NSArray<NSString *> *)roots;
- (BOOL)ownsWindowsRoot:(NSString *)root;
@end

/* Immutable checked directory ancestry. Paths retain numeric provenance and
 * parent paths, never FSItems or core nodes. The core owner remains external. */
@interface NTFSDirectoryPath : NSObject
@property(readonly) struct ntfs_volume *volume;
@property(readonly) uint64_t reference;
@property(readonly) NSUInteger depth;
@property(readonly, strong) NTFSDirectoryPath *parent;
- (instancetype)initWithVolume:(struct ntfs_volume *)volume
		     reference:(uint64_t)reference
			parent:(NTFSDirectoryPath *)parent;
@end

/* Accept windows-root=C: or windows-root=Volume{GUID}, including -o lists.
 * Unrelated existing task options keep their existing handling. */
enum ntfs_result ntfs_native_link_policy(uint64_t, NSArray<NSString *> *, NTFSLinkPolicy **);
/* The caller supplies a snapshot from this same core owner and retains it.
 * Translation reads only checked metadata and
 * never changes a native enumeration cursor or reads a target's file content.
 * Targets are relative to the checked containing directory, even for bound
 * Windows absolute roots. Required namespace scans share one entry budget. */
enum ntfs_result ntfs_native_link_target(struct ntfs_volume *, const struct ntfs_reparse *,
    NTFSDirectoryPath *, NTFSLinkPolicy *, uint32_t, FSFileName **);
