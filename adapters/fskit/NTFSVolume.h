/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSResource.h"
#import "NTFSLinks.h"
#import "NTFSReadCachePolicy.h"

typedef NS_ENUM(NSUInteger, NTFSVolumeLifecycle) {
	NTFSVolumeLoaded,
	NTFSVolumeActive,
	NTFSVolumeDraining,
	NTFSVolumeUnmounted,
	NTFSVolumeInvalidating,
	NTFSVolumeInvalidated
};

@interface NTFSVolume : FSVolume <FSVolumePathConfOperations>
/* Takes core ownership only on success. The resource remains retained until
 * all child objects are invalidated and the core is unmounted. */
- (instancetype)initWithCore:(struct ntfs_volume *)core resource:(NTFSResource *)resource;
/* Native namespace work budget, including hidden metadata and DOS aliases.
 * The ordinary initializer uses the default cap; limits are never silent skips. */
- (instancetype)initWithCore:(struct ntfs_volume *)core
		    resource:(NTFSResource *)resource
     maximumDirectoryEntries:(uint32_t)maximum;
/* The immutable policy binds explicit Windows roots to this core's serial.
 * Nil selects relative/current-volume paths without guessed drive aliases. */
- (instancetype)initWithCore:(struct ntfs_volume *)core
		    resource:(NTFSResource *)resource
     maximumDirectoryEntries:(uint32_t)maximum
		  linkPolicy:(NTFSLinkPolicy *)policy;
- (void)invalidate;
/* Admission state can be inspected without waiting for an outstanding read.
 * Unmount retains item identities for reclamation; invalidation is terminal. */
@property(readonly) NTFSVolumeLifecycle lifecycle;
/* Observation is independent of the operation monitor; returned policy state
 * does not authorize I/O. This observer is exclusively owned by the volume. */
@property(readonly) NTFSReadCachePolicy *readCachePolicy;
- (NTFSReadCachePolicy *)newReadCachePolicy;
/* Request policy may tighten the immutable core ceilings. The same read limits
 * also bound physical resource fragments, including alignment rounding. */
- (struct ntfs_operation_limits)operationLimits;
/* Serialize publication of native item results against reclaim and teardown.
 * Replies still run outside the core operation monitor. */
- (void)performItemPublication:(void (^)(void))publication;
/* Native bridge, invoked with publication/core ownership already serialized.
 * Older runtimes keep a node alive until the last FSItem reference disappears. */
- (BOOL)reclaimIfEligible:(FSItem *)item cleanup:(void (^)(void))cleanup;
- (FSItem *)activate:(NSError **)error;
- (FSItem *)activateWithOptions:(FSTaskOptions *)options error:(NSError **)error;
- (FSItem *)lookup:(FSFileName *)name
       inDirectory:(FSItem *)directory
	storedName:(FSFileName **)stored
	     error:(NSError **)error;
- (FSItemAttributes *)attributes:(FSItem *)item error:(NSError **)error;
- (FSFileName *)symbolicLink:(FSItem *)item error:(NSError **)error;
- (NSError *)enumerate:(FSItem *)directory
		cookie:(FSDirectoryCookie)cookie
	      verifier:(FSDirectoryVerifier)verifier
	    attributes:(BOOL)attributes
		packer:(FSDirectoryEntryPacker *)packer;
- (enum ntfs_result)readItem:(FSItem *)item
		      offset:(off_t)offset
		       bytes:(void *)bytes
		      length:(size_t)length
		   completed:(size_t *)completed;
- (NSArray<FSFileName *> *)xattrsForItem:(FSItem *)item error:(NSError **)error;
- (NSData *)xattrNamed:(FSFileName *)name ofItem:(FSItem *)item error:(NSError **)error;
@property(readonly) FSDirectoryVerifier directoryVerifier;
- (void)mountWithOptions:(FSTaskOptions *)options replyHandler:(void (^)(NSError *))reply;
- (void)unmountWithReplyHandler:(void (^)(void))reply;
- (void)synchronizeWithFlags:(FSSyncFlags)flags replyHandler:(void (^)(NSError *))reply;
- (void)reclaimItem:(FSItem *)item replyHandler:(void (^)(NSError *))reply;
@property(readonly) FSVolumeSupportedCapabilities *supportedVolumeCapabilities;
@property(readonly) FSStatFSResult *volumeStatistics;
@end

@interface NTFSLegacyVolume
    : NTFSVolume <FSVolumeOperations, FSVolumeReadWriteOperations, FSVolumeXattrOperations>
@end

#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
API_AVAILABLE(macos(27.0))
@interface NTFSModernVolume
    : NTFSVolume <FSVolumeHandler, FSVolumeReadWriteHandler, FSVolumeXattrHandler>
@end
#endif

NTFSVolume *ntfs_volume_create(struct ntfs_volume *core, NTFSResource *resource);
NTFSVolume *ntfs_volume_create_with_policy(
    struct ntfs_volume *core, NTFSResource *resource, NTFSLinkPolicy *policy);
