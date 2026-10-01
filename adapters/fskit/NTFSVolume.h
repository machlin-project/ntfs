/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSResource.h"

@interface NTFSVolume : FSVolume <FSVolumePathConfOperations>
/* Takes core ownership only on success. The resource remains retained until
 * all child objects are invalidated and the core is unmounted. */
- (instancetype)initWithCore:(struct ntfs_volume *)core resource:(NTFSResource *)resource;
- (void)invalidate;
- (FSItem *)activate:(NSError **)error;
- (FSItem *)lookup:(FSFileName *)name
       inDirectory:(FSItem *)directory
	storedName:(FSFileName **)stored
	     error:(NSError **)error;
- (FSItemAttributes *)attributes:(FSItem *)item error:(NSError **)error;
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
