/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolume.h"
#import "NTFSImageTransport.h"

/* Private offline-image integration without native mutation admission.
 * The caller owns the authorized transport and excludes uncooperative access.
 * Successful construction takes a private recovered write owner and immutable
 * read view. Native FSItems keep their identities across initialized writes. */
NTFSVolume *ntfs_image_volume_create(NTFSImageTransport *, NSError **);
/* Explicit native image editing on the modern runtime. The image's native owner
 * is the only admitted principal; Windows
 * DACL mapping remains outside this explicitly selected offline-image policy. */
NTFSVolume *ntfs_image_editing_volume_create(NTFSImageTransport *, NSError **);

@interface NTFSVolume (PrivateImageWrites)
/* Full durable completion reports the actual committed byte count even if a
 * later immutable-view allocation fails. Subsequent reads retry that allocation;
 * they never serve old metadata. Every child/reader closes before mutation.
 * An uncertain physical operation permanently stops this image transport. */
- (enum ntfs_result)overwriteImageItem:(FSItem *)item
				offset:(off_t)offset
				 bytes:(const void *)bytes
				length:(size_t)length
			      fileTime:(uint64_t)fileTime
			     completed:(size_t *)completed;
@property(readonly) BOOL nativeImageEditing;
- (NSError *)imageCallerErrorWithRealUserID:(uid_t)realUserID
			    effectiveUserID:(uid_t)effectiveUserID;
- (NSError *)checkImageAccessToItem:(FSItem *)item
		    requestedAccess:(FSAccessMask)access
			 realUserID:(uid_t)realUserID
		    effectiveUserID:(uid_t)effectiveUserID
			    allowed:(BOOL *)allowed;
- (NSError *)openImageItem:(FSItem *)item
		 withModes:(FSVolumeOpenModes)modes
		realUserID:(uid_t)realUserID
	   effectiveUserID:(uid_t)effectiveUserID;
/* Close may only remove previously admitted rights and needs no new view. */
- (NSError *)closeImageItem:(FSItem *)item keepingModes:(FSVolumeOpenModes)modes;
- (NSError *)imageReadErrorForItem:(FSItem *)item;
/* Prepare the reply, including updated attributes, before any mutation. The
 * builder must return a retained immutable result or nil on allocation refusal.
 * Durable completion performs no further reply/view allocation. */
- (id)writeImageContents:(NSData *)contents
		  toFile:(FSItem *)item
		atOffset:(off_t)offset
		fileTime:(uint64_t)fileTime
	    prepareReply:(id (^)(FSItemAttributes *, size_t))prepare
		   error:(NSError **)error;
- (enum ntfs_result)currentImageFileTime:(uint64_t *)fileTime;
@end
