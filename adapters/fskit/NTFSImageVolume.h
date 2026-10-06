/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolume.h"
#import "NTFSImageTransport.h"

/* Private offline-image integration; native mutation handlers remain disabled.
 * The caller owns the authorized transport and excludes uncooperative access.
 * Successful construction takes a private recovered write owner and immutable
 * read view. Native FSItems keep their identities across initialized writes. */
NTFSVolume *ntfs_image_volume_create(NTFSImageTransport *, NSError **);

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
@end
