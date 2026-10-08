/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
/* Private components share the existing volume owner and native item layout.
 * Callers retain the original operation, publication and lifecycle locks. */
#import "NTFSVolume.h"
#import "NTFSNames.h"
#import "NTFSImageVolume.h"
#include "../../core/disk.h"
#include <sys/stat.h>

enum {
	NTFS_FSKIT_ITEM_LIMIT = 16384,
	/* Ancestry tokens have their own bound and retain no filesystem items. */
	NTFS_FSKIT_PATH_LIMIT = NTFS_FSKIT_ITEM_LIMIT,
	NTFS_FSKIT_STREAM_LIMIT = 1024,
	NTFS_FSKIT_XATTR_SIZE_BITS = 20,
	NTFS_FSKIT_XATTR_BYTES = (1u << NTFS_FSKIT_XATTR_SIZE_BITS) - 1,
	NTFS_STREAM_MANIFEST_VERSION = 1,
	NTFS_HEX_DIGITS_PER_BYTE = 2,
	NTFS_HEX_NIBBLE_BITS = 4,
	NTFS_HEX_DECIMAL_DIGITS = 10,
	NTFS_STREAM_ALIAS_DIGITS = sizeof(uint32_t) * NTFS_HEX_DIGITS_PER_BYTE,
	NTFS_DIRECTORY_CURRENT_ENTRY = 0,
	NTFS_DIRECTORY_VIRTUAL_ENTRIES = 2,
	/* Two held continuations cover interleaved readers without an unbounded
	 * cookie cache. Each still consumes the resource's aggregate memory budget. */
	NTFS_DIRECTORY_CONTINUATIONS = 2,
	NTFS_READ_ONLY_FILE_MODE = S_IRUSR,
	NTFS_READ_ONLY_DIRECTORY_MODE = S_IRUSR | S_IXUSR
};

struct ntfs_directory_continuation {
	struct ntfs_directory *cursor;
	struct ntfs_dirent pending_entry;
	uint64_t position;
	uint32_t inspected_entries;
	enum ntfs_result failure;
	BOOL pending, attributes, in_use, complete;
};

@interface NTFSDirectoryContinuations : NSObject {
      @public
	struct ntfs_directory_continuation *states;
	NSUInteger mostRecent;
      @private
	NTFSResource *_allocator;
}
- (instancetype)initWithResource:(NTFSResource *)resource;
- (void)clear;
@end

@interface NTFSItem : FSItem {
      @public
	struct ntfs_node *node;
	struct ntfs_stream *stream;
	struct ntfs_stream_catalog *catalog;
	struct ntfs_reparse *reparse;
	FSFileName *linkTarget;
	BOOL wof;
	NTFSDirectoryPath *directoryPath;
	NTFSDirectoryContinuations *continuations;
	uint64_t continuationEpoch;
	uint32_t activeEnumerations;
	/* Owning native namespace edge, obtained from a checked index lookup.
	 * Files may have many parents; only directories use this reference. */
	uint64_t parentReference;
	struct ntfs_stat stat;
	struct ntfs_link_counts links;
	FSVolumeOpenModes nativeOpenModes;
	BOOL retired;
}
@property(strong) NTFSVolume *owner;
@end

@class NTFSImagePathPublication;
struct image_mutation_input;

@interface NTFSVolume () {
	struct ntfs_volume *_core;
	struct ntfs_info _info;
	NTFSResource *_resource;
	NSMapTable<NSNumber *, NTFSItem *> *_items;
	NSMapTable<NSNumber *, NTFSDirectoryPath *> *_paths;
	NTFSLinkPolicy *_linkPolicy;
	NTFSNativeAccessMode _nativeAccessMode;
	uid_t _nativeUserID;
	gid_t _nativeGroupID;
	FSDirectoryVerifier _directoryVerifier;
	uint64_t _freeClusters;
	uint32_t _maximumDirectoryEntries;
	BOOL _active;
	NSLock *_lifecycleLock;
	NSRecursiveLock *_publicationLock;
	NTFSVolumeLifecycle _lifecycle;
	NSUInteger _pendingUnmounts;
	NTFSReadCachePolicy *_readCachePolicy;
	BOOL _maintenanceOnly;
	NTFSVolumeLifecycle _beforeMaintenance;
	enum ntfs_result _mountError, _checkFailure;
	NTFSImageTransport *_imageTransport;
	struct ntfs_overwrite *_writeOwner;
	BOOL _nativeImageEditing, _nativeReplyPreparing;
	NSUInteger _readOperations;
	BOOL _imageViewPending, _imageViewOpening, _imageMutationActive;
	enum ntfs_result _itemAdmission;
}

@end

@interface NTFSVolume (OperationBodies)
- (FSItem *)activateWithArguments:(NSArray<NSString *> *)arguments error:(NSError **)error;
- (FSItem *)performActivation:(NSArray<NSString *> *)arguments error:(NSError **)error;
- (enum ntfs_result)admissionResult;
- (enum ntfs_result)operationBudgetResult;
- (void)finishUnmountWithReplyHandler:(void (^)(void))reply;
@end

@interface NTFSVolume (ItemStorage)
- (void)releaseReadCaches:(NTFSItem *)item;
- (void)finishReadCaches:(NTFSItem *)item;
- (void)clearItemCaches:(NTFSItem *)item;
- (enum ntfs_result)directoryContinuationForItem:(NTFSItem *)item
					position:(uint64_t)position
				      attributes:(BOOL)attributes
					 initial:(BOOL)initial
				    continuation:(struct ntfs_directory_continuation **)out;
- (void)releaseItem:(NTFSItem *)item;
- (void)releaseUnreferencedItem:(NTFSItem *)item;
- (NTFSItem *)checkedItem:(FSItem *)item;
- (NTFSDirectoryPath *)rebindImagePath:(NTFSDirectoryPath *)old result:(enum ntfs_result *)result;
- (enum ntfs_result)rebindImageItem:(NTFSItem *)item;
- (NTFSItem *)adoptNode:(struct ntfs_node *)node
	parentReference:(uint64_t)parentReference
	 containingPath:(NTFSDirectoryPath *)containingPath
		  error:(NSError **)error;
- (NTFSItem *)directoryItemAtPath:(NTFSDirectoryPath *)path error:(NSError **)error;
@end

@interface NTFSVolume (ReadOperations)
- (FSItem *)performLookup:(FSFileName *)name
	      inDirectory:(FSItem *)directory
	       storedName:(FSFileName **)stored
		    error:(NSError **)error;
- (FSItemAttributes *)performAttributes:(FSItem *)item error:(NSError **)error;
- (FSItemAttributes *)attributesForStat:(const struct ntfs_stat *)stat
			     linkCounts:(const struct ntfs_link_counts *)links
			   symbolicLink:(BOOL)link;
- (FSFileName *)performSymbolicLink:(FSItem *)item error:(NSError **)error;
- (enum ntfs_result)performReadItem:(FSItem *)item
			     offset:(off_t)offset
			      bytes:(void *)bytes
			     length:(size_t)length
			  completed:(size_t *)completed;
- (struct ntfs_stream_catalog *)catalogForItem:(NTFSItem *)item error:(NSError **)error;
- (NSArray<FSFileName *> *)performXattrsForItem:(FSItem *)item error:(NSError **)error;
- (NSData *)streamManifest:(NTFSItem *)item
		   catalog:(struct ntfs_stream_catalog *)catalog
		     error:(NSError **)error;
- (NSData *)performXattrNamed:(FSFileName *)name ofItem:(FSItem *)item error:(NSError **)error;
- (NSError *)performEnumeration:(FSItem *)directory
			 cookie:(FSDirectoryCookie)cookie
		       verifier:(FSDirectoryVerifier)verifier
		     attributes:(BOOL)attributes
			 packer:(FSDirectoryEntryPacker *)packer;
@end

@interface NTFSVolume (ImageOperationBodies)
- (void)attachImageTransport:(NTFSImageTransport *)transport
		  writeOwner:(struct ntfs_overwrite *)owner
	       nativeEditing:(BOOL)editing;
- (enum ntfs_result)ensureImageView;
- (enum ntfs_result)detachImageView;
- (NSArray<NTFSImagePathPublication *> *)prepareImagePaths:(NSArray<NTFSItem *> *)items
					    movedReference:(uint64_t)moved
						 newParent:(NTFSDirectoryPath *)newParent
						     epoch:(struct ntfs_volume *)epoch
						    result:(enum ntfs_result *)result;
- (id)performImageMutation:(const struct image_mutation_input *)input
	      prepareReply:(NTFSImageMutationReply)prepare
		    status:(enum ntfs_result *)outStatus
		     error:(NSError **)error;
@end

static inline BOOL
image_file_write_type(const struct ntfs_stat *stat)
{
	return !stat->directory && !stat->reparse &&
	    (stat->reference & NTFS_REFERENCE_RECORD_MASK) >= NTFS_FIRST_USER_RECORD &&
	    (stat->file_attributes &
		(NTFS_FILE_READ_ONLY | NTFS_FILE_SYSTEM | NTFS_FILE_COMPRESSED |
		    NTFS_FILE_ENCRYPTED | NTFS_FILE_SPARSE)) == 0;
}

static inline BOOL
image_directory_write_type(const struct ntfs_stat *stat)
{
	return stat->directory && !stat->reparse &&
	    ((stat->reference & NTFS_REFERENCE_RECORD_MASK) == NTFS_ROOT_RECORD ||
		(stat->reference & NTFS_REFERENCE_RECORD_MASK) >= NTFS_FIRST_USER_RECORD) &&
	    (stat->file_attributes &
		(NTFS_FILE_READ_ONLY | NTFS_FILE_COMPRESSED | NTFS_FILE_ENCRYPTED |
		    NTFS_FILE_SPARSE)) == 0;
}

static inline FSItemID
item_id(uint64_t reference)
{
	return (reference & NTFS_REFERENCE_RECORD_MASK) == NTFS_ROOT_RECORD ? FSItemIDRootDirectory
									    : (FSItemID)reference;
}
