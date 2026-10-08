/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolumeInternal.h"
#include "../../core/write_owner.h"
#include "../../core/write_mutation.h"
#include <errno.h>
#include <limits.h>
#include <time.h>

static NSError *
image_access_denied(void)
{
	return [NSError errorWithDomain:NSPOSIXErrorDomain code:EACCES userInfo:nil];
}

static id
image_write_failure(NSError **error, enum ntfs_result result)
{
	if (error != NULL) {
		*error = ntfs_error(result);
	}
	return nil;
}

struct image_mutation_input {
	enum ntfs_write_mutation_kind kind;
	__unsafe_unretained FSItem *item, *sourceDirectory, *destinationDirectory, *overItem;
	__unsafe_unretained FSFileName *sourceName, *destinationName;
	__unsafe_unretained NSData *contents;
	uint64_t size, offset, fileTime;
	struct ntfs_write_creation_times creationTimes;
	BOOL requireWriteOpen;
};

static enum ntfs_result
image_mutation_name(FSFileName *name, uint16_t *units, struct ntfs_write_name *out)
{
	enum ntfs_result result;

	if (![name isKindOfClass:FSFileName.class] || name.data.length == 0 ||
	    name.data.length > NTFS_FSKIT_NATIVE_NAME_BYTES || ntfs_native_name_reserved(name)) {
		return NTFS_INVALID;
	}
	result = ntfs_utf8_to_utf16(
	    name.data.bytes, name.data.length, units, NTFS_NAME_MAX, &out->count);
	if (result == NTFS_OK) {
		out->units = units;
	}
	return result;
}

static BOOL
image_set_attributes_supported(FSItemSetAttributesRequest *request, FSItemAttribute allowed)
{
	FSItemAttribute bit;

	if (![request isKindOfClass:FSItemSetAttributesRequest.class]) {
		return NO;
	}
	for (bit = FSItemAttributeType; bit <= FSItemAttributeInhibitKernelOffloadedIO; bit <<= 1) {
		if ((bit & allowed) == 0 && [request isValid:bit]) {
			return NO;
		}
	}
	return YES;
}

static enum ntfs_result
image_time_filetime(struct timespec time, uint64_t *filetime)
{
	uint64_t seconds, ticks, fraction;

	if (time.tv_nsec < 0 || (uint64_t)time.tv_nsec >= NSEC_PER_SEC) {
		return NTFS_RANGE;
	}
	if (time.tv_sec < 0) {
		if (time.tv_sec < -(int64_t)(NTFS_TIME_EPOCH / NTFS_TIME_TICKS)) {
			return NTFS_RANGE;
		}
		seconds = (uint64_t)-time.tv_sec;
		ticks = NTFS_TIME_EPOCH - seconds * NTFS_TIME_TICKS;
	} else {
		seconds = (uint64_t)time.tv_sec;
		if (seconds > (INT64_MAX - NTFS_TIME_EPOCH) / NTFS_TIME_TICKS) {
			return NTFS_RANGE;
		}
		ticks = NTFS_TIME_EPOCH + seconds * NTFS_TIME_TICKS;
	}
	fraction = (uint64_t)time.tv_nsec / NTFS_TIME_NANOSECONDS_PER_TICK;
	if (fraction > INT64_MAX - ticks) {
		return NTFS_RANGE;
	}
	*filetime = ticks + fraction;
	return NTFS_OK;
}

static enum ntfs_result
image_creation_times(
    FSItemSetAttributesRequest *attributes, struct ntfs_write_creation_times *times)
{
	enum ntfs_result result;

	if ([attributes isValid:FSItemAttributeBirthTime]) {
		result = image_time_filetime(attributes.birthTime, &times->created);
		if (result != NTFS_OK) {
			return result;
		}
		times->fields |= NTFS_WRITE_CREATION_CREATED;
	}
	if ([attributes isValid:FSItemAttributeModifyTime]) {
		result = image_time_filetime(attributes.modifyTime, &times->modified);
		if (result != NTFS_OK) {
			return result;
		}
		times->fields |= NTFS_WRITE_CREATION_MODIFIED;
	}
	if ([attributes isValid:FSItemAttributeChangeTime]) {
		result = image_time_filetime(attributes.changeTime, &times->changed);
		if (result != NTFS_OK) {
			return result;
		}
		times->fields |= NTFS_WRITE_CREATION_CHANGED;
	}
	if ([attributes isValid:FSItemAttributeAccessTime]) {
		result = image_time_filetime(attributes.accessTime, &times->accessed);
		if (result != NTFS_OK) {
			return result;
		}
		times->fields |= NTFS_WRITE_CREATION_ACCESSED;
	}
	return NTFS_OK;
}

@interface NTFSImagePathPublication : NSObject
@property(strong) NTFSItem *item;
@property(strong) NTFSDirectoryPath *path;
@end

@implementation NTFSImagePathPublication
@end

static NTFSVolume *
image_volume_create(NTFSImageTransport *transport, BOOL editing, NSError **error)
{
	struct ntfs_overwrite_environment environment;
	struct ntfs_overwrite_admission *admission = NULL;
	__block struct ntfs_write_recovery_report recovered;
	__block struct ntfs_overwrite *owner = NULL;
	struct ntfs_environment view;
	struct ntfs_volume *core = NULL;
	__attribute__((objc_precise_lifetime)) NTFSResource *resource = nil;
	NTFSVolume *volume = nil;
	enum ntfs_result result = NTFS_INVALID;

	if (transport != nil) {
		environment = [transport overwriteEnvironment];
		admission =
		    environment.reader.allocate(environment.reader.context, sizeof(*admission));
		result = admission == NULL ? NTFS_NO_MEMORY : [transport performExclusiveAccess:^{
		  return editing
		      ? ntfs_write_mutation_owner_open(&environment, admission, &recovered, &owner)
		      : ntfs_write_owner_open(&environment, admission, &recovered, &owner);
		}];
		if (admission != NULL) {
			environment.reader.release(
			    environment.reader.context, admission, sizeof(*admission));
		}
	}
	if (result == NTFS_OK) {
		resource = [transport newReadResource];
		result = resource != nil    ? NTFS_OK
		    : transport.isAvailable ? NTFS_NO_MEMORY
					    : NTFS_IO;
	}
	if (result == NTFS_OK) {
		view = [resource environment];
		result = ntfs_mount(&view, NULL, &core);
	}
	if (result == NTFS_OK) {
		volume = ntfs_volume_create_with_policies(
		    core, resource, nil, NTFSNativeAccessExtraction);
		if (volume == nil) {
			result = NTFS_NO_MEMORY;
		} else {
			[volume attachImageTransport:transport
					  writeOwner:owner
				       nativeEditing:editing];
		}
	}
	if (result != NTFS_OK) {
		(void)ntfs_unmount(core);
		resource = nil;
		ntfs_overwrite_close(owner);
	}
	if (error != NULL) {
		*error = ntfs_error(result);
	}
	return volume;
}

NTFSVolume *
ntfs_image_volume_create(NTFSImageTransport *transport, NSError **error)
{
	return image_volume_create(transport, NO, error);
}

NTFSVolume *
ntfs_image_editing_volume_create(NTFSImageTransport *transport, NSError **error)
{
	return image_volume_create(transport, YES, error);
}

@implementation NTFSVolume (PrivateImageWrites)

- (void)attachImageTransport:(NTFSImageTransport *)transport
		  writeOwner:(struct ntfs_overwrite *)owner
	       nativeEditing:(BOOL)editing
{
	NSAssert(_imageTransport == nil && _writeOwner == NULL, @"NTFS image owner binding");
	_imageTransport = transport;
	_writeOwner = owner;
	_nativeImageEditing = editing;
	if (editing) {
		_nativeAccessMode = NTFSNativeAccessImageEditing;
		_nativeUserID = transport.fileOwnerUserID;
		_nativeGroupID = transport.fileOwnerGroupID;
	}
}

- (enum ntfs_result)ensureImageView
{
	__attribute__((objc_precise_lifetime)) NTFSResource *resource;
	struct ntfs_environment environment;
	struct ntfs_volume *core = NULL;
	struct ntfs_info info;
	enum ntfs_result result;
	NTFSVolumeLifecycle state;
	BOOL drained = NO;

	if (!_imageViewPending) {
		return NTFS_OK;
	}
	state = self.lifecycle;
	if (_imageViewOpening || state == NTFSVolumeWriting) {
		return NTFS_BUSY;
	}
	if (state != NTFSVolumeLoaded && state != NTFSVolumeActive &&
	    state != NTFSVolumeUnmounted) {
		return NTFS_STALE;
	}
	if (!_imageTransport.isAvailable) {
		return NTFS_IO;
	}
	_imageViewOpening = YES;
	@try {
		resource = [_imageTransport newReadResource];
		if (resource == nil) {
			return _imageTransport.isAvailable ? NTFS_NO_MEMORY : NTFS_IO;
		}
		environment = [resource environment];
		result = ntfs_mount(&environment, NULL, &core);
		if (result == NTFS_OK) {
			ntfs_get_info(core, &info);
			if (info.serial != _info.serial || info.size_bytes != _info.size_bytes ||
			    info.cluster_count != _info.cluster_count ||
			    info.sector_size != _info.sector_size ||
			    info.cluster_size != _info.cluster_size ||
			    info.record_size != _info.record_size ||
			    info.index_size != _info.index_size) {
				result = NTFS_STALE;
			}
		}
		if (result == NTFS_OK && !resource.isAvailable) {
			result = NTFS_IO;
		}
		if (result == NTFS_OK) {
			/* Teardown can close admission while this unpublished mount reads,
			 * including by reentry before a native operation scope exists. */
			[_lifecycleLock lock];
			if (_lifecycle == NTFSVolumeLoaded || _lifecycle == NTFSVolumeActive ||
			    _lifecycle == NTFSVolumeUnmounted) {
				_core = core;
				_resource = resource;
				_imageViewPending = NO;
			} else {
				result = NTFS_STALE;
				drained = YES;
			}
			[_lifecycleLock unlock];
		}
		if (result != NTFS_OK) {
			(void)ntfs_unmount(core);
			resource = nil;
			if (result != NTFS_NO_MEMORY && !drained) {
				[_imageTransport invalidate];
			}
		}
		return result;
	} @finally {
		_imageViewOpening = NO;
		if (self.lifecycle == NTFSVolumeInvalidating) {
			/* Ordinary read callers hold only the operation monitor. Drain on
			 * another context to preserve publication-lock-before-monitor order,
			 * including a bare reentrant invalidate with no pending reply. */
			dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
			  [self invalidate];
			});
		}
	}
}

- (enum ntfs_result)detachImageView
{
	NTFSItem *item;
	enum ntfs_result result;

	for (item in _items.objectEnumerator.allObjects) {
		[self clearItemCaches:item];
		ntfs_node_close(item->node);
		item->node = NULL;
		/* The path remains a numeric ancestry token. Its old core pointer is
		 * never followed; rebind it before any native consumer can use it. */
	}
	[_paths removeAllObjects];
	result = ntfs_unmount(_core);
	if (result == NTFS_OK) {
		_core = NULL;
		_resource = nil;
		_imageViewPending = YES;
	}
	return result;
}

- (NSArray<NTFSImagePathPublication *> *)prepareImagePaths:(NSArray<NTFSItem *> *)items
					    movedReference:(uint64_t)moved
						 newParent:(NTFSDirectoryPath *)newParent
						     epoch:(struct ntfs_volume *)epoch
						    result:(enum ntfs_result *)result
{
	NSMutableDictionary<NSNumber *, NTFSDirectoryPath *> *memo =
	    [NSMutableDictionary dictionary];
	NSMutableArray<NTFSImagePathPublication *> *publications = [NSMutableArray array];
	NSMutableArray<NTFSDirectoryPath *> *ancestry;
	NTFSItem *item;
	NTFSDirectoryPath *entry, *path;
	NTFSImagePathPublication *publication;
	NSNumber *key;
	NSUInteger index;

	*result = NTFS_OK;
	if (memo == nil || publications == nil) {
		*result = NTFS_NO_MEMORY;
		return nil;
	}
	for (item in items) {
		if (item->directoryPath == nil || item->retired) {
			continue;
		}
		ancestry = [NSMutableArray array];
		if (ancestry == nil) {
			*result = NTFS_NO_MEMORY;
			return nil;
		}
		path = nil;
		for (entry = item->directoryPath; entry != nil; entry = entry.parent) {
			path = memo[@(entry.reference)];
			if (path != nil) {
				break;
			}
			if (ancestry.count >= NTFS_FSKIT_LINK_COMPONENT_LIMIT) {
				*result = NTFS_RANGE;
				return nil;
			}
			[ancestry addObject:entry];
		}
		for (index = ancestry.count; index != 0; index--) {
			entry = ancestry[index - 1];
			if (memo.count >= NTFS_FSKIT_PATH_LIMIT) {
				*result = NTFS_NO_MEMORY;
				return nil;
			}
			path = [[NTFSDirectoryPath alloc]
			    initWithVolume:epoch
				 reference:entry.reference
				    parent:entry.reference == moved ? newParent : path];
			key = @(entry.reference);
			if (path == nil || key == nil) {
				*result = NTFS_NO_MEMORY;
				return nil;
			}
			memo[key] = path;
		}
		publication = [[NTFSImagePathPublication alloc] init];
		if (publication == nil) {
			*result = NTFS_NO_MEMORY;
			return nil;
		}
		publication.item = item;
		publication.path = path;
		[publications addObject:publication];
	}
	return publications;
}

- (id)performImageMutation:(const struct image_mutation_input *)input
	      prepareReply:(NTFSImageMutationReply)prepare
		    status:(enum ntfs_result *)outStatus
		     error:(NSError **)error
{
	__block struct ntfs_write_mutation_execution *prepared = NULL;
	__block struct ntfs_write_mutation_report report = {0};
	__block id nativeReply = nil;
	__block NSError *preparedError = nil;
	__block NTFSItem *created = nil;
	__block NSNumber *createdKey = nil;
	__block NSArray<NTFSImagePathPublication *> *paths = nil;
	NSArray<NTFSItem *> *items;
	NTFSItem *item = nil, *source = nil, *destination = nil, *over = nil;
	NTFSImagePathPublication *publication;
	NTFSDirectoryPath *sourcePath, *destinationPath;
	struct ntfs_volume *epoch;
	struct ntfs_write_mutation_request request = {0};
	uint16_t sourceUnits[NTFS_NAME_MAX], destinationUnits[NTFS_NAME_MAX];
	__block enum ntfs_result result = NTFS_INVALID;
	BOOL committed = NO, invalidating, namespaceOperation;

	if (error != NULL) {
		*error = nil;
	}
	if (outStatus != NULL) {
		*outStatus = NTFS_INVALID;
	}
	[_publicationLock lock];
	@try {
		@synchronized(self) {
			if (self.lifecycle == NTFSVolumeInvalidating ||
			    self.lifecycle == NTFSVolumeInvalidated) {
				return image_write_failure(error, result = NTFS_STALE);
			}
			if (!_nativeImageEditing) {
				return image_write_failure(error, result = NTFS_READ_ONLY);
			}
			if (prepare == nil || input->fileTime > INT64_MAX) {
				return image_write_failure(error, result = NTFS_INVALID);
			}
			if (_imageTransport == nil || _writeOwner == NULL) {
				return image_write_failure(error, result = NTFS_STALE);
			}
			if (_readOperations != 0 || _imageViewOpening || _nativeReplyPreparing ||
			    _imageMutationActive) {
				return image_write_failure(error, result = NTFS_BUSY);
			}
			_imageMutationActive = YES;
			_nativeReplyPreparing = YES;
			@try {
				result = [self ensureImageView];
				if (result == NTFS_OK) {
					result = [self admissionResult];
				}
				if (result != NTFS_OK) {
					return image_write_failure(error, result);
				}
				if (input->item != nil) {
					item = [self checkedItem:input->item];
					if (item == nil) {
						return image_write_failure(
						    error, result = _itemAdmission);
					}
				}
				if (input->sourceDirectory != nil) {
					source = [self checkedItem:input->sourceDirectory];
					if (source == nil) {
						return image_write_failure(
						    error, result = _itemAdmission);
					}
					if (!image_directory_write_type(&source->stat) ||
					    source->linkTarget != nil) {
						return image_write_failure(
						    error, result = NTFS_UNSUPPORTED);
					}
				}
				if (input->destinationDirectory != nil) {
					destination =
					    [self checkedItem:input->destinationDirectory];
					if (destination == nil) {
						return image_write_failure(
						    error, result = _itemAdmission);
					}
					if (!image_directory_write_type(&destination->stat) ||
					    destination->linkTarget != nil) {
						return image_write_failure(
						    error, result = NTFS_UNSUPPORTED);
					}
				}
				if (input->overItem != nil) {
					over = [self checkedItem:input->overItem];
					if (over == nil) {
						return image_write_failure(
						    error, result = _itemAdmission);
					}
				}
				request.kind = input->kind;
				if ((request.kind == NTFS_WRITE_RENAME ||
					request.kind == NTFS_WRITE_REMOVE_FILE) &&
				    item == nil) {
					return image_write_failure(error, result = NTFS_INVALID);
				}
				if (request.kind == NTFS_WRITE_REMOVE_FILE && item != nil &&
				    item->stat.directory) {
					request.kind = NTFS_WRITE_REMOVE_DIRECTORY;
				}
				namespaceOperation = request.kind != NTFS_WRITE_RESIZE_FILE &&
				    request.kind != NTFS_WRITE_GROWING_RANGE;
				if (input->requireWriteOpen &&
				    (item == nil ||
					(item->nativeOpenModes & FSVolumeOpenModesWrite) == 0)) {
					result = NTFS_READ_ONLY;
					if (error != NULL) {
						*error = image_access_denied();
					}
					return nil;
				}
				if ((request.kind == NTFS_WRITE_REMOVE_FILE ||
					request.kind == NTFS_WRITE_REMOVE_DIRECTORY) &&
				    item != nil && item->nativeOpenModes != 0) {
					return image_write_failure(
					    error, result = NTFS_UNSUPPORTED);
				}
				if (over != nil && over != item && over->nativeOpenModes != 0) {
					return image_write_failure(
					    error, result = NTFS_UNSUPPORTED);
				}
				if (namespaceOperation) {
					if (source == nil) {
						return image_write_failure(
						    error, result = NTFS_INVALID);
					}
					request.source.parent_reference = source->stat.reference;
					result = image_mutation_name(
					    input->sourceName, sourceUnits, &request.source);
					if (result == NTFS_OK &&
					    request.kind == NTFS_WRITE_RENAME) {
						if (destination == nil) {
							return image_write_failure(
							    error, result = NTFS_INVALID);
						}
						request.destination.parent_reference =
						    destination->stat.reference;
						result = image_mutation_name(input->destinationName,
						    destinationUnits, &request.destination);
					}
					if (result != NTFS_OK) {
						return image_write_failure(error, result);
					}
				} else if (item == nil) {
					return image_write_failure(error, result = NTFS_INVALID);
				}
				request.reference = item != nil ? item->stat.reference : 0;
				request.filetime = input->fileTime;
				request.creation_times = input->creationTimes;
				request.size = input->size;
				request.offset = input->offset;
				request.replace = over != nil;
				if (request.kind == NTFS_WRITE_GROWING_RANGE) {
					if (![input->contents isKindOfClass:NSData.class]) {
						return image_write_failure(
						    error, result = NTFS_INVALID);
					}
					request.data = input->contents.bytes;
					request.bytes = input->contents.length;
				}
				epoch = _core;
				sourcePath = source != nil ? source->directoryPath : nil;
				destinationPath =
				    destination != nil ? destination->directoryPath : nil;
				items = _items.objectEnumerator.allObjects;
				[_lifecycleLock lock];
				if (_lifecycle == NTFSVolumeActive && _pendingUnmounts == 0) {
					_lifecycle = NTFSVolumeWriting;
					result = NTFS_OK;
				} else {
					result = NTFS_STALE;
				}
				[_lifecycleLock unlock];
				if (result == NTFS_OK) {
					result = [self detachImageView];
				}
				if (result != NTFS_OK) {
					return image_write_failure(error, result);
				}
				result = [_imageTransport performExclusiveAccess:^{
				  const struct ntfs_write_mutation_preview *preview;
				  FSItemAttributes *attrs,
				      *sourceAttrs = nil, *destinationAttrs = nil, *overAttrs = nil;
				  FSFileName *stored = nil, *requestedName;
				  id freeSpace = nil;
				  enum ntfs_result preparedResult;

				  preparedResult = ntfs_write_mutation_execution_prepare(
				      self->_writeOwner, &request, &prepared);
				  if (preparedResult != NTFS_OK) {
					  return preparedResult;
				  }
				  preview = ntfs_write_mutation_execution_preview(prepared);
				  if ((item != nil &&
					  preview->item.stat.reference != item->stat.reference) ||
				      (over != nil && over != item &&
					  (!preview->over_item_present ||
					      preview->over_item.stat.reference !=
						  over->stat.reference))) {
					  return NTFS_STALE;
				  }
				  if (namespaceOperation) {
					  requestedName = request.kind == NTFS_WRITE_RENAME
					      ? input->destinationName
					      : input->sourceName;
					  stored =
					      [FSFileName nameWithBytes:requestedName.data.bytes
								 length:requestedName.data.length];
					  if (stored == nil) {
						  return NTFS_NO_MEMORY;
					  }
				  }
				  if (request.kind == NTFS_WRITE_CREATE_FILE ||
				      request.kind == NTFS_WRITE_CREATE_DIRECTORY) {
					  if (self->_items.count >= NTFS_FSKIT_ITEM_LIMIT) {
						  return NTFS_NO_MEMORY;
					  }
					  created = [[NTFSItem alloc] init];
					  createdKey = @(preview->item.stat.reference);
					  if (created == nil || createdKey == nil) {
						  return NTFS_NO_MEMORY;
					  }
					  created->stat = preview->item.stat;
					  created->links = preview->item.links;
					  if (created->stat.directory) {
						  created->parentReference =
						      request.source.parent_reference;
						  created->directoryPath =
						      [[NTFSDirectoryPath alloc]
							  initWithVolume:epoch
							       reference:created->stat.reference
								  parent:sourcePath];
						  if (created->directoryPath == nil) {
							  return NTFS_NO_MEMORY;
						  }
					  }
					  created.owner = self;
					  [self->_items setObject:created forKey:createdKey];
				  }
				  if (request.kind == NTFS_WRITE_RENAME &&
				      preview->item.stat.directory) {
					  paths =
					      [self prepareImagePaths:items
						       movedReference:preview->item.stat.reference
							    newParent:destinationPath
								epoch:epoch
							       result:&preparedResult];
					  if (paths == nil) {
						  return preparedResult;
					  }
				  }
				  attrs = [self attributesForStat:&preview->item.stat
						       linkCounts:&preview->item.links
						     symbolicLink:NO];
				  if (preview->source_directory_present) {
					  sourceAttrs = [self
					      attributesForStat:&preview->source_directory.stat
						     linkCounts:&preview->source_directory.links
						   symbolicLink:NO];
				  }
				  if (preview->destination_directory_present) {
					  destinationAttrs = [self
					      attributesForStat:&preview->destination_directory.stat
						     linkCounts:&preview->destination_directory
								    .links
						   symbolicLink:NO];
				  }
				  if (preview->over_item_present) {
					  overAttrs =
					      [self attributesForStat:&preview->over_item.stat
							   linkCounts:&preview->over_item.links
							 symbolicLink:NO];
				  }
				  if (attrs == nil ||
				      (preview->source_directory_present && sourceAttrs == nil) ||
				      (preview->destination_directory_present &&
					  destinationAttrs == nil) ||
				      (preview->over_item_present && overAttrs == nil)) {
					  return NTFS_NO_MEMORY;
				  }
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
				  if (@available(macOS 27.0, *)) {
					  freeSpace = [[FSFreeSpace alloc] init];
					  if (freeSpace == nil) {
						  return NTFS_NO_MEMORY;
					  }
					  [freeSpace populateWithBytes:preview->free_clusters *
					      self->_info.cluster_size];
				  }
#endif
				  nativeReply = prepare(created != nil ? created : item, stored,
				      attrs, sourceAttrs, destinationAttrs, overAttrs, freeSpace);
				  if (nativeReply == nil) {
					  return NTFS_NO_MEMORY;
				  }
				  if (self.lifecycle != NTFSVolumeWriting ||
				      (item != nil && item.owner != self) ||
				      (source != nil && source.owner != self) ||
				      (destination != nil && destination.owner != self) ||
				      (over != nil && over.owner != self) ||
				      (created != nil && created.owner != self)) {
					  return NTFS_STALE;
				  }
				  if (input->requireWriteOpen &&
				      (item->nativeOpenModes & FSVolumeOpenModesWrite) == 0) {
					  preparedError = image_access_denied();
					  return NTFS_READ_ONLY;
				  }
				  return ntfs_write_mutation_execution_execute(prepared, &report);
				}];
				if (report.execution.poisoned) {
					[_imageTransport invalidate];
				}
				if (result != NTFS_OK) {
					if (preparedError != nil) {
						if (error != NULL) {
							*error = preparedError;
						}
						return nil;
					}
					return image_write_failure(error, result);
				}
				/* Publish only already reserved values. All core children closed
				 * before the first transfer; fresh readers bind lazily afterward.
				 */
				{
					const struct ntfs_write_mutation_preview *preview =
					    ntfs_write_mutation_execution_preview(prepared);

					if (item != nil) {
						item->stat = preview->item.stat;
						item->links = preview->item.links;
						item->retired = !preview->item_exists;
					}
					if (source != nil) {
						source->stat = preview->source_directory.stat;
						source->links = preview->source_directory.links;
					}
					if (destination != nil) {
						destination->stat =
						    preview->destination_directory.stat;
						destination->links =
						    preview->destination_directory.links;
					}
					if (over != nil && over != item) {
						over->stat = preview->over_item.stat;
						over->links = preview->over_item.links;
						over->retired = !preview->over_item_exists;
					}
					_freeClusters = preview->free_clusters;
				}
				for (publication in paths) {
					publication.item->directoryPath = publication.path;
					publication.item->parentReference =
					    publication.path.parent != nil
					    ? publication.path.parent.reference
					    : publication.path.reference;
				}
				if (namespaceOperation) {
					_directoryVerifier++;
					if (_directoryVerifier == 0) {
						_directoryVerifier++;
					}
				}
				committed = YES;
				return nativeReply;
			} @finally {
				ntfs_write_mutation_execution_close(prepared);
				if (!committed && created != nil) {
					if (createdKey != nil) {
						[_items removeObjectForKey:createdKey];
					}
					created.owner = nil;
				}
				_nativeReplyPreparing = NO;
				_imageMutationActive = NO;
				[_lifecycleLock lock];
				invalidating = _lifecycle == NTFSVolumeInvalidating;
				if (_lifecycle == NTFSVolumeWriting) {
					_lifecycle = NTFSVolumeActive;
				}
				[_lifecycleLock unlock];
				if (invalidating) {
					[self invalidate];
				}
			}
		}
	} @finally {
		if (outStatus != NULL) {
			*outStatus = result;
		}
		[_publicationLock unlock];
	}
}

- (id)createImageItemNamed:(FSFileName *)name
		      type:(FSItemType)type
	       inDirectory:(FSItem *)directory
		attributes:(FSItemSetAttributesRequest *)attributes
		  fileTime:(uint64_t)fileTime
	      prepareReply:(NTFSImageMutationReply)prepare
		     error:(NSError **)error
{
	struct image_mutation_input input = {0};
	FSItemAttribute supported = FSItemAttributeType | FSItemAttributeMode | FSItemAttributeUID |
	    FSItemAttributeGID | FSItemAttributeSize | FSItemAttributeFlags |
	    FSItemAttributeBirthTime | FSItemAttributeModifyTime | FSItemAttributeChangeTime |
	    FSItemAttributeAccessTime;
	FSItemAttribute bit, supplied = 0;
	uint32_t mode, typeMode;
	enum ntfs_result status;
	id result;

	if (type != FSItemTypeFile && type != FSItemTypeDirectory) {
		return image_write_failure(error, NTFS_UNSUPPORTED);
	}
	mode = type == FSItemTypeDirectory ? S_IRWXU : S_IRUSR | S_IWUSR;
	typeMode = type == FSItemTypeDirectory ? S_IFDIR : S_IFREG;
	if (attributes != nil &&
	    (!image_set_attributes_supported(attributes, supported) ||
		([attributes isValid:FSItemAttributeType] && attributes.type != type) ||
		([attributes isValid:FSItemAttributeSize] && attributes.size != 0) ||
		([attributes isValid:FSItemAttributeFlags] && attributes.flags != 0) ||
		([attributes isValid:FSItemAttributeMode] &&
		    ((attributes.mode & ~S_IFMT) != mode ||
			((attributes.mode & S_IFMT) != 0 &&
			    (attributes.mode & S_IFMT) != typeMode))) ||
		([attributes isValid:FSItemAttributeUID] && attributes.uid != _nativeUserID) ||
		([attributes isValid:FSItemAttributeGID] && attributes.gid != _nativeGroupID))) {
		return image_write_failure(error, NTFS_UNSUPPORTED);
	}
	status = image_creation_times(attributes, &input.creationTimes);
	if (status != NTFS_OK) {
		return image_write_failure(error, status);
	}
	for (bit = FSItemAttributeType; bit <= FSItemAttributeInhibitKernelOffloadedIO; bit <<= 1) {
		if ([attributes isValid:bit]) {
			supplied |= bit;
		}
	}
	input.kind =
	    type == FSItemTypeDirectory ? NTFS_WRITE_CREATE_DIRECTORY : NTFS_WRITE_CREATE_FILE;
	input.sourceDirectory = directory;
	input.sourceName = name;
	input.fileTime = fileTime;
	result = [self performImageMutation:&input prepareReply:prepare status:NULL error:error];
	if (result != nil && attributes != nil) {
		/* Matching fixed native presentation is applied without changing Windows
		 * security. Supplied times are part of the same durable creation. */
		attributes.consumedAttributes |= supplied;
	}
	return result;
}

- (id)renameImageItem:(FSItem *)item
	  inDirectory:(FSItem *)sourceDirectory
		named:(FSFileName *)sourceName
	    toNewName:(FSFileName *)name
	  inDirectory:(FSItem *)directory
	     overItem:(FSItem *)overItem
	     fileTime:(uint64_t)fileTime
	 prepareReply:(NTFSImageMutationReply)prepare
		error:(NSError **)error
{
	struct image_mutation_input input = {0};

	input.kind = NTFS_WRITE_RENAME;
	input.item = item;
	input.sourceDirectory = sourceDirectory;
	input.sourceName = sourceName;
	input.destinationDirectory = directory;
	input.destinationName = name;
	input.overItem = overItem;
	input.fileTime = fileTime;
	return [self performImageMutation:&input prepareReply:prepare status:NULL error:error];
}

- (id)removeImageItem:(FSItem *)item
		named:(FSFileName *)name
	fromDirectory:(FSItem *)directory
	     fileTime:(uint64_t)fileTime
	 prepareReply:(NTFSImageMutationReply)prepare
		error:(NSError **)error
{
	struct image_mutation_input input = {0};

	input.kind = NTFS_WRITE_REMOVE_FILE;
	input.item = item;
	input.sourceDirectory = directory;
	input.sourceName = name;
	input.fileTime = fileTime;
	return [self performImageMutation:&input prepareReply:prepare status:NULL error:error];
}

- (id)setImageAttributes:(FSItemSetAttributesRequest *)attributes
		  onItem:(FSItem *)item
		fileTime:(uint64_t)fileTime
	    prepareReply:(NTFSImageMutationReply)prepare
		   error:(NSError **)error
{
	struct image_mutation_input input = {0};
	id result;

	if (!image_set_attributes_supported(attributes, FSItemAttributeSize) ||
	    ![attributes isValid:FSItemAttributeSize]) {
		return image_write_failure(error, NTFS_UNSUPPORTED);
	}
	input.kind = NTFS_WRITE_RESIZE_FILE;
	input.item = item;
	input.size = attributes.size;
	input.fileTime = fileTime;
	result = [self performImageMutation:&input prepareReply:prepare status:NULL error:error];
	if (result != nil) {
		attributes.consumedAttributes |= FSItemAttributeSize;
	}
	return result;
}

- (enum ntfs_result)overwriteImageItem:(FSItem *)item
				offset:(off_t)offset
				 bytes:(const void *)bytes
				length:(size_t)length
			      fileTime:(uint64_t)fileTime
			     completed:(size_t *)completed
{
	__block enum ntfs_result result;
	__block struct ntfs_write_range_report written = {0};
	NTFSItem *value;
	uint64_t reference;

	if (completed == NULL) {
		return NTFS_INVALID;
	}
	*completed = 0;
	if (_nativeImageEditing) {
		struct image_mutation_input input = {0};
		NSData *contents;
		id reply;

		if (offset < 0 || (length != 0 && bytes == NULL)) {
			return NTFS_INVALID;
		}
		if (length > NTFS_OVERWRITE_MAX_BYTES) {
			return NTFS_RANGE;
		}
		contents = [NSData dataWithBytes:bytes length:length];
		if (contents == nil) {
			return NTFS_NO_MEMORY;
		}
		input.kind = NTFS_WRITE_GROWING_RANGE;
		input.item = item;
		input.contents = contents;
		input.offset = (uint64_t)offset;
		input.fileTime = fileTime;
		reply = [self performImageMutation:&input
				      prepareReply:^id(FSItem *preparedItem, FSFileName *name,
					  FSItemAttributes *attributes, FSItemAttributes *source,
					  FSItemAttributes *destination, FSItemAttributes *over,
					  id freeSpace) {
					(void)preparedItem;
					(void)name;
					(void)attributes;
					(void)source;
					(void)destination;
					(void)over;
					(void)freeSpace;
					return @YES;
				      }
					    status:&result
					     error:NULL];
		if (reply != nil) {
			*completed = length;
		}
		return result;
	}

	[_publicationLock lock];
	@try {
		@synchronized(self) {
			if (self.lifecycle == NTFSVolumeInvalidating ||
			    self.lifecycle == NTFSVolumeInvalidated) {
				return NTFS_STALE;
			}
			if (_imageTransport == nil || _writeOwner == NULL) {
				return NTFS_UNSUPPORTED;
			}
			if (_readOperations != 0 || _imageViewOpening || _nativeReplyPreparing) {
				return NTFS_BUSY;
			}
			result = [self ensureImageView];
			if (result == NTFS_OK) {
				result = [self admissionResult];
			}
			if (result != NTFS_OK) {
				return result;
			}
			value = [self checkedItem:item];
			if (value == nil) {
				return _itemAdmission;
			}
			if (offset < 0 || (length != 0 && bytes == NULL) || fileTime > INT64_MAX) {
				return NTFS_INVALID;
			}
			if (length > NTFS_OVERWRITE_MAX_BYTES) {
				return NTFS_RANGE;
			}
			if (length == 0) {
				return NTFS_OK;
			}
			reference = value->stat.reference;
			[_lifecycleLock lock];
			if (_lifecycle == NTFSVolumeActive && _pendingUnmounts == 0) {
				_lifecycle = NTFSVolumeWriting;
				result = NTFS_OK;
			} else {
				result = NTFS_STALE;
			}
			[_lifecycleLock unlock];
			if (result != NTFS_OK) {
				return result;
			}
			_imageMutationActive = YES;
			@try {
				result = [self detachImageView];
				if (result == NTFS_OK) {
					result = [_imageTransport performExclusiveAccess:^{
					  return ntfs_write_existing_range(self->_writeOwner,
					      reference, (uint64_t)offset, bytes, length, fileTime,
					      &written);
					}];
				}
				if (written.execution.poisoned) {
					[_imageTransport invalidate];
				}
				if (result == NTFS_OK) {
					*completed = (size_t)written.completed_bytes;
				}
				/* No allocation follows durable completion. The next read mounts
				 * a fresh immutable view and lazily rebinds its stable FSItem. */
				return result;
			} @finally {
				BOOL invalidating;

				_imageMutationActive = NO;
				[_lifecycleLock lock];
				invalidating = _lifecycle == NTFSVolumeInvalidating;
				if (_lifecycle == NTFSVolumeWriting) {
					_lifecycle = NTFSVolumeActive;
				}
				[_lifecycleLock unlock];
				if (invalidating) {
					[self invalidate];
				}
			}
		}
	} @finally {
		[_publicationLock unlock];
	}
}

- (BOOL)nativeImageEditing
{
	return _nativeImageEditing;
}

- (NSError *)imageCallerErrorWithRealUserID:(uid_t)realUserID effectiveUserID:(uid_t)effectiveUserID
{
	/* FSContext supplies these values in native handlers. No process-global
	 * credential, group membership or privileged bypass grants image access. */
	return _nativeImageEditing &&
		(realUserID != _nativeUserID || effectiveUserID != _nativeUserID)
	    ? image_access_denied()
	    : nil;
}

- (NSError *)checkImageAccessToItem:(FSItem *)item
		    requestedAccess:(FSAccessMask)access
			 realUserID:(uid_t)realUserID
		    effectiveUserID:(uid_t)effectiveUserID
			    allowed:(BOOL *)allowed
{
	NTFSItem *value;
	FSAccessMask supported;
	NSError *error;
	enum ntfs_result result;

	if (allowed == NULL) {
		return ntfs_error(NTFS_INVALID);
	}
	*allowed = NO;
	if (!_nativeImageEditing) {
		return ntfs_error(NTFS_READ_ONLY);
	}
	/* Deny a different native principal before opening an immutable view. */
	error = [self imageCallerErrorWithRealUserID:realUserID effectiveUserID:effectiveUserID];
	if (error != nil) {
		return nil;
	}
	@synchronized(self) {
		result = [self ensureImageView];
		if (result == NTFS_OK) {
			result = [self admissionResult];
		}
		if (result != NTFS_OK) {
			return ntfs_error(result);
		}
		value = [self checkedItem:item];
		if (value == nil) {
			return ntfs_error(_itemAdmission);
		}
		supported = FSAccessReadData | FSAccessReadAttributes | FSAccessReadXattr |
		    FSAccessReadSecurity;
		if (value->stat.directory && value->linkTarget == nil) {
			supported |= FSAccessSearch;
			if (image_directory_write_type(&value->stat)) {
				supported |=
				    FSAccessAddFile | FSAccessAddSubdirectory | FSAccessDeleteChild;
				if ((value->stat.reference & NTFS_REFERENCE_RECORD_MASK) !=
				    NTFS_ROOT_RECORD) {
					supported |= FSAccessDelete;
				}
			}
		} else if (image_file_write_type(&value->stat) && value->linkTarget == nil) {
			supported |= FSAccessWriteData | FSAccessAppendData |
			    FSAccessWriteAttributes | FSAccessDelete;
		}
		*allowed = (access & ~supported) == 0;
		return nil;
	}
}

- (NSError *)openImageItem:(FSItem *)item
		 withModes:(FSVolumeOpenModes)modes
		realUserID:(uid_t)realUserID
	   effectiveUserID:(uid_t)effectiveUserID
{
	__block NSError *error = nil;

	[self performItemPublication:^{
	  FSAccessMask access = 0;
	  BOOL allowed = NO;
	  NTFSItem *value;

	  @synchronized(self) {
		  if (modes == 0 ||
		      (modes & ~(FSVolumeOpenModesRead | FSVolumeOpenModesWrite)) != 0) {
			  error = ntfs_error(NTFS_INVALID);
			  return;
		  }
		  if ((modes & FSVolumeOpenModesRead) != 0) {
			  access |= FSAccessReadData;
		  }
		  if ((modes & FSVolumeOpenModesWrite) != 0) {
			  access |= FSAccessWriteData;
		  }
		  error = [self checkImageAccessToItem:item
				       requestedAccess:access
					    realUserID:realUserID
				       effectiveUserID:effectiveUserID
					       allowed:&allowed];
		  if (error != nil || !allowed) {
			  error = error != nil ? error : image_access_denied();
			  return;
		  }
		  value = [self checkedItem:item];
		  if (value == nil) {
			  error = ntfs_error(self->_itemAdmission);
		  } else {
			  value->nativeOpenModes |= modes;
		  }
	  }
	}];
	return error;
}

- (NSError *)closeImageItem:(FSItem *)item keepingModes:(FSVolumeOpenModes)modes
{
	__block NSError *error = nil;

	[self performItemPublication:^{
	  NTFSItem *value;

	  @synchronized(self) {
		  if (![item isKindOfClass:NTFSItem.class] || ((NTFSItem *)item).owner != self) {
			  error = ntfs_error(NTFS_STALE);
			  return;
		  }
		  value = (NTFSItem *)item;
		  if ((modes & ~value->nativeOpenModes) != 0) {
			  error = ntfs_error(NTFS_INVALID);
		  } else {
			  /* Final mmap close removes the last capability without allocating
			   * a view or depending on new caller authorization. */
			  value->nativeOpenModes = modes;
		  }
	  }
	}];
	return error;
}

- (NSError *)imageReadErrorForItem:(FSItem *)item
{
	if (!_nativeImageEditing) {
		return nil;
	}
	@synchronized(self) {
		if (![item isKindOfClass:NTFSItem.class] || ((NTFSItem *)item).owner != self) {
			return ntfs_error(NTFS_STALE);
		}
		/* A write-only descriptor also needs native page-in for a partial-page
		 * write. The kernel retains the descriptor's user-visible access mode. */
		return ((NTFSItem *)item)->nativeOpenModes == 0 ? image_access_denied() : nil;
	}
}

- (id)writeImageContents:(NSData *)contents
		  toFile:(FSItem *)item
		atOffset:(off_t)offset
		fileTime:(uint64_t)fileTime
	    prepareReply:(id (^)(FSItemAttributes *, size_t, id))prepare
		   error:(NSError **)error
{
	struct image_mutation_input input = {0};

	if (![contents isKindOfClass:NSData.class] || offset < 0 || prepare == nil) {
		return image_write_failure(error, NTFS_INVALID);
	}
	if (contents.length > NTFS_OVERWRITE_MAX_BYTES) {
		return image_write_failure(error, NTFS_RANGE);
	}
	input.kind = NTFS_WRITE_GROWING_RANGE;
	input.item = item;
	input.contents = contents;
	input.offset = (uint64_t)offset;
	input.fileTime = fileTime;
	input.requireWriteOpen = YES;
	return
	    [self performImageMutation:&input
			  prepareReply:^id(FSItem *preparedItem, FSFileName *name,
			      FSItemAttributes *attributes, FSItemAttributes *source,
			      FSItemAttributes *destination, FSItemAttributes *over, id freeSpace) {
			    (void)preparedItem;
			    (void)name;
			    (void)source;
			    (void)destination;
			    (void)over;
			    return prepare(attributes, contents.length, freeSpace);
			  }
				status:NULL
				 error:error];
}

- (enum ntfs_result)currentImageFileTime:(uint64_t *)fileTime
{
	struct timespec time;

	if (fileTime == NULL) {
		return NTFS_INVALID;
	}
	*fileTime = 0;
	if (clock_gettime(CLOCK_REALTIME, &time) != 0) {
		return NTFS_IO;
	}
	return image_time_filetime(time, fileTime);
}

@end
