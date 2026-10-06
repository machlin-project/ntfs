/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolume.h"
#import "NTFSImageVolume.h"
#include <errno.h>
#include <os/log.h>

#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
@implementation NTFSModernVolume

- (NSError *)imageContextError:(FSContext *)context operation:(const char *)operation
{
	uid_t realUserID, effectiveUserID;
	NSError *error;

	if (!self.nativeImageEditing) {
		return nil;
	}
	if (![context isKindOfClass:FSContext.class]) {
		os_log_error(OS_LOG_DEFAULT,
		    "NTFS image authorization refused in %{public}s: missing FSContext", operation);
		return [NSError errorWithDomain:NSPOSIXErrorDomain code:EACCES userInfo:nil];
	}
	realUserID = (uid_t)context.realUserID;
	effectiveUserID = (uid_t)context.effectiveUserID;
	if ((NSInteger)realUserID != context.realUserID ||
	    (NSInteger)effectiveUserID != context.effectiveUserID) {
		os_log_error(OS_LOG_DEFAULT,
		    "NTFS image authorization refused in %{public}s: invalid native user IDs",
		    operation);
		return [NSError errorWithDomain:NSPOSIXErrorDomain code:EACCES userInfo:nil];
	}
	error = [self imageCallerErrorWithRealUserID:realUserID effectiveUserID:effectiveUserID];
	if (error != nil) {
		os_log_error(OS_LOG_DEFAULT,
		    "NTFS image authorization refused in %{public}s: real UID=%u effective UID=%u "
		    "image owner UID=%u",
		    operation, realUserID, effectiveUserID, self.nativeUserID);
	}
	return error;
}

- (BOOL)isAccessCheckInhibited
{
	return !self.nativeImageEditing;
}

- (BOOL)isOpenCloseInhibited
{
	return !self.nativeImageEditing;
}

- (void)checkAccessToItem:(FSItem *)item
	  requestedAccess:(FSAccessMask)access
		  context:(FSContext *)context
	     replyHandler:(void (^)(FSCheckAccessResult *, NSError *))reply
{
	NSError *error = [self imageContextError:context operation:__func__];
	BOOL allowed = NO;
	FSCheckAccessResult *result = nil;

	if (error == nil) {
		error = [self checkImageAccessToItem:item
				     requestedAccess:access
					  realUserID:(uid_t)context.realUserID
				     effectiveUserID:(uid_t)context.effectiveUserID
					     allowed:&allowed];
	}
	if (error == nil) {
		result = [[FSCheckAccessResult alloc] initWithAccessAllowed:allowed];
	}
	reply(result, ntfs_native_result_error(result, error));
}

- (void)openItem:(FSItem *)item
       withModes:(FSVolumeOpenModes)modes
	 context:(FSContext *)context
    replyHandler:(void (^)(NSError *))reply
{
	NSError *error = [self imageContextError:context operation:__func__];

	if (error == nil) {
		error = [self openImageItem:item
				  withModes:modes
				 realUserID:(uid_t)context.realUserID
			    effectiveUserID:(uid_t)context.effectiveUserID];
	}
	reply(error);
}

- (void)closeItem:(FSItem *)item
     keepingModes:(FSVolumeOpenModes)modes
	  context:(FSContext *)context
     replyHandler:(void (^)(NSError *))reply
{
	(void)context;
	reply([self closeImageItem:item keepingModes:modes]);
}

- (void)activateVolumeWithOptions:(FSTaskOptions *)options
		     replyHandler:(void (^)(FSActivateResult *, NSError *))reply
{
	[self performItemPublication:^{
	  NSError *error = nil;
	  FSItem *item = [self activateWithOptions:options error:&error];
	  FSActivateResult *result =
	      item != nil ? [[FSActivateResult alloc] initWithRootItem:item] : nil;

	  if (self.nativeImageEditing) {
		  os_log_info(OS_LOG_DEFAULT,
		      "NTFS image activation reply: root=%d error=%{public}s:%ld options=%lu",
		      item != nil, error != nil ? error.domain.UTF8String : "none",
		      (long)error.code, (unsigned long)options.taskOptions.count);
	  }
	  reply(result, ntfs_native_result_error(result, error));
	}];
}

- (void)deactivateVolumeWithOptions:(FSDeactivateOptions)options
		       replyHandler:(void (^)(NSError *))reply
{
	(void)options;
	[self invalidateWithReplyHandler:^{
	  reply(nil);
	}];
}

- (void)lookupItemNamed:(FSFileName *)name
	    inDirectory:(FSItem *)directory
		context:(FSContext *)context
	   replyHandler:(void (^)(FSLookupItemResult *, NSError *))reply
{
	NSError *contextError = [self imageContextError:context operation:__func__];

	if (contextError != nil) {
		reply(nil, contextError);
		return;
	}
	[self performItemPublication:^{
	  NSError *error = nil;
	  FSFileName *stored = nil;
	  FSItem *item;
	  FSItemAttributes *attrs;
	  FSLookupItemResult *result = nil;

	  @synchronized(self) {
		  item = [self lookup:name inDirectory:directory storedName:&stored error:&error];
		  if (item != nil) {
			  attrs = [self attributes:item error:&error];
			  if (attrs != nil) {
				  result = [[FSLookupItemResult alloc] initWithFoundItem:item
										itemName:stored
									  itemAttributes:attrs];
			  }
		  }
	  }
	  reply(result, ntfs_native_result_error(result, error));
	}];
}

- (void)getAttributes:(FSItemGetAttributesRequest *)request
	       ofItem:(FSItem *)item
	      context:(FSContext *)context
	 replyHandler:(void (^)(FSGetAttributesResult *, NSError *))reply
{
	NSError *error = nil;
	FSItemAttributes *attrs = [self attributes:item error:&error];
	FSGetAttributesResult *result =
	    attrs != nil ? [[FSGetAttributesResult alloc] initWithAttributes:attrs] : nil;

	/* Vnode attributes describe an already published item. FSKit also requests
	 * the root's attributes with a system context while constructing a mount.
	 * This response grants no namespace, open or data capability. Those complete
	 * operations retain their authenticated owner checks; the attribute engine
	 * still validates scope, revocation and the original backing identity. */
	(void)request;
	if (self.nativeImageEditing && attrs != nil && attrs.fileID == FSItemIDRootDirectory &&
	    [context isKindOfClass:FSContext.class]) {
		os_log_info(OS_LOG_DEFAULT,
		    "NTFS image root attributes reply: real UID=%ld effective UID=%ld image owner "
		    "UID=%u",
		    (long)context.realUserID, (long)context.effectiveUserID, attrs.uid);
	}
	reply(result, ntfs_native_result_error(result, error));
}

- (void)enumerateDirectory:(FSItem *)directory
	  startingAtCookie:(FSDirectoryCookie)cookie
		  verifier:(FSDirectoryVerifier)verifier
       providingAttributes:(FSItemGetAttributesRequest *)attributes
	       usingPacker:(FSDirectoryEntryPacker *)packer
		   context:(FSContext *)context
	      replyHandler:(void (^)(FSEnumerateDirectoryResult *, NSError *))reply
{
	NSError *error = [self imageContextError:context operation:__func__];
	FSEnumerateDirectoryResult *result = nil;

	if (error == nil) {
		error = [self enumerate:directory
				 cookie:cookie
			       verifier:verifier
			     attributes:attributes != nil
				 packer:packer];
	}
	result = error == nil
	    ? [[FSEnumerateDirectoryResult alloc] initWithVerifier:self.directoryVerifier]
	    : nil;

	reply(result, ntfs_native_result_error(result, error));
}

- (void)readFromFile:(FSItem *)item
	      offset:(off_t)offset
	      length:(size_t)length
	  intoBuffer:(FSMutableFileDataBuffer *)buffer
	replyHandler:(void (^)(FSReadFileResult *, NSError *))reply
{
	size_t completed = 0;
	enum ntfs_result status;
	FSItemAttributes *attrs;
	FSReadFileResult *result = nil;
	NSError *error = nil;

	@synchronized(self) {
		error = [self imageReadErrorForItem:item];
		status = error != nil ? NTFS_IO
				      : (length > buffer.length ? NTFS_INVALID
								: [self readItem:item
									  offset:offset
									   bytes:buffer.mutableBytes
									  length:length
								       completed:&completed]);
		if (error == nil) {
			error = ntfs_error(status);
		}
		if (status == NTFS_OK) {
			attrs = [self attributes:item error:&error];
			if (attrs != nil) {
				result = [[FSReadFileResult alloc] initWithBytesRead:completed
								      itemAttributes:attrs];
			}
		}
	}
	reply(result, ntfs_native_result_error(result, error));
}

- (void)writeContents:(NSData *)contents
	       toFile:(FSItem *)item
	     atOffset:(off_t)offset
	 replyHandler:(void (^)(FSWriteFileResult *, NSError *))reply
{
	NSError *error = nil;
	FSWriteFileResult *result = nil;
	uint64_t fileTime;
	enum ntfs_result status;

	if (!self.nativeImageEditing) {
		reply(nil, ntfs_error(NTFS_READ_ONLY));
		return;
	}
	status = [self currentImageFileTime:&fileTime];
	if (status != NTFS_OK) {
		reply(nil, ntfs_error(status));
		return;
	}
	result = [self writeImageContents:contents
				   toFile:item
				 atOffset:offset
				 fileTime:fileTime
			     prepareReply:^id(FSItemAttributes *attributes, size_t length) {
			       return [[FSWriteFileResult alloc]
				   initWithBytesWritten:length
					 itemAttributes:attributes
					      freeSpace:FSFreeSpace.noUpdate];
			     }
				    error:&error];
	reply(result, ntfs_native_result_error(result, error));
}

- (void)createItemNamed:(FSFileName *)name
		   type:(FSItemType)type
	    inDirectory:(FSItem *)directory
	     attributes:(FSItemSetAttributesRequest *)attributes
		context:(FSContext *)context
	   replyHandler:(void (^)(FSCreateItemResult *, NSError *))reply
{
	(void)name;
	(void)type;
	(void)directory;
	(void)attributes;
	(void)context;
	reply(nil, ntfs_error(NTFS_READ_ONLY));
}

- (void)createSymbolicLinkNamed:(FSFileName *)name
		    inDirectory:(FSItem *)directory
		     attributes:(FSItemSetAttributesRequest *)attributes
		   linkContents:(FSFileName *)contents
			context:(FSContext *)context
		   replyHandler:(void (^)(FSCreateSymlinkResult *, NSError *))reply
{
	(void)name;
	(void)directory;
	(void)attributes;
	(void)contents;
	(void)context;
	reply(nil, ntfs_error(NTFS_READ_ONLY));
}

- (void)createLinkToItem:(FSItem *)item
		   named:(FSFileName *)name
	     inDirectory:(FSItem *)directory
		 context:(FSContext *)context
	    replyHandler:(void (^)(FSCreateLinkResult *, NSError *))reply
{
	(void)item;
	(void)name;
	(void)directory;
	(void)context;
	reply(nil, ntfs_error(NTFS_READ_ONLY));
}

- (void)renameItem:(FSItem *)item
       inDirectory:(FSItem *)sourceDirectory
	     named:(FSFileName *)sourceName
	 toNewName:(FSFileName *)name
       inDirectory:(FSItem *)directory
	  overItem:(FSItem *)overItem
	   context:(FSContext *)context
      replyHandler:(void (^)(FSRenameItemResult *, NSError *))reply
{
	(void)item;
	(void)sourceDirectory;
	(void)sourceName;
	(void)name;
	(void)directory;
	(void)overItem;
	(void)context;
	reply(nil, ntfs_error(NTFS_READ_ONLY));
}

- (void)removeItem:(FSItem *)item
	     named:(FSFileName *)name
     fromDirectory:(FSItem *)directory
	   context:(FSContext *)context
      replyHandler:(void (^)(FSRemoveItemResult *, NSError *))reply
{
	(void)item;
	(void)name;
	(void)directory;
	(void)context;
	reply(nil, ntfs_error(NTFS_READ_ONLY));
}

- (void)setAttributes:(FSItemSetAttributesRequest *)attributes
	       onItem:(FSItem *)item
	      context:(FSContext *)context
	 replyHandler:(void (^)(FSSetAttributesResult *, NSError *))reply
{
	(void)attributes;
	(void)item;
	(void)context;
	reply(nil, ntfs_error(NTFS_READ_ONLY));
}

- (void)readSymbolicLink:(FSItem *)item
		 context:(FSContext *)context
	    replyHandler:(void (^)(FSReadSymlinkResult *, NSError *))reply
{
	NSError *error = [self imageContextError:context operation:__func__];
	FSFileName *target = error == nil ? [self symbolicLink:item error:&error] : nil;
	FSItemAttributes *attrs;
	FSReadSymlinkResult *result = nil;

	if (target != nil) {
		attrs = [self attributes:item error:&error];
		if (attrs != nil) {
			result = [[FSReadSymlinkResult alloc] initWithContents:target
							     symlinkAttributes:attrs];
		}
	}
	reply(result, ntfs_native_result_error(result, error));
}

- (void)getXattrNamed:(FSFileName *)name
	       ofItem:(FSItem *)item
	      context:(FSContext *)context
	 replyHandler:(void (^)(FSGetXattrResult *, NSError *))reply
{
	NSError *error = [self imageContextError:context operation:__func__];
	NSData *data = error == nil ? [self xattrNamed:name ofItem:item error:&error] : nil;
	FSGetXattrResult *result =
	    data != nil ? [[FSGetXattrResult alloc] initWithXattrValue:data] : nil;

	reply(result, ntfs_native_result_error(result, error));
}

- (void)listXattrsOfItem:(FSItem *)item
		 context:(FSContext *)context
	    replyHandler:(void (^)(FSListXattrsResult *, NSError *))reply
{
	NSError *error = [self imageContextError:context operation:__func__];
	NSArray<FSFileName *> *names = error == nil ? [self xattrsForItem:item error:&error] : nil;
	FSListXattrsResult *result =
	    names != nil ? [[FSListXattrsResult alloc] initWithXattrNames:names] : nil;

	reply(result, ntfs_native_result_error(result, error));
}

- (void)setXattrNamed:(FSFileName *)name
	       toData:(NSData *)data
	       onItem:(FSItem *)item
	       policy:(FSSetXattrPolicy)policy
	      context:(FSContext *)context
	 replyHandler:(void (^)(FSSetXattrResult *, NSError *))reply
{
	(void)name;
	(void)data;
	(void)item;
	(void)policy;
	(void)context;
	reply(nil, ntfs_error(NTFS_READ_ONLY));
}

@end
#endif
