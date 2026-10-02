/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolume.h"

#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
@implementation NTFSModernVolume

- (void)activateVolumeWithOptions:(FSTaskOptions *)options
		     replyHandler:(void (^)(FSActivateResult *, NSError *))reply
{
	[self performItemPublication:^{
	  NSError *error = nil;
	  FSItem *item = [self activateWithOptions:options error:&error];

	  reply(item != nil ? [[FSActivateResult alloc] initWithRootItem:item] : nil, error);
	}];
}

- (void)deactivateVolumeWithOptions:(FSDeactivateOptions)options
		       replyHandler:(void (^)(NSError *))reply
{
	(void)options;
	[self invalidate];
	reply(nil);
}

- (void)lookupItemNamed:(FSFileName *)name
	    inDirectory:(FSItem *)directory
		context:(FSContext *)context
	   replyHandler:(void (^)(FSLookupItemResult *, NSError *))reply
{
	(void)context;
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
	  reply(result, error);
	}];
}

- (void)getAttributes:(FSItemGetAttributesRequest *)request
	       ofItem:(FSItem *)item
	      context:(FSContext *)context
	 replyHandler:(void (^)(FSGetAttributesResult *, NSError *))reply
{
	NSError *error = nil;
	FSItemAttributes *attrs = [self attributes:item error:&error];

	(void)request;
	(void)context;
	reply(attrs != nil ? [[FSGetAttributesResult alloc] initWithAttributes:attrs] : nil, error);
}

- (void)enumerateDirectory:(FSItem *)directory
	  startingAtCookie:(FSDirectoryCookie)cookie
		  verifier:(FSDirectoryVerifier)verifier
       providingAttributes:(FSItemGetAttributesRequest *)attributes
	       usingPacker:(FSDirectoryEntryPacker *)packer
		   context:(FSContext *)context
	      replyHandler:(void (^)(FSEnumerateDirectoryResult *, NSError *))reply
{
	NSError *error = [self enumerate:directory
				  cookie:cookie
				verifier:verifier
			      attributes:attributes != nil
				  packer:packer];

	(void)context;
	reply(error == nil
		? [[FSEnumerateDirectoryResult alloc] initWithVerifier:self.directoryVerifier]
		: nil,
	    error);
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
		status = length > buffer.length ? NTFS_INVALID
						: [self readItem:item
							  offset:offset
							   bytes:buffer.mutableBytes
							  length:length
						       completed:&completed];
		error = ntfs_error(status);
		if (status == NTFS_OK) {
			attrs = [self attributes:item error:&error];
			if (attrs != nil) {
				result = [[FSReadFileResult alloc] initWithBytesRead:completed
								      itemAttributes:attrs];
			}
		}
	}
	reply(result, error);
}

- (void)writeContents:(NSData *)contents
	       toFile:(FSItem *)item
	     atOffset:(off_t)offset
	 replyHandler:(void (^)(FSWriteFileResult *, NSError *))reply
{
	(void)contents;
	(void)item;
	(void)offset;
	reply(nil, ntfs_error(NTFS_READ_ONLY));
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
	NSError *error = nil;
	FSFileName *target = [self symbolicLink:item error:&error];
	FSItemAttributes *attrs;
	FSReadSymlinkResult *result = nil;

	(void)context;
	if (target != nil) {
		attrs = [self attributes:item error:&error];
		if (attrs != nil) {
			result = [[FSReadSymlinkResult alloc] initWithContents:target
							     symlinkAttributes:attrs];
			if (result == nil) {
				error = ntfs_error(NTFS_IO);
			}
		}
	}
	reply(result, error);
}

- (void)getXattrNamed:(FSFileName *)name
	       ofItem:(FSItem *)item
	      context:(FSContext *)context
	 replyHandler:(void (^)(FSGetXattrResult *, NSError *))reply
{
	NSError *error = nil;
	NSData *data = [self xattrNamed:name ofItem:item error:&error];

	(void)context;
	reply(data != nil ? [[FSGetXattrResult alloc] initWithXattrValue:data] : nil, error);
}

- (void)listXattrsOfItem:(FSItem *)item
		 context:(FSContext *)context
	    replyHandler:(void (^)(FSListXattrsResult *, NSError *))reply
{
	NSError *error = nil;
	NSArray<FSFileName *> *names = [self xattrsForItem:item error:&error];

	(void)context;
	reply(names != nil ? [[FSListXattrsResult alloc] initWithXattrNames:names] : nil, error);
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
