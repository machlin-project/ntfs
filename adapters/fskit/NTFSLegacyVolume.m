/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolume.h"

@implementation NTFSLegacyVolume

- (void)activateWithOptions:(FSTaskOptions *)options
	       replyHandler:(void (^)(FSItem *, NSError *))reply
{
	NSError *error = nil;
	FSItem *item = [self activate:&error];

	(void)options;
	reply(item, error);
}

- (void)deactivateWithOptions:(FSDeactivateOptions)options replyHandler:(void (^)(NSError *))reply
{
	(void)options;
	[self invalidate];
	reply(nil);
}

- (void)lookupItemNamed:(FSFileName *)name
	    inDirectory:(FSItem *)directory
	   replyHandler:(void (^)(FSItem *, FSFileName *, NSError *))reply
{
	NSError *error = nil;
	FSFileName *stored = nil;
	FSItem *item = [self lookup:name inDirectory:directory storedName:&stored error:&error];

	reply(item, stored, error);
}

- (void)getAttributes:(FSItemGetAttributesRequest *)request
	       ofItem:(FSItem *)item
	 replyHandler:(void (^)(FSItemAttributes *, NSError *))reply
{
	NSError *error = nil;
	FSItemAttributes *attrs = [self attributes:item error:&error];

	(void)request;
	reply(attrs, error);
}

- (void)enumerateDirectory:(FSItem *)directory
	  startingAtCookie:(FSDirectoryCookie)cookie
		  verifier:(FSDirectoryVerifier)verifier
       providingAttributes:(FSItemGetAttributesRequest *)attributes
	       usingPacker:(FSDirectoryEntryPacker *)packer
	      replyHandler:(void (^)(FSDirectoryVerifier, NSError *))reply
{
	NSError *error = [self enumerate:directory
				  cookie:cookie
				verifier:verifier
			      attributes:attributes != nil
				  packer:packer];

	reply(self.directoryVerifier, error);
}

- (void)readFromFile:(FSItem *)item
	      offset:(off_t)offset
	      length:(size_t)length
	  intoBuffer:(FSMutableFileDataBuffer *)buffer
	replyHandler:(void (^)(size_t, NSError *))reply
{
	size_t completed = 0;
	enum ntfs_result result;

	result = length > buffer.length ? NTFS_INVALID
					: [self readItem:item
						  offset:offset
						   bytes:buffer.mutableBytes
						  length:length
					       completed:&completed];
	reply(completed, ntfs_error(result));
}

- (void)writeContents:(NSData *)contents
	       toFile:(FSItem *)item
	     atOffset:(off_t)offset
	 replyHandler:(void (^)(size_t, NSError *))reply
{
	(void)contents;
	(void)item;
	(void)offset;
	reply(0, ntfs_error(NTFS_READ_ONLY));
}

- (void)createItemNamed:(FSFileName *)name
		   type:(FSItemType)type
	    inDirectory:(FSItem *)directory
	     attributes:(FSItemSetAttributesRequest *)attributes
	   replyHandler:(void (^)(FSItem *, FSFileName *, NSError *))reply
{
	(void)name;
	(void)type;
	(void)directory;
	(void)attributes;
	reply(nil, nil, ntfs_error(NTFS_READ_ONLY));
}

- (void)createSymbolicLinkNamed:(FSFileName *)name
		    inDirectory:(FSItem *)directory
		     attributes:(FSItemSetAttributesRequest *)attributes
		   linkContents:(FSFileName *)contents
		   replyHandler:(void (^)(FSItem *, FSFileName *, NSError *))reply
{
	(void)name;
	(void)directory;
	(void)attributes;
	(void)contents;
	reply(nil, nil, ntfs_error(NTFS_READ_ONLY));
}

- (void)createLinkToItem:(FSItem *)item
		   named:(FSFileName *)name
	     inDirectory:(FSItem *)directory
	    replyHandler:(void (^)(FSFileName *, NSError *))reply
{
	(void)item;
	(void)name;
	(void)directory;
	reply(nil, ntfs_error(NTFS_READ_ONLY));
}

- (void)renameItem:(FSItem *)item
       inDirectory:(FSItem *)sourceDirectory
	     named:(FSFileName *)sourceName
	 toNewName:(FSFileName *)name
       inDirectory:(FSItem *)directory
	  overItem:(FSItem *)overItem
      replyHandler:(void (^)(FSFileName *, NSError *))reply
{
	(void)item;
	(void)sourceDirectory;
	(void)sourceName;
	(void)name;
	(void)directory;
	(void)overItem;
	reply(nil, ntfs_error(NTFS_READ_ONLY));
}

- (void)removeItem:(FSItem *)item
	     named:(FSFileName *)name
     fromDirectory:(FSItem *)directory
      replyHandler:(void (^)(NSError *))reply
{
	(void)item;
	(void)name;
	(void)directory;
	reply(ntfs_error(NTFS_READ_ONLY));
}

- (void)setAttributes:(FSItemSetAttributesRequest *)attributes
	       onItem:(FSItem *)item
	 replyHandler:(void (^)(FSItemAttributes *, NSError *))reply
{
	(void)attributes;
	(void)item;
	reply(nil, ntfs_error(NTFS_READ_ONLY));
}

- (void)readSymbolicLink:(FSItem *)item replyHandler:(void (^)(FSFileName *, NSError *))reply
{
	(void)item;
	reply(nil, ntfs_error(NTFS_UNSUPPORTED));
}

@end

NTFSVolume *
ntfs_volume_create(struct ntfs_volume *core, NTFSResource *resource)
{
	Class selected = NTFSLegacyVolume.class;

#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
	if (@available(macOS 27.0, *)) {
		selected = NTFSModernVolume.class;
	}
#endif
	return [[selected alloc] initWithCore:core resource:resource];
}
