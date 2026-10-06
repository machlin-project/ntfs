/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "image_fault.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { NTFS_IMAGE_FAULT_PATH_BYTES = 4096 };

static enum ntfs_result
fault_claim(void *context)
{
	struct ntfs_image_fault *fault = context;

	return fault->image.environment.claim(&fault->image);
}

static void
fault_unclaim(void *context)
{
	struct ntfs_image_fault *fault = context;

	fault->image.environment.unclaim(&fault->image);
}

static enum ntfs_result
fault_read(void *context, uint64_t physical, void *bytes, size_t length)
{
	struct ntfs_image_fault *fault = context;

	return fault->image.environment.reader.read(&fault->image, physical, bytes, length);
}

static void *
fault_allocate(void *context, size_t bytes)
{
	struct ntfs_image_fault *fault = context;

	return fault->image.environment.reader.allocate(&fault->image, bytes);
}

static void
fault_release(void *context, void *bytes, size_t length)
{
	struct ntfs_image_fault *fault = context;

	fault->image.environment.reader.release(&fault->image, bytes, length);
}

static enum ntfs_result
fault_write(void *context, uint64_t physical, const void *bytes, size_t length, size_t *completed)
{
	struct ntfs_image_fault *fault = context;
	struct ntfs_image_fault_event *event;
	size_t transferred;

	if (!fault->enabled) {
		return fault->image.environment.write(
		    &fault->image, physical, bytes, length, completed);
	}
	*completed = 0;
	if (fault->events == NTFS_IMAGE_FAULT_EVENTS || length > NTFS_OVERWRITE_MAX_BYTES) {
		return NTFS_RANGE;
	}
	event = &fault->event[fault->events];
	memcpy(fault->storage + fault->events * NTFS_OVERWRITE_MAX_BYTES, bytes, length);
	fault->events++;
	fault->writes++;
	event->physical = physical;
	event->bytes = length;
	event->injected = fault->writes == fault->fail_write;
	transferred = event->injected ? fault->prefix : length;
	if (transferred > length) {
		event->native_result = NTFS_INVALID;
	} else if (transferred != 0) {
		event->native_attempted = true;
		event->native_result = fault->image.environment.write(
		    &fault->image, physical, bytes, transferred, completed);
	}
	event->completed = *completed;
	event->result = event->native_result;
	if (event->native_result != NTFS_OK) {
		fault->native_failure = true;
	}
	if (event->injected) {
		fault->triggered = true;
		fault->image.uncertain = true;
		event->result = NTFS_IO;
	}
	return event->result;
}

static enum ntfs_result
fault_persist(void *context)
{
	struct ntfs_image_fault *fault = context;
	struct ntfs_image_fault_event *event;

	if (!fault->enabled) {
		return fault->image.environment.persist(&fault->image);
	}
	if (fault->events == NTFS_IMAGE_FAULT_EVENTS) {
		return NTFS_RANGE;
	}
	event = &fault->event[fault->events++];
	event->barrier = true;
	event->native_attempted = true;
	fault->barriers++;
	event->native_result = fault->image.environment.persist(&fault->image);
	event->result = event->native_result;
	if (event->native_result != NTFS_OK) {
		fault->native_failure = true;
	}
	event->injected = fault->barriers == fault->fail_barrier;
	if (event->injected) {
		/* Failure cannot prove loss. Persist the predecessor writes, then
		 * report an uncertain barrier and forbid reuse of this raw owner. */
		fault->triggered = true;
		fault->image.uncertain = true;
		event->result = NTFS_IO;
	}
	return event->result;
}

int
ntfs_image_fault_open(
    const char *path, size_t write, size_t prefix, size_t barrier, struct ntfs_image_fault *fault)
{
	int error;

	memset(fault, 0, sizeof(*fault));
	fault->image.fd = -1;
	if (write > NTFS_IMAGE_FAULT_EVENTS || barrier > NTFS_IMAGE_FAULT_EVENTS ||
	    (write != 0 && barrier != 0) || prefix > NTFS_OVERWRITE_MAX_BYTES ||
	    prefix % NTFS_OVERWRITE_MIN_ALIGNMENT != 0 || (write == 0 && prefix != 0)) {
		return EINVAL;
	}
	fault->storage = malloc(NTFS_IMAGE_FAULT_EVENTS * NTFS_OVERWRITE_MAX_BYTES);
	if (fault->storage == NULL) {
		return ENOMEM;
	}
	error = ntfs_overwrite_image_open(path, &fault->image);
	if (error != 0) {
		ntfs_image_fault_close(fault);
		return error;
	}
	fault->environment = fault->image.environment;
	fault->environment.reader.context = fault;
	fault->environment.reader.read = fault_read;
	fault->environment.reader.allocate = fault_allocate;
	fault->environment.reader.release = fault_release;
	fault->environment.claim = fault_claim;
	fault->environment.unclaim = fault_unclaim;
	fault->environment.write = fault_write;
	fault->environment.persist = fault_persist;
	fault->fail_write = write;
	fault->fail_barrier = barrier;
	fault->prefix = prefix;
	return 0;
}

void
ntfs_image_fault_close(struct ntfs_image_fault *fault)
{
	ntfs_overwrite_image_close(&fault->image);
	free(fault->storage);
	fault->storage = NULL;
}

int
ntfs_image_fault_dump(const struct ntfs_image_fault *fault, const char *directory)
{
	const struct ntfs_image_fault_event *event;
	char path[NTFS_IMAGE_FAULT_PATH_BYTES];
	FILE *output;
	size_t index;
	int formatted, error = 0;

	formatted = snprintf(path, sizeof(path), "%s/events.json", directory);
	if (formatted < 0 || (size_t)formatted >= sizeof(path)) {
		return ENAMETOOLONG;
	}
	output = fopen(path, "wx");
	if (output == NULL) {
		return errno;
	}
	fprintf(output,
	    "{\"triggered\":%s,\"native_failure\":%s,\"writes\":%zu,"
	    "\"barriers\":%zu,\"events\":[",
	    fault->triggered ? "true" : "false", fault->native_failure ? "true" : "false",
	    fault->writes, fault->barriers);
	for (index = 0; index < fault->events; index++) {
		event = &fault->event[index];
		fprintf(output,
		    "%s{\"barrier\":%s,\"physical\":%llu,\"bytes\":%zu,"
		    "\"completed\":%zu,\"native_result\":%u,\"result\":%u,"
		    "\"injected\":%s,\"native_attempted\":%s}",
		    index == 0 ? "" : ",", event->barrier ? "true" : "false",
		    (unsigned long long)event->physical, event->bytes, event->completed,
		    event->native_result, event->result, event->injected ? "true" : "false",
		    event->native_attempted ? "true" : "false");
	}
	fputs("]}\n", output);
	if (ferror(output)) {
		error = EIO;
	}
	if (fclose(output) != 0) {
		error = EIO;
	}
	for (index = 0; error == 0 && index < fault->events; index++) {
		event = &fault->event[index];
		if (event->barrier) {
			continue;
		}
		formatted = snprintf(path, sizeof(path), "%s/event-%zu.bin", directory, index);
		if (formatted < 0 || (size_t)formatted >= sizeof(path)) {
			return ENAMETOOLONG;
		}
		output = fopen(path, "wx");
		if (output == NULL) {
			return errno;
		}
		if (fwrite(fault->storage + index * NTFS_OVERWRITE_MAX_BYTES, 1, event->bytes,
			output) != event->bytes) {
			error = EIO;
		}
		if (fclose(output) != 0) {
			error = EIO;
		}
	}
	return error;
}
