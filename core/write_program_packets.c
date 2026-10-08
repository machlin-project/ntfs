/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_program_internal.h"
#include "pointer_range.h"

enum {
	PROGRAM_OPEN_PAYLOAD_BYTES = sizeof(struct ntfs_disk_log_update_storage) +
	    sizeof(struct ntfs_disk_log_open_attribute) +
	    NTFS_WRITE_MUTATION_TARGET_NAME_UNITS * sizeof(uint16_t)
};

struct ntfs_write_packet_workspace {
	struct ntfs_write_batch_packet *packet;
	uint8_t *payload;
	size_t count, packet_bytes, payload_bytes, used;
};

static enum ntfs_result
packet_workspace_allocate(const struct ntfs_environment *source, size_t count, size_t payload_bytes,
    struct ntfs_write_packet_workspace *work)
{
	if (count == 0 || count > NTFS_WRITE_BATCH_MAX_PACKETS ||
	    count > SIZE_MAX / sizeof(*work->packet) || payload_bytes == 0) {
		return NTFS_RANGE;
	}
	work->count = count;
	work->packet_bytes = count * sizeof(*work->packet);
	work->payload_bytes = payload_bytes;
	if (work->packet_bytes > NTFS_DEFAULT_MAX_LIVE_BYTES ||
	    work->payload_bytes > NTFS_DEFAULT_MAX_LIVE_BYTES - work->packet_bytes) {
		return NTFS_RANGE;
	}
	work->packet = source->allocate(source->context, work->packet_bytes);
	work->payload = source->allocate(source->context, work->payload_bytes);
	if (work->packet == NULL || work->payload == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(work->packet, work->packet_bytes);
	ntfs_zero(work->payload, work->payload_bytes);
	return NTFS_OK;
}

static void
packet_workspace_release(
    const struct ntfs_environment *source, struct ntfs_write_packet_workspace *work)
{
	if (work->packet != NULL) {
		source->release(source->context, work->packet, work->packet_bytes);
	}
	if (work->payload != NULL) {
		source->release(source->context, work->payload, work->payload_bytes);
	}
}

static enum ntfs_result
program_packet_encode(struct ntfs_write_packet_workspace *work, size_t ordinal,
    const struct ntfs_logfile_update_input *update, uint16_t sequence, uint32_t transaction,
    uint16_t flags, size_t previous, size_t undo)
{
	struct ntfs_write_batch_packet *packet = &work->packet[ordinal];
	uint8_t *payload = work->payload + work->used;
	uint32_t bytes;
	enum ntfs_result result;

	result =
	    ntfs_write_payload_encode(update, payload, work->payload_bytes - work->used, &bytes);
	if (result != NTFS_OK) {
		return result;
	}
	work->used += bytes;
	packet->record = (struct ntfs_logfile_record){0};
	packet->record.type = NTFS_LOGFILE_RECORD_UPDATE;
	packet->record.client_sequence = sequence;
	packet->record.transaction = transaction;
	packet->record.flags = flags;
	packet->record.data =
	    (struct ntfs_logfile_span){sizeof(struct ntfs_disk_log_record), bytes};
	packet->payload = (struct ntfs_logfile_buffer){payload, bytes};
	packet->previous = previous;
	packet->undo_next = undo;
	return NTFS_OK;
}

static enum ntfs_result
program_pages_admit(const struct ntfs_environment *source, const struct ntfs_write_program *program,
    const struct ntfs_logfile_client *client, const struct ntfs_write_batch_pages_input *input,
    struct ntfs_write_batch_pages **out)
{
	if (!ntfs_pointer_range_valid(out, sizeof(*out)) ||
	    (program != NULL && !ntfs_write_program_output_separate(program, out, sizeof(*out))) ||
	    (source != NULL &&
		!ntfs_pointer_ranges_separate(source, sizeof(*source), out, sizeof(*out))) ||
	    (client != NULL &&
		!ntfs_pointer_ranges_separate(client, sizeof(*client), out, sizeof(*out))) ||
	    (input != NULL &&
		!ntfs_pointer_ranges_separate(input, sizeof(*input), out, sizeof(*out)))) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (program == NULL || source == NULL || input == NULL || client == NULL ||
	    source->api_version != NTFS_API_VERSION || source->allocate == NULL ||
	    source->release == NULL || input->packet != NULL || input->packets != 0 ||
	    input->restart.client_count != 1 || input->restart.in_use_head != 0 ||
	    client->oldest_lsn != input->floor_lsn || client->restart_lsn > input->tail_lsn ||
	    client->name_length != sizeof("NTFS") - 1 || client->name[0] != 'N' ||
	    client->name[1] != 'T' || client->name[2] != 'F' || client->name[3] != 'S') {
		return NTFS_INVALID;
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_write_program_pages_prepare(const struct ntfs_environment *source,
    const struct ntfs_write_program *program, const struct ntfs_logfile_client *client,
    const struct ntfs_write_batch_pages_input *input, struct ntfs_write_batch_pages **out)
{
	struct ntfs_write_packet_workspace work = {0};
	struct ntfs_write_batch_pages_input placement;
	struct ntfs_logfile_update_input update = {0};
	struct ntfs_disk_log_open_attribute entry;
	const struct program_target *identity;
	struct ntfs_write_batch_packet *packet;
	uint8_t name[NTFS_WRITE_MUTATION_TARGET_NAME_UNITS * sizeof(uint16_t)];
	uint16_t sequence;
	size_t index, ordinal, unit;
	enum ntfs_result result;

	result = program_pages_admit(source, program, client, input, out);
	if (result != NTFS_OK) {
		return result;
	}
	/* Client sequence comes from the exact selected owner, not an OAT key.
	 * It is carried in this private descriptor's selected restart client. */
	sequence = client->sequence;
	result = packet_workspace_allocate(source, program->targets + program->count + 1,
	    program->targets * PROGRAM_OPEN_PAYLOAD_BYTES +
		sizeof(struct ntfs_disk_log_update_storage),
	    &work);
	if (result != NTFS_OK) {
		goto done;
	}
	for (index = 0; index < program->targets; index++) {
		identity = &program->target[index];
		ntfs_zero(&entry, sizeof(entry));
		ntfs_put_u32(entry.allocated, NTFS_LOG_TABLE_ALLOCATED);
		ntfs_put_u32(entry.index_buffer_bytes,
		    identity->identity.attribute_type == NTFS_ATTR_INDEX_ALLOCATION
			? NTFS_WRITE_CLUSTER_BYTES
			: 0);
		ntfs_put_u32(entry.attribute_type, identity->identity.attribute_type);
		ntfs_put_u64(entry.reference, identity->identity.reference);
		ntfs_put_u64(entry.open_lsn, input->tail_lsn);
		ntfs_zero(name, sizeof(name));
		for (unit = 0; unit < identity->identity.name_count; unit++) {
			ntfs_put_u16(name + unit * sizeof(uint16_t), identity->identity.name[unit]);
		}
		ntfs_zero(&update, sizeof(update));
		update.redo_operation = NTFS_LOG_OP_OPEN_NONRESIDENT_ATTRIBUTE;
		update.target_attribute = identity->key;
		update.attribute_flags = identity->flags;
		update.redo = (struct ntfs_logfile_buffer){&entry, sizeof(entry)};
		update.undo = (struct ntfs_logfile_buffer){
		    name, identity->identity.name_count * sizeof(uint16_t)};
		result = program_packet_encode(&work, index, &update, sequence, NTFS_WRITE_MFT_KEY,
		    identity->identity.name_count == 0 ? NTFS_LOGFILE_RECORD_ADDING : 0, SIZE_MAX,
		    SIZE_MAX);
		if (result != NTFS_OK) {
			goto done;
		}
	}
	for (index = 0; index < program->targets; index++) {
		work.packet[index].open_predecessor = true;
	}
	for (index = 0; index < program->count; index++) {
		ordinal = program->targets + index;
		packet = &work.packet[ordinal];
		packet->record.client_sequence = sequence;
		packet->record.type = NTFS_LOGFILE_RECORD_UPDATE;
		packet->record.transaction = NTFS_WRITE_TRANSACTION_KEY;
		packet->record.flags = program->update[index].record_flags;
		packet->record.data =
		    (struct ntfs_logfile_span){sizeof(struct ntfs_disk_log_record),
			(uint32_t)program->update[index].payload.bytes};
		packet->payload = program->update[index].payload;
		packet->previous = packet->undo_next = index == 0 ? SIZE_MAX : ordinal - 1;
	}
	ordinal = program->targets + program->count;
	ntfs_zero(&update, sizeof(update));
	update.redo_operation = NTFS_LOG_OP_FORGET_TRANSACTION;
	update.undo_operation = NTFS_LOG_OP_COMPENSATION;
	result = program_packet_encode(&work, ordinal, &update, sequence,
	    NTFS_WRITE_TRANSACTION_KEY, NTFS_LOGFILE_RECORD_DELETING, ordinal - 1, SIZE_MAX);
	if (result != NTFS_OK) {
		goto done;
	}
	placement = *input;
	placement.packet = work.packet;
	placement.packets = work.count;
	result = ntfs_write_batch_pages_prepare(source, &placement, out);
done:
	packet_workspace_release(source, &work);
	return result;
}

static enum ntfs_result
program_original_packets_bind(const struct ntfs_environment *source,
    const struct ntfs_write_program *program, const struct ntfs_write_batch_pages *original,
    size_t prefix, const struct ntfs_logfile_client *client)
{
	struct ntfs_logfile_record record;
	struct ntfs_logfile_update update;
	const struct ntfs_disk_log_open_attribute *entry;
	const struct program_target *target;
	const struct ntfs_write_program_update *step;
	uint8_t *packet;
	size_t index, bytes, unit;
	uint64_t previous;
	enum ntfs_result result = NTFS_OK;

	packet = source->allocate(source->context, NTFS_WRITE_BATCH_MAX_PACKET_BYTES);
	if (packet == NULL) {
		return NTFS_NO_MEMORY;
	}
	for (index = 0; result == NTFS_OK && index < program->targets + prefix; index++) {
		result = ntfs_write_batch_pages_packet_copy(
		    original, index, packet, NTFS_WRITE_BATCH_MAX_PACKET_BYTES, &bytes);
		if (result == NTFS_OK) {
			result = ntfs_logfile_record_decode(
			    packet, bytes, sizeof(struct ntfs_disk_log_record), &record);
		}
		if (result != NTFS_OK) {
			break;
		}
		if (record.lsn != ntfs_write_batch_pages_lsn(original, index) ||
		    record.type != NTFS_LOGFILE_RECORD_UPDATE || record.client_index != 0 ||
		    record.client_sequence != client->sequence) {
			result = NTFS_STALE;
			break;
		}
		if (index >= program->targets) {
			step = &program->update[index - program->targets];
			previous = index == program->targets
			    ? 0
			    : ntfs_write_batch_pages_lsn(original, index - 1);
			if (record.transaction != NTFS_WRITE_TRANSACTION_KEY ||
			    (record.flags & ~NTFS_LOGFILE_RECORD_MULTI_PAGE) !=
				step->record_flags ||
			    record.previous_lsn != previous || record.undo_next_lsn != previous ||
			    record.data.length != step->payload.bytes ||
			    !ntfs_equal(packet + record.data.offset, step->payload.data,
				step->payload.bytes)) {
				result = NTFS_STALE;
			}
			continue;
		}
		target = &program->target[index];
		result = ntfs_logfile_update_decode(
		    packet + record.data.offset, record.data.length, &update);
		if (result != NTFS_OK) {
			break;
		}
		if (record.transaction != NTFS_WRITE_MFT_KEY || record.previous_lsn != 0 ||
		    record.undo_next_lsn != 0 ||
		    record.flags !=
			(target->identity.name_count == 0 ? NTFS_LOGFILE_RECORD_ADDING : 0) ||
		    update.redo_operation != NTFS_LOG_OP_OPEN_NONRESIDENT_ATTRIBUTE ||
		    update.undo_operation != NTFS_LOG_OP_NOOP ||
		    update.target_attribute != target->key ||
		    update.attribute_flags != target->flags ||
		    update.redo.length != sizeof(*entry) ||
		    update.undo.length != target->identity.name_count * sizeof(uint16_t) ||
		    update.lcn_count != 0 || update.target_vcn != 0 || update.record_offset != 0 ||
		    update.attribute_offset != 0 || update.cluster_index != 0) {
			result = NTFS_STALE;
			break;
		}
		entry = (const void *)(packet + record.data.offset + update.redo.offset);
		if (ntfs_u32(entry->allocated) != NTFS_LOG_TABLE_ALLOCATED ||
		    ntfs_u64(entry->reference) != target->identity.reference ||
		    ntfs_u32(entry->attribute_type) != target->identity.attribute_type ||
		    ntfs_u32(entry->index_buffer_bytes) !=
			(target->identity.attribute_type == NTFS_ATTR_INDEX_ALLOCATION
				? NTFS_WRITE_CLUSTER_BYTES
				: 0) ||
		    (index != 0 &&
			ntfs_u64(entry->open_lsn) !=
			    ntfs_write_batch_pages_lsn(original, index - 1)) ||
		    ntfs_u64(entry->open_lsn) >= record.lsn) {
			result = NTFS_STALE;
			break;
		}
		for (unit = 0; unit < target->identity.name_count; unit++) {
			if (ntfs_u16(packet + record.data.offset + update.undo.offset +
				unit * sizeof(uint16_t)) != target->identity.name[unit]) {
				result = NTFS_STALE;
				break;
			}
		}
	}
	source->release(source->context, packet, NTFS_WRITE_BATCH_MAX_PACKET_BYTES);
	return result;
}

enum ntfs_result
ntfs_write_program_compensation_prepare(const struct ntfs_environment *source,
    const struct ntfs_write_program *program, const struct ntfs_write_batch_pages *original,
    size_t prefix, const struct ntfs_logfile_client *client,
    const struct ntfs_write_batch_pages_input *input, struct ntfs_write_batch_pages **out)
{
	struct ntfs_write_packet_workspace work = {0};
	struct ntfs_write_batch_pages_input placement;
	struct ntfs_logfile_update_input inverse = {0};
	struct ntfs_logfile_update update;
	const struct ntfs_write_program_update *step;
	const uint8_t *payload;
	size_t index, original_index, payload_bytes = sizeof(struct ntfs_disk_log_update_storage),
				      bytes;
	uint16_t flags;
	enum ntfs_result result;

	if (original != NULL &&
	    !ntfs_write_batch_pages_output_separate(original, out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	result = program_pages_admit(source, program, client, input, out);
	if (result != NTFS_OK) {
		return result;
	}
	if (original == NULL || prefix == 0 || prefix > program->count) {
		return NTFS_INVALID;
	}
	if (input->tail_lsn !=
	    ntfs_write_batch_pages_lsn(original, program->targets + prefix - 1)) {
		return NTFS_STALE;
	}
	result = program_original_packets_bind(source, program, original, prefix, client);
	if (result != NTFS_OK) {
		return result;
	}
	for (index = 0; index < prefix; index++) {
		step = &program->update[index];
		result =
		    ntfs_logfile_update_decode(step->payload.data, step->payload.bytes, &update);
		if (result != NTFS_OK) {
			return result;
		}
		bytes = sizeof(struct ntfs_disk_log_update_storage) + update.undo.length;
		if (bytes > NTFS_DEFAULT_MAX_LIVE_BYTES - payload_bytes) {
			return NTFS_RANGE;
		}
		payload_bytes += bytes;
	}
	result = packet_workspace_allocate(source, prefix + 1, payload_bytes, &work);
	if (result != NTFS_OK) {
		goto done;
	}
	for (index = 0; index < prefix; index++) {
		original_index = prefix - 1 - index;
		step = &program->update[original_index];
		payload = step->payload.data;
		result = ntfs_logfile_update_decode(payload, step->payload.bytes, &update);
		if (result != NTFS_OK) {
			goto done;
		}
		ntfs_zero(&inverse, sizeof(inverse));
		inverse.redo_operation = update.undo_operation;
		inverse.undo_operation = NTFS_LOG_OP_COMPENSATION;
		inverse.target_attribute = update.target_attribute;
		inverse.target_vcn = update.target_vcn;
		inverse.record_offset = update.record_offset;
		inverse.attribute_offset = update.attribute_offset;
		inverse.cluster_index = update.cluster_index;
		inverse.attribute_flags = update.attribute_flags;
		inverse.lcns =
		    (struct ntfs_logfile_buffer){payload + update.lcns.offset, update.lcns.length};
		inverse.redo =
		    (struct ntfs_logfile_buffer){payload + update.undo.offset, update.undo.length};
		/* Empty Noop redo uses the native missing-redo flag, also for compensation. */
		flags =
		    inverse.redo_operation == NTFS_LOG_OP_NOOP ? NTFS_LOGFILE_RECORD_DELETING : 0;
		result = program_packet_encode(&work, index, &inverse, client->sequence,
		    NTFS_WRITE_TRANSACTION_KEY, flags, index == 0 ? SIZE_MAX : index - 1, SIZE_MAX);
		if (result != NTFS_OK) {
			goto done;
		}
		work.packet[index].record.previous_lsn = index == 0
		    ? ntfs_write_batch_pages_lsn(original, program->targets + prefix - 1)
		    : 0;
		work.packet[index].record.undo_next_lsn = original_index == 0
		    ? 0
		    : ntfs_write_batch_pages_lsn(original, program->targets + original_index - 1);
	}
	ntfs_zero(&inverse, sizeof(inverse));
	inverse.redo_operation = NTFS_LOG_OP_FORGET_TRANSACTION;
	inverse.undo_operation = NTFS_LOG_OP_COMPENSATION;
	result = program_packet_encode(&work, prefix, &inverse, client->sequence,
	    NTFS_WRITE_TRANSACTION_KEY, NTFS_LOGFILE_RECORD_DELETING, prefix - 1, SIZE_MAX);
	if (result == NTFS_OK) {
		placement = *input;
		placement.packet = work.packet;
		placement.packets = work.count;
		result = ntfs_write_batch_pages_prepare(source, &placement, out);
	}
done:
	packet_workspace_release(source, &work);
	return result;
}
