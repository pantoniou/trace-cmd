/*
 * Copyright (C) 2009 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 * Copyright (C) 2009 Johannes Berg <johannes@sipsolutions.net>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "event-parse.h"

#ifndef NO_AUDIT
#include <libaudit.h>
#endif

#include "trace-cmd.h"

static struct pevent_plugin_option PEVENT_PLUGIN_OPTIONS[] = {
	{
		.name = "arch",
		.description = "Use this libaudit arch (machine) description (x86, armv7l etc)",
		.value = "host",
	},
	{
		.name = NULL,
	},
};

static struct pevent_plugin_option *syscall_arch = &PEVENT_PLUGIN_OPTIONS[0];

static int syscall_to_name(int sc, char *buf, int bufsz)
{
#ifndef NO_AUDIT
	const char *name = NULL;
	int machine;

	if (!syscall_arch->value || !strcmp(syscall_arch->value, "host"))
		machine = audit_detect_machine();
	else
		machine = audit_determine_machine(syscall_arch->value);
	if (machine < 0)
		goto fail;

	name = audit_syscall_to_name(sc, machine);
	if (!name)
		goto fail;
	if (strlen(name) + 1 > bufsz)
		goto fail;
	strcpy(buf, name);
	return 0;
fail:
#endif
	return -1;
}

static int sys_enter_handler(struct trace_seq *s, struct pevent_record *record,
				struct event_format *event, void *context)
{
	char sysname[80];
	void *data;
	struct format_field *field;
	unsigned long long sysnr, val;
	unsigned int i;

	/* id, args */
	field = pevent_find_field(event, "id");
	if (!field ||
	    pevent_read_number_field(field, record->data, &sysnr))
		return 1;

	field = pevent_find_field(event, "args");
	if (!field ||
	    ((field->flags & (FIELD_IS_ARRAY | FIELD_IS_LONG)) != (FIELD_IS_ARRAY | FIELD_IS_LONG)))
		return 1;

	if (syscall_to_name((int)sysnr, sysname, sizeof(sysname)))
		trace_seq_printf(s, "NR %llu", sysnr);
	else
		trace_seq_printf(s, "%s", sysname);

	trace_seq_printf(s, " (");
	data = record->data;
	for (i = 0; i < field->arraylen; i++) {
		val = pevent_read_number(field->event->pevent,
					data + field->offset + i * field->elementsize,
					field->elementsize);
		trace_seq_printf(s, "%llx", val);
		if (i < field->arraylen - 1)
			trace_seq_printf(s, ", ");
	}

	trace_seq_printf(s, ")");

	return 0;
}

static int sys_exit_handler(struct trace_seq *s, struct pevent_record *record,
			       struct event_format *event, void *context)
{
	char sysname[80];
	struct format_field *field;
	unsigned long long sysnr, ret;

	/* id, ret */
	field = pevent_find_field(event, "id");
	if (!field ||
	    pevent_read_number_field(field, record->data, &sysnr))
		return 1;

	field = pevent_find_field(event, "ret");
	if (!field ||
	    pevent_read_number_field(field, record->data, &ret))
		return 1;

	if (syscall_to_name((int)sysnr, sysname, sizeof(sysname)))
		trace_seq_printf(s, "NR %llu", sysnr);
	else
		trace_seq_printf(s, "%s", sysname);

	trace_seq_printf(s, " = %lld", ret);

	return 0;
}

int PEVENT_PLUGIN_LOADER(struct pevent *pevent)
{
	pevent_register_event_handler(pevent, -1, "raw_syscalls", "sys_enter",
				      sys_enter_handler, NULL);

	pevent_register_event_handler(pevent, -1, "raw_syscalls", "sys_exit",
				      sys_exit_handler, NULL);

	trace_util_add_options("syscall", PEVENT_PLUGIN_OPTIONS);

	return 0;
}

void PEVENT_PLUGIN_UNLOADER(struct pevent *pevent)
{
	trace_util_remove_options(PEVENT_PLUGIN_OPTIONS);

	pevent_unregister_event_handler(pevent, -1,
					"raw_syscalls", "sys_enter",
					sys_enter_handler, NULL);

	pevent_unregister_event_handler(pevent, -1, "raw_syscalls", "sys_exit",
					sys_exit_handler, NULL);
}
