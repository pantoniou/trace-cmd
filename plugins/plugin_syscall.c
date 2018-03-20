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
#include "event-utils.h"

static struct pevent_plugin_option PEVENT_PLUGIN_OPTIONS[] = {
	{
		.name = "arch",
		.description = "Use this libaudit arch (machine) description (auto, host, x86, armv7l, ...)",
		.value = "auto",
	},
	{
		.name = NULL,
	},
};

#ifndef NO_AUDIT

static struct pevent_plugin_option *syscall_arch = &PEVENT_PLUGIN_OPTIONS[0];

static const char *syscall_uname;

#define MACHINE_UNINIT	-1
#define MACHINE_BAD	-2

static int syscall_machine = MACHINE_UNINIT;

static int syscall_get_machine(const char *archid)
{
	const char *s;
	int machine = -1;

	/* we got a bad machine? return illegal */
	if (syscall_machine == MACHINE_BAD)
		return -1;

	/* we got a good machine, return it */
	if (syscall_machine >= 0)
		return syscall_machine;

	/* no archid defaults to "auto" */
	if (!archid)
		archid = "auto";

	/* with no uname, "auto" switches to "host" */
	if (!syscall_uname && !strcmp(archid, "auto"))
		archid = "host";

	/* okay, we have to probe, first try auto and uname parsing */
	if (syscall_uname && !strcmp(archid, "auto")) {
		archid = NULL;
		s = syscall_uname;
		/* make sure it's a Linux uname string */
		if (s && strlen(s) > 6 && !strncmp(s, "Linux", 5)) {
			/* arch is the last word */
			s = strrchr(s, ' ');
			if (s && strlen(s + 1) > 0) {
				archid = s + 1;
			}
		}
		/* default to host if not found */
		if (!archid) {
			archid = "host";
			pr_stat("bad uname \"%s\"; switching to \"%s\" archid\n",
					syscall_uname, archid);
		}
	}

	/* something other than host? */
	if (strcmp(archid, "host")) {
		machine = audit_determine_machine(archid);
		if (machine < 0) {
			pr_stat("could not determine machine id for \"%s\"\n",
					archid);
			archid = "host";
		}
	}

	/* fallback to host */
	if (machine < 0) {
		machine = audit_detect_machine();
		if (machine < 0)
			pr_stat("could not determine host machine id\n");
	}

	if (machine < 0) {
		syscall_machine = MACHINE_BAD;
		return -1;
	}

	pr_stat("syscall selected machine name \"%s\"",
			audit_machine_to_name(machine));

	return syscall_machine = machine;
}
#endif

static int syscall_to_name(int sc, char *buf, int bufsz)
{
#ifndef NO_AUDIT
	const char *name = NULL;
	int machine;

	machine = syscall_get_machine(syscall_arch->value);
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
		trace_seq_printf(s, "NR %llu ", sysnr);
	else
		trace_seq_printf(s, "%s", sysname);

	trace_seq_printf(s, "(");
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
		trace_seq_printf(s, "%s()", sysname);

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

#ifndef NO_AUDIT
void PEVENT_PLUGIN_INIT_DATA(struct pevent *pevent, struct tracecmd_input *handle)
{
	syscall_uname = tracecmd_get_uname(handle);
	/* always uninit here, on first handle event it will be probed again again */
	syscall_machine = MACHINE_UNINIT;

	/* immediately probe machine id to cause any messages to be output early */
	(void)syscall_get_machine(syscall_arch->value);
}
#endif
