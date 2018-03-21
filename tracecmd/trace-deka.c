/*
 * Copyright (C) 2018, DEKA Research & Development Corp.
 *
 * Author: Pantelis Antoniou <pantelis.antoniou@konsulko.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#define _LARGEFILE64_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <pthread.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include "trace-local.h"

/* copy trace seq buffer to allocated string */
static char *trace_seq_do_copy(struct trace_seq *s)
{
	char *buf;

	if (s->state != TRACE_SEQ__GOOD)
		return NULL;

	buf = malloc(s->len + 1);
	if (!buf)
		return NULL;

	memcpy(buf, s->buffer, s->len);
	buf[s->len] = '\0';

	return buf;
}

enum {
	OPT_debug	= 255,
};

static const char *default_input_file = "trace.dat";
static const char *input_file;

struct deka_record {
	struct pevent_record *record;
	struct event_format *event;
	char *time_str;
	char *info_str;
	/* parsed and stored for speed */
	int pid;
	const char *comm;
};

static inline const char *dr_time_str(struct deka_record *dr)
{
	return dr->time_str;
}

static inline const char *dr_info_str(struct deka_record *dr)
{
	return dr->info_str;
}

static inline const char *dr_event_name(struct deka_record *dr)
{
	return dr->event->name;
}

static inline const char *dr_comm(struct deka_record *dr)
{
	return dr->comm;
}

static inline int dr_pid(struct deka_record *dr)
{
	return dr->pid;
}

static inline int dr_cpu(struct deka_record *dr)
{
	return dr->record->cpu;
}

static inline unsigned long long dr_ts(struct deka_record *dr)
{
	return dr->record->ts;
}

struct deka_data {
	struct tracecmd_input *handle;

	/* maximum sizes of string lengths */
	int comm_len_max;
	int time_str_len_max;
	int info_str_len_max;
	int event_name_len_max;
	int pid_len_max;
	int cpu_len_max;

	int recnr;
	struct deka_record rec[];
};

static struct deka_data *deka_init(const char *input_file)
{
	struct tracecmd_input *handle;
	struct pevent *pevent;
	struct pevent_record *record;
	struct event_format *event;
	struct deka_data *dd;
	int i, size, ret, cpu;

	pr_stat("DEKA scheduling analysis on %s\n", input_file);

	handle = read_trace_header(input_file);
	if (!handle)
		die("error reading header for %s", input_file);

	ret = tracecmd_read_headers(handle);
	if (ret)
		die("error reading headers for %s", input_file);

	ret = tracecmd_init_data(handle);
	if (ret < 0)
		die("failed to init data for %s", input_file);

	pevent = tracecmd_get_pevent(handle);

	/* first find out how many records there are */
	i = 0;
	while ((record = tracecmd_read_next_data(handle, &cpu)) != NULL) {
		event = pevent_find_event_by_record(pevent, record);
		/* skipping all records without a matching format */
		if (event)
			i++;
		free_record(record);
	}

	/* to start */
	tracecmd_set_all_cpus_to_timestamp(handle, 0);

	size = sizeof(*dd) + sizeof(struct deka_record) * i;
	dd = malloc(size);
	if (!dd)
		die("Failed to allocate memory for all the records\n");
	memset(dd, 0, size);

	dd->handle = handle;
	dd->recnr = i;

	for (i = 0; i < dd->recnr; ) {
		record = tracecmd_read_next_data(handle, &cpu);
		if (!record)
			die("Record rewind failed at #%d out of #%d",
					i, dd->recnr);

		event = pevent_find_event_by_record(pevent, record);
		if (!event)
			continue;

		dd->rec[i].record = record;
		dd->rec[i].event = event;
		i++;
	}
	pr_stat("DEKA stored #%d records", dd->recnr);

	return dd;
}

static void deka_cleanup(struct deka_data *dd)
{
	struct deka_record *dr;
	int i;

	/* cleanup */
	for (i = 0; i < dd->recnr; i++) {
		dr = &dd->rec[i];
		if (dr->time_str)
			free(dr->time_str);
		if (dr->info_str)
			free(dr->info_str);
		free_record(dr->record);
		memset(dr, 0, sizeof(*dr));
	}

	tracecmd_close(dd->handle);

	free(dd);
}

static void deka_preprocess(struct deka_data *dd)
{
	struct deka_record *dr;
	struct pevent *pevent;
	struct pevent_record *record;
	struct event_format *event;
	struct trace_seq s;
	char *ss, *se, *time_str;
	int i, len;
	char buf[32];	/* for printing integers */

	printf("DEKA: preprocessing %d records\n", dd->recnr);

	trace_seq_init(&s);

	pevent = tracecmd_get_pevent(dd->handle);

	/* prepare display strings */
	for (i = 0; i < dd->recnr; i++) {
		dr = &dd->rec[i];
		record = dr->record;
		event = dr->event;

		trace_seq_reset(&s);
		pevent_print_event_time(pevent, &s, event, record, false);
		time_str = trace_seq_do_copy(&s);
		if (!time_str)
			die("deka: time_print: out of memory");

		/* strip spaces and : */
		ss = time_str;
		while (*ss && isspace(*ss))
			ss++;
		se = strrchr(ss, ':');
		if (se)
			*se = '\0';
		dr->time_str = strdup(ss);
		if (!dr->time_str)
			die("deka: time_str: out of memory");
		free(time_str);

		/* info */
		trace_seq_reset(&s);
		pevent_event_info(&s, event, record);
		dr->info_str = trace_seq_do_copy(&s);
		if (!dr->info_str)
			die("deka: info_print: out of memory");

		dr->pid = pevent_data_pid(pevent, record);
		dr->comm = pevent_data_comm_from_pid(pevent, dr->pid);
	}

	dd->comm_len_max = 0;
	dd->time_str_len_max = 0;
	dd->info_str_len_max = 0;
	dd->event_name_len_max = 0;
	dd->pid_len_max = 0;
	dd->cpu_len_max = 0;
	for (i = 0; i < dd->recnr; i++) {
		dr = &dd->rec[i];

		len = strlen(dr_comm(dr));
		if (len > dd->comm_len_max)
			dd->comm_len_max = len;

		len = strlen(dr_time_str(dr));
		if (len > dd->time_str_len_max)
			dd->time_str_len_max = len;

		len = strlen(dr_info_str(dr));
		if (len > dd->info_str_len_max)
			dd->info_str_len_max = len;

		len = strlen(dr_event_name(dr));
		if (len > dd->event_name_len_max)
			dd->event_name_len_max = len;

		snprintf(buf, sizeof(buf) - 1, "%d", dr_pid(dr));
		buf[sizeof(buf)-1] = '\0';
		len = strlen(buf);
		if (len > dd->pid_len_max)
			dd->pid_len_max = len;

		snprintf(buf, sizeof(buf) - 1, "%d", dr_cpu(dr));
		buf[sizeof(buf)-1] = '\0';
		len = strlen(buf);
		if (len > dd->cpu_len_max)
			dd->cpu_len_max = len;
	}

	trace_seq_destroy(&s);
}

static void deka_perform_analysis(struct deka_data *dd)
{
	struct deka_record *dr;
	int i;

	for (i = 0; i < dd->recnr; i++) {
		dr = &dd->rec[i];
		printf("%*s-%-*d | %*s [%*d] | %-*s | %s\n",
			dd->comm_len_max, dr_comm(dr),
			dd->pid_len_max, dr_pid(dr),
			dd->time_str_len_max, dr_time_str(dr),
			dd->cpu_len_max, dr_cpu(dr),
			dd->event_name_len_max, dr_event_name(dr),
			dr_info_str(dr));
	}
}

void trace_deka(int argc, char **argv)
{
	struct deka_data *dd;
	int c;

	for (;;) {
		int option_index = 0;
		static struct option long_options[] = {
			{"debug", no_argument, NULL, OPT_debug},
			{"help", no_argument, NULL, '?'},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc-1, argv+1, "+hVq",
			long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'V':
			show_status = 1;
			break;
		case 'q':
			silence_warnings = 1;
			break;
		case OPT_debug:
			debug = 1;
			break;
		default:
			usage(argv);
		}
	}

	if ((argc - optind) >= 2) {
		if (input_file)
			usage(argv);
		input_file = argv[optind + 1];
	}

	if (!input_file)
		input_file = default_input_file;

	dd = deka_init(input_file);
	if (!dd)
		die("deka_init() failed\n");

	/* preprocess the data */
	deka_preprocess(dd);

	/* perform the analysis */
	deka_perform_analysis(dd);

	deka_cleanup(dd);
}
