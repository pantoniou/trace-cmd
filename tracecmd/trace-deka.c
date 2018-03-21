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

enum {
	OPT_debug	= 255,
};

static const char *default_input_file = "trace.dat";
static const char *input_file;

struct deka_data {
	struct tracecmd_input *handle;
	int recnr;
	struct pevent_record *rec[];
};

static struct deka_data *deka_init(const char *input_file)
{
	struct tracecmd_input *handle;
	struct pevent_record *record;
	struct deka_data *dd;
	int i, ret, cpu;

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

	/* first find out how many records there are */
	i = 0;
	while ((record = tracecmd_read_next_data(handle, &cpu)) != NULL) {
		i++;
		free_record(record);
	}

	/* to start */
	tracecmd_set_all_cpus_to_timestamp(handle, 0);

	dd = malloc(sizeof(*dd) + sizeof(struct pevent_record *) * i);
	if (!dd)
		die("Failed to allocate memory for all the records\n");

	dd->handle = handle;
	dd->recnr = i;
	memset(dd->rec, 0, sizeof(struct pevent_record *) * dd->recnr);

	for (i = 0; i < dd->recnr; i++) {
		dd->rec[i] = tracecmd_read_next_data(handle, &cpu);
		if (!dd->rec[i])
			die("Record rewind failed at #%d out of #%d",
					i, dd->recnr);
	}
	pr_stat("DEKA stored #%d records", dd->recnr);

	return dd;
}

static void deka_cleanup(struct deka_data *dd)
{
	int i;

	/* cleanup */
	for (i = 0; i < dd->recnr; i++) {
		free_record(dd->rec[i]);
		dd->rec[i] = NULL;
	}

	tracecmd_close(dd->handle);

	free(dd);
}

static void deka_perform_analysis(struct deka_data *dd)
{
	struct pevent *pevent;
	struct pevent_record *record;
	struct trace_seq s;
	int i;

	printf("DEKA: performing analysis on %d records (%s)\n",
			dd->recnr, tracecmd_get_uname(dd->handle));

	trace_seq_init(&s);

	pevent = tracecmd_get_pevent(dd->handle);

	for (i = 0; i < dd->recnr; i++) {
		record = dd->rec[i];
		pevent_print_event(pevent, &s, record, false);
		trace_seq_printf(&s, "\n");
		trace_seq_do_printf(&s);
		trace_seq_reset(&s);
	}

	trace_seq_destroy(&s);
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

	/* perform the analysis */
	deka_perform_analysis(dd);

	deka_cleanup(dd);
}
