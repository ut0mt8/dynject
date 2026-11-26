/*
 * log.c — shared logging implementation for dynjectd and dynject_loader
 */

#include "log.h"

#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static const char *g_program_name = "dynject";
static FILE       *g_logfile      = NULL;
static int         g_verbose      = 0;

void log_init(const char *program_name, const char *log_path, int verbose)
{
    g_program_name = program_name;
    g_verbose      = verbose;

    if (log_path != NULL) {
        g_logfile = fopen(log_path, "a");
        if (g_logfile == NULL) {
            fprintf(stderr, "[%s] warning: cannot open log %s\n", program_name, log_path);
        }
    }
}

/* One line is formatted first and written with a single call, so lines from
 * different threads don't mix, and localtime_r keeps the time per thread. */
void log_write(int is_verbose, const char *fmt, ...) {
    va_list    args;
    time_t     now;
    struct tm  tm_info;
    char       timestamp[20];
    char       message[PATH_MAX + 512];
    FILE      *output;

    if (is_verbose && !g_verbose) {
        return;
    }

    now = time(NULL);
    localtime_r(&now, &tm_info);
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &tm_info);

    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    output = (g_logfile != NULL) ? g_logfile : stderr;
    fprintf(output, "[%s %s] %s: %s\n", g_program_name, timestamp, g_program_name, message);

    if (output == g_logfile) {
        fflush(output);
    }
}
