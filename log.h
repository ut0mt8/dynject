/*
 * log.h — shared logging for dynjectd and dynject_loader
 *
 * format: [programname HH:MM:SS] programname: message
 *
 */

#pragma once

#include <stdio.h>

void log_init(const char *program_name, const char *log_path, int verbose);
void log_write(int is_verbose, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* LOG  — always printed */
#define LOG(fmt, ...)  log_write(0, fmt, ##__VA_ARGS__)

/* VLOG — printed only when verbose is enabled */
#define VLOG(fmt, ...) log_write(1, fmt, ##__VA_ARGS__)
