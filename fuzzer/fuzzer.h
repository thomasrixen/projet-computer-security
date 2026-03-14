#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include "help.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif


void write_tar(const char* filename, struct tar_t* header);

int run_target(const char* target);

void init_base_header(struct tar_t* header);


