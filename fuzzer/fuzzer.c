#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include "help.h"
#include "strat/strat_name.c"
#include "strat/strat_linkname.c"
#include "strat/strat_size.c"
#include "strat/strat_typeflag.c"
#include "strat/strat_checksum.c"
#include "fuzzer.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* ------------------------------------------------------------------ */
/* Progress Bar                                                       */
/* ------------------------------------------------------------------ */
void print_progress(int current, int total) {
    const int bar_width = 50;
    float progress = (float)current / total;
    if (current % (total / 100 + 1) != 0 && current != total) return;

    int pos = (int)(bar_width * progress);
    printf("\r[");
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("] %d%% (%d/%d)", (int)(progress * 100.0), current, total);
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/* File Operations                                                    */
/* ------------------------------------------------------------------ */
void write_tar(const char* filename, struct tar_t* header)
{
    FILE* f = fopen(filename, "wb");
    if (!f) return;
    fwrite(header, 512, 1, f);
    
    char zeros[1024] = {0}; 
    if (rand() % 2) memset(zeros, 'A', 1024);
    
    fwrite(zeros, sizeof(zeros), 1, f);
    fclose(f);
}

int run_target(const char* target)
{
    char base_dir[PATH_MAX];
    char archive_abs[PATH_MAX];
    char cmd[PATH_MAX * 3 + 128];

    if (!getcwd(base_dir, sizeof(base_dir))) return -1;
    snprintf(archive_abs, sizeof(archive_abs), "%s/archive.tar", base_dir);
    snprintf(cmd, sizeof(cmd), "cd crashes/temp && \"%s\" \"%s\" 2>&1", target, archive_abs);

    FILE* fp = popen(cmd, "r");
    if (!fp) return -1;

    char buf[256];
    int rv = 0;

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        if (strstr(buf, "*** The program has crashed ***") != NULL) {
            rv = 1;
            break;
        }
    }
    pclose(fp);
    return rv;
}

void init_base_header(struct tar_t* header) {
    memset(header, 0, sizeof(struct tar_t));
    strcpy(header->name,  "test.txt");
    strcpy(header->mode,  "0000644");
    strcpy(header->uid,   "0000000");
    strcpy(header->gid,   "0000000");
    strcpy(header->size,  "00000000020"); 
    strcpy(header->mtime, "00000000000");
    strcpy(header->magic, "ustar");
    header->typeflag = '0';
    memcpy(header->version, "00", 2);
}

/* ------------------------------------------------------------------ */
/* Advanced Generation Strategies                                     */
/* ------------------------------------------------------------------ */

// 1. Classic bit flipping and byte garbage
static void strat_random_garbage(struct tar_t* h) {
    unsigned char* raw = (unsigned char*)h;
    int count = rand() % 30 + 1;
    for (int i = 0; i < count; i++) {
        raw[rand() % 512] = rand() % 256;
    }
}


// 3. Integer Anomalies (Negative, Max Int, Non-Octal)
static void strat_bad_numbers(struct tar_t* h) {
    const char* bad_sizes[] = {
        "77777777777", // Max octal
        "99999999999", // Invalid octal
        "-0000000001", // Negative
        "18446744073", // Overflow 64-bit
        "21474836480", // Overflow 32-bit
        "00000000000"  // Zero
    };
    memcpy(h->size, bad_sizes[rand() % 6], 11);
    
    if (rand() % 2) memcpy(h->uid, bad_sizes[rand() % 6], 7);
    if (rand() % 2) memcpy(h->gid, bad_sizes[rand() % 6], 7);
}

// 4. Massive Overflow (Non-null terminated fields)
static void strat_massive_overflow(struct tar_t* h) {
    memset(h->name, 'A', 100);
    memset(h->mode, 'B', 8);
    memset(h->uid,  'C', 8);
    memset(h->gid,  'D', 8);
    memset(h->size, 'E', 12);
    memset(h->mtime,'F', 12);
}

// 5. Invalid Headers
static void strat_corrupt_structure(struct tar_t* h) {
    if (rand() % 2) memset(h->magic, 0, 6);   
    if (rand() % 2) memset(h->chksum, 'X', 8); 
    if (rand() % 2) h->typeflag = (rand() % 255); 
}

// 6. Binary Nasties (The idea from the Article)
// Injects raw binary integers where text is expected
static void strat_binary_nasties(struct tar_t* h) {
    // Dangerous raw values (Max Ints, Negative Ints, etc)
    unsigned char nasty_bytes[] = { 
        0xFF, 0x7F, 0x80, 0x00, 0x01, 0x02, 0xFE, 0xFD 
    };

    // Pick a target field (size, uid, gid, or mode)
    char* target;
    int len = 8;
    int choice = rand() % 4;
    switch(choice) {
        case 0: target = h->size; len = 12; break;
        case 1: target = h->uid; len = 8; break;
        case 2: target = h->gid; len = 8; break;
        case 3: target = h->mode; len = 8; break;
    }

    // Fill the field with a repeating nasty byte (e.g. 0xFFFFFF...)
    // This simulates an integer underflow if interpreted as a signed char/int
    memset(target, nasty_bytes[rand() % 8], len);
    
    // Occasionally put a full 32-bit integer pattern
    if (rand() % 3 == 0) {
        unsigned int* int_ptr = (unsigned int*)target;
        *int_ptr = 0xFFFFFFFF; // -1 or MAX_UINT
    }
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */
int main(int argc, char* argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <target_binary>\n", argv[0]);
        return 1;
    }

    char* target_abs = realpath(argv[1], NULL);
    if (!target_abs) { perror("Target path"); return 1; }

    mkdir("crashes", 0755);
    mkdir("crashes/temp", 0755);

    int crashes_name = strat_nasty_name(target_abs);
    int crashes_linkname = strat_nasty_linkname(target_abs);
    int crashes_size = strat_nasty_size(target_abs);
    int crashes_typeflag = strat_nasty_typeflag(target_abs);
    int crashes_checksum = strat_nasty_checksum(target_abs);

    printf("\n\nDone. %d crashes found.\n", crashes_name+crashes_linkname+crashes_size+crashes_typeflag+crashes_checksum);

    free(target_abs);
    return 0;
}