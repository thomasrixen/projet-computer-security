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

static int run_target(const char* target)
{
    char cmd[PATH_MAX + 50];
    snprintf(cmd, sizeof(cmd), "%s archive.tar 2>&1", target);

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

static void strat_nasty_strings(struct tar_t* h) {
    const char* nasties[] = {
        "%s%s%s%s%s%s", 
        "%n%n%n%n", 
        "../../../../../../../../etc/passwd",
        "\\x00\\x00\\x00",
        "\n\n\n\n",    // New: Newlines
        "\r\n\r\n",    // New: Carriage Returns
        "test\0file",  // New: Null byte in middle of string
        ""             // empty string
    };
    const char* nasty = nasties[rand() % 8]; // Updated count to 8
    strncpy(h->name, nasty, 99);
    strncpy(h->linkname, nasty, 99);
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
        fprintf(stderr, "Usage: %s <target_binary> [iterations]\n", argv[0]);
        return 1;
    }

    char* target_abs = realpath(argv[1], NULL);
    if (!target_abs) { perror("Target path"); return 1; }

    int iterations = (argc >= 3) ? atoi(argv[2]) : 10000;
    int crashes = 0;

    mkdir("crashes", 0755);
    mkdir("crashes/tmp", 0755);
    srand((unsigned)time(NULL));

    if (chdir("crashes/tmp") != 0) { perror("chdir"); return 1; }

    printf("Fuzzing target: %s\n", target_abs);
    printf("Iterations: %d\n\n", iterations);

    for (int i = 0; i < iterations; i++) {
        print_progress(i, iterations);

        struct tar_t header;
        memset(&header, 0, sizeof(header));

        // Base valid header
        strcpy(header.name,  "test.txt");
        strcpy(header.mode,  "0000644");
        strcpy(header.uid,   "0000000");
        strcpy(header.gid,   "0000000");
        strcpy(header.size,  "00000000020"); 
        strcpy(header.mtime, "00000000000");
        strcpy(header.magic, "ustar");
        header.typeflag = '0';
        memcpy(header.version, "00", 2);

        // --- CHAINED GENERATION ---
        int mutations = (rand() % 3) + 1;
        
        for(int m=0; m<mutations; m++) {
            // FIXED: rand() % 6 covers cases 0,1,2,3,4,5
            int strat = rand() % 6; 
            switch(strat) {
                case 0: strat_random_garbage(&header); break;
                case 1: strat_nasty_strings(&header); break;
                case 2: strat_bad_numbers(&header); break;
                case 3: strat_massive_overflow(&header); break;
                case 4: strat_corrupt_structure(&header); break;
                case 5: strat_binary_nasties(&header); break;
            }
        }

        // 90% chance to fix checksum (so we pass the first check)
        if (rand() % 10 != 0) {
            calculate_checksum(&header);
        }

        write_tar("archive.tar", &header);

        if (run_target(target_abs) == 1) {
            crashes++;
            char crash_name[PATH_MAX];
            snprintf(crash_name, sizeof(crash_name), "../crash_%d.tar", i);
            rename("archive.tar", crash_name);
            printf("\r\033[KCRASH at iter %d -> %s (Total: %d)\n", i, crash_name+3, crashes);
        }
    }

    print_progress(iterations, iterations);
    printf("\n\nDone. %d crashes found.\n", crashes);
    
    free(target_abs);
    return 0;
}