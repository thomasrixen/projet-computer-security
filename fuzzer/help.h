#ifndef HELP_H
#define HELP_H

#include <stdio.h>
#include <string.h>

struct tar_t
{                              /* byte offset */
    char name[100];               /*   0 */
    char mode[8];                 /* 100 */
    char uid[8];                  /* 108 */
    char gid[8];                  /* 116 */
    char size[12];                /* 124 */
    char mtime[12];               /* 136 */
    char chksum[8];               /* 148 */
    char typeflag;                /* 156 */
    char linkname[100];           /* 157 */
    char magic[6];                /* 257 */
    char version[2];              /* 263 */
    char uname[32];               /* 265 */
    char gname[32];               /* 297 */
    char devmajor[8];             /* 329 */
    char devminor[8];             /* 337 */
    char prefix[155];             /* 345 */
    char padding[12];             /* 500 */
};

/**
 * Launches another executable given as argument,
 * parses its output and checks whether it matches "*** The program has crashed ***".
 * @param target: the path to the executable
 * @return -1 if cannot be launched, 0 if no crash, 1 if crash detected.
 */
int launch_target(const char* target);

/**
 * Computes the checksum for a tar header and encodes it on the header.
 * @param entry: The tar header
 * @return the value of the checksum
 */
unsigned int calculate_checksum(struct tar_t* entry);

#endif /* HELP_H */