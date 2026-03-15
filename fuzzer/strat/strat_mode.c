#include "../help.h"
#include "../fuzzer.h"

static int strat_nasty_mode(const char* target)
{
    static int crash_count = 0;

    const char *values[] = {
        "7777777",
        "77777777",
        "777777777",

        "17777777777",     // dépasse 32 bits
        "37777777777",
        "777777777777",

        "77777777777777777777",

        "2147483647",
        "40000000000",
        "-000644",
        "-7777777",
        "9999999",
        "8888888",
        "abcdefg",

        "77abc77",
        "00000x0",

        "FFFFFFFF",
        "////////",

        "\0\0\0\0\0\0\0\0"
    };

    int count = sizeof(values)/sizeof(values[0]);

    for (int i = 0; i < count; i++) {

        struct tar_t header;
        init_base_header(&header);

        memset(header.mode, 0, sizeof(header.mode));
        strcpy(header.mode, values[i]);

        calculate_checksum(&header);
        write_tar("archive.tar", &header);

        if (run_target(target) == 1) {

            char crash_name[PATH_MAX];

            snprintf(crash_name, sizeof(crash_name),
                     "crashes/crash_mode_%d.tar",
                     values[i]);

            if (rename("archive.tar", crash_name) != 0)
                perror("rename crash file");
            else {
                printf("CRASH -> %s\n", crash_name);
                crash_count++;
            }
        }
    }

    return crash_count;
}