#include "../help.h"
#include "../fuzzer.h"


static void write_tar_modify_zero(const char* filename, struct tar_t* header, size_t size)
{
    FILE* f = fopen(filename, "wb");
    if (!f) return;
    fwrite(header, 512, 1, f);
    
    char zeros[1024] = {0};
    if (rand() % 2) memset(zeros, 'A', 1024);
    
    fwrite(zeros, size, 1, f);
    fclose(f);
}

static int strat_nasty_structure_zero(const char* target){
    int crash_count = 0;

    const size_t values[] = {
        0,
        1,
        510,
        511,
        513,
        1023,
        1025,
        77777777777,
        99999999999,
        -1,
    };

    int count = sizeof(values)/sizeof(values[0]);

    for (int i = 0; i < count; i++) {
        struct tar_t header;
        init_base_header(&header);

        const size_t test = values[i];

        calculate_checksum(&header);

        write_tar_modify_zero("archive.tar", &header, test);

        if (run_target(target) == 1) {
            char crash_name[PATH_MAX];
            snprintf(crash_name, sizeof(crash_name),
                     "crashes/crash_structure_zero_%ld.tar", test);
            if (rename("archive.tar", crash_name) != 0) {
                perror("rename crash file");
            } else {
                printf("CRASH -> %s\n", crash_name);
                crash_count++;
            }
        }
    }

    return crash_count;
}