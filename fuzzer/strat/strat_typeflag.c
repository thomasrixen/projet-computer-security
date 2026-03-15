#include "../help.h"
#include "../fuzzer.h"


static int strat_nasty_typeflag(const char* target)
{
    static int crash_count = 0;

    for (int i = 0; i < 0x100; i++) {
        
        struct tar_t header;
        init_base_header(&header);

        header.typeflag = (char)i;

        calculate_checksum(&header);

        write_tar("archive.tar", &header);

        // Lancer le test et sauvegarder le crash
        if (run_target(target) == 1) {
            char crash_name[PATH_MAX];
            /* store crashes in crashes/ */
            snprintf(crash_name, sizeof(crash_name), "crashes/crash_typeflag_%d.tar", i);
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