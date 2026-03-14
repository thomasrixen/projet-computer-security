#include "../help.h"
#include "../fuzzer.h"


static int strat_nasty_typeflag(const char* target)
{
    static int crash_count = 0;


    // Liste de toutes les valeurs "values"
    unsigned char values[] = {
        '0','1','2','3','4','5','6','7',
        'A','Z',
        '\0',
        '\n',
        0xFF,
        0x80,
        'S','L','M'
    };
    int count = sizeof(values)/sizeof(values[0]);

    // Modifier un seul élément
    for (int i = 0; i < count; i++) {
        
        struct tar_t header;
        init_base_header(&header);

        header.typeflag = values[i];

        calculate_checksum(&header);

        write_tar("archive.tar", &header);

        // Lancer le test et sauvegarder le crash
        if (run_target(target) == 1) {
            char crash_name[PATH_MAX];
            /* store crashes in crashes/ */
            snprintf(crash_name, sizeof(crash_name), "crashes/crash_typeflag_%d.tar", crash_count);
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