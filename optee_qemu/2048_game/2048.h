#ifndef BOARD_H
#define BOARD_H

// define our drm code section.
#define __drm_code      __attribute__((section("secure_code")))

#define SAVE_FILE "2048_save.txt"
#define SIZE 4
#define PAGE_SIZE 4096

typedef uint8_t board_t[SIZE][SIZE];

#define MAX_MEASURES 200
void print_bench();

#endif
