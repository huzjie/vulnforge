/*
 * Deliberately vulnerable C sample: buffer overflow via strcpy/gets.
 * (CWE-120 / CWE-787). DO NOT compile or run against untrusted input.
 */
#include <stdio.h>
#include <string.h>

void copy_name(char *dest, const char *src) {
    // vulnforge-static: buffer-overflow
    strcpy(dest, src);
}

void read_line(char *buf) {
    // vulnforge-static: buffer-overflow
    gets(buf);
}

int main(void) {
    char name[16];
    read_line(name);
    printf("Hello, %s\n", name);
    return 0;
}
