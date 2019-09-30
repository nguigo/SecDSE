#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>

#define MAXSIZE 256

const int magic = 0x12345678;

typedef struct STRING {
    int  magic;
    char size;
    int  id;
    char str[0];
} STRING, *PSTRING;

PSTRING cache = NULL;

PSTRING parse(char *input, ssize_t len)
{
    PSTRING copy, str;
    char *buf;
    int size;

    str = (PSTRING)input;
    // Check magic
    if(str->magic!=magic) {
        return 0;
    }
    // This should really be elsewhere but convenient for testing
    if(!cache) {
        cache = (PSTRING)malloc(sizeof(STRING));
        cache->size = 0;
    }
    else if(str->id==cache->id) {
        return cache;
    }
    // Realloc cache if needed
    if(str->size > cache->size) {
        free(cache);
        cache = (PSTRING)malloc(sizeof(STRING)+str->size+1);
        cache->size = str->size;
    }
    cache->magic = str->magic;
    cache->id = str->id;
    // Copy string to cache
    memcpy(cache->str, str->str, str->size); // READAV

    // Return a null str-terminated copy
    copy = (PSTRING)malloc(sizeof(STRING)+str->size+1);
    memcpy(copy, cache, sizeof(STRING)+str->size+1); // UNINIT
    // NULL terminate it
    cache->str[str->size] = 0; // WRITEAV
    return copy;
}

int main(int argc, char *argv[])
{
    int fp, index=0;
    char temp[MAXSIZE];
    ssize_t readlen;
    PSTRING str;

    // Open and read file
    fp = open(argv[1], O_RDONLY);
    if(fp==-1) {
        return errno;
    }
    readlen = read(fp, temp, sizeof(temp));
    if(readlen < sizeof(STRING)) {
        return -1;
    }
    str = parse(temp, readlen);
    if(!str) {
        return -1;
    }
    //
    // IMAGINE SOME PROCESSING HAPPENING HERE
    //
    // Write it to another file
    printf("%s\n", str->str);
    return 0;
}
