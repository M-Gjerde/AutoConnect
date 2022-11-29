//
// Created by magnus on 11/28/22.
//

/** Compilation: gcc -o memreader memreader.c -lrt -lpthread **/
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <semaphore.h>
#include <string.h>
#include <iostream>

#define ByteSize 1024
#define BackingFile "/mem"
#define AccessPerms 0777
#define SemaphoreName "sem"

void report_and_exit(const char *msg) {
    perror(msg);
    exit(-1);
}

int main() {
    int fd = shm_open(BackingFile, O_RDWR, AccessPerms);  /* empty to begin */
    if (fd < 0) report_and_exit("Can't get file descriptor...");

    /* get a pointer to memory */
    caddr_t memptr = static_cast<caddr_t>(mmap(NULL,       /* let system pick where to put segment */
                                               ByteSize,   /* how many bytes */
                                               PROT_READ | PROT_WRITE, /* access protections */
                                               MAP_SHARED, /* mapping visible to other processes */
                                               fd,         /* file descriptor */
                                               0));         /* offset: start at 1st byte */
    if ((caddr_t) -1 == memptr) report_and_exit("Can't access segment...");

    /* create a semaphore for mutual exclusion */
    sem_t *semptr = sem_open(SemaphoreName, /* name */
                             O_CREAT,       /* create the semaphore */
                             AccessPerms,   /* protection perms */
                             0);            /* initial value */
    if (semptr == (void *) -1 || semptr == nullptr)
        report_and_exit("sem_open");

    /* use semaphore as a mutex (lock) by waiting for writer to increment it */
    if (!sem_wait(semptr)) { /* wait until semaphore != 0 */
        int i;
        std::string str(memptr);
        std::cout << str << std::endl;

        std::cout << std::endl;
        sem_post(semptr);
    }

    /* cleanup */
    munmap(memptr, ByteSize);
    close(fd);
    sem_close(semptr);
    unlink(BackingFile);
    return 0;
}