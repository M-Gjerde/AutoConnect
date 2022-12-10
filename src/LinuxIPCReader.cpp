/**
 * @file: AutoConnect/src/reader.cpp
 *
 * Copyright 2022
 * Carnegie Robotics, LLC
 * 4501 Hatfield Street, Pittsburgh, PA 15201
 * http://www.carnegierobotics.com
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Carnegie Robotics, LLC nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL CARNEGIE ROBOTICS, LLC BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Significant history (date, user, action):
 *   2022-11-28, mgjerde@carnegierobotics.com, Created file.
 **/

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