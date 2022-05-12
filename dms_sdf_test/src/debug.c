
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "debug.h"

static pthread_mutex_t printf_mutex;

/**
 * @brief ：数据打印
 * @param in ：
 * @param out ：
 * @return ：
 */
void print_data_in_hex(uint8_t *data, int length, char *identify) {
    int i = 0;
    pthread_mutex_lock(&printf_mutex);
    printf("%s:\n", identify);
    for (i = 0; i < length; i++) {
        printf("0x%02x ", (unsigned char)*(data + i));
        if (((i + 1) % 16) == 0) printf("\n");
    }
    printf("\n");
    pthread_mutex_unlock(&printf_mutex);
}

/**
 * @brief ：数据大数组的数据
 * @param in ：
 * @param out ：
 * @return ：
 */
void printf_big_arry_in_hex(uint8_t *data, long data_length, int head_len,
                            int tail_len, char *identify) {
    int i = 0;
    pthread_mutex_lock(&printf_mutex);
    printf("[%lu]%s is :", pthread_self(), identify);
    for (i = 0; i < head_len; i++) {
        printf("%02x ", (unsigned char)*(data + i));
        
    }
    printf(".......");
    for (i = 0; i < tail_len; i++) {
        printf("%02x ", (unsigned char)*(data + data_length - tail_len + i));

    }
    printf("\n");
    pthread_mutex_unlock(&printf_mutex);
}

void print_data_in_file(char *data, int length, int fd) {
    write(fd, data, length);
    //sync();
}

int print_in_files(char *rec_data, int rec_length, char *send_data,
                   int send_length, int thread_id) {
    int right_data_fd;
    int rec_data_fd;
    char right_name[128] = {0};
    char rec_name[128] = {0};
    sprintf(right_name, "./rec/rec_%d.bin", thread_id);
    sprintf(rec_name, "./send/send_%d.bin", thread_id);
    right_data_fd = open(right_name, O_CREAT | O_RDWR | O_APPEND);
    rec_data_fd = open(rec_name, O_CREAT | O_RDWR | O_APPEND);
    if (-1 == right_data_fd || rec_data_fd == -1) {
        printf("open w.c r.c.cerror !\n");
        return 1;
    }
    print_data_in_file(rec_data, rec_length, right_data_fd);
    print_data_in_file(send_data, send_length, rec_data_fd);
    close(right_data_fd);
    close(rec_data_fd);
    return 0;
}

void debug_init(void) { pthread_mutex_init(&printf_mutex, NULL); }
