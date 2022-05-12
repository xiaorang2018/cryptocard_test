
#ifndef __DEBUG__H_
#define __DEBUG__H_
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

#define NONE                 "\e[0m"
#define BLACK                "\e[0;30m"
#define L_BLACK              "\e[1;30m"
#define RED                  "\e[0;31m"
#define L_RED                "\e[1;31m"
#define GREEN                "\e[0;32m"
#define L_GREEN              "\e[1;32m"
#define BROWN                "\e[0;33m"
#define YELLOW               "\e[1;33m"
#define BLUE                 "\e[0;34m"
#define L_BLUE               "\e[1;34m"
#define PURPLE               "\e[0;35m"
#define L_PURPLE             "\e[1;35m"
#define L_CYAN               "\e[1;36m"
#define GRAY                 "\e[0;37m"
#define WHITE                "\e[1;37m"

#define BOLD                 "\e[1m"
#define UNDERLINE            "\e[4m"
#define BLINK                "\e[5m"
#define REVERSE              "\e[7m"
#define HIDE                 "\e[8m"
#define CLEAR                "\e[2J"
#define CLRLINE              "\r\e[K" 

#define Printf_with_color(color,format,arg...)  printf(color""format""NONE,##arg)

#define Debug_err(format,arg...)        printf(RED"""[%lu]"format""NONE,pthread_self(),##arg)

#define Debug_info(format,arg...)        printf("[%s]"format,__FUNCTION__,##arg)


void print_data_in_hex(uint8_t *data,int length ,char *identify);
void printf_big_arry_in_hex(uint8_t *data,long data_length,int head_len,int tail_len,char *identify);
void debug_init(void);


#endif
