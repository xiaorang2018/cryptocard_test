#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h> 
#endif 



void get_local_time(char* buffer)
{
	time_t rawtime;
	struct tm* timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	sprintf(buffer, "%04d-%02d-%02d %02d:%02d:%02d",
	(timeinfo->tm_year+1900), timeinfo->tm_mon, timeinfo->tm_mday,
	timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
} 


void dmsWriteLog(char *fileName, char *log)
{
	char time[1024] = { 0 };
	FILE *fp;

	get_local_time(time);

	fp = fopen(fileName, "a+");
	fprintf(fp, "[%s] DEBUG INFO : %s\n", time, log);
	fclose(fp);
	system("sync");
}

