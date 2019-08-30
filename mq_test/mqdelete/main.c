
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mqueue.h>
#include <fcntl.h>
#include <sys/stat.h>
#define FILE_MODE (S_IWUSR|S_IRUSR|S_IRGRP|S_IROTH) //0644
int main(int argc,char* argv[]){
	if(argc < 2){
		printf("usage:%s [-q <maxmsg>] [-l <msglen>] <mqname>\n",argv[0]);
		return 1;
	}
	mq_unlink(argv[1]);
}