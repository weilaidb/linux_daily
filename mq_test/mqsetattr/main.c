#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mqueue.h>
#include <fcntl.h>
#include <sys/stat.h>
#define FILE_MODE (S_IWUSR|S_IRUSR|S_IRGRP|S_IROTH) //0644
int main(int argc,char* argv[]){
	if(argc < 2){
		printf("usage:%s <mqname>\n",argv[0]);
		return 1;
	}
	
	mqd_t mqd = mq_open(argv[1],O_RDWR);
	if(-1 == mqd){
		perror("mq_open error");
		return;
	}
	struct mq_attr new_attr;
	bzero(&new_attr,sizeof(new_attr));
	//设置新属性
	new_attr.mq_flags = O_NONBLOCK;
	struct mq_attr attr;
	if(-1 == mq_setattr(mqd,&new_attr,&attr)){
		perror("mq_setattr error");
		return 1;
	}
	//输出旧属性
	printf("flag:%ld,Max msg:%ld,Max msgsize:%ld,Cur msgnun:%ld\n",attr.mq_flags,attr.mq_maxmsg,attr.mq_msgsize,attr.mq_curmsgs);
}