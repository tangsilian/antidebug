#include <jni.h>
#include <string>
#include <unistd.h>
#include<Android/log.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/inotify.h>
#define TAG "TSL" // 这个是自定义的LOG的标识
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,TAG ,__VA_ARGS__) // 定义LOGD类型

//声明方法anti_debug01
void anti_debug01();
void anti_debug02();
void anti_debug03();
void anti_debug04();
void anti_debug05();
void anti_debug06();
void anti_debug07();
void anti_debug08();
unsigned long GetLibAddr();

extern "C"
JNIEXPORT jstring JNICALL
Java_com_tangsilian_antidebug_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    anti_debug04();
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}
//方法一：附加到自身 让ida附加不上 无法实现调试
void anti_debug01(){
    ptrace(PTRACE_TRACEME,0,0,0);
    LOGD("%s","antidebug01 run");
}
//方法二：检测TracerPid的值 如果不为0 说明正在被调试
void anti_debug02(){
    const int bufsize=1024;
    char filename[bufsize];
    char line [bufsize];
    int pid=getpid();//getpid ()用来取得目前进程的进程识别码，许多程序利用取到的此值来建立临时文件， 以避免临时文件相同带来的问题。
    FILE *fp;
    sprintf(filename,"proc/%d/status",pid);//C语言sprintf()函数：将格式化的数据写入字符串
    fp=fopen(filename,"r");//
    if (fp!= NULL){
    while(fgets(line,bufsize,fp)){
    if(strncmp(line,"TracerPid",9)==0){
        int status=atoi(&line[10]);//第10为转成整数
    if(status!=0){
        fclose(fp);//先关闭
        LOGD("%s","antidebug02 run  exit");
        int ret=kill(pid,SIGKILL);
    }
        break;
    }
        LOGD("%s","no antidebug02 run");
    }
    }
}
//方法三：检测常用的端口
void anti_debug03(){
    const int bufsize=1024;
    char filename[bufsize];
    char line [bufsize];
    int pid=getpid();
    FILE *fp;
    sprintf(filename,"proc/net/tcp");//C语言sprintf()函数：将格式化的数据写入字符串
    fp=fopen(filename,"r");//
    if (fp!= NULL){
        while(fgets(line,bufsize,fp)){
            if(strncmp(line,"5D8A",4)==0){
                int ret=kill(pid,SIGKILL);
                }
        }
    }
    fclose(fp);//关闭流
}


//第四种检测是否存在android_server 判断是否正在被调试  这里要有读取目录的权限
void anti_debug04(){
    const char* rootPath = "/data/local/tmp";
    LOGD("%s","read dir");
    DIR* dir;
    dir = opendir(rootPath);
    LOGD("%s","read dir finsh");
    if (dir!= NULL) {
        dirent *currentDir;
        while ((currentDir = readdir(dir)) != NULL) {
            //readdir()方法就像java中迭代器的next()方法一样
            //currentDir->d_name; //文件名，目录名
            //currentDir->d_type; //类型，是目录还是文件啥的
            if(strncmp(currentDir->d_name,"android_server",14)==0){
                LOGD("%s",currentDir->d_name);
                LOGD("%s","antidebug04 run android_server exit  the programe exit");
            }
        }
        closedir(dir); //用完要关掉，要不然会出错
    } else{
        LOGD("%s","dir not access");
    }
}
//从maps中读取elf文件在内存中的起始地址
unsigned long GetLibAddr() {
    unsigned long ret = 0;
    char name[] = "libnative-lib.so";
    char buf[4096], *temp;
    int pid;
    FILE *fp;
    pid = getpid();
    sprintf(buf, "/proc/%d/maps", pid);
    fp = fopen(buf, "r");
    if (fp == NULL) {
        puts("open failed");
        goto _error;
    }
    while (fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, name)) {
            temp = strtok(buf, "-");//将buf由"-"参数分割成片段
            ret = strtoul(temp, NULL, 16);//将字符串转换成unsigned long(无符号长整型数)
            break;
        }
    }
    _error: fclose(fp);
    return ret;
}


/**
 * 第五种：检测在调试状态下的软件断点
 * 读取其周围的偏移地址有没有ARM等指令集的断点指令
 * 遍历so中可执行segment，查找是否出现breakpoint指令即可
 **/

void anti_debug05(){

    Elf32_Ehdr *elfhdr;
    Elf32_Phdr *pht;
    unsigned int size, base, offset,phtable;
    int n, i,j;
    char *p;
    //从maps中读取elf文件在内存中的起始地址
    base = GetLibAddr();
    if(base == 0){
        LOGD("find base error/n");
        return;
    }
    elfhdr = (Elf32_Ehdr *) base;

    phtable = elfhdr->e_phoff + base;

    for(i=0;i<elfhdr->e_phnum;i++){

        pht = (Elf32_Phdr*)(phtable+i*sizeof(Elf32_Phdr));

        if(pht->p_flags&1){
            offset = pht->p_vaddr + base + sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr)*elfhdr->e_phnum;
            LOGD("offset:%X ,len:%X",offset,pht->p_memsz);

            p = (char*)offset;
            size = pht->p_memsz;

            for(j=0,n=0;j<size;++j,++p){

                if(*p == 0x10 && *(p+1) == 0xde){
                    n++;
                    LOGD("### find thumb bpt %X /n",p);

                }else if(*p == 0xf0 && *(p+1) == 0xf7 && *(p+2) == 0x00 && *(p+3) == 0xa0){
                    n++;
                    LOGD("### find thumb2 bpt %X /n",p);
                }else if(*p == 0x01 && *(p+1) == 0x00 && *(p+2) == 0x9f && *(p+3) == 0xef){
                    n++;
                    LOGD("### find arm bpt %X /n",p);
                }
            }
            LOGD("### find breakpoint num: %d/n",n);
        }
    }

}

//方法六：inotify检测
void anti_debug06(){
    const int MAXLEN = 2048;
    int ppid =getpid();
    char buf[1024],readbuf[MAXLEN];
    int pid, wd, ret,len,i;
    int fd;
    fd_set readfds;
    //防止调试子进程
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    fd =  inotify_init();
    sprintf(buf, "/proc/%d/maps",ppid);

    //wd = inotify_add_watch(fd, "/proc/self/mem", IN_ALL_EVENTS);
    wd = inotify_add_watch(fd, buf, IN_ALL_EVENTS);
    if (wd < 0) {
        LOGD("can't watch %s",buf);
        return;
    }
    while (1) {
        i = 0;
        //注意要对fd_set进行初始化
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        //第一个参数固定要+1，第二个参数是读的fdset，第三个是写的fdset，最后一个是等待的时间
        //最后一个为NULL则为阻塞
        //select系统调用是用来让我们的程序监视多个文件句柄的状态变化
        ret = select(fd + 1, &readfds, 0, 0, 0);
        if (ret == -1)
            break;
        if (ret) {
            len = read(fd,readbuf,MAXLEN);
            while(i < len){
                //返回的buf中可能存了多个inotify_event
                struct inotify_event *event = (struct inotify_event*)&readbuf[i];
                LOGD("event mask %d\n",(event->mask&IN_ACCESS) || (event->mask&IN_OPEN));
                //这里监控读和打开事件
                if((event->mask&IN_ACCESS) || (event->mask&IN_OPEN)){
                    LOGD("kill!!!!!\n");
                    //事件出现则杀死父进程
                    int ret = kill(ppid,SIGKILL);
                    LOGD("ret = %d",ret);
                    return;
                }
                i+=sizeof (struct inotify_event) + event->len;
            }
        }
    }
    inotify_rm_watch(fd,wd);
    close(fd);
}

//方法七：检测代码执行时间差
int gettimeofday(struct timeval *tv, struct timezone *tz);
void anti_debug07()
{
    int pid = getpid();
    struct timeval t1;
    struct timeval t2;
    struct timezone tz;
    gettimeofday(&t1, &tz);
    gettimeofday(&t2, &tz);
    int timeoff = (t2.tv_sec) - (t1.tv_sec);
    if (timeoff > 1) {
        int ret = kill(pid, SIGKILL);
        return ;
    }
}