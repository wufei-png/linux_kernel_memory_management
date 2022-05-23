#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>

#define SIZE 1 << 12
//prot 参数指定共享内存的访问权限。可取如下几个值的或：PROT_READ（可读） , PROT_WRITE （可写）, PROT_EXEC （可执行）, PROT_NONE（不可访问）。
// MAP_PRIVATE	创建一个私有映射。映射区域中内存发生变化对使用同一映射 的其他进程不可见。对文件映射来讲，所发生的变更将不会反应在底层文件上。
int main(void)
{
    int fd = open("/proc/maptest", O_RDONLY);
    if (fd == -1) {
        perror("open /proc/maptest error\n");
    }
    char* buf = (char*) mmap(NULL, SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    fputs(buf, stdout);
    munmap(buf, SIZE);//解除内存映射
    return 0;
}