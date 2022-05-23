#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/highmem.h>

#define MAX_SIZE 128

static struct proc_dir_entry *proc_ent;
static char output[MAX_SIZE];
static int out_len;
static char proc_buf[40];//假定传来的数据最多40位
// static char *pid;
// static char content[1];//固定一个字节，这爽了
// static char *vir_addr;

enum operation {
    OP_READ, OP_WRITE
};

static ssize_t proc_read(struct file *fp, char __user *ubuf, size_t len, loff_t *pos)
{
    int count; /* the number of characters to be copied */
    if (out_len - *pos > len) {
        count = len;
    }
    else {
        count = out_len - *pos;
    }
    
    pr_info("Reading the proc file\n");
    pr_info("用户想要得到的字节为的len为%ld",len);
    pr_info("文件系统的当前位置为%lld",*pos);//重新运行用户进程始终为0
    pr_info("写入user的字节为%d",count);
    // count=1;
    if (copy_to_user(ubuf, output + *pos, count)) return -EFAULT;
    *pos += count;
    
    return count;
}

static struct page* find_page(struct mm_struct *mm, unsigned long addr)
{

    pgd_t *pgd = pgd_offset(mm, addr);
    p4d_t *p4d = NULL;
    pud_t *pud = NULL;
    pmd_t *pmd = NULL;
    pte_t *pte = NULL;
    struct page *page = NULL;

    if(pgd_none(*pgd) || pgd_bad(*pgd))
        return NULL;
    p4d = p4d_offset(pgd, addr);
    if(p4d_none(*p4d) || p4d_bad(*p4d))
        return NULL;
    pud = pud_offset(p4d, addr);
    if(pud_none(*pud) || pud_bad(*pud))
        return NULL;
    pmd = pmd_offset(pud, addr);
    if(pmd_none(*pmd) || pmd_bad(*pmd))
        return NULL;
    pte = pte_offset_map(pmd, addr);
    if(pte_none(*pte) || !pte_present(*pte))
        return NULL;
    page = pte_page(*pte);
    if(!page)
        return NULL;
    pte_unmap(pte);
    pr_info("找到物理页了！");
    return page;
}
        // page_addr = pte_val(*pte) & PAGE_MASK;
        // page_offset = addr & ~PAGE_MASK;
        // phy_addr = page_addr | page_offset;
static void mtest_read(int pid_num,unsigned long int vir_addr){

    unsigned long int  kernel_addr;
    unsigned long int final_kernel_addr;
    
    struct pid * pid=find_get_pid(pid_num);//得到pid结构体
    struct task_struct * task=pid_task(pid,PIDTYPE_PID);//得到task_struct结构体
    struct mm_struct *mm=task->mm;//得到mm_struct结构体
    struct page *page=find_page(mm,vir_addr);//得到物理页
    pr_info("可以执行到这里");
    kernel_addr = (unsigned long )kmap_local_page(page);
    // pr_info("%d",kernel_addr==NULL);
    pr_info("此刻kernel_addr的值为:%lx",kernel_addr);//long按16进制打印
    // pr_info("此刻PAGE_MASK的值为:%lx",PAGE_MASK);//long按16进制打印
    // // *output=*((char*)(kmap_local_page(page)+page_offset));//映射到内核空间内并读取它的值 1字节
    final_kernel_addr=(kernel_addr & PAGE_MASK)|(vir_addr & ~PAGE_MASK);//这里有问题？
    pr_info("此刻final_kernel_addr的值为:%lx",final_kernel_addr);
    char *c;
    c=(char *)final_kernel_addr;
    pr_info("此刻读取到用户空间内C的值为:%c",*c);
    // char c;
    // &c=final_kernel_addr;
    *output=*c;
    out_len=1; 
    // pr_info("此刻ouput的值为:%c",*final_kernel_addr);
}

static void mtest_write(int pid_num,unsigned long int vir_addr,int content){
    unsigned long int  kernel_addr;
    unsigned long int final_kernel_addr;
    
    struct pid * pid=find_get_pid(pid_num);//得到pid结构体
    struct task_struct * task=pid_task(pid,PIDTYPE_PID);//得到task_struct结构体
    struct mm_struct *mm=task->mm;//得到mm_struct结构体
    struct page *page=find_page(mm,vir_addr);//得到物理页
    pr_info("可以执行到这里");
    kernel_addr = (unsigned long )kmap_local_page(page);
    // pr_info("%d",kernel_addr==NULL);
    pr_info("此刻kernel_addr的值为:%lx",kernel_addr);//long按16进制打印
    // pr_info("此刻PAGE_MASK的值为:%lx",PAGE_MASK);//long按16进制打印
    // // *output=*((char*)(kmap_local_page(page)+page_offset));//映射到内核空间内并读取它的值 1字节
    final_kernel_addr=(kernel_addr & PAGE_MASK)|(vir_addr & ~PAGE_MASK);//这里有问题？
    pr_info("此刻final_kernel_addr的值为:%lx",final_kernel_addr);
    char *c;
    c=(char *)final_kernel_addr;
    pr_info("此刻读取到用户空间内C的值为:%c",*c);
    // char c;
    // &c=final_kernel_addr;
    *c=content;
    // pr_info("此刻ouput的值为:%c",*final_kernel_addr);
}

static ssize_t proc_write(struct file *fp, const char __user *ubuf, size_t len, loff_t *pos)
{
    // TODO: parse the input, read/write process' memory
    size_t procfs_buffer_size;
    procfs_buffer_size = len;                                  //操作系统自动传递
    pr_info("从用户空间传入的长度：%ld\n", procfs_buffer_size); // 2是因为换行符？

    if (copy_from_user(proc_buf, ubuf, len))
    {
        printk(KERN_ERR "Copy from user unfinished\n");
        return -EFAULT;
    }
    if (strncmp(proc_buf, "r", 1) == 0)
    {   int pid_num;
        unsigned long int vir_addr;
        // pid = (char *)kmalloc((procfs_buffer_size-13) * sizeof(char), GFP_KERNEL);
        // vir_addr=(char *)kmalloc((12) * sizeof(char), GFP_KERNEL);
        // memcpy(pid,proc_buf+1,procfs_buffer_size-13);
        // memcpy(vir_addr,proc_buf+(procfs_buffer_size-12),12);
        sscanf(proc_buf + 2, "%d %lx", &pid_num, &vir_addr);//包含一个空格把
        // pr_info('pid:',pid)
        // pr_info('vir_addr:',vir_addr)
        printk(KERN_INFO "读取 %d 进程中 0x%lx 地址的⼀字节内容写入到proc/mtest中 \n",pid_num,vir_addr);
        mtest_read(pid_num,vir_addr);
    }
    else if (strncmp(proc_buf, "w", 1) == 0)
    {   int pid_num;
        unsigned long int vir_addr;

        int content;
        // memcpy(pid,proc_buf+1,procfs_buffer_size-14);
        // memcpy(vir_addr,proc_buf+(procfs_buffer_size-13),12);
        // memcpy(content,proc_buf+(procfs_buffer_size-1),1);
        // pr_info('pid:',pid)
        // pr_info('vir_addr:',vir_addr)
        sscanf(proc_buf + 2, "%d %lx %d", &pid_num, &vir_addr,&content);//包含一个空格把
        printk(KERN_INFO "把⼀字节内容 %d 写入 %d 进程中 %lx 地址的变量\n",content,pid_num,vir_addr);
        mtest_write(pid_num,vir_addr,content);
    }
    else
    {
        printk(KERN_ERR "Invalid input!\n");
    }
    return len;
}

static const struct proc_ops proc_ops = {
    .proc_read = proc_read,
    .proc_write = proc_write,
};

static int __init mtest_init(void)
{
    proc_ent = proc_create("mtest", 0666, NULL, &proc_ops);//读写不能执行的权限
    if (!proc_ent)
    {
        proc_remove(proc_ent);
        pr_alert("Error: Could not initialize /proc/mtest\n");
        return -EFAULT;
    }
    pr_info("/proc/mtest created\n");
    return 0;
}

static void __exit mtest_exit(void)
{
    proc_remove(proc_ent);
    pr_info("/proc/mtest removed\n");
}

module_init(mtest_init);
module_exit(mtest_exit);
MODULE_LICENSE("GPL");