#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/highmem.h>

static struct proc_dir_entry *proc_ent;
static struct page* page;
static  int index=0;
static char content[] =
"Listen to me say thanks\n";

static int proc_mmap(struct file* fp, struct vm_area_struct* vma)
{
    // TODO
    //  unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
    //  unsigned long pfn_start = (unsigned long )kmap_local_page(page);
    // unsigned long size = vma->vm_end - vma->vm_start;
     int ret = 0;

    //  printk("phy: 0x%lx, offset: 0x%lx, size: 0x%lx\n", pfn_start << PAGE_SHIFT, offset, size);
    pr_info("index:%d",index);
     ret = remap_pfn_range(vma, vma->vm_start, page_to_pfn(page), (unsigned long)index, vma->vm_page_prot);
    if (ret)
         pr_info("remap_pfn_range failed \n");
     else
        pr_info("remap success!");
   return ret;
}

static const struct proc_ops proc_ops = {
    .proc_mmap = proc_mmap,
};

static int __init maptest_init(void)
{
    void* base;

    proc_ent = proc_create("maptest", 0666, NULL, &proc_ops);
    if (!proc_ent)
    {
        proc_remove(proc_ent);
        pr_alert("Error: Could not initialize /proc/maptest\n");
        return -EFAULT;
    }
    pr_info("/proc/maptest created\n");

    // TODO: allocate page and copy content
    unsigned long int  kernel_addr;
    page=alloc_page(GFP_KERNEL);
    kernel_addr = (unsigned long )kmap_local_page(page);
    char *c;
    // char *c_copy;
    c=(char *)kernel_addr;
    // c_copy=c;
    while(content[index]!='\n'){
        *c=content[index];
        c++;
        index++;
    }
    c++;
    *c='\n';
    index++;
    return 0;
}

static void __exit maptest_exit(void)
{
    proc_remove(proc_ent);
    pr_info("/proc/maptest removed\n");
    __free_page(page);
    pr_info("memory freed\n");
}

module_init(maptest_init);
module_exit(maptest_exit);
MODULE_LICENSE("GPL");