#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

struct proc_dir_entry * slam_entry = NULL;
struct proc_dir_entry * single_slam_entry = NULL;

static char * entry_name = "slam";
static char * single_entry_name = "single_slam";

#define MAX_SLAM_SIZE 10

static int slam[MAX_SLAM_SIZE];

static void * slam_start(struct seq_file *m, loff_t *pos)
{
        return (*pos < MAX_SLAM_SIZE) ? pos : NULL;
}

static int slam_show(struct seq_file *m, void *p)
{
        unsigned int i = *(loff_t *)p;
        seq_printf(m, "The %d data is : %d\n", i, slam[i]);
        return 0;
}

static void * slam_next(struct seq_file *m, void *p, loff_t *pos)
{
        (*pos)++;
        if (*pos >= MAX_SLAM_SIZE)
                return NULL;
        return pos;
}

static void slam_stop(struct seq_file *m, void *p)
{
}

static int single_slam_show(struct seq_file *m, void *p)
{
        seq_printf(m, "%s\n", "In single slam show!");
        return 0;
}

static struct seq_operations slam_seq_op =
{
        .start = slam_start,
        .next = slam_next,
        .stop = slam_stop,
        .show = slam_show,
};

static int slam_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &slam_seq_op);
}

static int single_slam_open(struct inode *inode, struct file *file)
{
        return single_open(file, single_slam_show, NULL);
}

static const struct file_operations slam_fops =
{
        .owner = THIS_MODULE,
        .open = slam_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = seq_release,
};

static const struct file_operations single_slam_fops =
{
        .owner = THIS_MODULE,
        .open = single_slam_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = single_release,

};

static __init int seqfile_example_init(void)
{
        #ifdef CONFIG_PROC_FS
                int i;
                for (i = 0; i < MAX_SLAM_SIZE; i++)
                {
                        slam[i] = 2 * i + 1;
                }

                slam_entry = proc_create(entry_name, 0666, NULL, &slam_fops);
                if (!slam_entry)
                {
                        printk("Create file \"%s\" failed.\n", entry_name);
                        return -1;
                }

                single_slam_entry = proc_create(single_entry_name, 0666, NULL, &single_slam_fops);
                if (!single_slam_entry)
                {
                        printk("Create file \"%s\" failed.\n", single_entry_name);
                        return -1;
                }

        #else
                printk("This module requests the kernel to support procfs,need set CONFIG_PROC_FS configure Y\n");
        #endif
        return 0;
}

static __exit void seqfile_example_exit(void)
{
        #ifdef CONFIG_PROC_FS
                remove_proc_entry(single_slam_entry);
                remove_proc_entry(slam_entry);
        #endif
}

module_init(seqfile_example_init);
module_exit(seqfile_example_exit);