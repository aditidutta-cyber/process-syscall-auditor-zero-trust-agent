#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

#define DEVICE_NAME "process_auditor"
#define CLASS_NAME  "auditor"

static int major_number;
static struct class *auditor_class;
static struct device *auditor_device;

static char event_buffer[256];
static spinlock_t event_lock;

static int execve_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long flags;
    kuid_t uid;

    uid = current_uid();

    spin_lock_irqsave(&event_lock, flags);

    scnprintf(event_buffer, sizeof(event_buffer),
              "EXEC_EVENT PID=%d PPID=%d UID=%u COMM=%s\n",
              current->pid,
              current->real_parent->pid,
              __kuid_val(uid),
              current->comm);

    spin_unlock_irqrestore(&event_lock, flags);

    printk(KERN_INFO "PROCESS_AUDITOR: %s", event_buffer);

    return 0;
}

static struct kprobe execve_probe = {
    .symbol_name = "__x64_sys_execve",
    .pre_handler = execve_pre_handler,
};

static ssize_t auditor_read(struct file *file,
                            char __user *buffer,
                            size_t length,
                            loff_t *offset)
{
    unsigned long flags;
    size_t len;

    if (*offset > 0)
        return 0;

    spin_lock_irqsave(&event_lock, flags);

    len = strlen(event_buffer);

    if (len > length)
        len = length;

    if (copy_to_user(buffer, event_buffer, len)) {
        spin_unlock_irqrestore(&event_lock, flags);
        return -EFAULT;
    }

    spin_unlock_irqrestore(&event_lock, flags);

    *offset += len;

    return len;
}

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = auditor_read,
};


static int __init auditor_init(void)
{
    int result;

    spin_lock_init(&event_lock);

    memset(event_buffer, 0, sizeof(event_buffer));

    major_number = register_chrdev(0, DEVICE_NAME, &fops);

    if (major_number < 0) {
        printk(KERN_ERR "PROCESS_AUDITOR: failed to register device\n");
        return major_number;
    }

    auditor_class = class_create(CLASS_NAME);

    if (IS_ERR(auditor_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(auditor_class);
    }

    auditor_device =
        device_create(auditor_class,
                      NULL,
                      MKDEV(major_number, 0),
                      NULL,
                      DEVICE_NAME);

    if (IS_ERR(auditor_device)) {
        class_destroy(auditor_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(auditor_device);
    }

    result = register_kprobe(&execve_probe);

    if (result < 0) {
        printk(KERN_ERR
               "PROCESS_AUDITOR: kprobe registration failed: %d\n",
               result);

        device_destroy(auditor_class, MKDEV(major_number, 0));
        class_destroy(auditor_class);
        unregister_chrdev(major_number, DEVICE_NAME);

        return result;
    }

    printk(KERN_INFO
           "PROCESS_AUDITOR: module loaded successfully\n");

    printk(KERN_INFO
           "PROCESS_AUDITOR: monitoring execve()\n");

    return 0;
}


static void __exit auditor_exit(void)
{
    unregister_kprobe(&execve_probe);

    device_destroy(auditor_class, MKDEV(major_number, 0));
    class_destroy(auditor_class);
    unregister_chrdev(major_number, DEVICE_NAME);

    printk(KERN_INFO
           "PROCESS_AUDITOR: module unloaded\n");
}

module_init(auditor_init);
module_exit(auditor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aditi Dutta");
MODULE_DESCRIPTION(
    "Process Syscall Auditor and Zero-Trust Behavioral Agent kernel component"
);
MODULE_VERSION("1.0");
