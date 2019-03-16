import core.stdc.config;
import list_head_h;
import spinlock_types_h : spinlock_t, atomic_t;
import lockdep_map_h : dstruct_lockdep_map = lockdep_map;

struct dstruct_module;
struct kobject;
struct attribute_group;
struct kobj_uevent_env;
struct umode_t;
struct kobj_ns_type_operations;
struct kuid_t;
struct kgid_t;
struct dev_pm_ops;
struct subsys_private;

struct dstruct_class {
    const char *name;
    dstruct_module *owner;

    const attribute_group **class_groups;
    const attribute_group **dev_groups;
    kobject *dev_kobj;

    int function(device *dev, kobj_uevent_env *env) dev_uevent;
    char* function(device *dev, umode_t *mode) devnode;

    void function(dstruct_class *dstruct_class_param) class_release;
    void function(device *dev) dev_release;

    int function(device *dev) shutdown_pre;

    const kobj_ns_type_operations *ns_type;
    const void* function(device *dev) namespace;

    void function(device *dev, kuid_t *uid, kgid_t *gid) get_ownership;

    const dev_pm_ops *pm;

    subsys_private *p;
}

struct device_private;
struct device_type;
struct bus_type;
struct device_driver;
struct dev_pm_domain;
struct dma_map_ops;
struct device_node;
struct fwnode_handle;
struct dma_coherent_mem;
struct device_dma_parameters;

import kobject_h : dstruct_kobject = kobject, dstruct_kref;
import mutex_h : dstruct_mutex = mutex;

struct iommu_group;
struct iommu_fwspec;

alias dstruct_iommu_group = iommu_group;
alias dstruct_iommu_fwspec = iommu_fwspec;

struct klist_node {
    void *n_klist;
    list_head	n_node;
    dstruct_kref n_ref;
};

enum dl_dev_state {
    DL_DEV_NO_DRIVER = 0,
    DL_DEV_PROBING,
    DL_DEV_DRIVER_BOUND,
    DL_DEV_UNBINDING,
}

struct dev_links_info {
    list_head suppliers;
    list_head consumers;
    dl_dev_state status;
}

struct pm_message {
    int event;
}

struct pm_subsys_data;
struct dev_pm_qos;

version(CONFIG_INTEL_IOMMU) {
    enum ENABLE_INTEL_IOMMU = 1;
}
else {

    enum ENABLE_INTEL_IOMMU = 0;
}

version(CONFIG_AMD_IOMMU) {
    enum ENABLE_AMD_IOMMU = 1;
}
else {
    enum ENABLE_AMD_IOMMU = 0;
}

version(CONFIG_STA2X11) {
    enum ENABLE_STA2X11 = 1;
}
else {
    enum ENABLE_STA2X11 = 0;
}

struct dev_archdata {

    static if (ENABLE_INTEL_IOMMU || ENABLE_AMD_IOMMU) {
        void *iommu;
    }

    static if (ENABLE_STA2X11) {
        bool is_sta2x11;
    }
}

struct completion {
    uint done;
    wait_queue_head_t wait;
};

struct wait_queue_head {
    spinlock_t		lock;
    list_head	head;
}

struct timer_list {
    hlist_node entry;
    c_ulong expires;
    void function(timer_list *) dlang_function;
    uint flags;

    version(CONFIG_LOCKDEP) {
        dstruct_lockdep_map lockdep_map;
    }
}

alias work_func_t = void function(work_struct *work);

import mutex_h : atomic_long_t;

struct work_struct {
    atomic_long_t data;
    list_head entry;
    work_func_t func;

    version(CONFIG_LOCKDEP) {
        dstruct_lockdep_map lockdep_map;
    }
}

struct wakeup_source;
struct wake_irq;

alias wait_queue_head_t = wait_queue_head;
alias pm_message_t = pm_message;

import std.bitmanip : bitfields;

struct dev_pm_info {
    pm_message_t		power_state;

    mixin(bitfields!(
        uint, "can_wakeup", 1,
        uint, "async_suspend", 1,
        bool, "in_dpm_list", 1,
        bool, "is_prepared", 1,
        bool, "is_suspended", 1,
        bool, "is_noirq_suspended", 1,
        bool, "is_late_suspended", 1,
        bool, "early_init", 1,
        bool, "direct_complete", 1,
        uint, "", 7
        ));

    uint driver_flags;
    spinlock_t		lock;

    version(CONFIG_PM_SLEEP) {
        list_head	entry;
        completion	completion;
        wakeup_source	*wakeup;

        mixin(bitfields!(
            bool, wakeup_path, 1,
            bool, syscore, 1,
            bool, no_pm_callbacks, 1,
            uint, must_resume, 1,
            uint, may_skip_resume, 1
            ));
    }
    else {
        mixin(bitfields!(
            uint, "should_wakeup", 1,
            uint, "", 7
            ));
    }

    version(CONFIG_PM) {
        timer_list	suspend_timer;
        c_ulong		timer_expires;
        work_struct	work;
        wait_queue_head_t	wait_queue;
        wake_irq		*wakeirq;
        atomic_t		usage_count;
        atomic_t		child_count;

        mixin(bitfields!(
            uint, "disable_depth", 3,
            uint, "idle_notification", 1,
            uint, "request_pending", 1,
            uint, "deferred_resume", 1,
            uint, "runtime_auto", 1,
            bool, "ignore_children", 1,
            uint, "no_callbacks", 1,
            uint, "irq_safe", 1,
            uint, "use_autosuspend", 1,
            uint, "timer_autosuspends", 1,
            uint, "memalloc_noio", 1
            ));

        uint		links_count;
        rpm_request	request;
        rpm_status		runtime_status;
        int			runtime_error;
        int			autosuspend_delay;
        c_ulong		last_busy;
        c_ulong		active_jiffies;
        c_ulong		suspended_jiffies;
        c_ulong		accounting_timestamp;
    }
    pm_subsys_data	*subsys_data;
    void function(device *, int) set_latency_tolerance;
    dev_pm_qos	*qos;
}

struct cma;
struct irq_domain;
struct dev_pin_info;

struct device {
    device *parent;

    device_private	*p;

    dstruct_kobject kobj;

    const char *init_name; /* initial name of the device */

    const device_type *type;

    dstruct_mutex mutex; /* mutex to synchronize calls to  its driver.*/

    bus_type *bus; /* type of bus device is on */

    device_driver *driver; /* which driver has allocated this device */

    void *platform_data; /* Platform specific data, device core doesn't touch it */

    void *driver_data; /* Driver data, set and get with dev_set/get_drvdata */

    dev_links_info links;

    dev_pm_info power;

    dev_pm_domain *pm_domain;

    version(CONFIG_GENERIC_MSI_IRQ_DOMAIN) {
        irq_domain *msi_domain;
    }

    version(CONFIG_PINCTRL) {
        dev_pin_info *pins;
    }

    version(CONFIG_GENERIC_MSI_IRQ) {
        list_head msi_list;
    }

    version(CONFIG_NUMA)
    {
        int numa_node; /* NUMA node this device is close to */
    }

    const dma_map_ops *dma_ops;

    ulong *dma_mask; /* dma mask (if dma'able device) */

    ulong coherent_dma_mask; /* Like dma_mask, but for
                            alloc_coherent mappings as
                            not all hardware supports
                            64 bit addresses for consistent
                            allocations such descriptors. */
    ulong bus_dma_mask; /* upstream dma_mask constraint */

    c_ulong dma_pfn_offset;

    device_dma_parameters *dma_parms;

    list_head dma_pools; /* dma pools (if dma'ble) */

    dma_coherent_mem *dma_mem; /* internal for coherent mem override */

    version(CONFIG_DMA_CMA)
    {
        cma *cma_area; /* contiguous memory area for dma allocations */
    }

    /* arch specific additions */
    static if(ENABLE_INTEL_IOMMU || ENABLE_AMD_IOMMU || ENABLE_STA2X11) {
        dev_archdata archdata;
    }

    device_node *of_node; /* associated device tree node */
    fwnode_handle *fwnode; /* firmware device node */

    uint devt; /* dev_t, creates the sysfs "dev" */
    uint id; /* device instance */

    spinlock_t devres_lock;
    list_head devres_head;

    klist_node knode_class;
    dstruct_class *dstruct_class_pointer;
    const attribute_group **groups; /* optional groups */

    void function(device *dev) release;
    dstruct_iommu_group *iommu_group;
    dstruct_iommu_fwspec *iommu_fwspec;

    mixin(bitfields! (
               bool, "offline_disabled", 1,
               bool, "offline", 1,
               bool, "of_node_reused", 1,
               bool, "", 5
                ));
}
