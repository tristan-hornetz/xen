/******************************************************************************
 * dom0_ops.c
 * 
 * Process command requests from domain-0 guest OS.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <public/dom0_ops.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <asm/domain_page.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <public/sched_ctl.h>

extern long arch_do_dom0_op(dom0_op_t *op, dom0_op_t *u_dom0_op);
extern void arch_getdomaininfo_ctxt(
    struct exec_domain *, struct vcpu_guest_context *);

static inline int is_free_domid(domid_t dom)
{
    struct domain *d;

    if ( dom >= DOMID_FIRST_RESERVED )
        return 0;

    if ( (d = find_domain_by_id(dom)) == NULL )
        return 1;

    put_domain(d);
    return 0;
}

/*
 * Allocate a free domain id. We try to reuse domain ids in a fairly low range,
 * only expanding the range when there are no free domain ids. This is to keep 
 * domain ids in a range depending on the number that exist simultaneously,
 * rather than incrementing domain ids in the full 32-bit range.
 */
static int allocate_domid(domid_t *pdom)
{
    static spinlock_t domid_lock = SPIN_LOCK_UNLOCKED;
    static domid_t curdom = 0;
    static domid_t topdom = 101;
    int err = 0;
    domid_t dom;

    spin_lock(&domid_lock);

    /* Try to use a domain id in the range 0..topdom, starting at curdom. */
    for ( dom = curdom + 1; dom != curdom; dom++ )
    {
        if ( dom == topdom )
            dom = 1;
        if ( is_free_domid(dom) )
            goto exit;
    }

    /* Couldn't find a free domain id in 0..topdom, try higher. */
    for ( dom = topdom; dom < DOMID_FIRST_RESERVED; dom++ )
    {
        if ( is_free_domid(dom) )
        {
            topdom = dom + 1;
            goto exit;
        }
    }

    /* No free domain ids. */
    err = -ENOMEM;

  exit:
    if ( err == 0 )
    {
        curdom = dom;
        *pdom = dom;
    }

    spin_unlock(&domid_lock);
    return err;
}

long do_dom0_op(dom0_op_t *u_dom0_op)
{
    long ret = 0;
    dom0_op_t curop, *op = &curop;

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( copy_from_user(op, u_dom0_op, sizeof(*op)) )
        return -EFAULT;

    if ( op->interface_version != DOM0_INTERFACE_VERSION )
        return -EACCES;

    switch ( op->cmd )
    {

    case DOM0_SETDOMAININFO:
    {
        struct domain *d = find_domain_by_id(op->u.setdomaininfo.domain);
        ret = -ESRCH;
        if ( d != NULL )
        {
            ret = set_info_guest(d, &op->u.setdomaininfo);
            put_domain(d);
        }
    }
    break;

    case DOM0_PAUSEDOMAIN:
    {
        struct domain *d = find_domain_by_id(op->u.pausedomain.domain);
        ret = -ESRCH;
        if ( d != NULL )
        {
            ret = -EINVAL;
            if ( d != current->domain )
            {
                domain_pause_by_systemcontroller(d);
                ret = 0;
            }
            put_domain(d);
        }
    }
    break;

    case DOM0_UNPAUSEDOMAIN:
    {
        struct domain *d = find_domain_by_id(op->u.unpausedomain.domain);
        ret = -ESRCH;
        if ( d != NULL )
        {
            ret = -EINVAL;
            if ( (d != current->domain) && 
                 test_bit(_DOMF_constructed, &d->domain_flags) )
            {
                domain_unpause_by_systemcontroller(d);
                ret = 0;
            }
            put_domain(d);
        }
    }
    break;

    case DOM0_CREATEDOMAIN:
    {
        struct domain      *d;
        unsigned int        pro;
        domid_t             dom;
        struct exec_domain *ed;
        unsigned int        i, cnt[NR_CPUS] = { 0 };


        dom = op->u.createdomain.domain;
        if ( (dom > 0) && (dom < DOMID_FIRST_RESERVED) )
        {
            ret = -EINVAL;
            if ( !is_free_domid(dom) )
                break;
        }
        else if ( (ret = allocate_domid(&dom)) != 0 )
        {
            break;
        }

        /* Do an initial CPU placement. Pick the least-populated CPU. */
        read_lock(&domlist_lock);
        for_each_domain ( d )
            for_each_exec_domain ( d, ed )
                cnt[ed->processor]++;
        read_unlock(&domlist_lock);
        
        /*
         * If we're on a HT system, we only use the first HT for dom0, other 
         * domains will all share the second HT of each CPU. Since dom0 is on 
	     * CPU 0, we favour high numbered CPUs in the event of a tie.
         */
        pro = ht_per_core - 1;
        for ( i = pro; i < num_online_cpus(); i += ht_per_core )
            if ( cnt[i] <= cnt[pro] )
                pro = i;

        ret = -ENOMEM;
        if ( (d = do_createdomain(dom, pro)) == NULL )
            break;

        ret = 0;
        
        op->u.createdomain.domain = d->domain_id;
        copy_to_user(u_dom0_op, op, sizeof(*op));
    }
    break;

    case DOM0_DESTROYDOMAIN:
    {
        struct domain *d = find_domain_by_id(op->u.destroydomain.domain);
        ret = -ESRCH;
        if ( d != NULL )
        {
            ret = -EINVAL;
            if ( d != current->domain )
            {
                domain_kill(d);
                ret = 0;
            }
            put_domain(d);
        }
    }
    break;

    case DOM0_PINCPUDOMAIN:
    {
        domid_t dom = op->u.pincpudomain.domain;
        struct domain *d = find_domain_by_id(dom);
        struct exec_domain *ed;
        cpumap_t cpumap;


        if ( d == NULL )
        {
            ret = -ESRCH;            
            break;
        }
        
        if ( (op->u.pincpudomain.vcpu >= MAX_VIRT_CPUS) ||
             !d->exec_domain[op->u.pincpudomain.vcpu] )
        {
            ret = -EINVAL;
            put_domain(d);
            break;
        }

        ed = d->exec_domain[op->u.pincpudomain.vcpu];
        if ( ed == NULL )
        {
            ret = -ESRCH;
            put_domain(d);
            break;
        }

        if ( ed == current )
        {
            ret = -EINVAL;
            put_domain(d);
            break;
        }

        if ( copy_from_user(&cpumap, op->u.pincpudomain.cpumap,
                            sizeof(cpumap)) )
        {
            ret = -EFAULT;
            put_domain(d);
            break;
        }

        /* update cpumap for this ed */
        ed->cpumap = cpumap;

        if ( cpumap == CPUMAP_RUNANYWHERE )
            clear_bit(_VCPUF_cpu_pinned, &ed->vcpu_flags);
        else
        {
            /* pick a new cpu from the usable map */
            int new_cpu = (int)find_first_set_bit(cpumap) % num_online_cpus();

            exec_domain_pause(ed);
            if ( ed->processor != new_cpu )
                set_bit(_VCPUF_cpu_migrated, &ed->vcpu_flags);
            set_bit(_VCPUF_cpu_pinned, &ed->vcpu_flags);
            ed->processor = new_cpu;
            exec_domain_unpause(ed);
        }

        put_domain(d);
    }
    break;

    case DOM0_SCHEDCTL:
    {
        ret = sched_ctl(&op->u.schedctl);
        copy_to_user(u_dom0_op, op, sizeof(*op));
    }
    break;

    case DOM0_ADJUSTDOM:
    {
        ret = sched_adjdom(&op->u.adjustdom);
        copy_to_user(u_dom0_op, op, sizeof(*op));
    }
    break;

    case DOM0_GETDOMAININFO:
    { 
        struct domain             *d;
        struct exec_domain        *ed;
        u64 cpu_time = 0;
        int vcpu_count = 0;
        int flags = DOMFLAGS_PAUSED | DOMFLAGS_BLOCKED;

        read_lock(&domlist_lock);

        for_each_domain ( d )
        {
            if ( d->domain_id >= op->u.getdomaininfo.domain )
                break;
        }

        if ( (d == NULL) || !get_domain(d) )
        {
            read_unlock(&domlist_lock);
            ret = -ESRCH;
            break;
        }

        read_unlock(&domlist_lock);

        op->u.getdomaininfo.domain = d->domain_id;

        memset(&op->u.getdomaininfo.vcpu_to_cpu, -1,
               sizeof(op->u.getdomaininfo.vcpu_to_cpu));
        memset(&op->u.getdomaininfo.cpumap, 0,
               sizeof(op->u.getdomaininfo.cpumap));

        /* 
         * - domain is marked as paused or blocked only if all its vcpus 
         *   are paused or blocked 
         * - domain is marked as running if any of its vcpus is running
         */
        for_each_exec_domain ( d, ed ) {
            op->u.getdomaininfo.vcpu_to_cpu[ed->vcpu_id] = ed->processor;
            op->u.getdomaininfo.cpumap[ed->vcpu_id]      = ed->cpumap;
            if ( !(ed->vcpu_flags & VCPUF_ctrl_pause) )
                flags &= ~DOMFLAGS_PAUSED;
            if ( !(ed->vcpu_flags & VCPUF_blocked) )
                flags &= ~DOMFLAGS_BLOCKED;
            if ( ed->vcpu_flags & VCPUF_running )
                flags |= DOMFLAGS_RUNNING;
            if ( ed->cpu_time > cpu_time )
                cpu_time += ed->cpu_time;
            vcpu_count++;
        }

        op->u.getdomaininfo.cpu_time = cpu_time;
        op->u.getdomaininfo.n_vcpu = vcpu_count;

        op->u.getdomaininfo.flags = flags |
            ((d->domain_flags & DOMF_dying)    ? DOMFLAGS_DYING    : 0) |
            ((d->domain_flags & DOMF_crashed)  ? DOMFLAGS_CRASHED  : 0) |
            ((d->domain_flags & DOMF_shutdown) ? DOMFLAGS_SHUTDOWN : 0) |
            d->shutdown_code << DOMFLAGS_SHUTDOWNSHIFT;

        op->u.getdomaininfo.tot_pages   = d->tot_pages;
        op->u.getdomaininfo.max_pages   = d->max_pages;
        op->u.getdomaininfo.shared_info_frame = 
            __pa(d->shared_info) >> PAGE_SHIFT;

        if ( copy_to_user(u_dom0_op, op, sizeof(*op)) )     
            ret = -EINVAL;

        put_domain(d);
    }
    break;

    case DOM0_GETVCPUCONTEXT:
    { 
        struct vcpu_guest_context *c;
        struct domain             *d;
        struct exec_domain        *ed;

        d = find_domain_by_id(op->u.getvcpucontext.domain);
        if ( d == NULL )
        {
            ret = -ESRCH;
            break;
        }

        if ( op->u.getvcpucontext.vcpu >= MAX_VIRT_CPUS )
        {
            ret = -EINVAL;
            put_domain(d);
            break;
        }
        
        ed = d->exec_domain[op->u.getvcpucontext.vcpu];
        if ( ed == NULL )
        {
            ret = -ESRCH;
            put_domain(d);
            break;
        }

        op->u.getvcpucontext.cpu_time = ed->cpu_time;

        if ( op->u.getvcpucontext.ctxt != NULL )
        {
            if ( (c = xmalloc(struct vcpu_guest_context)) == NULL )
            {
                ret = -ENOMEM;
                put_domain(d);
                break;
            }

            if ( ed != current )
                exec_domain_pause(ed);

            arch_getdomaininfo_ctxt(ed,c);

            if ( ed != current )
                exec_domain_unpause(ed);

            if ( copy_to_user(op->u.getvcpucontext.ctxt, c, sizeof(*c)) )
                ret = -EINVAL;

            xfree(c);
        }

        if ( copy_to_user(u_dom0_op, op, sizeof(*op)) )     
            ret = -EINVAL;

        put_domain(d);
    }
    break;

    case DOM0_SETTIME:
    {
        do_settime(op->u.settime.secs, 
                   op->u.settime.usecs, 
                   op->u.settime.system_time);
        ret = 0;
    }
    break;

#ifdef TRACE_BUFFER
    case DOM0_TBUFCONTROL:
    {
        ret = tb_control(&op->u.tbufcontrol);
        copy_to_user(u_dom0_op, op, sizeof(*op));
    }
    break;
#endif
    
    case DOM0_READCONSOLE:
    {
        ret = read_console_ring(op->u.readconsole.str, 
                                op->u.readconsole.count,
                                op->u.readconsole.cmd); 
    }
    break;

    case DOM0_SCHED_ID:
    {
        op->u.sched_id.sched_id = sched_id();
        copy_to_user(u_dom0_op, op, sizeof(*op));
        ret = 0;        
    }
    break;

    case DOM0_SETDOMAINMAXMEM:
    {
        struct domain *d; 
        ret = -ESRCH;
        d = find_domain_by_id(op->u.setdomainmaxmem.domain);
        if ( d != NULL )
        {
            d->max_pages = op->u.setdomainmaxmem.max_memkb >> (PAGE_SHIFT-10);
            put_domain(d);
            ret = 0;
        }
    }
    break;

#ifdef PERF_COUNTERS
    case DOM0_PERFCCONTROL:
    {
        extern int perfc_control(dom0_perfccontrol_t *);
        ret = perfc_control(&op->u.perfccontrol);
        copy_to_user(u_dom0_op, op, sizeof(*op));
    }
    break;
#endif

    default:
        ret = arch_do_dom0_op(op,u_dom0_op);

    }

    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
