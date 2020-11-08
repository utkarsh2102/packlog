#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Utkarsh Gupta");
MODULE_DESCRIPTION("Logging incoming packaets.");

// default struct for Netfilter hook option
static struct nf_hook_ops nfho;

// packet counter
uint64_t counter = 0;

// this function is used for hook-ing
unsigned int tmp_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
  // struct sock *sk = skb->sk;
  printk("Packet number %llu", ++counter);
  return NF_ACCEPT; // to drop these packets, return NF_DROP instead
}

static int init_filter_if(void) {
  nfho.hook = tmp_hook; // call tmp_hook when below conditions are met
  nfho.hooknum = 0; // for NF_IP_PRE_ROUTING (used interchangably!)
  nfho.pf = PF_INET; // IPv4 packets
  nfho.priority = NF_IP_PRI_FIRST; // set highest priority

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
  nf_register_net_hook(&init_net, &nfho); // registering the hook here
#else
  nf_register_hook(&nfho); // registering the hook here
#endif

  return 0;
}

int init_module(void) {
    init_filter_if(); // call the init_filter_if for initialization
    printk(KERN_INFO "packlog module initialized.\n");
    return 0;
}

void cleanup_module(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
  nf_unregister_net_hook(&init_net, &nfho); // unregistering the hook here
#else
  nf_unregister_hook(&nfho); // unregistering the hook here
#endif
  printk(KERN_INFO "packlog module removed.\n");
}
