#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Utkarsh Gupta");
MODULE_DESCRIPTION("Logging incoming packaets.");

static struct nf_hook_ops nfho;

uint64_t counter = 0;

/*
unsigned int my_hook(unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))  {
      struct sock *sk = skb->sk;
      printk("Packet's here!");
      return NF_ACCEPT;
}
*/

unsigned int my_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
  struct sock *sk = skb->sk;
  printk("Hello packet number %llu", ++counter);
  return NF_ACCEPT;
}

static int init_filter_if(void) {
  nfho.hook = my_hook;
  nfho.hooknum = 0;
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FIRST;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
  nf_register_net_hook(&init_net, &nfho);
#else
  nf_register_hook(&nfho);
#endif

  return 0;
}

int init_module(void) {
    printk(KERN_INFO "Module initialized.\n");
    init_filter_if();
    return 0;
}

void cleanup_module(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
  nf_unregister_net_hook(&init_net, &nfho);
#else
  nf_unregister_hook(&nfho);
#endif

  printk(KERN_INFO "Module cleaned up.\n");
}
