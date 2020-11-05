#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Utkarsh Gupta");
MODULE_DESCRIPTION("Logging incoming packaets.");

static struct nf_hook_ops nfho;

uint64_t counter = 0;

unsigned int my_hook(unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))  {
      struct sock *sk = skb->sk;
      printk("Packet's here!");
      return NF_ACCEPT;
}

static int init_filter_if(void) {
  nfho.hook = my_hook;
  nfho.hooknum = 0;
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FIRST;
  nf_register_hook(&nfho);
  return 0;
}

int init_module(void) {
    printk(KERN_INFO "Module initialized.\n");
    init_filter_if();
    return 0;
}

void cleanup_module(void) {
  nf_unregister_hook(&nfho);
  printk(KERN_INFO "Module cleaned up.\n");
}
