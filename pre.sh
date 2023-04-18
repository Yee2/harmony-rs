#!/usr/sbin/nft -f

table inet https.nat {
}
delete table inet https.nat
table inet https.nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        tcp dport 443 ip daddr != { 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,224.0.0.0/4,240.0.0.0/4} redirect to 8443
        tcp dport 80 ip daddr != { 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,224.0.0.0/4,240.0.0.0/4 } redirect to 8080
    }

    chain forward {
        type filter hook forward priority 0; policy accept;
    }

    chain input {
        type nat hook input priority -100;
    }

    chain output {
        type nat hook output priority -100; policy accept;
        meta mark 8366 return
        skuid nobody skgid nobody return
        tcp dport 443 ip daddr != { 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,224.0.0.0/4,240.0.0.0/4} redirect to 8443
        tcp dport 80 ip daddr != { 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,224.0.0.0/4,240.0.0.0/4 } redirect to 8080
    }

    chain postrouting {
        type nat hook postrouting priority 100;
    }
}
