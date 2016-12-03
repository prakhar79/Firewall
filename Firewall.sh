# This is a firewall script
SERVER_IP="192.168.220.131"
KALI="192.168.220.128"
META="192.168.220.129"

if [ $1 = "start" ]; then
    #Flusing iptables before stating applying new rules.
    iptables --flush
    iptables -t mangle --flush

    #Adding a new chain called LOG

    iptables -N LOG
    iptables -A LOG -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
    iptables -A LOG -j DROP

    #Default polices.
    iptables --policy INPUT DROP
    iptables --policy OUTPUT ACCEPT
    iptables --policy FORWARD DROP

    #Accept packets to and from local interface
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    #Accept the packets of already connected streams
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    #Allow everyone except KALI to connect using SSH
    iptables -A INPUT -i eth0 -p tcp -s $KALI -d $SERVER_IP --dport 21 -j DROP
    iptables -A INPUT -i eth0 -p tcp -d $SERVER_IP --dport 21 -j ACCEPT

    #Allow ICMP to local network but block for others
    iptables -A INPUT -i eth0 -p icmp -s 192.168.220.0/24 -j ACCEPT
    iptables -A OUTPUT -o eth0 -p icmp -d 192.168.220.0/24 -j ACCEPT
    iptables -A INPUT -i eth0 -p icmp -j REJECT

    #Block bad or private ip addresses
    iptables -A INPUT -i eth0 -s 0.0.0.0/8 -j LOG
    iptables -A INPUT -i eth0 -s 127.0.0.0/8 -j LOG
    iptables -A INPUT -i eth0 -s 10.0.0.0/8 -j LOG
    iptables -A INPUT -i eth0 -s 172.16.0.0/12 -j LOG
    iptables -A INPUT -i eth0 -s 224.0.0.0/3 -j LOG

    # Protection against port scanning 
    iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j REJECT

    #Block flag based in Pre-routing
    iptables -t mangle -A PREROUTING -i lo -j ACCEPT
    iptables -t mangle -A PREROUTING -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -t mangle -A PREROUTING -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j LOG
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j LOG
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j LOG
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j LOG
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j LOG
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j LOG
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j LOG
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j LOG
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j LOG
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j LOG
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j LOG
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j LOG
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j LOG
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j LOG
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j LOG

    #DDoS attack protection
    iptables -A INPUT -p tcp -m connlimit --connlimit-above 20 -j REJECT --reject-with tcp-reset

    #SSH brute-force protection 
    iptables -A INPUT -p tcp --dport 21 -m conntrack --ctstate NEW -m recent --set
    iptables -A INPUT -p tcp --dport 21 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j LOG
    
fi

if [ $1 = "stop" ]; then 
    #Clear all the rules in iptables
    iptables --flush
    iptables -t mangle --flush
fi






