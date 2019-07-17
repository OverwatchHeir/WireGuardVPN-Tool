
function isRoot () {
	if [ "$EUID" -ne 0 ]; then
		echo " ⚠️ You need to run this script as root ⚠️" > /dev/tty
		exit 1
	fi
}

function checkSupport(){
	if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ is not supported ❗" > /dev/tty
    exit
	fi

	if [ "$(systemd-detect-virt)" == "lxc" ]; then
		echo "LXC is not supported (yet)." > /dev/tty
		echo "WireGuard can technically run in an LXC container," > /dev/tty
		echo "but the kernel module has to be installed on the host," > /dev/tty
		echo "the container has to be run with some specific parameters" > /dev/tty
		echo "and only the tools need to be installed in the container ❗" > /dev/tty
		exit
	fi
}

function checkOS(){
	if [[ -e /etc/debian_version ]]; then
		source /etc/os-release
		OS=$ID # debian or ubuntu
	elif [[ -e /etc/fedora-release ]]; then
		OS=fedora
	elif [[ -e /etc/centos-release ]]; then
		OS=centos
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo " ⚠️  Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS or Arch Linux system ⚠️" > /dev/tty
		exit 1
	fi
}

function installWireGuardVPN(){
	echo "Installing WireGuardVPN tools and modules ⏳" > /dev/tty
	echo ""

	if [[ "$OS" = 'ubuntu' ]]; then
		apt-get install linux-headers-$(uname --kernel-release) 
		add-apt-repository ppa:wireguard/wireguard
		apt-get update
		apt-get install wireguard   
	elif [[ "$OS" = 'debian' ]] || [[ "$OS" = 'kali' ]]; then
		echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list > /dev/tty
		printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
		apt update
		apt-get install linux-headers-$(uname --kernel-release) 
		apt install wireguard   
	elif [[ "$OS" = 'fedora' ]]; then
		dnf copr enable jdoss/wireguard
		dnf install wireguard-dkms wireguard-tools  
	elif [[ "$OS" = 'centos' ]]; then
		curl -Lo /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
		yum install epel-release
		yum install wireguard-dkms wireguard-tools  
	elif [[ "$OS" = 'arch' ]]; then
		pacman -S wireguard-tools  
	fi

	# Make sure the directory exists (this does not seem the be the case on fedora)
	mkdir /etc/wireguard > /dev/null 2>&1
	
	echo "" > /dev/tty
	echo " ✅  WireGuardVPN installed" > /dev/tty
	echo "" > /dev/tty
}

function uninstallWireGuardVPN(){
	echo "" > /dev/tty

	REMOVE="n"
	read -rp " ⚠️  Do you really want to remove WireGuardVPN ? ⚠️ [y/n]: " -e -i "$REMOVE" REMOVE

	if [[ "$REMOVE" = 'y' ]]; then
			systemctl disable wg-quick@wg0 --quiet
			systemctl stop wg-quick@wg0 --quiet
		if [[ "$OS" = 'ubuntu' ]] || [[ "$OS" = 'debian' ]] || [[ "$OS" = 'kali' ]]; then
			apt-get autoremove --purge -y wireguard
		elif [[ "$OS" = 'fedora' ]]; then
			dnf copr disable jdoss/wireguard
			dnf remove -y wireguard
			dnf remove wireguard-dkms wireguard-tools
		elif [[ "$OS" = 'centos' ]]; then
			yum remove epel-release
			yum remove -y wireguard
			yum remove wireguard-dkms wireguard-tools
		elif [[ "$OS" = 'arch' ]]; then
			pacman --noconfirm -R wireguard
			pacman -Rs wireguard-tools
		fi

		# Remove the iptables rules related to the script
		systemctl stop iptables-wireguardvpn --quiet
		
		# Cleanup
		systemctl disable iptables-wireguardvpn --quiet
		rm /etc/systemd/system/iptables-wireguardvpn.service
		systemctl daemon-reload --quiet
		rm /etc/iptables/add-wireguardvpn-rules.sh
		rm /etc/iptables/rm-wireguardvpn-rules.sh

		if [[ -e /etc/wireguard/wg0.conf ]]; then
			rm -rf /etc/wireguard
			rm -rf /usr/share/doc/wireguard*
			rm -f /etc/sysctl.d/wg.conf
		fi

		echo "" > /dev/tty
		echo " ✅  WireGuardVPN uninstalled" > /dev/tty
		echo "" > /dev/tty

	else
		echo "" > /dev/tty
		echo "WireGuardVPN removal aborted ❗" > /dev/tty
		echo "" > /dev/tty
	fi
}

function get_hostname(){
	echo "" > /dev/tty
	echo "We need to know the IPv4 or IPv6 public address of the network interface you want WireGuardVPN listening to." > /dev/tty
	echo "Unless your server is behind NAT, it should be your public IPv4 or IPv6 public address ." > /dev/tty
	echo "" > /dev/tty

	# Detect public IPv4 address and pre-fill for the user
	HOST=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
	read -rp "	IPv4 adress: " -e -i "$HOST" HOST
	
	# If $IP is a private IP address, the server must be behind NAT
	if echo "$HOST" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo "" > /dev/tty
		echo "It seems this server is behind NAT. What is its public IPv4 address or hostname?" > /dev/tty
		echo "We need it for the clients to connect to the server." > /dev/tty
		echo "" > /dev/tty

		until [[ "$ENDPOINT" != "" ]]; do
			read -rp "	Public IPv4 address or hostname: " -e ENDPOINT
		done
	fi
}

function get_dns_resolvers(){
	echo "" > /dev/tty
	echo "	Choose a primary and a secondary DNS resolver. Options: " > /dev/tty
	echo "" > /dev/tty
	echo "   		1) Custom" > /dev/tty
	echo "   		2) Cloudflare 🌍 " > /dev/tty
	echo "   		3) Quad9 🌍 " > /dev/tty
	echo "   		4) Quad9 uncensored 🌍 " > /dev/tty
	echo "   		5) FDN 🇫🇷 " > /dev/tty
	echo "   		6) DNS.WATCH 🇩🇪 " > /dev/tty
	echo "   		7) OpenDNS 🌍 " > /dev/tty
	echo "   		8) Google 🌍 " > /dev/tty
	echo "   		9) Yandex Basic 🇷🇺 " > /dev/tty
	echo "   		10) AdGuard DNS 🇷🇺 " > /dev/tty
	echo "" > /dev/tty

	until [[ "$DNS" =~ ^[0-9]+$ ]] && [ "$DNS" -ge 1 ] && [ "$DNS" -le 10 ]; do
		read -rp "	DNS [1-10]: " -e -i 2 DNS
	done

	DNS_1=""
	DNS_2=""

	case $DNS in
		1)  echo "" > /dev/tty
			read -rp "  Primary DNS resolver: " -e -i  "$DNS_1" DNS_1
			read -rp "  Secondary DNS resolver: " -e -i  "$DNS_2" DNS_2
		;;
		2) # Cloudflare
			DNS_1="1.1.1.1"
			DNS_2="1.0.0.1"
		;;
		3) # Quad9
			DNS_1="9.9.9.9"
			DNS_2="149.112.112.112"
		;;
		4) # Quad9 uncensored
			DNS_1="9.9.9.10"
			DNS_2="149.112.112.10"
		;;
		5) # FDN
			DNS_1="80.67.169.40"
			DNS_2="80.67.169.12"
		;;
		6) # DNS.WATCH
			DNS_1="84.200.69.80"
			DNS_2="84.200.70.40"
		;;
		7) # OpenDNS
			DNS_1="208.67.222.222"
			DNS_2="208.67.220.220"
		;;
		8) # Google
			DNS_1="8.8.8.8"
			DNS_2="8.8.4.4"
		;;
		9) # Yandex Basic
			DNS_1="77.88.8.8"
			DNS_2="77.88.8.1"
		;;
		10) # AdGuard DNS
			DNS_1="176.103.130.130"
			DNS_2="176.103.130.131"
		;;
	esac

}

function wireguard_server_conf(){

	echo "" > /dev/tty
	echo "⚙️  Configuring WireGuardVPN server ⚙️" > /dev/tty
	
	echo "" > /dev/tty
	echo "	Generating server 🔑" > /dev/tty

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY"| wg pubkey)

	echo "	✅  Key generated" > /dev/tty
	
	echo "" > /dev/tty
	echo "	Setting a tunnel interface (wg0) for WireGuard Server " > /dev/tty

	SERVER_GATEWAY_IPV4="10.10.0.1"
	read -rp "	WireGuard Server Gateway IPv4: " -e -i "$SERVER_GATEWAY_IPV4" SERVER_GATEWAY_IPV4

	SERVER_GATEWAY_IPV6="fd42:42:42::1"
	read -rp "	WireGuard Server Gateway IPv6: " -e -i "$SERVER_GATEWAY_IPV6" SERVER_GATEWAY_IPV6

	SERVER_PORT=51820
	read -rp "	WireGuard Server Port: " -e -i "$SERVER_PORT" SERVER_PORT

	# Saving config to file
	echo "[Interface]
	PrivateKey = $SERVER_PRIV_KEY
	Address = $SERVER_GATEWAY_IPV4/24,$SERVER_GATEWAY_IPV6/64
	ListenPort = $SERVER_PORT
	PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $PUB_NETWORK_INTERFACE -j MASQUERADE;
	PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $PUB_NETWORK_INTERFACE -j MASQUERADE;
	SaveConfig = true" >> /etc/wireguard/wg0.conf

	chmod 600 -R /etc/wireguard/

	# Network settings for WireGuardVPN server
	echo "" > /dev/tty
	echo "⚙️  Configuring network settings and firewall rules for WireGuardVPN server ⚙️" > /dev/tty

	echo "net.ipv4.ip_forward=1
	net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/wg.conf
	
	sysctl --quiet --system 

	systemctl enable wg-quick@wg0 --quiet
    systemctl start wg-quick@wg0 --quiet

	echo "" > /dev/tty
	echo "	Adding iptables rules ⏳ " > /dev/tty

	# Add iptables rules in two scripts
	if [ ! -d /etc/iptables ]; then
		mkdir /etc/iptables
	fi

	# Script to add rules
	echo "#!/bin/sh
	iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o $PUB_NETWORK_INTERFACE  -j MASQUERADE
	iptables -A INPUT -i wg0 -j ACCEPT
	iptables -A FORWARD -i $PUB_NETWORK_INTERFACE  -o wg0 -j ACCEPT
	iptables -A FORWARD -i wg0 -o $PUB_NETWORK_INTERFACE  -j ACCEPT
	iptables -A INPUT -i $PUB_NETWORK_INTERFACE  -p udp --dport $SERVER_PORT -j ACCEPT" > /etc/iptables/add-wireguardvpn-rules.sh

	# Script to remove rules
	echo "#!/bin/sh
	iptables -t nat -D POSTROUTING -s 10.10.0.0/24 -o $PUB_NETWORK_INTERFACE -j MASQUERADE
	iptables -D INPUT -i wg0 -j ACCEPT
	iptables -D FORWARD -i $PUB_NETWORK_INTERFACE -o wg0 -j ACCEPT
	iptables -D FORWARD -i wg0 -o $PUB_NETWORK_INTERFACE -j ACCEPT
	iptables -D INPUT -i $PUB_NETWORK_INTERFACE -p udp --dport $SERVER_PORT -j ACCEPT" > /etc/iptables/rm-wireguardvpn-rules.sh

	chmod +x /etc/iptables/add-wireguardvpn-rules.sh
	chmod +x /etc/iptables/rm-wireguardvpn-rules.sh

	echo "	✅  Iptables rules added" > /dev/tty

	# Handle the rules via a systemd script
	echo "" > /dev/tty
	echo "	Adding a way to handle the iptables rules via a systemd ⏳ " > /dev/tty

	echo "[Unit]
	Description=iptables rules for WireGuardVPN
	Before=network-online.target
	Wants=network-online.target
	[Service]
	Type=oneshot
	ExecStart=/etc/iptables/add-wireguardvpn-rules.sh
	ExecStop=/etc/iptables/rm-wireguardvpn-rules.sh
	RemainAfterExit=yes
	[Install]
	WantedBy=multi-user.target" > /etc/systemd/system/iptables-wireguardvpn.service

	echo "	✅  Iptables rules via a systemd added " > /dev/tty

	echo "" > /dev/tty
	echo "  Enabling service and applying rules ⏳ " > /dev/tty

	# Enable service and apply rules
	systemctl daemon-reload --quiet
	systemctl enable iptables-wireguardvpn --quiet
	systemctl start iptables-wireguardvpn --quiet

	echo "" > /dev/tty
	echo " ✅  WireGuard VPN server configured " > /dev/tty
	echo "" > /dev/tty
}

function add_wireguard_client(){

	echo "" > /dev/tty
	echo " ⚙️  Configuring WireGuard VPN client ⚙️ " > /dev/tty
	get_hostname

	echo "" > /dev/tty
	CLIENT_NAME=""
	read -rp "	WireGuard Client Name: " -e -i  "$CLIENT_NAME" CLIENT_NAME

	SUBNET_IPV4=$(ifconfig wg0 | grep inet | sed -e 's/^.*inet \([^ ]\+\).*/\1/' | grep -oE '10\.[0-9]{1,3}\.[0-9]{1,3}\.')
	SUBNET_IPV6=$(ifconfig wg0 | grep inet6 | sed -e 's/^.*inet6 \([^ ]\+\).*/\1/' | cut -d "1" -f 1)

	LAST_IP=$(wg show | grep 'allowed ips: ' | tail -1 | grep -oE '10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d '.' -f 4)

	if [[ -z "$LAST_IP" ]]; then
		LAST_IP=1
	fi

	CLIENT_IPV4="$SUBNET_IPV4$((LAST_IP + 1))"
	read -rp "	WireGuard Client IPv4 : " -e -i "$CLIENT_IPV4" CLIENT_IPV4

	CLIENT_IPV6="$SUBNET_IPV6$((LAST_IP + 1))"
	read -rp "	WireGuard Client IPv6 : " -e -i "$CLIENT_IPV6" CLIENT_IPV6

	get_dns_resolvers

	echo "" > /dev/tty
	IS_PRE_SYMM="y"
	read -rp "	Want to use pre-shared symmetric key? [Y/n]: " -e -i "$IS_PRE_SYMM" IS_PRE_SYMM

	echo "" > /dev/tty
	echo "	Generating client ($CLIENT_NAME) 🔑 "  > /dev/tty
	local CLIENT_PRIV_KEY=$(wg genkey)
	local CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)

	## Saving config to files
	echo "" > /dev/tty
	echo "	Adding $CLIENT_NAME to allowed client's ⏳ " > /dev/tty

	# (1) Create client file with interface
	SERVER_PUB_KEY=$(wg show | grep 'public key' | grep -oE '[-a-zA-Z0-9!@#$&()`.+,/\"=!@?¿*]+' | tail -1)
	SERVER_PORT=$(wg show | grep 'listening port'| grep -oE '[0-9]+')

	echo "[Interface]
	PrivateKey = $CLIENT_PRIV_KEY
	Address = $CLIENT_IPV4/24,$CLIENT_IPV6/64
	DNS = $DNS_1,$DNS_2
	[Peer] # Server
	PublicKey = $SERVER_PUB_KEY
	Endpoint = $ENDPOINT:$SERVER_PORT
	AllowedIPs = 0.0.0.0/0,::/0
	PersistentKeepalive = 20" >> "$HOME/wg0-client-$CLIENT_NAME.conf"

	# (2) Add the client as a peer to the server
	if [ "$IS_PRE_SYMM" = 'y' ]; then
		# With pre shared symmetric key
		CLIENT_SYMM_PRE_KEY=$( wg genpsk )
		wg set wg0 peer $CLIENT_PUB_KEY allowed-ips $CLIENT_IPV4/32,$CLIENT_IPV6/128 preshared-key <(echo $CLIENT_SYMM_PRE_KEY)
		echo "	PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "$HOME/wg0-client-$CLIENT_NAME.conf"
	else
		# Without pre shared symmetric key
		wg set wg0 peer $CLIENT_PUB_KEY allowed-ips $CLIENT_IPV4/32,$CLIENT_IPV6/128
	fi

	echo "" > /dev/tty
	echo "	✅  Client $CLIENT_NAME added" > /dev/tty

	echo "" > /dev/tty
	echo "	Client $CLIENT_NAME available as conf file in the home directory" > /dev/tty
	
}

#PENDING
function remove_wireguard_client(){
	echo "" > /dev/tty
	
	REMOVE="n"
	read -rp " ⚠️  Do you really want to remove a WireGuardVPN peer ? ⚠️  [y/n]: " -e -i "$REMOVE" REMOVE

	if [[ "$REMOVE" = 'y' ]]; then
		echo "" > /dev/tty
		LIST=$(wg show all peers)

		if [[ "$LIST" != '' ]]; then
			echo "Available Peers : " > /dev/tty
			echo "" > /dev/tty
			echo "$LIST" > /dev/tty
			echo "" > /dev/tty

			PEER=""
			read -rp "	WireGuardVPN peer to remove: " -e -i "$PEER" PEER
			wg set wg0 peer $PEER remove
		else
			echo "No peers to remove❗" > /dev/tty
		fi
		
		
	else
		echo "" > /dev/tty
		echo "WireGuardVPN peer removal aborted ❗" > /dev/tty
		echo "" > /dev/tty
	fi

}

function modify_wireguard_server_conf(){
	echo "" > /dev/tty
	
	MODIFY="n"
	read -rp " ⚠️  Do you really want to modify the WireGuardVPN server configuration ? ⚠️ [y/n]: " -e -i "$MODIFY" MODIFY

	if [[ "$MODIFY" = 'y' ]]; then
		rm /etc/sysctl.d/wg.conf
		rm /etc/wireguard/wg0.conf
		wireguard_server_conf
	else
		echo "" > /dev/tty
		echo "WireGuardVPN server modification aborted ❗" > /dev/tty
		echo "" > /dev/tty
	fi
}

function displayMenu(){
	echo "It looks like WireGuardVPN is already installed." > /dev/tty
	echo "" > /dev/tty
	echo "What do you want to do?" > /dev/tty
	echo "   1) Add a new peer (client)" > /dev/tty
	echo "   2) Revoke existing peer (client)" > /dev/tty
	echo "   3) Modify WireGuardVPN server" > /dev/tty
	echo "   4) Remove WireGuardVPN" > /dev/tty
	echo "   5) Exit" > /dev/tty
	echo ""

	until [[ "$MENU_OPTION" =~ ^[1-5]$ ]]; do
		read -rp "Select an option [1-5]: " MENU_OPTION
	done

	case $MENU_OPTION in
		1) add_wireguard_client;;
		2) remove_wireguard_client;;
		3) modify_wireguard_server_conf;;
		4) uninstallWireGuardVPN;;
		5) exit 0;;
	esac
}

function wireguard_setup() {
	isRoot
	checkOS
	checkSupport
	installWireGuardVPN

	echo "" > /dev/tty
	echo "----------------------------------------" > /dev/tty
	echo "           WireGuardVPN Setup           " > /dev/tty
	echo "----------------------------------------" > /dev/tty
	echo "" > /dev/tty
	echo "You will be asked a few questions before starting the setup." > /dev/tty
	echo "You can leave the default options and just press enter if you are ok with them." > /dev/tty

	echo "" > /dev/tty
	PUB_NETWORK_INTERFACE="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
	read -rp "	Public network interface: " -e -i "$PUB_NETWORK_INTERFACE" PUB_NETWORK_INTERFACE
	
	wireguard_server_conf

}


function main(){
	echo ""
	echo "----------------------------------------"
	echo " Welcome to the WireGuardVPN assistant!"
	echo "----------------------------------------"
	echo ""

	if [[ -e /etc/wireguard/wg0.conf ]]; then
		displayMenu
	else
		wireguard_setup
	fi
}

main

