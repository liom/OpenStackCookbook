#!/bin/bash

# controller.sh

# Authors: Kevin Jackson (kevin@linuxservices.co.uk)
#          Cody Bunch (bunchc@gmail.com)
#          Egle Sigler (ushnishtha@hotmail.com)

# Vagrant scripts used by the OpenStack Cloud Computing Cookbook, 3rd Edition
# Website: http://www.openstackcookbook.com/
# Scripts updated for Juno

# Source in common env vars
. /vagrant/common.sh

# The routeable IP of the node is on our eth1 interface
ETH1_IP=$(ifconfig eth1 | awk '/inet addr/ {split ($2,A,":"); print A[2]}')
ETH2_IP=$(ifconfig eth2 | awk '/inet addr/ {split ($2,A,":"); print A[2]}')
ETH3_IP=$(ifconfig eth3 | awk '/inet addr/ {split ($2,A,":"); print A[2]}')

PUBLIC_IP=${ETH3_IP}
INT_IP=${ETH1_IP}
ADMIN_IP=${ETH3_IP}

#export LANG=C

# MySQL
export MYSQL_HOST=${ETH1_IP}
export MYSQL_ROOT_PASS=openstack
export MYSQL_DB_PASS=openstack

echo "mysql-server-5.5 mysql-server/root_password password $MYSQL_ROOT_PASS" | sudo debconf-set-selections
echo "mysql-server-5.5 mysql-server/root_password_again password $MYSQL_ROOT_PASS" | sudo debconf-set-selections
echo "mysql-server-5.5 mysql-server/root_password seen true" | sudo debconf-set-selections
echo "mysql-server-5.5 mysql-server/root_password_again seen true" | sudo debconf-set-selections

sudo apt-get -y install mariadb-server python-mysqldb

sudo sed -i "s/^bind\-address.*/bind-address = 0.0.0.0/g" /etc/mysql/my.cnf
sudo sed -i "s/^#max_connections.*/max_connections = 512/g" /etc/mysql/my.cnf

# Skip Name Resolve
echo "[mysqld]
skip-name-resolve" > /etc/mysql/conf.d/skip-name-resolve.cnf


# UTF-8 Stuff
echo "[mysqld]
collation-server = utf8_general_ci
init-connect='SET NAMES utf8'
character-set-server = utf8" > /etc/mysql/conf.d/01-utf8.cnf

sudo service mysql stop > /dev/null
sudo service mysql start > /dev/null

# Ensure root can do its job
mysql -u root -p${MYSQL_ROOT_PASS} -h localhost -e "GRANT ALL ON *.* to root@\"localhost\" IDENTIFIED BY \"${MYSQL_ROOT_PASS}\" WITH GRANT OPTION;"
mysql -u root -p${MYSQL_ROOT_PASS} -h localhost -e "GRANT ALL ON *.* to root@\"${MYSQL_HOST}\" IDENTIFIED BY \"${MYSQL_ROOT_PASS}\" WITH GRANT OPTION;"
mysql -u root -p${MYSQL_ROOT_PASS} -h localhost -e "GRANT ALL ON *.* to root@\"%\" IDENTIFIED BY \"${MYSQL_ROOT_PASS}\" WITH GRANT OPTION;"

mysqladmin -uroot -p${MYSQL_ROOT_PASS} flush-privileges






######################
# Chapter 1 KEYSTONE #
######################

# Create database
sudo apt-get -y install ntp keystone python-keyring

# Config Files
KEYSTONE_CONF=/etc/keystone/keystone.conf
#SSL_PATH=/etc/ssl/

MYSQL_ROOT_PASS=openstack
MYSQL_KEYSTONE_PASS=openstack
mysql -uroot -p$MYSQL_ROOT_PASS -e 'CREATE DATABASE keystone;'
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'localhost' IDENTIFIED BY '$MYSQL_KEYSTONE_PASS';"
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'%' IDENTIFIED BY '$MYSQL_KEYSTONE_PASS';"

sudo sed -i "s#^connection.*#connection = mysql://keystone:${MYSQL_KEYSTONE_PASS}@${MYSQL_HOST}/keystone#" ${KEYSTONE_CONF}
sudo sed -i 's/^#admin_token.*/admin_token = ADMIN/' ${KEYSTONE_CONF}
sudo sed -i 's,^#log_dir.*,log_dir = /var/log/keystone,' ${KEYSTONE_CONF}

sudo echo "use_syslog = True" >> ${KEYSTONE_CONF}
sudo echo "syslog_log_facility = LOG_LOCAL0" >> ${KEYSTONE_CONF}

sudo apt-get -y install python-keystoneclient python-openstackclient

#echo "
#[signing]
#certfile=/etc/keystone/ssl/certs/signing_cert.pem
#keyfile=/etc/keystone/ssl/private/signing_key.pem
#ca_certs=/etc/keystone/ssl/certs/ca.pem
#ca_key=/etc/keystone/ssl/private/cakey.pem
#key_size=2048
#valid_days=3650
#cert_subject=/C=US/ST=Unset/L=Unset/O=Unset/CN=172.16.0.200

#[ssl]
#enable = True
#certfile = /etc/keystone/ssl/certs/keystone.pem
#keyfile = /etc/keystone/ssl/private/keystonekey.pem
#ca_certs = /etc/keystone/ssl/certs/ca.pem
#cert_subject=/C=US/ST=Unset/L=Unset/O=Unset/CN=192.168.100.200
##cert_subject=/C=US/ST=Unset/L=Unset/O=Unset/CN=172.16.0.200
#ca_key = /etc/keystone/ssl/certs/cakey.pem" | sudo tee -a ${KEYSTONE_CONF}

#rm -rf /etc/keystone/ssl
#sudo keystone-manage ssl_setup --keystone-user keystone --keystone-group keystone
#sudo cp /etc/keystone/ssl/certs/ca.pem /etc/ssl/certs/ca.pem
#sudo c_rehash /etc/ssl/certs/ca.pem
#sudo cp /etc/keystone/ssl/certs/ca.pem /vagrant/ca.pem
#sudo cp /etc/keystone/ssl/certs/cakey.pem /vagrant/cakey.pem

# This runs for both LDAP and non-LDAP configs
create_endpoints(){
  echo "Creating Endpoints"
  set -x
  export ENDPOINT=${PUBLIC_IP}
  export INT_ENDPOINT=${INT_IP}
  export ADMIN_ENDPOINT=${ADMIN_IP}
  export PASSWORD=openstack

  export OS_TOKEN=ADMIN
  export OS_URL=http://${KEYSTONE_ADMIN_ENDPOINT}:35357/v3
  export OS_IDENTITY_API_VERSION=3

   # OpenStack Compute Nova API Endpoint
  openstack service create --name nova --description 'OpenStack Compute Service' compute

  # Glance Image Service Endpoint
  openstack service create --name glance --description 'OpenStack Image Service' image

  # Keystone Identity Service Endpoint
  openstack service create --name keystone --description 'OpenStack Identity Service' identity

  # Cinder Block Storage Endpoint
  openstack service create --name volume --description 'Volume Service' volume
  openstack service create --name volume --description 'Volume Service v2' volumev2

  # Neutron Network Service Endpoint
  openstack service create --name network --description 'Neutron Network Service' network

  # Nova Compute Endpoint
  PUBLIC="http://$ENDPOINT:8774/v2/\$(tenant_id)s"
  ADMIN="http://$ADMIN_ENDPOINT:8774/v2/\$(tenant_id)s"
  INTERNAL="http://$INT_ENDPOINT:8774/v2/\$(tenant_id)s"

  openstack endpoint create --region RegionOne compute public $PUBLIC
  openstack endpoint create --region RegionOne compute internal $INTERNAL
  openstack endpoint create --region RegionOne compute admin $ADMIN

  # Glance Image Service Endpoint
  PUBLIC="http://$ENDPOINT:9292/v2"
  ADMIN="http://$ADMIN_ENDPOINT:9292/v2"
  INTERNAL="http://$INT_ENDPOINT:9292/v2"

  openstack endpoint create --region RegionOne image public $PUBLIC
  openstack endpoint create --region RegionOne image internal $INTERNAL
  openstack endpoint create --region RegionOne image admin $ADMIN

  # Keystone OpenStack Identity Service Endpoint
  PUBLIC="http://$ENDPOINT:5000/v3"
  ADMIN="http://$ADMIN_ENDPOINT:35357/v3"
  INTERNAL="http://$INT_ENDPOINT:5000/v3"

  openstack endpoint create --region RegionOne identity public $PUBLIC
  openstack endpoint create --region RegionOne identity internal $INTERNAL
  openstack endpoint create --region RegionOne identity admin $ADMIN

  # Cinder Block Storage Service Endpoint
  #Dynamically determine first three octets if user specifies alternative IP ranges.  Fourth octet still hardcoded
  CINDER_ENDPOINT=$(ifconfig eth1 | awk '/inet addr/ {split ($2,A,":"); print A[2]}' | sed 's/\.[0-9]*$/.211/')
  PUBLIC="http://$CINDER_ENDPOINT:8776/v1/%(tenant_id)s"
  ADMIN=$PUBLIC
  INTERNAL=$PUBLIC

  openstack endpoint create --region RegionOne volume public $PUBLIC
  openstack endpoint create --region RegionOne volume internal $INTERNAL
  openstack endpoint create --region RegionOne volume admin $ADMIN

  openstack endpoint create --region RegionOne volumev2 public $PUBLIC
  openstack endpoint create --region RegionOne volumev2 internal $INTERNAL
  openstack endpoint create --region RegionOne volumev2 admin $ADMIN

  # Neutron Network Service Endpoint
  PUBLIC="http://$ENDPOINT:9696"
  ADMIN="http://$ADMIN_ENDPOINT:9696"
  INTERNAL="http://$INT_ENDPOINT:9696"

  openstack endpoint create --region RegionOne network public $PUBLIC
  openstack endpoint create --region RegionOne network internal $INTERNAL
  openstack endpoint create --region RegionOne network admin $ADMIN
}

# If LDAP is up, all the users/groups should be mapped already, leaving us to configure keystone and add in endpoints
configure_ldap_keystone(){
  echo "
[identity]
driver=keystone.identity.backends.ldap.Identity

[ldap]
url = ldap://openldap
user = cn=admin,ou=Users,dc=cook,dc=book
password = openstack
suffix = cn=cook,cn=book

user_tree_dn = ou=Users,dc=cook,dc=book
user_objectclass = inetOrgPerson
user_id_attribute = cn
user_mail_attribute = mail

user_enabled_attribute = userAccountControl
user_enabled_mask      = 2
user_enabled_default   = 512

tenant_tree_dn = ou=Groups,dc=cook,dc=book
tenant_objectclass = groupOfNames
tenant_id_attribute = cn
tenant_desc_attribute = description

use_dumb_member = True

role_tree_dn = ou=Roles,dc=cook,dc=book
role_objectclass = organizationalRole
role_id_attribute = cn
role_member_attribute = roleOccupant" | sudo tee -a ${KEYSTONE_CONF}

}

# Check if OpenLDAP is up and running, if so, configure keystone.
if ping -c 1 openldap
then
  echo "[+] Found OpenLDAP, Configuring Keystone."
  sudo stop keystone
  sudo start keystone
  sudo keystone-manage db_sync
  create_endpoints

  configure_ldap_keystone

  sudo stop keystone
  sudo start keystone
else
  echo "[+] OpenLDAP not found, moving along."
  sudo stop keystone
  sudo start keystone
  sudo keystone-manage db_sync

  export ENDPOINT=${PUBLIC_IP}
  export INT_ENDPOINT=${INT_IP}
  export ADMIN_ENDPOINT=${ADMIN_IP}
  export PASSWORD=openstack

  export OS_TOKEN=ADMIN
  export OS_URL=http://${KEYSTONE_ADMIN_ENDPOINT}:35357/v3
  export OS_IDENTITY_API_VERSION=3

  sleep 5

  #
  # Roles
  #

  # create the admin role
  openstack role create admin

  # create the Member role
  openstack role create Member

  # List the roles
  openstack role list

  # Create the cookbook project (in default domain)
  openstack project create --domain default --description "Default Cookbook Project" cookbook

  # Creae the admin project
  openstack project create --domain default --description "Admin Project" admin

  # Create the admin user
  openstack user create --domain default --password $PASSWORD --email root@localhost admin
  # Assign the admin role to the admin user in the admin project
  openstack role add --project admin --user admin admin

  # Create the demo user
  openstack user create --domain default --password $PASSWORD --email demo@localhost demo
  # Assign the Member role to the demo user in the cookbook project
  openstack role add --project cookbook --user demo Member

  create_endpoints

  # Service Project
  openstack project create --domain default --description "Service Project" service

  # Create nova service user
  openstack user create --domain default --password nova --email nova@localhost nova
  # Assign the nova user the admin role in service tenant
  openstack role add --project service --user nova admin

  # Create glance service user
  openstack user create --domain default --password glance --email glance@localhost glance
  # Assign the glance user the admin role in service tenant
  openstack role add --project service --user glance admin

  # Create keystone service user
  openstack user create --domain default --password keystone --email keystone@localhost keystone
  # Assign the keystone user the admin role in service tenant
  openstack role add --project service --user keystone admin

  # Create cinder service user
  openstack user create --domain default --password cinder --email cinder@localhost cinder
  # Assign the cinder user the admin role in service tenant
  openstack role add --project service --user cinder admin

  # Create neutron service user
  openstack user create --domain default --password neutron --email neutron@localhost neutron
  # Assign the neutron user the admin role in service tenant
  openstack role add --project service --user neutron admin
fi







######################
# Chapter 2 GLANCE   #
######################

# Install Service
sudo apt-get update
sudo apt-get -y install glance
sudo apt-get -y install python-glanceclient

# Config Files
GLANCE_API_CONF=/etc/glance/glance-api.conf
GLANCE_REGISTRY_CONF=/etc/glance/glance-registry.conf

SERVICE_TENANT=service
GLANCE_SERVICE_USER=glance
GLANCE_SERVICE_PASS=glance

# Create database
MYSQL_ROOT_PASS=openstack
MYSQL_GLANCE_PASS=openstack
mysql -uroot -p$MYSQL_ROOT_PASS -e 'CREATE DATABASE glance;'
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON glance.* TO 'glance'@'localhost' IDENTIFIED BY '$MYSQL_GLANCE_PASS';"
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON glance.* TO 'glance'@'%' IDENTIFIED BY '$MYSQL_GLANCE_PASS';"

## /etc/glance/glance-api.conf
echo "[DEFAULT]
default_store = file
bind_host = 0.0.0.0
bind_port = 9292
log_file = /var/log/glance/api.log
backlog = 4096
registry_host = 0.0.0.0
registry_port = 9191
registry_client_protocol = http
rabbit_host = localhost
rabbit_port = 5672
rabbit_use_ssl = false
rabbit_userid = guest
rabbit_password = guest
rabbit_virtual_host = /
rabbit_notification_exchange = glance
rabbit_notification_topic = notifications
rabbit_durable_queues = False

delayed_delete = False
scrub_time = 43200
scrubber_datadir = /var/lib/glance/scrubber
image_cache_dir = /var/lib/glance/image-cache/

[database]
backend = sqlalchemy
connection = mysql://glance:openstack@172.16.0.200/glance

[keystone_authtoken]
auth_uri = http://${KEYSTONE_ADMIN_ENDPOINT}:35357/v2.0/
identity_uri = http://${KEYSTONE_ADMIN_ENDPOINT}:5000
admin_tenant_name = service
admin_user = glance
admin_password = glance
#signing_dir = \$state_path/keystone-signing
insecure = True

[glance_store]
filesystem_store_datadir = /var/lib/glance/images/
#stores = glance.store.swift.Store
#swift_store_auth_version = 2
#swift_store_auth_address = http://${ETH3_IP}:5000/v2.0/
#swift_store_user = service:glance
#swift_store_key = glance
#swift_store_container = glance
#swift_store_create_container_on_put = True
#swift_store_large_object_size = 5120
#swift_store_large_object_chunk_size = 200
#swift_enable_snet = False
#swift_store_auth_insecure = True

use_syslog = True
syslog_log_facility = LOG_LOCAL0

[paste_deploy]
config_file = /etc/glance/glance-api-paste.ini
flavor = keystone
" | sudo tee ${GLANCE_API_CONF}


## /etc/glance/glance-registry.conf

echo "[DEFAULT]
bind_host = 0.0.0.0
bind_port = 9191
log_file = /var/log/glance/registry.log
backlog = 4096
api_limit_max = 1000
limit_param_default = 25

rabbit_host = localhost
rabbit_port = 5672
rabbit_use_ssl = false
rabbit_userid = guest
rabbit_password = guest
rabbit_virtual_host = /
rabbit_notification_exchange = glance
rabbit_notification_topic = notifications
rabbit_durable_queues = False

[database]
sqlite_db = /var/lib/glance/glance.sqlite
backend = sqlalchemy
connection = mysql://glance:openstack@172.16.0.200/glance

[keystone_authtoken]
auth_uri = http://${KEYSTONE_ADMIN_ENDPOINT}:35357/v2.0/
identity_uri = http://${KEYSTONE_ADMIN_ENDPOINT}:5000
admin_tenant_name = service
admin_user = glance
admin_password = glance
#signing_dir = \$state_path/keystone-signing
insecure = True

use_syslog = True
syslog_log_facility = LOG_LOCAL0

[paste_deploy]
config_file = /etc/glance/glance-registry-paste.ini
flavor = keystone
" | sudo tee ${GLANCE_REGISTRY_CONF}

sudo stop glance-registry
sudo start glance-registry
sudo stop glance-api
sudo start glance-api

sudo glance-manage db_sync

# Get some images and upload
export OS_TENANT_NAME=admin
export OS_USERNAME=admin
export OS_PASSWORD=openstack
export OS_AUTH_URL=http://${ETH3_IP}:5000/v3
export OS_NO_CACHE=1

#sudo apt-get -y install wget

echo "[+] Uploading images to Glance. Please wait."

# Get the images
# First check host
CIRROS="cirros-0.3.0-x86_64-disk.img"
UBUNTU="trusty-server-cloudimg-amd64-disk1.img"

if [[ ! -f /vagrant/${CIRROS} ]]
then
        # Download then store on local host for next time
	wget --quiet http://launchpad.net/cirros/trunk/0.3.0/+download/cirros-0.3.0-x86_64-disk.img -O /vagrant/${CIRROS}
fi

if [[ ! -f /vagrant/${UBUNTU} ]]
then
        # Download then store on local host for next time
	wget --quiet http://cloud-images.ubuntu.com/trusty/current/trusty-server-cloudimg-amd64-disk1.img -O /vagrant/${UBUNTU}
fi

openstack image create --disk-format qcow2 --container-format bare --is-public True --file /vagrant/${UBUNTU} trusty-image
openstack image create --disk-format qcow2 --container-format bare --is-public True --file /vagrant/${CIRROS} cirros-image

echo "[+] Image upload done."







#######################
# Chapter 3 Neutron   #
# See also network.sh #
#######################

# Create database
MYSQL_ROOT_PASS=openstack
MYSQL_NEUTRON_PASS=openstack
NEUTRON_SERVICE_USER=neutron
NEUTRON_SERVICE_PASS=neutron
NOVA_SERVICE_USER=nova
NOVA_SERVICE_PASS=nova

mysql -uroot -p$MYSQL_ROOT_PASS -e 'CREATE DATABASE neutron;'
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON neutron.* TO 'neutron'@'localhost' IDENTIFIED BY '$MYSQL_NEUTRON_PASS';"
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON neutron.* TO 'neutron'@'%' IDENTIFIED BY '$MYSQL_NEUTRON_PASS';"

sudo apt-get -y install neutron-server neutron-plugin-ml2

# Config Files
NEUTRON_CONF=/etc/neutron/neutron.conf
NEUTRON_PLUGIN_ML2_CONF_INI=/etc/neutron/plugins/ml2/ml2_conf.ini

# Configure Neutron
cat > ${NEUTRON_CONF}<<EOF
[DEFAULT]
verbose = True
debug = True
state_path = /var/lib/neutron
lock_path = \$state_path/lock
log_dir = /var/log/neutron

bind_host = 0.0.0.0
bind_port = 9696

# Plugin
core_plugin = ml2
#service_plugins = router, firewall
service_plugins = router, lbaas
allow_overlapping_ips = True
#router_distributed = True
router_distributed = False

# auth
auth_strategy = keystone

# RPC configuration options. Defined in rpc __init__
# The messaging module to use, defaults to kombu.
rpc_backend = neutron.openstack.common.rpc.impl_kombu

rabbit_host = ${CONTROLLER_HOST}
rabbit_password = guest
rabbit_port = 5672
rabbit_userid = guest
rabbit_virtual_host = /
rabbit_ha_queues = false

# ============ Notification System Options =====================
notification_driver = neutron.openstack.common.notifier.rpc_notifier

# ======== neutron nova interactions ==========
notify_nova_on_port_status_changes = True
notify_nova_on_port_data_changes = True
nova_url = http://${CONTROLLER_HOST}:8774/v2
nova_region_name = RegionOne
nova_admin_username = nova
nova_admin_tenant_id = service
nova_admin_password = nova
nova_admin_auth_url = http://${KEYSTONE_ADMIN_ENDPOINT}:35357/v2.0
# nova_api_insecure = True

[quotas]
# quota_driver = neutron.db.quota_db.DbQuotaDriver
# quota_items = network,subnet,port
# default_quota = -1
# quota_network = 10
# quota_subnet = 10
# quota_port = 50
# quota_security_group = 10
# quota_security_group_rule = 100
# quota_vip = 10
# quota_pool = 10
# quota_member = -1
# quota_health_monitor = -1
# quota_router = 10
# quota_floatingip = 50

[agent]
root_helper = sudo

[keystone_authtoken]
auth_uri = http://${KEYSTONE_ADMIN_ENDPOINT}:35357/v2.0/
identity_uri = http://${KEYSTONE_ADMIN_ENDPOINT}:5000
admin_tenant_name = service
admin_user = neutron
admin_password = neutron

[database]
connection = mysql://neutron:${MYSQL_NEUTRON_PASS}@${CONTROLLER_HOST}/neutron

[service_providers]
service_provider=LOADBALANCER:Haproxy:neutron.services.loadbalancer.drivers.haproxy.plugin_driver.HaproxyOnHostPluginDriver:default
#service_provider=VPN:openswan:neutron.services.vpn.service_drivers.ipsec.IPsecVPNDriver:default
#service_provider=FIREWALL:Iptables:neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver:default

EOF


cat > ${NEUTRON_PLUGIN_ML2_CONF_INI} <<EOF
[ml2]
type_drivers = vxlan,gre,flat
tenant_network_types = vxlan
mechanism_drivers = openvswitch,l2population

[ml2_type_gre]
tunnel_id_ranges = 1:1000

[ml2_type_vxlan]
vxlan_group =
vni_ranges = 1:1000

[ml2_type_flat]
flat_networks = eth3

[vxlan]
enable_vxlan = True
vxlan_group =
l2_population = True


[agent]
tunnel_types = vxlan
## VXLAN udp port
# This is set for the vxlan port and while this
# is being set here it's ignored because
# the port is assigned by the kernel
vxlan_udp_port = 4789


[securitygroup]
firewall_driver = neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver
enable_security_group = True
EOF

echo "
Defaults !requiretty
neutron ALL=(ALL:ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers


sudo neutron-db-manage --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugins/ml2/ml2_conf.ini upgrade juno

sudo service neutron-server stop
sudo service neutron-server start





########################
# Chapter 4 - Compute  #
# See also compute.sh  #
########################

# Create database
MYSQL_HOST=${ETH3_IP}
GLANCE_HOST=${ETH3_IP}
KEYSTONE_ENDPOINT=${ETH3_IP}
SERVICE_TENANT=service
NOVA_SERVICE_USER=nova
NOVA_SERVICE_PASS=nova

MYSQL_ROOT_PASS=openstack
MYSQL_NOVA_PASS=openstack
mysql -uroot -p$MYSQL_ROOT_PASS -e 'CREATE DATABASE nova;'
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON nova.* TO 'nova'@'localhost' IDENTIFIED BY '$MYSQL_NOVA_PASS';"
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON nova.* TO 'nova'@'%' IDENTIFIED BY '$MYSQL_NOVA_PASS';"

sudo apt-get -y install rabbitmq-server nova-novncproxy novnc nova-api nova-ajax-console-proxy nova-cert nova-conductor nova-consoleauth nova-doc nova-scheduler python-novaclient dnsmasq nova-objectstore

# Make ourselves a new rabbit.conf
sudo cat > /etc/rabbitmq/rabbitmq.config <<EOF
[{rabbit, [{loopback_users, []}]}].
EOF

sudo cat > /etc/rabbitmq/rabbitmq-env.conf <<EOF
RABBITMQ_NODE_PORT=5672
EOF

sudo /etc/init.d/rabbitmq-server restart

# Clobber the nova.conf file with the following
NOVA_CONF=/etc/nova/nova.conf

# Qemu or KVM (VT-x/AMD-v)
KVM=$(egrep '(vmx|svm)' /proc/cpuinfo)
if [[ ${KVM} ]]
then
        LIBVIRT=kvm
else
        LIBVIRT=qemu
fi

cp ${NOVA_CONF}{,.bak}
cat > ${NOVA_CONF} <<EOF
[DEFAULT]
dhcpbridge_flagfile=/etc/nova/nova.conf
dhcpbridge=/usr/bin/nova-dhcpbridge
logdir=/var/log/nova
state_path=/var/lib/nova
lock_path=/var/lock/nova
root_helper=sudo nova-rootwrap /etc/nova/rootwrap.conf
verbose=True

use_syslog = True
syslog_log_facility = LOG_LOCAL0

api_paste_config=/etc/nova/api-paste.ini
enabled_apis=ec2,osapi_compute,metadata

# Libvirt and Virtualization
libvirt_use_virtio_for_bridges=True
connection_type=libvirt
libvirt_type=${LIBVIRT}

# Database
sql_connection=mysql://nova:${MYSQL_NOVA_PASS}@${MYSQL_HOST}/nova

# Messaging
rabbit_host=${MYSQL_HOST}

# EC2 API Flags
ec2_host=${MYSQL_HOST}
ec2_dmz_host=${MYSQL_HOST}
ec2_private_dns_show_ip=True

# Network settings
network_api_class=nova.network.neutronv2.api.API
neutron_url=http://${ETH3_IP}:9696
neutron_auth_strategy=keystone
neutron_admin_tenant_name=service
neutron_admin_username=neutron
neutron_admin_password=neutron
neutron_admin_auth_url=http://${ETH3_IP}:5000/v2.0
libvirt_vif_driver=nova.virt.libvirt.vif.LibvirtHybridOVSBridgeDriver
linuxnet_interface_driver=nova.network.linux_net.LinuxOVSInterfaceDriver
#firewall_driver=nova.virt.libvirt.firewall.IptablesFirewallDriver
security_group_api=neutron
firewall_driver=nova.virt.firewall.NoopFirewallDriver

service_neutron_metadata_proxy=true
neutron_metadata_proxy_shared_secret=foo

#Metadata
metadata_host = ${CONTROLLER_HOST}
metadata_listen = ${CONTROLLER_HOST}
metadata_listen_port = 8775

# Cinder #
volume_driver=nova.volume.driver.ISCSIDriver
enabled_apis=ec2,osapi_compute,metadata
volume_api_class=nova.volume.cinder.API
iscsi_helper=tgtadm
iscsi_ip_address=${CINDER_ENDPOINT}

# Images
image_service=nova.image.glance.GlanceImageService
glance_api_servers=${GLANCE_HOST}:9292

# Scheduler
scheduler_default_filters=AllHostsFilter

# Auth
auth_strategy=keystone

# NoVNC
novnc_enabled=true
novncproxy_host=${ETH3_IP}
novncproxy_base_url=http://${ETH3_IP}:6080/vnc_auto.html
novncproxy_port=6080

xvpvncproxy_port=6081
xvpvncproxy_host=${ETH3_IP}
xvpvncproxy_base_url=http://${ETH3_IP}:6081/console

vncserver_proxyclient_address=${ETH3_IP}
vncserver_listen=0.0.0.0

[keystone_authtoken]
auth_uri = http://${KEYSTONE_ADMIN_ENDPOINT}:35357/v2.0/
identity_uri = http://${KEYSTONE_ADMIN_ENDPOINT}:5000
admin_tenant_name = service
admin_user = nova
admin_password = nova

EOF

sudo chmod 0640 $NOVA_CONF
sudo chown nova:nova $NOVA_CONF

sudo nova-manage db sync

sudo stop nova-api
sudo stop nova-scheduler
sudo stop nova-novncproxy
sudo stop nova-consoleauth
sudo stop nova-conductor
sudo stop nova-cert


sudo start nova-api
sudo start nova-scheduler
sudo start nova-conductor
sudo start nova-cert
sudo start nova-consoleauth
sudo start nova-novncproxy





######################
# Chapter 8 - Cinder #
# See also cinder.sh #
######################

# Install the DB
MYSQL_ROOT_PASS=openstack
MYSQL_CINDER_PASS=openstack
mysql -uroot -p$MYSQL_ROOT_PASS -e 'CREATE DATABASE cinder;'
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON cinder.* TO 'cinder'@'localhost' IDENTIFIED BY '$MYSQL_CINDER_PASS';"
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON cinder.* TO 'cinder'@'%' IDENTIFIED BY '$MYSQL_CINDER_PASS';"





########################
# Chapter 10 - Horizon #
########################

# Install dependencies
sudo apt-get install -y memcached

# Install the dashboard (horizon)
sudo apt-get install -y openstack-dashboard
sudo dpkg --purge openstack-dashboard-ubuntu-theme

cat > /etc/openstack-dashboard/local_settings.py << EOF
import os

from django.utils.translation import ugettext_lazy as _

from horizon.utils import secret_key

from openstack_dashboard import exceptions
from openstack_dashboard.settings import HORIZON_CONFIG

DEBUG = False
TEMPLATE_DEBUG = DEBUG


# WEBROOT is the location relative to Webserver root
# should end with a slash.
WEBROOT = '/'
LOGIN_URL = WEBROOT + 'auth/login/'
LOGOUT_URL = WEBROOT + 'auth/logout/'
#
# LOGIN_REDIRECT_URL can be used as an alternative for
# HORIZON_CONFIG.user_home, if user_home is not set.
# Do not set it to '/home/', as this will cause circular redirect loop
#LOGIN_REDIRECT_URL = WEBROOT

# Required for Django 1.5.
# If horizon is running in production (DEBUG is False), set this
# with the list of host/domain names that the application can serve.
# For more information see:
# https://docs.djangoproject.com/en/dev/ref/settings/#allowed-hosts
#ALLOWED_HOSTS = ['horizon.example.com', ]

# Set SSL proxy settings:
# For Django 1.4+ pass this header from the proxy after terminating the SSL,
# and don't forget to strip it from the client's request.
# For more information see:
# https://docs.djangoproject.com/en/1.4/ref/settings/#secure-proxy-ssl-header
#SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTOCOL', 'https')
# https://docs.djangoproject.com/en/1.5/ref/settings/#secure-proxy-ssl-header
#SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# If Horizon is being served through SSL, then uncomment the following two
# settings to better secure the cookies from security exploits
#CSRF_COOKIE_SECURE = True
#SESSION_COOKIE_SECURE = True

# Overrides for OpenStack API versions. Use this setting to force the
# OpenStack dashboard to use a specific API version for a given service API.
# Versions specified here should be integers or floats, not strings.
# NOTE: The version should be formatted as it appears in the URL for the
# service API. For example, The identity service APIs have inconsistent
# use of the decimal point, so valid options would be 2.0 or 3.
#OPENSTACK_API_VERSIONS = {
#    "data-processing": 1.1,
#    "identity": 3,
#    "volume": 2,
#}

# Set this to True if running on multi-domain model. When this is enabled, it
# will require user to enter the Domain name in addition to username for login.
#OPENSTACK_KEYSTONE_MULTIDOMAIN_SUPPORT = False

# Overrides the default domain used when running on single-domain model
# with Keystone V3. All entities will be created in the default domain.
#OPENSTACK_KEYSTONE_DEFAULT_DOMAIN = 'Default'

# Set Console type:
# valid options are "AUTO"(default), "VNC", "SPICE", "RDP", "SERIAL" or None
# Set to None explicitly if you want to deactivate the console.
#CONSOLE_TYPE = "AUTO"

# Show backdrop element outside the modal, do not close the modal
# after clicking on backdrop.
#HORIZON_CONFIG["modal_backdrop"] = "static"

# Specify a regular expression to validate user passwords.
#HORIZON_CONFIG["password_validator"] = {
#    "regex": '.*',
#    "help_text": _("Your password does not meet the requirements."),
#}

# Disable simplified floating IP address management for deployments with
# multiple floating IP pools or complex network requirements.
#HORIZON_CONFIG["simple_ip_management"] = False

# Turn off browser autocompletion for forms including the login form and
# the database creation workflow if so desired.
#HORIZON_CONFIG["password_autocomplete"] = "off"

# Setting this to True will disable the reveal button for password fields,
# including on the login form.
#HORIZON_CONFIG["disable_password_reveal"] = False

LOCAL_PATH = os.path.dirname(os.path.abspath(__file__))

# Set custom secret key:
# You can either set it to a specific value or you can let horizon generate a
# default secret key that is unique on this machine, e.i. regardless of the
# amount of Python WSGI workers (if used behind Apache+mod_wsgi): However,
# there may be situations where you would want to set this explicitly, e.g.
# when multiple dashboard instances are distributed on different machines
# (usually behind a load-balancer). Either you have to make sure that a session
# gets all requests routed to the same dashboard instance or you set the same
# SECRET_KEY for all of them.
SECRET_KEY = secret_key.generate_or_read_from_file('/var/lib/openstack-dashboard/secret_key')

# We recommend you use memcached for development; otherwise after every reload
# of the django development server, you will have to login again. To use
# memcached set CACHES to something like
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
        'LOCATION': '127.0.0.1:11211',
    }
}

#CACHES = {
#    'default': {
#        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
#    }
#}

# Send email to the console by default
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
# Or send them to /dev/null
#EMAIL_BACKEND = 'django.core.mail.backends.dummy.EmailBackend'

# Configure these for your outgoing email host
#EMAIL_HOST = 'smtp.my-company.com'
#EMAIL_PORT = 25
#EMAIL_HOST_USER = 'djangomail'
#EMAIL_HOST_PASSWORD = 'top-secret!'

# For multiple regions uncomment this configuration, and add (endpoint, title).
#AVAILABLE_REGIONS = [
#    ('http://cluster1.example.com:5000/v2.0', 'cluster1'),
#    ('http://cluster2.example.com:5000/v2.0', 'cluster2'),
#]

OPENSTACK_HOST = "${ETH3_IP}"
OPENSTACK_KEYSTONE_URL = "http://%s:5000/v2.0" % OPENSTACK_HOST
OPENSTACK_KEYSTONE_DEFAULT_ROLE = "_member_"

# Enables keystone web single-sign-on if set to True.
#WEBSSO_ENABLED = False

# Determines which authentication choice to show as default.
#WEBSSO_INITIAL_CHOICE = "credentials"

# The list of authentication mechanisms
# which include keystone federation protocols.
# Current supported protocol IDs are 'saml2' and 'oidc'
# which represent SAML 2.0, OpenID Connect respectively.
# Do not remove the mandatory credentials mechanism.
#WEBSSO_CHOICES = (
#    ("credentials", _("Keystone Credentials")),
#    ("oidc", _("OpenID Connect")),
#    ("saml2", _("Security Assertion Markup Language")))

# Disable SSL certificate checks (useful for self-signed certificates):
#OPENSTACK_SSL_NO_VERIFY = True

# The CA certificate to use to verify SSL connections
#OPENSTACK_SSL_CACERT = '/path/to/cacert.pem'

# The OPENSTACK_KEYSTONE_BACKEND settings can be used to identify the
# capabilities of the auth backend for Keystone.
# If Keystone has been configured to use LDAP as the auth backend then set
# can_edit_user to False and name to 'ldap'.
#
# TODO(tres): Remove these once Keystone has an API to identify auth backend.
OPENSTACK_KEYSTONE_BACKEND = {
    'name': 'native',
    'can_edit_user': True,
    'can_edit_group': True,
    'can_edit_project': True,
    'can_edit_domain': True,
    'can_edit_role': True,
}

# Setting this to True, will add a new "Retrieve Password" action on instance,
# allowing Admin session password retrieval/decryption.
#OPENSTACK_ENABLE_PASSWORD_RETRIEVE = False

# The Launch Instance user experience has been significantly enhanced.
# You can choose whether to enable the new launch instance experience,
# the legacy experience, or both. The legacy experience will be removed
# in a future release, but is available as a temporary backup setting to ensure
# compatibility with existing deployments. Further development will not be
# done on the legacy experience. Please report any problems with the new
# experience via the Launchpad tracking system.
#
# Toggle LAUNCH_INSTANCE_LEGACY_ENABLED and LAUNCH_INSTANCE_NG_ENABLED to
# determine the experience to enable.  Set them both to true to enable
# both.
#LAUNCH_INSTANCE_LEGACY_ENABLED = True
#LAUNCH_INSTANCE_NG_ENABLED = False

# The Xen Hypervisor has the ability to set the mount point for volumes
# attached to instances (other Hypervisors currently do not). Setting
# can_set_mount_point to True will add the option to set the mount point
# from the UI.
OPENSTACK_HYPERVISOR_FEATURES = {
    'can_set_mount_point': False,
    'can_set_password': False,
    'requires_keypair': False,
}

# The OPENSTACK_CINDER_FEATURES settings can be used to enable optional
# services provided by cinder that is not exposed by its extension API.
OPENSTACK_CINDER_FEATURES = {
    'enable_backup': False,
}

# The OPENSTACK_NEUTRON_NETWORK settings can be used to enable optional
# services provided by neutron. Options currently available are load
# balancer service, security groups, quotas, VPN service.
OPENSTACK_NEUTRON_NETWORK = {
    'enable_router': True,
    'enable_quotas': True,
    'enable_ipv6': True,
    'enable_distributed_router': False,
    'enable_ha_router': False,
    'enable_lb': True,
    'enable_firewall': True,
    'enable_vpn': True,
    'enable_fip_topology_check': True,

    # Neutron can be configured with a default Subnet Pool to be used for IPv4
    # subnet-allocation. Specify the label you wish to display in the Address
    # pool selector on the create subnet step if you want to use this feature.
    'default_ipv4_subnet_pool_label': None,

    # Neutron can be configured with a default Subnet Pool to be used for IPv6
    # subnet-allocation. Specify the label you wish to display in the Address
    # pool selector on the create subnet step if you want to use this feature.
    # You must set this to enable IPv6 Prefix Delegation in a PD-capable
    # environment.
    'default_ipv6_subnet_pool_label': None,

    # The profile_support option is used to detect if an external router can be
    # configured via the dashboard. When using specific plugins the
    # profile_support can be turned on if needed.
    'profile_support': None,
    #'profile_support': 'cisco',

    # Set which provider network types are supported. Only the network types
    # in this list will be available to choose from when creating a network.
    # Network types include local, flat, vlan, gre, and vxlan.
    'supported_provider_types': ['*'],

    # Set which VNIC types are supported for port binding. Only the VNIC
    # types in this list will be available to choose from when creating a
    # port.
    # VNIC types include 'normal', 'macvtap' and 'direct'.
    # Set to empty list or None to disable VNIC type selection.
    'supported_vnic_types': ['*']
}

# The OPENSTACK_IMAGE_BACKEND settings can be used to customize features
# in the OpenStack Dashboard related to the Image service, such as the list
# of supported image formats.
#OPENSTACK_IMAGE_BACKEND = {
#    'image_formats': [
#        ('', _('Select format')),
#        ('aki', _('AKI - Amazon Kernel Image')),
#        ('ami', _('AMI - Amazon Machine Image')),
#        ('ari', _('ARI - Amazon Ramdisk Image')),
#        ('docker', _('Docker')),
#        ('iso', _('ISO - Optical Disk Image')),
#        ('ova', _('OVA - Open Virtual Appliance')),
#        ('qcow2', _('QCOW2 - QEMU Emulator')),
#        ('raw', _('Raw')),
#        ('vdi', _('VDI - Virtual Disk Image')),
#        ('vhd', ('VHD - Virtual Hard Disk')),
#        ('vmdk', _('VMDK - Virtual Machine Disk')),
#    ]
#}

# The IMAGE_CUSTOM_PROPERTY_TITLES settings is used to customize the titles for
# image custom property attributes that appear on image detail pages.
IMAGE_CUSTOM_PROPERTY_TITLES = {
    "architecture": _("Architecture"),
    "kernel_id": _("Kernel ID"),
    "ramdisk_id": _("Ramdisk ID"),
    "image_state": _("Euca2ools state"),
    "project_id": _("Project ID"),
    "image_type": _("Image Type"),
}

# The IMAGE_RESERVED_CUSTOM_PROPERTIES setting is used to specify which image
# custom properties should not be displayed in the Image Custom Properties
# table.
IMAGE_RESERVED_CUSTOM_PROPERTIES = []

# OPENSTACK_ENDPOINT_TYPE specifies the endpoint type to use for the endpoints
# in the Keystone service catalog. Use this setting when Horizon is running
# external to the OpenStack environment. The default is 'publicURL'.
#OPENSTACK_ENDPOINT_TYPE = "publicURL"

# SECONDARY_ENDPOINT_TYPE specifies the fallback endpoint type to use in the
# case that OPENSTACK_ENDPOINT_TYPE is not present in the endpoints
# in the Keystone service catalog. Use this setting when Horizon is running
# external to the OpenStack environment. The default is None.  This
# value should differ from OPENSTACK_ENDPOINT_TYPE if used.
#SECONDARY_ENDPOINT_TYPE = "publicURL"

# The number of objects (Swift containers/objects or images) to display
# on a single page before providing a paging element (a "more" link)
# to paginate results.
API_RESULT_LIMIT = 1000
API_RESULT_PAGE_SIZE = 20

# The size of chunk in bytes for downloading objects from Swift
SWIFT_FILE_TRANSFER_CHUNK_SIZE = 512 * 1024

# Specify a maximum number of items to display in a dropdown.
DROPDOWN_MAX_ITEMS = 30

# The timezone of the server. This should correspond with the timezone
# of your entire OpenStack installation, and hopefully be in UTC.
TIME_ZONE = "UTC"

# When launching an instance, the menu of available flavors is
# sorted by RAM usage, ascending. If you would like a different sort order,
# you can provide another flavor attribute as sorting key. Alternatively, you
# can provide a custom callback method to use for sorting. You can also provide
# a flag for reverse sort. For more info, see
# http://docs.python.org/2/library/functions.html#sorted
#CREATE_INSTANCE_FLAVOR_SORT = {
#    'key': 'name',
#     # or
#    'key': my_awesome_callback_method,
#    'reverse': False,
#}

# Set this to True to display an 'Admin Password' field on the Change Password
# form to verify that it is indeed the admin logged-in who wants to change
# the password.
#ENFORCE_PASSWORD_CHECK = False

# Modules that provide /auth routes that can be used to handle different types
# of user authentication. Add auth plugins that require extra route handling to
# this list.
#AUTHENTICATION_URLS = [
#    'openstack_auth.urls',
#]

# The Horizon Policy Enforcement engine uses these values to load per service
# policy rule files. The content of these files should match the files the
# OpenStack services are using to determine role based access control in the
# target installation.

# Path to directory containing policy.json files
#POLICY_FILES_PATH = os.path.join(ROOT_PATH, "conf")

# Map of local copy of service policy files.
# Please insure that your identity policy file matches the one being used on
# your keystone servers. There is an alternate policy file that may be used
# in the Keystone v3 multi-domain case, policy.v3cloudsample.json.
# This file is not included in the Horizon repository by default but can be
# found at
# http://git.openstack.org/cgit/openstack/keystone/tree/etc/ \
# policy.v3cloudsample.json
# Having matching policy files on the Horizon and Keystone servers is essential
# for normal operation. This holds true for all services and their policy files.
#POLICY_FILES = {
#    'identity': 'keystone_policy.json',
#    'compute': 'nova_policy.json',
#    'volume': 'cinder_policy.json',
#    'image': 'glance_policy.json',
#    'orchestration': 'heat_policy.json',
#    'network': 'neutron_policy.json',
#    'telemetry': 'ceilometer_policy.json',
#}

# Trove user and database extension support. By default support for
# creating users and databases on database instances is turned on.
# To disable these extensions set the permission here to something
# unusable such as ["!"].
#TROVE_ADD_USER_PERMS = []
#TROVE_ADD_DATABASE_PERMS = []

# Change this patch to the appropriate static directory containing
# two files: _variables.scss and _styles.scss
#CUSTOM_THEME_PATH = 'themes/default'

LOGGING = {
    'version': 1,
    # When set to True this will disable all logging except
    # for loggers specified in this configuration dictionary. Note that
    # if nothing is specified here and disable_existing_loggers is True,
    # django.db.backends will still log unless it is disabled explicitly.
    'disable_existing_loggers': False,
    'handlers': {
        'null': {
            'level': 'DEBUG',
            'class': 'django.utils.log.NullHandler',
        },
        'console': {
            # Set the level to "DEBUG" for verbose output logging.
            'level': 'INFO',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        # Logging from django.db.backends is VERY verbose, send to null
        # by default.
        'django.db.backends': {
            'handlers': ['null'],
            'propagate': False,
        },
        'requests': {
            'handlers': ['null'],
            'propagate': False,
        },
        'horizon': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'openstack_dashboard': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'novaclient': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'cinderclient': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'keystoneclient': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'glanceclient': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'neutronclient': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'heatclient': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'ceilometerclient': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'troveclient': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'swiftclient': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'openstack_auth': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'nose.plugins.manager': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'django': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'iso8601': {
            'handlers': ['null'],
            'propagate': False,
        },
        'scss': {
            'handlers': ['null'],
            'propagate': False,
        },
    }
}

# 'direction' should not be specified for all_tcp/udp/icmp.
# It is specified in the form.
SECURITY_GROUP_RULES = {
    'all_tcp': {
        'name': _('All TCP'),
        'ip_protocol': 'tcp',
        'from_port': '1',
        'to_port': '65535',
    },
    'all_udp': {
        'name': _('All UDP'),
        'ip_protocol': 'udp',
        'from_port': '1',
        'to_port': '65535',
    },
    'all_icmp': {
        'name': _('All ICMP'),
        'ip_protocol': 'icmp',
        'from_port': '-1',
        'to_port': '-1',
    },
    'ssh': {
        'name': 'SSH',
        'ip_protocol': 'tcp',
        'from_port': '22',
        'to_port': '22',
    },
    'smtp': {
        'name': 'SMTP',
        'ip_protocol': 'tcp',
        'from_port': '25',
        'to_port': '25',
    },
    'dns': {
        'name': 'DNS',
        'ip_protocol': 'tcp',
        'from_port': '53',
        'to_port': '53',
    },
    'http': {
        'name': 'HTTP',
        'ip_protocol': 'tcp',
        'from_port': '80',
        'to_port': '80',
    },
    'pop3': {
        'name': 'POP3',
        'ip_protocol': 'tcp',
        'from_port': '110',
        'to_port': '110',
    },
    'imap': {
        'name': 'IMAP',
        'ip_protocol': 'tcp',
        'from_port': '143',
        'to_port': '143',
    },
    'ldap': {
        'name': 'LDAP',
        'ip_protocol': 'tcp',
        'from_port': '389',
        'to_port': '389',
    },
    'https': {
        'name': 'HTTPS',
        'ip_protocol': 'tcp',
        'from_port': '443',
        'to_port': '443',
    },
    'smtps': {
        'name': 'SMTPS',
        'ip_protocol': 'tcp',
        'from_port': '465',
        'to_port': '465',
    },
    'imaps': {
        'name': 'IMAPS',
        'ip_protocol': 'tcp',
        'from_port': '993',
        'to_port': '993',
    },
    'pop3s': {
        'name': 'POP3S',
        'ip_protocol': 'tcp',
        'from_port': '995',
        'to_port': '995',
    },
    'ms_sql': {
        'name': 'MS SQL',
        'ip_protocol': 'tcp',
        'from_port': '1433',
        'to_port': '1433',
    },
    'mysql': {
        'name': 'MYSQL',
        'ip_protocol': 'tcp',
        'from_port': '3306',
        'to_port': '3306',
    },
    'rdp': {
        'name': 'RDP',
        'ip_protocol': 'tcp',
        'from_port': '3389',
        'to_port': '3389',
    },
}

# Deprecation Notice:
#
# The setting FLAVOR_EXTRA_KEYS has been deprecated.
# Please load extra spec metadata into the Glance Metadata Definition Catalog.
#
# The sample quota definitions can be found in:
# <glance_source>/etc/metadefs/compute-quota.json
#
# The metadata definition catalog supports CLI and API:
#  $glance --os-image-api-version 2 help md-namespace-import
#  $glance-manage db_load_metadefs <directory_with_definition_files>
#
# See Metadata Definitions on: http://docs.openstack.org/developer/glance/

# Indicate to the Sahara data processing service whether or not
# automatic floating IP allocation is in effect.  If it is not
# in effect, the user will be prompted to choose a floating IP
# pool for use in their cluster.  False by default.  You would want
# to set this to True if you were running Nova Networking with
# auto_assign_floating_ip = True.
#SAHARA_AUTO_IP_ALLOCATION_ENABLED = False

# The hash algorithm to use for authentication tokens. This must
# match the hash algorithm that the identity server and the
# auth_token middleware are using. Allowed values are the
# algorithms supported by Python's hashlib library.
#OPENSTACK_TOKEN_HASH_ALGORITHM = 'md5'

# Hashing tokens from Keystone keeps the Horizon session data smaller, but it
# doesn't work in some cases when using PKI tokens.  Uncomment this value and
# set it to False if using PKI tokens and there are 401 errors due to token
# hashing.
#OPENSTACK_TOKEN_HASH_ENABLED = True

# AngularJS requires some settings to be made available to
# the client side. Some settings are required by in-tree / built-in horizon
# features. These settings must be added to REST_API_REQUIRED_SETTINGS in the
# form of ['SETTING_1','SETTING_2'], etc.
#
# You may remove settings from this list for security purposes, but do so at
# the risk of breaking a built-in horizon feature. These settings are required
# for horizon to function properly. Only remove them if you know what you
# are doing. These settings may in the future be moved to be defined within
# the enabled panel configuration.
# You should not add settings to this list for out of tree extensions.
# See: https://wiki.openstack.org/wiki/Horizon/RESTAPI
REST_API_REQUIRED_SETTINGS = ['OPENSTACK_HYPERVISOR_FEATURES']

# Additional settings can be made available to the client side for
# extensibility by specifying them in REST_API_ADDITIONAL_SETTINGS
# !! Please use extreme caution as the settings are transferred via HTTP/S
# and are not encrypted on the browser. This is an experimental API and
# may be deprecated in the future without notice.
#REST_API_ADDITIONAL_SETTINGS = []

###############################################################################
# Ubuntu Settings
###############################################################################

# Enable the Ubuntu theme if it is present.
try:
  from ubuntu_theme import *
except ImportError:
  pass

# Default Ubuntu apache configuration uses /horizon as the application root.
WEBROOT='/'

# By default, validation of the HTTP Host header is disabled.  Production
# installations should have this set accordingly.  For more information
# see https://docs.djangoproject.com/en/dev/ref/settings/.
ALLOWED_HOSTS = '*'

# Compress all assets offline as part of packaging installation
COMPRESS_OFFLINE = True

# DISALLOW_IFRAME_EMBED can be used to prevent Horizon from being embedded
# within an iframe. Legacy browsers are still vulnerable to a Cross-Frame
# Scripting (XFS) vulnerability, so this option allows extra security hardening
# where iframes are not used in deployment. Default setting is True.
# For more information see:
# http://tinyurl.com/anticlickjack
#DISALLOW_IFRAME_EMBED = True
EOF

#cat > /etc/openstack-dashboard/local_settings.py << EOF
#import os
#
#from django.utils.translation import ugettext_lazy as _
#
#from openstack_dashboard import exceptions
#
#DEBUG = False
#TEMPLATE_DEBUG = DEBUG
#
## Required for Django 1.5.
## If horizon is running in production (DEBUG is False), set this
## with the list of host/domain names that the application can serve.
## For more information see:
## http://docs.djangoproject.com/en/dev/ref/settings/#allowed-hosts
##ALLOWED_HOSTS = ['horizon.example.com', ]
#
## Set SSL proxy settings:
## For Django 1.4+ pass this header from the proxy after terminating the SSL,
## and don't forget to strip it from the client's request.
## For more information see:
## http://docs.djangoproject.com/en/1.4/ref/settings/#secure-proxy-ssl-header
## SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTOCOL', 'http')
#
## If Horizon is being served through SSL, then uncomment the following two
## settings to better secure the cookies from security exploits
##CSRF_COOKIE_SECURE = True
##SESSION_COOKIE_SECURE = True
#
## Overrides for OpenStack API versions. Use this setting to force the
## OpenStack dashboard to use a specific API version for a given service API.
## NOTE: The version should be formatted as it appears in the URL for the
## service API. For example, The identity service APIs have inconsistent
## use of the decimal point, so valid options would be "2.0" or "3".
## OPENSTACK_API_VERSIONS = {
##     "data_processing": 1.1,
##     "identity": 3,
##     "volume": 2
## }
#
## Set this to True if running on multi-domain model. When this is enabled, it
## will require user to enter the Domain name in addition to username for login.
## OPENSTACK_KEYSTONE_MULTIDOMAIN_SUPPORT = False
#
## Overrides the default domain used when running on single-domain model
## with Keystone V3. All entities will be created in the default domain.
## OPENSTACK_KEYSTONE_DEFAULT_DOMAIN = 'Default'
#
## Set Console type:
## valid options would be "AUTO"(default), "VNC", "SPICE", "RDP" or None
## Set to None explicitly if you want to deactivate the console.
## CONSOLE_TYPE = "AUTO"
#
## Default OpenStack Dashboard configuration.
#HORIZON_CONFIG = {
#    'dashboards': ('project', 'admin', 'settings',),
#    'default_dashboard': 'project',
#    'user_home': 'openstack_dashboard.views.get_user_home',
#    'ajax_queue_limit': 10,
#    'auto_fade_alerts': {
#        'delay': 3000,
#        'fade_duration': 1500,
#        'types': ['alert-success', 'alert-info']
#    },
#    'help_url': "http://docs.openstack.org",
#    'exceptions': {'recoverable': exceptions.RECOVERABLE,
#                   'not_found': exceptions.NOT_FOUND,
#                   'unauthorized': exceptions.UNAUTHORIZED},
#    'angular_modules': [],
#    'js_files': [],
#}
#
## Specify a regular expression to validate user passwords.
## HORIZON_CONFIG["password_validator"] = {
##     "regex": '.*',
##     "help_text": _("Your password does not meet the requirements.")
## }
#
## Disable simplified floating IP address management for deployments with
## multiple floating IP pools or complex network requirements.
## HORIZON_CONFIG["simple_ip_management"] = False
#
## Turn off browser autocompletion for forms including the login form and
## the database creation workflow if so desired.
## HORIZON_CONFIG["password_autocomplete"] = "off"
#
#LOCAL_PATH = os.path.dirname(os.path.abspath(__file__))
#
## Set custom secret key:
## You can either set it to a specific value or you can let horizon generate a
## default secret key that is unique on this machine, e.i. regardless of the
## amount of Python WSGI workers (if used behind Apache+mod_wsgi): However, there
## may be situations where you would want to set this explicitly, e.g. when
## multiple dashboard instances are distributed on different machines (usually
## behind a load-balancer). Either you have to make sure that a session gets all
## requests routed to the same dashboard instance or you set the same SECRET_KEY
## for all of them.
#from horizon.utils import secret_key
#SECRET_KEY = secret_key.generate_or_read_from_file('/var/lib/openstack-dashboard/secret_key')
#
## We recommend you use memcached for development; otherwise after every reload
## of the django development server, you will have to login again. To use
## memcached set CACHES to something like
#CACHES = {
#   'default': {
#       'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
#       'LOCATION': '127.0.0.1:11211',
#   }
#}
#
##CACHES = {
##    'default': {
##        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'
##    }
##}
#
## Send email to the console by default
#EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
## Or send them to /dev/null
##EMAIL_BACKEND = 'django.core.mail.backends.dummy.EmailBackend'
#
## Configure these for your outgoing email host
## EMAIL_HOST = 'smtp.my-company.com'
## EMAIL_PORT = 25
## EMAIL_HOST_USER = 'djangomail'
## EMAIL_HOST_PASSWORD = 'top-secret!'
#
## For multiple regions uncomment this configuration, and add (endpoint, title).
## AVAILABLE_REGIONS = [
##     ('http://cluster1.example.com:5000/v2.0', 'cluster1'),
##     ('http://cluster2.example.com:5000/v2.0', 'cluster2'),
## ]
#
#OPENSTACK_HOST = "${ETH3_IP}"
#OPENSTACK_KEYSTONE_URL = "http://%s:5000/v2.0" % OPENSTACK_HOST
#OPENSTACK_KEYSTONE_DEFAULT_ROLE = "_member_"
#
## Disable SSL certificate checks (useful for self-signed certificates):
#OPENSTACK_SSL_NO_VERIFY = True
#
## The CA certificate to use to verify SSL connections
## OPENSTACK_SSL_CACERT = '/path/to/cacert.pem'
#
## The OPENSTACK_KEYSTONE_BACKEND settings can be used to identify the
## capabilities of the auth backend for Keystone.
## If Keystone has been configured to use LDAP as the auth backend then set
## can_edit_user to False and name to 'ldap'.
##
## TODO(tres): Remove these once Keystone has an API to identify auth backend.
#OPENSTACK_KEYSTONE_BACKEND = {
#    'name': 'native',
#    'can_edit_user': True,
#    'can_edit_group': True,
#    'can_edit_project': True,
#    'can_edit_domain': True,
#    'can_edit_role': True
#}
#
##Setting this to True, will add a new "Retrieve Password" action on instance,
##allowing Admin session password retrieval/decryption.
##OPENSTACK_ENABLE_PASSWORD_RETRIEVE = False
#
## The Xen Hypervisor has the ability to set the mount point for volumes
## attached to instances (other Hypervisors currently do not). Setting
## can_set_mount_point to True will add the option to set the mount point
## from the UI.
#OPENSTACK_HYPERVISOR_FEATURES = {
#    'can_set_mount_point': False,
#    'can_set_password': False,
#}
#
## The OPENSTACK_CINDER_FEATURES settings can be used to enable optional
## services provided by cinder that is not exposed by its extension API.
#OPENSTACK_CINDER_FEATURES = {
#    'enable_backup': False,
#}
#
## The OPENSTACK_NEUTRON_NETWORK settings can be used to enable optional
## services provided by neutron. Options currently available are load
## balancer service, security groups, quotas, VPN service.
#OPENSTACK_NEUTRON_NETWORK = {
#    'enable_router': True,
#    'enable_quotas': True,
#    'enable_ipv6': True,
#    'enable_distributed_router': False,
#    'enable_ha_router': False,
#    'enable_lb': True,
#    'enable_firewall': True,
#    'enable_vpn': True,
#    # The profile_support option is used to detect if an external router can be
#    # configured via the dashboard. When using specific plugins the
#    # profile_support can be turned on if needed.
#    'profile_support': None,
#    #'profile_support': 'cisco',
#    # Set which provider network types are supported. Only the network types
#    # in this list will be available to choose from when creating a network.
#    # Network types include local, flat, vlan, gre, and vxlan.
#    'supported_provider_types': ['*'],
#}
#
## The OPENSTACK_IMAGE_BACKEND settings can be used to customize features
## in the OpenStack Dashboard related to the Image service, such as the list
## of supported image formats.
## OPENSTACK_IMAGE_BACKEND = {
##     'image_formats': [
##         ('', _('Select format')),
##         ('aki', _('AKI - Amazon Kernel Image')),
##         ('ami', _('AMI - Amazon Machine Image')),
##         ('ari', _('ARI - Amazon Ramdisk Image')),
##         ('iso', _('ISO - Optical Disk Image')),
##         ('qcow2', _('QCOW2 - QEMU Emulator')),
##         ('raw', _('Raw')),
##         ('vdi', _('VDI')),
##         ('vhd', _('VHD')),
##         ('vmdk', _('VMDK'))
##     ]
## }
#
## The IMAGE_CUSTOM_PROPERTY_TITLES settings is used to customize the titles for
## image custom property attributes that appear on image detail pages.
#IMAGE_CUSTOM_PROPERTY_TITLES = {
#    "architecture": _("Architecture"),
#    "kernel_id": _("Kernel ID"),
#    "ramdisk_id": _("Ramdisk ID"),
#    "image_state": _("Euca2ools state"),
#    "project_id": _("Project ID"),
#    "image_type": _("Image Type")
#}
#
## The IMAGE_RESERVED_CUSTOM_PROPERTIES setting is used to specify which image
## custom properties should not be displayed in the Image Custom Properties
## table.
#IMAGE_RESERVED_CUSTOM_PROPERTIES = []
#
## OPENSTACK_ENDPOINT_TYPE specifies the endpoint type to use for the endpoints
## in the Keystone service catalog. Use this setting when Horizon is running
## external to the OpenStack environment. The default is 'publicURL'.
##OPENSTACK_ENDPOINT_TYPE = "publicURL"
#
## SECONDARY_ENDPOINT_TYPE specifies the fallback endpoint type to use in the
## case that OPENSTACK_ENDPOINT_TYPE is not present in the endpoints
## in the Keystone service catalog. Use this setting when Horizon is running
## external to the OpenStack environment. The default is None.  This
## value should differ from OPENSTACK_ENDPOINT_TYPE if used.
##SECONDARY_ENDPOINT_TYPE = "publicURL"
#
## The number of objects (Swift containers/objects or images) to display
## on a single page before providing a paging element (a "more" link)
## to paginate results.
#API_RESULT_LIMIT = 1000
#API_RESULT_PAGE_SIZE = 20
#
## The timezone of the server. This should correspond with the timezone
## of your entire OpenStack installation, and hopefully be in UTC.
#TIME_ZONE = "UTC"
#
## When launching an instance, the menu of available flavors is
## sorted by RAM usage, ascending. If you would like a different sort order,
## you can provide another flavor attribute as sorting key. Alternatively, you
## can provide a custom callback method to use for sorting. You can also provide
## a flag for reverse sort. For more info, see
## http://docs.python.org/2/library/functions.html#sorted
## CREATE_INSTANCE_FLAVOR_SORT = {
##     'key': 'name',
##      # or
##     'key': my_awesome_callback_method,
##     'reverse': False,
## }
#
## The Horizon Policy Enforcement engine uses these values to load per service
## policy rule files. The content of these files should match the files the
## OpenStack services are using to determine role based access control in the
## target installation.
#
## Path to directory containing policy.json files
##POLICY_FILES_PATH = os.path.join(ROOT_PATH, "conf")
## Map of local copy of service policy files
##POLICY_FILES = {
##    'identity': 'keystone_policy.json',
##    'compute': 'nova_policy.json',
##    'volume': 'cinder_policy.json',
##    'image': 'glance_policy.json',
##    'orchestration': 'heat_policy.json',
##    'network': 'neutron_policy.json',
##}
#
## Trove user and database extension support. By default support for
## creating users and databases on database instances is turned on.
## To disable these extensions set the permission here to something
## unusable such as ["!"].
## TROVE_ADD_USER_PERMS = []
## TROVE_ADD_DATABASE_PERMS = []
#
#LOGGING = {
#    'version': 1,
#    # When set to True this will disable all logging except
#    # for loggers specified in this configuration dictionary. Note that
#    # if nothing is specified here and disable_existing_loggers is True,
#    # django.db.backends will still log unless it is disabled explicitly.
#    'disable_existing_loggers': False,
#    'handlers': {
#        'null': {
#            'level': 'DEBUG',
#            'class': 'django.utils.log.NullHandler',
#        },
#        'console': {
#            # Set the level to "DEBUG" for verbose output logging.
#            'level': 'INFO',
#            'class': 'logging.StreamHandler',
#        },
#    },
#    'loggers': {
#        # Logging from django.db.backends is VERY verbose, send to null
#        # by default.
#        'django.db.backends': {
#            'handlers': ['null'],
#            'propagate': False,
#        },
#        'requests': {
#            'handlers': ['null'],
#            'propagate': False,
#        },
#        'horizon': {
#            'handlers': ['console'],
#            'level': 'DEBUG',
#            'propagate': False,
#        },
#        'openstack_dashboard': {
#            'handlers': ['console'],
#            'level': 'DEBUG',
#            'propagate': False,
#        },
#        'novaclient': {
#            'handlers': ['console'],
#            'level': 'DEBUG',
#            'propagate': False,
#        },
#        'cinderclient': {
#            'handlers': ['console'],
#            'level': 'DEBUG',
#            'propagate': False,
#        },
#        'keystoneclient': {
#            'handlers': ['console'],
#            'level': 'DEBUG',
#            'propagate': False,
#        },
#        'glanceclient': {
#            'handlers': ['console'],
#            'level': 'DEBUG',
#            'propagate': False,
#        },
#        'neutronclient': {
#            'handlers': ['console'],
#            'level': 'DEBUG',
#            'propagate': False,
#        },
#        'heatclient': {
#            'handlers': ['console'],
#            'level': 'DEBUG',
#            'propagate': False,
#        },
#        'ceilometerclient': {
#            'handlers': ['console'],
#            'level': 'DEBUG',
#            'propagate': False,
#        },
#        'troveclient': {
#            'handlers': ['console'],
#            'level': 'DEBUG',
#            'propagate': False,
#        },
#        'swiftclient': {
#            'handlers': ['console'],
#            'level': 'DEBUG',
#            'propagate': False,
#        },
#        'openstack_auth': {
#            'handlers': ['console'],
#            'level': 'DEBUG',
#            'propagate': False,
#        },
#        'nose.plugins.manager': {
#            'handlers': ['console'],
#            'level': 'DEBUG',
#            'propagate': False,
#        },
#        'django': {
#            'handlers': ['console'],
#            'level': 'DEBUG',
#            'propagate': False,
#        },
#        'iso8601': {
#            'handlers': ['null'],
#            'propagate': False,
#        },
#        'scss': {
#            'handlers': ['null'],
#            'propagate': False,
#        },
#    }
#}
#
## 'direction' should not be specified for all_tcp/udp/icmp.
## It is specified in the form.
#SECURITY_GROUP_RULES = {
#    'all_tcp': {
#        'name': _('All TCP'),
#        'ip_protocol': 'tcp',
#        'from_port': '1',
#        'to_port': '65535',
#    },
#    'all_udp': {
#        'name': _('All UDP'),
#        'ip_protocol': 'udp',
#        'from_port': '1',
#        'to_port': '65535',
#    },
#    'all_icmp': {
#        'name': _('All ICMP'),
#        'ip_protocol': 'icmp',
#        'from_port': '-1',
#        'to_port': '-1',
#    },
#    'ssh': {
#        'name': 'SSH',
#        'ip_protocol': 'tcp',
#        'from_port': '22',
#        'to_port': '22',
#    },
#    'smtp': {
#        'name': 'SMTP',
#        'ip_protocol': 'tcp',
#        'from_port': '25',
#        'to_port': '25',
#    },
#    'dns': {
#        'name': 'DNS',
#        'ip_protocol': 'tcp',
#        'from_port': '53',
#        'to_port': '53',
#    },
#    'http': {
#        'name': 'HTTP',
#        'ip_protocol': 'tcp',
#        'from_port': '80',
#        'to_port': '80',
#    },
#    'pop3': {
#        'name': 'POP3',
#        'ip_protocol': 'tcp',
#        'from_port': '110',
#        'to_port': '110',
#    },
#    'imap': {
#        'name': 'IMAP',
#        'ip_protocol': 'tcp',
#        'from_port': '143',
#        'to_port': '143',
#    },
#    'ldap': {
#        'name': 'LDAP',
#        'ip_protocol': 'tcp',
#        'from_port': '389',
#        'to_port': '389',
#    },
#    'http': {
#        'name': 'HTTPS',
#        'ip_protocol': 'tcp',
#        'from_port': '443',
#        'to_port': '443',
#    },
#    'smtps': {
#        'name': 'SMTPS',
#        'ip_protocol': 'tcp',
#        'from_port': '465',
#        'to_port': '465',
#    },
#    'imaps': {
#        'name': 'IMAPS',
#        'ip_protocol': 'tcp',
#        'from_port': '993',
#        'to_port': '993',
#    },
#    'pop3s': {
#        'name': 'POP3S',
#        'ip_protocol': 'tcp',
#        'from_port': '995',
#        'to_port': '995',
#    },
#    'ms_sql': {
#        'name': 'MS SQL',
#        'ip_protocol': 'tcp',
#        'from_port': '1433',
#        'to_port': '1433',
#    },
#    'mysql': {
#        'name': 'MYSQL',
#        'ip_protocol': 'tcp',
#        'from_port': '3306',
#        'to_port': '3306',
#    },
#    'rdp': {
#        'name': 'RDP',
#        'ip_protocol': 'tcp',
#        'from_port': '3389',
#        'to_port': '3389',
#    },
#}
#
## Deprecation Notice:
##
## The setting FLAVOR_EXTRA_KEYS has been deprecated.
## Please load extra spec metadata into the Glance Metadata Definition Catalog.
##
## The sample quota definitions can be found in:
## <glance_source>/etc/metadefs/compute-quota.json
##
## The metadata definition catalog supports CLI and API:
##  $glance --os-image-api-version 2 help md-namespace-import
##  $glance-manage db_load_metadefs <directory_with_definition_files>
##
## See Metadata Definitions on: http://docs.openstack.org/developer/glance/
#
## Indicate to the Sahara data processing service whether or not
## automatic floating IP allocation is in effect.  If it is not
## in effect, the user will be prompted to choose a floating IP
## pool for use in their cluster.  False by default.  You would want
## to set this to True if you were running Nova Networking with
## auto_assign_floating_ip = True.
## SAHARA_AUTO_IP_ALLOCATION_ENABLED = False
#
## The hash algorithm to use for authentication tokens. This must
## match the hash algorithm that the identity server and the
## auth_token middleware are using. Allowed values are the
## algorithms supported by Python's hashlib library.
## OPENSTACK_TOKEN_HASH_ALGORITHM = 'md5'
#
################################################################################
## Ubuntu Settings
################################################################################
#
## Enable the Ubuntu theme if it is present.
#try:
#  from ubuntu_theme import *
#except ImportError:
#  pass
#
## Default Ubuntu apache configuration uses /horizon as the application root.
## Configure auth redirects here accordingly.
#LOGIN_URL='/auth/login/'
#LOGOUT_URL='/auth/logout/'
#LOGIN_REDIRECT_URL='/'
#
## By default, validation of the HTTP Host header is disabled.  Production
## installations should have this set accordingly.  For more information
## see http://docs.djangoproject.com/en/dev/ref/settings/.
#ALLOWED_HOSTS = '*'
#
## Compress all assets offline as part of packaging installation
#COMPRESS_OFFLINE = True
#EOF

# Apache Conf
cat > /etc/apache2/conf-enabled/openstack-dashboard.conf << EOF
WSGIScriptAlias / /usr/share/openstack-dashboard/openstack_dashboard/wsgi/django.wsgi
WSGIDaemonProcess horizon user=horizon group=horizon processes=3 threads=10
WSGIProcessGroup horizon
Alias /static /usr/share/openstack-dashboard/openstack_dashboard/static/
<Directory /usr/share/openstack-dashboard/openstack_dashboard/wsgi>
  Order allow,deny
  Allow from all
</Directory>
EOF

service apache2 restart

# rsyslog remote connections
sudo echo "\$ModLoad imudp" >> /etc/rsyslog.conf
sudo echo "\$UDPServerRun 5140" >> /etc/rsyslog.conf
sudo echo "\$ModLoad imtcp" >> /etc/rsyslog.conf
sudo echo "\$InputTCPServerRun 5140" >> /etc/rsyslog.conf
sudo restart rsyslog

# Create an openrc  file
cat > /vagrant/openrc <<EOF
export OS_DOMAIN_NAME=default
export OS_PROJECT_NAME=admin
export OS_USERNAME=admin
export OS_PASSWORD=openstack
export OS_AUTH_URL=http://${ETH3_IP}:5000/v3/
EOF

# Copy openrc file to local instance vagrant root folder in case of loss of file share
sudo cp /vagrant/openrc /home/vagrant 

# Hack: restart neutron again...
service neutron-server restart




####################
# Chapter 9 - Heat #
# (More OpenStack) #
####################

echo "[+] Executing Heat installation script"
sudo /vagrant/heat.sh
echo "[+] Heat installation complete."



#########################
# Chapter 9 -Ceilometer #
# (More OpenStack)      #
#########################

echo "[+] Executing Ceilometer installation script"
sudo /vagrant/ceilometer.sh
echo "[+] Ceilometer install complete."



# Sort out keys for root user
sudo ssh-keygen -t rsa -N "" -f /root/.ssh/id_rsa
rm -f /vagrant/id_rsa*
sudo cp /root/.ssh/id_rsa /vagrant
sudo cp /root/.ssh/id_rsa.pub /vagrant
cat /vagrant/id_rsa.pub | sudo tee -a /root/.ssh/authorized_keys



##################################
# Chapter 12 - Logstash & Kibana #
# (Production OpenStack)         #
##################################
# sudo /vagrant/logstash.sh
