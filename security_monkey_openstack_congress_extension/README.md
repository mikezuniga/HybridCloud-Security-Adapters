This is an extension of security monkey for monitoring on top of openstack security monkey monitoring (through openstack congress).

Prerequist:
1. security monkey installed.
2. openstack congress installed.

minimum_datapush.py is used to push data into security monkey 
config-inetvm.txt is an example of configuration file for the issue called "VMs with internet access"

Four congress policies have been enabled for this functionality and they can be found as follow: 

Security Group Management (Implemented)
Security group management policies check against existing security group properties. In our implementation at Symantec, we alert security groups with no incoming traffic control. . We trace such violation at both tenant and instance level.  We also have policies to further highlight those violated VMs with internet access.

Data Sources:
Nova
Neutron

Policies:
// Name: tenants with no ingress control for certain ports
ingress_free_tenant(tenant_id, security_group_id, protocol, ethertype, port_range_min, port_range_max):- 
neutronv2:security_group_rules(security_group_id, id, tenant_id, remote_group_id, "ingress", ethertype, protocol, port_range_min, port_range_max, "0.0.0.0/0")

// Name:  instances with no ingress control for certain ports
ingress_free_vm(vm_id, tenant_id, security_group_id):- neutronv2:security_group_port_bindings (port_id, security_group_id), 
neutronv2:ports(port_id, tenant_id, name, network_id, mac_address, admin_state_up, status, vm_id, port_type), 
ingress_free_tenant(tenant_id, security_group_id, protocol, ethertype, port_range_min, port_range_max)

// Name: instances with internet access
connected_to_internet(port_id, vm_id) :-
neutronv2:external_gateway_infos(router_id=router_id, network_id=network_id_gw), neutronv2:ports(network_id = all_network, device_id = router_id), 
neutronv2:ports(network_id = all_network, id=port_id, device_id=vm_id), nova:servers(id=vm_id)

// Name: violated instances with internet access
external_ac_ingress_free_vm(vm_id, port_id):- connected_to_internet(port_id, vm_id), ingress_free_vm(vm_id, tenant_id, security_group_id)

References:
[NFV-USE-CASE] “ETSI GS NFV 001Network Functions Virtualization (NFV); Use Cases,” http://www.etsi.org/deliver/etsi_gs/NFV/001_099/001/01.01.01_60/gs_NFV001v010101p.pdf
[NFV-ARCH] “NFV Architectural Framework,” http://www.etsi.org/deliver/etsi_gs/NFV/001_099/002/01.01.01_60/gs_NFV002v010101p.pdf
[NFV-REQ] “NFV Virtualization Requirements,” http://www.etsi.org/deliver/etsi_gs/NFV/001_099/004/01.01.01_60/gs_NFV004v010101p.pdf





