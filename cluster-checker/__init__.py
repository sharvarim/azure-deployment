import logging
import os
import requests
import sys

import time
import json
from ipaddress import IPv4Network, ip_network
import traceback
import copy

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.keyvault.secrets import SecretClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.network import NetworkManagementClient

import azure.functions as func

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('=> %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def get_vault_url(subscription_id, resource_group):
    keyvault_client = KeyVaultManagementClient(credential=DefaultAzureCredential(), subscription_id=subscription_id)

    key_vaults = keyvault_client.vaults.list_by_resource_group(resource_group)

    for key_vault in key_vaults:
        logger.info(f"Found a key vault {key_vault.name}")
        return f"https://{key_vault.name}.vault.azure.net/"

    raise ValueError(f"No vaults present in resource_group {resource_group}")

def get_adc_password(subscription_id, resource_group):
    client = SecretClient(vault_url=get_vault_url(subscription_id, resource_group), 
                credential=DefaultAzureCredential(), subscription_id=subscription_id)

    retrieved_secret = client.get_secret("adc-nsroot-pwd")
    logger.info("Successfully fetched ADC password")
    return retrieved_secret.value
    
def get_adc_vmss_name(compute_client, resource_group):

    vmss_list = compute_client.virtual_machine_scale_sets.list(resource_group)
    
    for vmss in vmss_list:
        if vmss.name.startswith("vmss-adc-"):
            logger.info(f"Fetched vmss name = {vmss.name}")
            return vmss.name
    raise ValueError(f"Unable to fetch adc vmss name : {[vmss.name for vmss in vmss_list]}")

def get_vmss_instances_ips(compute_client, network_client, resource_group, vmss_name):
    mgmt_ips, client_ips = [], []
    vmss_vms = compute_client.virtual_machine_scale_set_vms.list(resource_group, vmss_name)

    for vm in vmss_vms:
        vm_details = compute_client.virtual_machines.get(resource_group, vm.name)
        for interface in vm_details.network_profile.network_interfaces:
            if "mgmt-nic" not in interface.id and "client-nic" not in interface.id:
                continue
            nic = network_client.network_interfaces.get(resource_group, interface.id.split('/')[-1])
            for ip_configuration in nic.ip_configurations:
                if ip_configuration.name == "mgmt-ip":
                    mgmt_ips.append(ip_configuration.private_ip_address)
                elif ip_configuration.name == "client-ip":
                    client_ips.append(ip_configuration.private_ip_address)
    logger.info(f"Fetched mgmt-ips={mgmt_ips}  client-ips={client_ips}")
    return mgmt_ips, client_ips
    
def main(event: func.EventGridEvent):
    subscription_id = os.environ.get("SUBSCRIPTION_ID")
    resource_group = os.environ.get("RESOURCE_GROUP")
    clip = os.environ.get("CLIP")
    logger.info(f"Received event {event} type={event.event_type}  details={event.get_json()}")
    r = requests.get("https://ifconfig.me")
    logger.info(f"MY PUBLIC IP IS =============== {r.text}")
    #return
    adc_password = get_adc_password(subscription_id, resource_group)
    compute_client = ComputeManagementClient(credential=DefaultAzureCredential(), subscription_id=subscription_id)
    network_client = NetworkManagementClient(credential=DefaultAzureCredential(), subscription_id=subscription_id)
    vmss_name = get_adc_vmss_name(compute_client, resource_group)
    mgmt_ips, client_ips = get_vmss_instances_ips(compute_client, network_client, resource_group, vmss_name)
    '''
    cluster = Cluster(clip=clip, nspass=adc_password)
    cluster.cleanup_stale_nodes(mgmt_ips, client_ips)
    '''
    
    
    
