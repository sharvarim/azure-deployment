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
    

def main(timer: func.TimerRequest):
    subscription_id = os.environ.get("SUBSCRIPTION_ID")
    resource_group = os.environ.get("RESOURCE_GROUP")
    clip = os.environ.get("CLIP")
    logger.info(f"Received timer event to send stats")
    adc_password = get_adc_password(subscription_id, resource_group)
    
