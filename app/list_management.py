# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
import copy
from datetime import datetime
import json
import os
import sys
from urllib.parse import urlparse
from uuid import uuid4

import cbor2
from app.config_service import ConfService as cfgservice

#current_dir = os.path.dirname(os.path.abspath(__file__))
#sys.path.append(os.path.join(current_dir, '..', 'token-status-list-py'))

from token_status_list import IssuerStatusList, NoMoreIndices

from app.status_list_format import cwt_format, jwt_format
from app.identifier_list_format import (
    identifier_list_cwt_format,
    identifier_list_jwt_format,
)

status_list = {}

identifier_list = {}


def new_list(country: str,doctype: str):
    """
    Initializes a new status list which inclues both the token status list and identifier status list, separated by country and doctype.

    Args:
        country (str): country code 
        doctype (str): doctype of the attestation
    """

    status_list.update(
        {
            country:{
                doctype: {
                    "token_status_list": IssuerStatusList.new(
                        1, cfgservice.token_status_list_size, "random"
                    ),
                    "identifier_list": identifier_list,
                    "expires": None,
                    "rand": str(uuid4()),
                }
            }
        }
    )


def dump_list(specific_status_list, country, doctype):
    """
    Dumps the status lists to disk. 

    Args:
        specific_status_list (dict): status list to dump
        country (str): country code 
        doctype (str): doctype of the attestation
    """

    rand = specific_status_list["rand"]
    directory = f"{cfgservice.status_list_dir}/token_status_list/{country}/{doctype}/{rand}"
    os.makedirs(directory, exist_ok=True)

    json_file_path = os.path.join(directory, "full_list.json")

    dict_copy = copy.deepcopy(specific_status_list)
    dict_copy["token_status_list"] = dict_copy["token_status_list"].dump()
    dict_copy["country"] = country
    dict_copy["doctype"] = doctype

    with open(json_file_path, "w") as f:
        f.write(json.dumps(dict_copy))

    jwt_file_path = os.path.join(directory, "token_status_list.jwt")
    with open(jwt_file_path, "w") as f:
        f.write(jwt_format(specific_status_list["token_status_list"], country, cfgservice.service_url
            + f"token_status_list/{country}/{doctype}/{rand}"))

    cwt_file_path = os.path.join(directory, "token_status_list.cwt")
    with open(cwt_file_path, "w") as f:
        f.write(cwt_format(specific_status_list["token_status_list"], country, cfgservice.service_url
            + f"token_status_list/{country}/{doctype}/{rand}" ))

    specific_status_list.update(
        {
            "status_list_uri": cfgservice.service_url
            + f"token_status_list/{country}/{doctype}/{rand}"
        }
    )
    ##
    identifier_list_directory = f"{cfgservice.status_list_dir}/identifier_list/{country}/{doctype}/{rand}"

    os.makedirs(identifier_list_directory, exist_ok=True)

    json_file_path = os.path.join(identifier_list_directory, "full_list.json")
    with open(json_file_path, "w") as f:
        f.write(json.dumps(dict_copy))

    jwt_file_path = os.path.join(identifier_list_directory, "identifier_list.jwt")
    with open(jwt_file_path, "w") as f:
        f.write(identifier_list_jwt_format(specific_status_list["identifier_list"], country, cfgservice.service_url
            + f"identifier_list/{country}/{doctype}/{rand}"))

    cwt_file_path = os.path.join(identifier_list_directory, "identifier_list.cwt")
    with open(cwt_file_path, "w") as f:
        f.write(identifier_list_cwt_format(specific_status_list["identifier_list"], country, cfgservice.service_url
            + f"identifier_list/{country}/{doctype}/{rand}"))

    specific_status_list.update(
        {
            "identifier_list_uri": cfgservice.service_url
            + f"identifier_list/{country}/{doctype}/{rand}"
        }
    )


def load_list(uri):
    """
    Loads a list from disk

    Args:
        uri (str): uri pointing to the status list to load
    
    Returns:
        dict: The loaded list
    """

    parsed_uri = urlparse(uri)
    path = parsed_uri.path

    folder_path = f"{cfgservice.status_list_dir}{path}/full_list.json"

    with open(folder_path, "r") as json_file:
        temp_list = json.load(json_file)

    temp_list["token_status_list"] = IssuerStatusList.load(
        temp_list["token_status_list"]
    )

    return temp_list


def take_index_list(country,doctype, expiry_date):
    """
    Takes a new index/id from list

    Args:
        country (str): country code 
        doctype (str): doctype of the attestation
        expiry_date (str): expiry date of the attestation
    
    Returns:
        str: The index/id
    """

    global status_list

    if country not in status_list:
        status_list.update({country:{}})
    
    if doctype not in status_list[country]:
        status_list[country].update(
            {
                doctype: {
                    "token_status_list": IssuerStatusList.new(
                        1, cfgservice.token_status_list_size, "random"
                    ),
                    "identifier_list": {},
                    "expires": expiry_date,
                    "rand": str(uuid4()),
                }
            }
        )

    try:
        index = status_list[country][doctype]["token_status_list"].allocator.take()

        if status_list[country][doctype]["expires"] is None:
            status_list[country][doctype]["expires"] = expiry_date
        else:
            new_exp = datetime.strptime(expiry_date, '%Y-%m-%d')
            current_exp = datetime.strptime(status_list[country][doctype]["expires"], '%Y-%m-%d')
            if new_exp > current_exp:
                status_list[country][doctype]["expires"] = expiry_date
        
        print("\nStatus List Expiry Changed to: ", status_list[country][doctype]["expires"], flush=True)

        dump_list(status_list[country][doctype], country, doctype)
    except NoMoreIndices as e:
        dump_list(status_list[country][doctype], country, doctype)
        status_list = {}
        new_list(country, doctype)
        index = status_list[country][doctype]["token_status_list"].allocator.take()
        dump_list(status_list[country][doctype], country, doctype)

    # status_list[doctype]["identifier_list"].update({str(index): {"status": 0}})
    # print(status_list)
    return index


def generate_StatusListInfo(country,doctype, expiry_date):
    """
    Generates the structure sent to the issuer

    Args:
        country (str): country code 
        doctype (str): doctype of the attestation
        expiry_date (str): expiry date of the attestation

    Returns:
        dict: structure to pass to the issuer
    """

    index = take_index_list(country,doctype, expiry_date)

    status_list_uri = status_list[country][doctype]["status_list_uri"]
    identifier_list_uri = status_list[country][doctype]["identifier_list_uri"]


    StatusListInfo = {
        "status_list": {
            "uri": status_list_uri,
            "idx": index,
        },
        "identifier_list": {
            "uri": identifier_list_uri,
            "id": str(index),
        },
    }

    return StatusListInfo

#in case where status list is still the same
def update_status_list(country,doctype,id, index):
    print("\nRevoking country: ", country)
    print("\nRevoking doctype: ", doctype)
    print("\nRevoking ID: ", id)

    if country in status_list and doctype in status_list[country] and status_list[country][doctype]["rand"] == id:
        status_list[country][doctype]["token_status_list"].status_list.set(index, 1)

        if "identifier_list" in status_list[country][doctype]:
            status_list[country][doctype]["identifier_list"].update({str(index): 1})