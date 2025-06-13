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
import json
import shutil
import sys
import threading
import time
from datetime import datetime, timedelta
import os
from app.config_service import ConfService as cfgservice
from app.status_list_format import cwt_format, jwt_format
from app.identifier_list_format import (
    identifier_list_cwt_format,
    identifier_list_jwt_format,
)

#current_dir = os.path.dirname(os.path.abspath(__file__))
#sys.path.append(os.path.join(current_dir, '..', 'token-status-list-py'))
from token_status_list import IssuerStatusList



def renew_lists():
    """
    Renews all the status lists that haven't expired
    """
    base_dir = cfgservice.status_list_dir
    backup_dir = cfgservice.backup_dir
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Traverse subdirectories
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file == "full_list.json":
                file_path = os.path.join(root, file)
                dir_path = root

                try:
                    with open(file_path, "r") as json_file:
                            temp_list = json.load(json_file)
                except Exception as e:
                    cfgservice.app_logger.info(f"An error occurred while processing the file: {file_path}", exc_info=True)
                    continue
                
                if "status_list_uri" not in temp_list or "identifier_list_uri" not in temp_list:
                    cfgservice.app_logger.info(f"Uris don't exist: {file_path}")
                    continue

                expires_date = datetime.strptime(temp_list["expires"], "%Y-%m-%d")

                if expires_date < datetime.now():
                    cfgservice.app_logger.info(f'Removing {dir_path} as it is expired.')
                    shutil.rmtree(dir_path)
                    continue

                relative_path = os.path.relpath(root, base_dir)
                copy_dir = os.path.join(backup_dir, timestamp, relative_path)
                os.makedirs(copy_dir, exist_ok=True)

                if "token_status_list" in dir_path:
                    list_type = "token_status_list"

                    shutil.copy(dir_path + "/token_status_list.jwt",  copy_dir)
                    shutil.copy(dir_path + "/token_status_list.cwt",  copy_dir)
                    shutil.copy(dir_path + "/full_list.json",  copy_dir)

                    temp_list["token_status_list"] = IssuerStatusList.load(temp_list["token_status_list"])
                    #temp_list[list_type] = temp_list[list_type].dump()

                    jwt_file_path = os.path.join(dir_path, "token_status_list.jwt")
                    with open(jwt_file_path, "w") as f:
                        f.write(jwt_format(temp_list["token_status_list"], temp_list["country"],temp_list["status_list_uri"]))
                    
                    cwt_file_path = os.path.join(dir_path,"token_status_list.cwt")
                    with open(cwt_file_path, "w") as f:
                        f.write(cwt_format(temp_list["token_status_list"], temp_list["country"],temp_list["status_list_uri"]))

                elif "identifier_list" in dir_path:
                    list_type = "identifier_list"

                    shutil.copy(dir_path + "/identifier_list.jwt",  copy_dir)
                    shutil.copy(dir_path + "/identifier_list.cwt",  copy_dir)
                    shutil.copy(dir_path + "/full_list.json",  copy_dir)

                    jwt_file_path = os.path.join(dir_path, "identifier_list.jwt")
                    with open(jwt_file_path, "w") as f:
                        f.write(identifier_list_jwt_format(temp_list["identifier_list"], temp_list["country"],temp_list["identifier_list_uri"]))

                    cwt_file_path = os.path.join(dir_path, "identifier_list.cwt")
                    with open(cwt_file_path, "w") as f:
                        f.write(identifier_list_cwt_format(temp_list["identifier_list"], temp_list["country"],temp_list["identifier_list_uri"]))


def daily_renewal():
    while True:
        now = datetime.now()

        if now.hour < 12:
            next_execution = now.replace(hour=12, minute=0, second=0, microsecond=0)
        else:
            next_execution = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)

        #next_execution = now + timedelta(minutes=1)
        
        seconds_until_execution = (next_execution - now).total_seconds()

        cfgservice.app_logger.info(f"Renewing in {int(seconds_until_execution // 3600):02}:{int((seconds_until_execution % 3600) // 60):02}:{round(seconds_until_execution % 60):02}")

        time.sleep(seconds_until_execution)

        cfgservice.app_logger.info("Renewing Revocation Lists")

        
        try:
            renew_lists()
        except Exception as e:
            print(f"Error: {e}")



def start_renewal_thread():
    task_thread = threading.Thread(target=daily_renewal, daemon=True)
    task_thread.start()

