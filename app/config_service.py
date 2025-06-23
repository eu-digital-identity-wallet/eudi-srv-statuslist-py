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
import logging
from logging.handlers import TimedRotatingFileHandler
import os


class ConfService:

    service_url = "https://issuer.eudiw.dev/"
    # Token status list size (Bytes)
    token_status_list_size = 10000

    status_list_dir = "/var/opt/status_lists"

    backup_dir = "/var/opt/status_list_backup"

    countries = {
        "FC":{
            "privKey":"/etc/eudiw/pid-issuer/privKey/PID-DS-0001_UT.pem",
            "privkey_passwd": None,
            "cert":"/etc/eudiw/pid-issuer/cert/PID-DS-0001_UT_cert.der"
        },
        "PT":{
            "privKey":"/etc/eudiw/pid-issuer/privKey/PID-DS-0001_PT.pem",
            "privkey_passwd": None,
            "cert":"/etc/eudiw/pid-issuer/cert/PID-DS-0001_PT_cert.der"
        },
        "EE":{
            "privKey":"/etc/eudiw/pid-issuer/privKey/PID-DS-0001_EE.pem",
            "privkey_passwd": None,
            "cert":"/etc/eudiw/pid-issuer/cert/PID-DS-0001_EE_cert.der"
        },
        "CZ":{
            "privKey":"/etc/eudiw/pid-issuer/privKey/PID-DS-0001_CZ.pem",
            "privkey_passwd": None,
            "cert":"/etc/eudiw/pid-issuer/cert/PID-DS-0001_CZ_cert.der"
        },
        "NL":{
            "privKey":"/etc/eudiw/pid-issuer/privKey/PID-DS-0001_NL.pem",
            "privkey_passwd": None,
            "cert":"/etc/eudiw/pid-issuer/cert/PID-DS-0001_NL_cert.der"
        },
        "LU":{
            "privKey":"/etc/eudiw/pid-issuer/privKey/PID-DS-0001_LU.pem",
            "privkey_passwd": None,
            "cert":"/etc/eudiw/pid-issuer/cert/PID-DS-0001_LU_cert.der"
        },
        "EU":{
            "privKey":"/etc/eudiw/pid-issuer/privKey/PID-DS-0001_EU.pem",
            "privkey_passwd": None,
            "cert":"/etc/eudiw/pid-issuer/cert/PID-DS-0001_EU_cert.der"
        },
    }

    # ------------------------------------------------------------------------------------------------
    # LOGS

    log_dir = "/tmp/status_lists"
    # log_dir = "../../log"
    log_file_info = "status_lists.log"

    backup_count = 7

    try:
        os.makedirs(log_dir)
    except FileExistsError:
        pass

    log_handler_info = TimedRotatingFileHandler(
        filename=f"{log_dir}/{log_file_info}",
        when="midnight",  # Rotation midnight
        interval=1,  # new file each day
        backupCount=backup_count,
    )

    log_handler_info.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))

    app_logger = logging.getLogger("revocation_app_logger")
    app_logger.addHandler(log_handler_info)
    app_logger.setLevel(logging.INFO)