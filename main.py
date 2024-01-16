import configparser
import logging
import logging.handlers
import logging.config as logconfig
import requests
import json
import csv

# init logger
logconfig.fileConfig(fname='logconfig.ini', disable_existing_loggers=False)
#FORMAT = '[%(levelname)s] - PID %(process)d - %(asctime)s - %(name)s - %(message)s'
#logging.basicConfig(filename='logs.log', format=FORMAT, level=logging.DEBUG)
logger = logging.getLogger(__name__)

# init config
config = configparser.ConfigParser()
logger.debug('reading config.ini')
config.read('config.ini')
logger.debug('config.ini sections: {}'.format(config.sections()))


""" retrieving properties by section name inside config.ini
    properties are returned through key-value pair in a dictionary
"""
def get_config_section(section):
    dictionary = {}
    keys = config.options(section)
    for key in keys:
        try:
            dictionary[key] = config.get(section, key)
            if dictionary[key] == -1:
                logger.info("skiping key: %s" % key)
        except:
            logger.error("exception on key:%s!" % key)
            dictionary[key] = None
    return dictionary

def call_http_endpoint(method, url, queryparam=None, payload=None, auth=None, timeout=5, headers=None):
    r = None
    match str(method).lower():
        case "get":
            r = requests.get(url=url, params=queryparam, auth=auth, timeout=timeout)
        case "post":
            r = requests.post(url=url, json=payload, timeout=timeout, headers=headers, auth=auth)
        case "put":
            logger.info("implement me when needed: callHTTPEndpoint() >> PUT")
            exit()
        case _ :
            logger.error('unsupported HTTP method: {}'.format(method))
            exit()
    return r

def fd_get_tickets(fd_configs):
    fd_url = fd_configs.get("url")
    fd_get_tickets_path = fd_configs.get("get_tickets_path")
    fd_apikey = fd_configs.get("apikey")

    """
        GET https://<freshdesk_host_url>/api/v2/tickets
        Basic Authentication only needs the API Key as username, leave the password blank or any string
        see "Authentication" section in https://developers.freshdesk.com/api/
    """
    response = call_http_endpoint("GET", fd_url+fd_get_tickets_path, auth=(fd_apikey, None))
    status_code = response.status_code
    if(status_code==200):
        json_data = json.dumps(response.json(), indent=2, sort_keys=True)

    return status_code, json_data

def zd_post_create_ticket(zd_configs, payload, headers=None):
    zd_url = zd_configs.get("url")
    zd_post_create_ticket_path = zd_configs.get("post_create_ticket_path")
    zd_apikey = zd_configs.get("apikey")
    zd_username = zd_configs.get("username")
    """
        GET https://<zendesk_host_url>/api/v2/tickets
        Basic Authentication needs both username and password
        username is <email_address>/token (e.g johndoe@gmail.com/token)
        password is the API Key
        see "API token" section in https://developer.zendesk.com/api-reference/introduction/security-and-auth/#api-token
    """
    response = call_http_endpoint("POST", zd_url+zd_post_create_ticket_path, auth=(zd_username, zd_apikey), headers=headers, payload=payload)
    status_code = response.status_code
    json_data = json.dumps(response.json(), indent=2, sort_keys=True)

    return status_code, json_data

def zd_get_list_ticket_fields(zd_configs):
    zd_url = zd_configs.get("url")
    zd_get_list_ticket_fields_path = zd_configs.get("get_list_ticket_fields_path")
    zd_apikey = zd_configs.get("apikey")
    zd_username = zd_configs.get("username")
    """
        GET https://<zendesk_host_url>/api/v2/ticket_fields?locale=<string>&creator=<boolean>
        Basic Authentication needs both username and password
        username is <email_address>/token (e.g johndoe@gmail.com/token)
        password is the API Key
        see "API token" section in https://developer.zendesk.com/api-reference/introduction/security-and-auth/#api-token
    """
    response = call_http_endpoint("GET", zd_url+zd_get_list_ticket_fields_path, auth=(zd_username, zd_apikey))
    status_code = response.status_code
    if(status_code==200):
        json_data = json.dumps(response.json(), indent=2, sort_keys=True)

    return status_code, json_data

# TODO: needs the full implementation
def solution_a(fd_configs, zd_configs):
    
    fd_sc, fd_jd = fd_get_tickets(fd_configs)
    # logger.info(fd_sc)
    # logger.info(fd_jd)

    zd_sc, zd_jd = zd_get_list_ticket_fields(zd_configs)
    # logger.info(zd_sc)
    # logger.info(zd_jd)

def convert_to_zendesk_status_category(zd_configs, fd_status):
    fd_status = fd_status.lower()
    
    #new_zd_status_category = zd_configs.get("new_zendesk_status_category_freshdesk_status").split(",")
    open_zd_status_category = zd_configs.get("open_zendesk_status_category_freshdesk_status").split(",")
    pending_zd_status_category = zd_configs.get("pending_zendesk_status_category_freshdesk_status").split(",")
    hold_zd_status_category = zd_configs.get("hold_zendesk_status_category_freshdesk_status").split(",")
    solved_zd_status_category = zd_configs.get("solved_zendesk_status_category_freshdesk_status").split(",")

    if(fd_status in solved_zd_status_category):
        return 'solved'
    elif(fd_status in pending_zd_status_category):
        return 'pending'
    elif(fd_status in hold_zd_status_category):
        return 'hold'
    elif(fd_status in open_zd_status_category):
        return 'open'
    else:
        return 'new'

def get_zd_custom_status_id(zd_configs, fd_status):
    match fd_status.lower():
        case 'new':
            return zd_configs.get('new_custom_status_id')
        case 'open':
            return zd_configs.get('open_custom_status_id')
        case 'pending':
            return zd_configs.get('pending_custom_status_id')
        case 'waiting on customer':
            return zd_configs.get('waiting_on_customer_custom_status_id')
        case 'waiting on third party':
            return zd_configs.get('waiting_on_third_party_custom_status_id')
        case 'closed':
            return zd_configs.get('closed_custom_status_id')
        case 'resolved':
            return zd_configs.get('solved_custom_status_id')
        case _:
            return zd_configs.get('new_custom_status_id')

def get_zd_ticket_type(zd_configs, fd_ticket_type):
    match fd_ticket_type.lower().strip():
        case 'feature request':
            return zd_configs.get('feature_request')
        case 'incident':
            return zd_configs.get('incident')
        case 'ingestion':
            return zd_configs.get('ingestion')
        case 'problem / bug' | 'problem/bug':
            return zd_configs.get('problem_bug')
        case 'question':
            return zd_configs.get('question')
        case _:
            return ''

# TODO: needs further testing, checking caveats (rate limit: https://developer.zendesk.com/api-reference/ticketing/introduction/#rate-limits)
# current expected number of tickets to be migrated to zendesk: 16K
# might need some delays; also need to catch errors and do retry maybe?
def solution_b(zd_configs, csv_file_path):
    # zd_sc, zd_jd = zd_get_list_ticket_fields(zd_configs)
    # logger.info(zd_sc)
    # logger.info(zd_jd)

    ticket_type_custom_field_id= zd_configs.get("ticket_type_custom_field_id")
    freshdesk_ticket_id_custom_field_id= zd_configs.get("freshdesk_ticket_id_custom_field_id")

    with open(csv_file_path) as f:
        reader = csv.DictReader(f, delimiter=',')
        for row in reader:
            ticket_id = row['Ticket ID']
            subject = row['Subject']
            status = row['Status']
            ticket_type = row['Type']
            priority = row['Priority'] 
            #logger.debug("Ticket ID: {} || Subject: {} || Status: {} || Type: {} || Priority: {}".format(ticket_id, subject, status, ticket_type, priority) )

            if(ticket_id.strip() == '' or subject.strip()== ''):
                continue

            ticket = {
                "ticket": {
                    "status": convert_to_zendesk_status_category(zd_configs, status),
                    "custom_status_id": get_zd_custom_status_id(zd_configs, status),
                    "subject": subject,
                    "tags": [
                        "migrated_from_freshdesk"
                    ], 
                    "priority": 'normal' if priority == 'Medium' else priority.lower(),
                    "custom_fields": [
                        {"id": freshdesk_ticket_id_custom_field_id, "value": ticket_id},
                        {"id": ticket_type_custom_field_id, "value": get_zd_ticket_type(zd_configs, ticket_type)}
                    ],
                    "description": "This ticket is migrated from FreshDesk." #TODO: description is a required parameter, please ask where to pull this data from
                }
            }

            headers=None
            # https://developer.zendesk.com/api-reference/ticketing/introduction/#idempotency
            if(zd_configs.get("enable_idempotency").lower() == 'true'):
                logger.debug("idempotency is enabled")
                headers = {"Idempotency-Key": ticket_id}
            
            status_code, json_data = zd_post_create_ticket(zd_configs, ticket, headers)
            logger.debug("\nticket id: {} => publish result: status_code={} \n{}".format(ticket_id, status_code, json_data))

def main():
    settings = get_config_section("settings")
    solution = settings.get("solution")

    match solution:
        case "a":
            fd_configs = get_config_section("freshdesk")
            zd_configs = get_config_section("zendesk")
            solution_a(fd_configs, zd_configs)
        case "b":
            csv_file_path = settings.get("csv_file_path")
            zd_configs = get_config_section("zendesk")
            solution_b(zd_configs, csv_file_path)
        case _:
            logger.error("unsupported value for settings >> solution")
            exit()

if __name__ == "__main__":
    main()