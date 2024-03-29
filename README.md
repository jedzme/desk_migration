
## January 11, 2024

## Project: FreshDesk to ZenDesk Tickets  Migration

## Description
This project migrates customer service ticketing system data from [FreshDesk](https://www.freshworks.com/freshdesk/) to [ZenDesk](https://www.zendesk.com/).

![solutions](solutions.jpg)

## Installation and Dependencies

### Overall Config
1. Go to config.ini and change value for **solution** (either **a** or **b**). Refer to Diagram above for the workflow
2. Please take a look at **csv_column_to_zendesk_ticket_mapping** map, the metadata mapping from CSV row to a FreshDesk ticket. Modify this mapping as necessary.

#### Data Files
The following data files are needed for this program (if solution B will be used):  
- tickets_data.csv

### FreshDesk
Retrieve an **API Key** to use for REST API calls.
1. **Log in** to your **Support/Customer Portal**. 
2. **Click** on your **profile picture on** the top right corner of your portal
3. Go to **Profile Settings** page.
4. Your API key will be available below the change password section to your right. Look for **View API Key** button.
5. Update FreshDesk **apikey** value in _config.ini_ file
6.  Update the urls and paths as necessary

Note: The number of API calls per minute is based on the account's plan. Trial accounts/users have a "Rate Limit" when calling the REST APIs; see [Rate Limit](https://developers.freshdesk.com/api/#introduction) for more information.

### ZenDesk
Generate an **API Key** to use for REST API calls.
1. Login as admin and go to **Admin Center**. Refer [here](https://support.zendesk.com/hc/en-us/articles/4581766374554#topic_hfg_dyz_1hb)
2. Go to **Apps and Integrations** >> **Zendesk API**.
3. Click **Add API token** button to generate an API token. 
4. Fillup the **API token description**. 
5. Copy the API token by clicking **Copy** button.
6. Click **Save** button to save your API token.
7. Update the ZenDesk **api_key** value in _config.ini_ file using the copied API token on step 5.
8. Update the urls and paths as necessary

Note: ZenDesk also has [Rate Limits](https://developer.zendesk.com/api-reference/introduction/rate-limits/) on the API calls.

### Running migrate.py
1. Download and install [python](https://www.python.org/downloads/)
2. Download and install [pip](https://pip.pypa.io/en/stable/installation/)
3. Create your local environment:  
    ```$ python -m venv <your_environment_name>```
4. Activate your local environment:  
    ```$ <you_environment_name>\Scripts\activate```
5. Install dependencies from _requirements.txt_ :  
    ```$ pip install -r requirements.txt```
6. Run _migrate.py_  
    ```$ python migrate.py```

## References

### FreshDesk API
Freshdesk's APIs belong to the Representational State Transfer (REST) category. They allow you to perform 'RESTful' operations such as reading, modifying, adding or deleting data from your helpdesk. The APIs also support Cross-Origin Resource Sharing (CORS).
Current FreshDesk API version is v2, for more information see API documentation [here](https://developers.freshdesk.com/api/).

### ZenDesk API
Zendesk’s APIs are organized around REST. See API documentation [here](https://developer.zendesk.com/api-reference).