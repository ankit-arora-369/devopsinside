import boto3
import dotenv
import os
import requests
import json
from datetime import datetime, timedelta

# load the environment variables
dotenv.load_dotenv()

# create boto3 client for ec2
client = boto3.client('ec2',
                      region_name=os.getenv('AWS_REGION'),
                      aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                      aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'))

# create boto3 client for cloudtrail
ct_client = boto3.client('cloudtrail')

# create a list where the volume ids of unused volumes will be stored
volumes_to_list = list()

## create a list where the volume ids of unused volumes will be stored
detached_volumes_to_list = list()

# Define number of days here.
x_days_threshold = 30

# Flock token
flock_token = "<enter flock token here>"

# call describe_volumes() method of client to get the details of all ebs volumes in given region
# if you have large number of volumes then get the volume detail in batch by using nextToken and process accordingly
volume_detail = client.describe_volumes()

## start and end date vars for aws cloudtrail
date_diff = datetime.now() - timedelta(days=90)
start_date = datetime(date_diff.year, date_diff.month, date_diff.day)
date_today = datetime.now()
end_date = datetime(date_today.year, date_today.month, date_today.day)


## Function to calculate and get age of disk.
def check_if_created_object_date_less_than_x_days(x_days):
    x_day = x_days.replace(tzinfo=None)
    now = datetime.now()
    differ = now - x_day
    diff_in_days = str(differ).split()
    return int(diff_in_days[0])


## Function to get string and sending to flock channel.
def get_and_send_message_to_flock_channel(msg):
    url = flock_token
    message = msg
    flock_data = {
        "flockml": message
    }

    headers = {'Content-Type': "application/json"}
    response = requests.post(url, data=json.dumps(flock_data), headers=headers)
    if response.status_code != 200:
        raise Exception(response.status_code, response.text)


## Evaluating if disk is not attached and age of the disk is > x_days
if volume_detail['ResponseMetadata']['HTTPStatusCode'] == 200:
    for each_volume in volume_detail['Volumes']:
        if len(each_volume['Attachments']) == 0 and each_volume['State'] == 'available' and check_if_created_object_date_less_than_x_days(each_volume['CreateTime']) > x_days_threshold:
            volumes_to_list.append(each_volume['VolumeId'])
            response = ct_client.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'ResourceName',
                        'AttributeValue': each_volume['VolumeId']
                    },
                ],
                StartTime=start_date,
                EndTime=end_date,
                MaxResults=1,
            )

            events_details = response['Events']

            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                for event in events_details:
                    if event['EventName'] == "DetachVolume" and check_if_created_object_date_less_than_x_days(event['EventTime']) > x_days_threshold:
                        detached_volumes_to_list.append(each_volume['VolumeId'])


flock_output = ("<flockml><b>ENV: STAGING</b></flockml>" +
             "<br/><br/> <flockml><b>AWS DiskUtilization ALERT!!!</b></flockml>" +
             "<br/><br/> <flockml><b>Total number of unattached disks found: </b></flockml>" + str(len(volumes_to_list)) +
             "<br/><br/> <flockml><b>Total number of disks that didn\'t get attached in last </b></flockml>" + f"<flockml><b> {str(x_days_threshold)} </b></flockml>" + "<flockml><b> days : </b></flockml>" + str(len(detached_volumes_to_list)) +
             "<br/><br/> <flockml><b>Volume id of disks that didn\'t get attached in last </b></flockml><br/>" + f"<flockml><b> {str(x_days_threshold)} </b></flockml>" + "<flockml><b> days : </b></flockml>" + str(detached_volumes_to_list))


if detached_volumes_to_list == []:
    print("No disks found that didn\'t get attach in last " + x_days_threshold + " days")
else:
    get_and_send_message_to_flock_channel(flock_output)

