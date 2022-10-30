import os
import logging
import sys
import time
import json
import base64
import re

from wrapped_pytwitter_api import *

import pytwitter

if sys.version_info < (3, 7):
    # script uses functools.partial which is a pretty recent capability
    print("Python 3.7 or later required to run")
    sys.exit(-1)

LOCAL_HTTPD_SERVER_PORTS_TO_TRY = [8888, 8880, 8080, 9977, 4356, 3307]

TWITTER_CLIENT_ID = os.environ.get("TWITTER_CLIENT_ID")

logging_file_name = None

if logging_file_name is not None:
    logging.basicConfig(
        filename=logging_file_name,
        format='%(asctime)s %(name)s %(levelname)-8s %(message)s',
        level=logging.DEBUG,
        datefmt='%Y-%m-%d %H:%M:%S')
else:
    logging.basicConfig(
        format='%(asctime)s %(name)s %(levelname)-8s %(message)s',
        level=logging.DEBUG,
        datefmt='%Y-%m-%d %H:%M:%S')

# The scopes requested of the Twitter OAUTH2 API on behalf of the user that will bleach their account
twitter_api_scopes = ["tweet.read", "tweet.write", "users.read", "tweet.read",
                      "users.read", "like.write", "like.read", "follows.read",
                      "follows.write", "offline.access"]

#twitter_api_scopes = ["follows.read"]

api = WrappedPyTwitterAPI(client_id=TWITTER_CLIENT_ID, oauth_flow=True, scopes=twitter_api_scopes)
auth_details = api.OAuth2AuthenticationFlowHelper(local_ports_to_try=LOCAL_HTTPD_SERVER_PORTS_TO_TRY)
logging.info(f"Twitter OAuth2 details '{auth_details}'")

# Get details about the account. Specifically the Twitter ID for the user that authorized the app.
twitter_me = api.get_me(return_json=True)
my_twitter_id = twitter_me["data"]["id"]

twitter_me = api.get_me(return_json=True)
twitter_user_id = twitter_me["data"]["id"]

pagination_token = None
total_twitter_follows_scanned = 0

mastodon_username_regex = r"@[a-zA-Z0-9]*@[a-zA-Z0-9\.-]*"

while True:

    try:
        following_query_result = api.get_following(user_id=twitter_user_id,
                                                   return_json=True,
                                                   pagination_token=pagination_token)

        twitter_users_followed = following_query_result["data"]

        #for followed_user in twitter_users_followed:
            #print(followed_user)

        followed_users_ids = list(map(lambda user_json: user_json["id"], twitter_users_followed))

        followed_users_response = api.get_users(ids=followed_users_ids, user_fields=["description"])

        followed_users_details = followed_users_response.data

        for followed_user_detail in followed_users_details:
            total_twitter_follows_scanned += 1
            #print (f"\"{followed_user_detail.name}\" @{followed_user_detail.username} => {followed_user_detail.description}")
            mastodon_usernames = re.findall(mastodon_username_regex, followed_user_detail.description)
            if len(mastodon_usernames) > 0:
                print (f"\"{followed_user_detail.name}\" @{followed_user_detail.username} => {mastodon_usernames}")

        """
        look for @yourname@servername in profile
        
        check against mastodon followers list
        
        
        """

        if 'next_token' not in following_query_result['meta'].keys():
            break

        pagination_token = following_query_result['meta']['next_token']

    except WrappedPyTwitterAPIRateLimitExceededException:
        logging.info(
            "Twitter API rate limit exceeded. Waiting 15min. Scanned users so far {}".format(
                total_twitter_follows_scanned))
        time.sleep(900)
        continue
    except WrappedPyTwitterAPIUnauthorizedException:
        logging.info("Authentication failed. Access token may have expired")
        api.refresh_access_token()
        continue
    except WrappedPyTwitterAPIServiceUnavailableException:
            logging.info("API service unavailable. Waiting 5 seconds, resetting pagination and trying again")
            pagination_token = None
            time.sleep(5)
            continue
    except pytwitter.error.PyTwitterError as ptw:
        logging.fatal("PyTwitterError with unknown message format '{}'".format(ptw.message['status'], ptw.message))
        break
    except Exception as e:
        logging.fatal("Exception of unhandled type {}. Message is '{}'".format(type(e), e))
        # Going to break out of the loop because if the problem persists it could cause an API call to be
        # made over and over again using up the allocated requests per second allowance and forcing a 15 min wait
        break

logging.debug(f"Total scanned count {total_twitter_follows_scanned}")

