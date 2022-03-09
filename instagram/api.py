import json
import random
import struct
import datetime
import binascii
import time
from typing import List

import requests
import re
import pickle
import base64

# pip install pycryptodomex
from Cryptodome import Random
from Cryptodome.Cipher import AES

# pip install PyNaCl
from nacl.public import PublicKey, SealedBox

from . import query_hash, exceptions
from .exceptions import InstagramChallengeRequiredException, InstagramProfileDoesntExists


class Instagram:
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' \
                 '(KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36'
    ig_app_id = '936619743392459'

    def __init__(self, new_session: bool = True):
        self.session: requests.Session = requests.session()
        self.session.headers['user-agent'] = self.user_agent

        self.csrf_token = None
        self.key_id = None
        self.public_key = None
        self.encryption_version = 0
        self.roll_out_hash = None
        self.ig_www_claim = '0'

        if new_session:
            self.construct_data()

    def get_shared_data(self):
        shared_data = self.session.get('https://www.instagram.com/data/shared_data/')
        self.update_csrf_token_from_headers(shared_data.headers)
        return shared_data.json()

    def get_headers(self):
        return {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'x-csrftoken': self.csrf_token,
            'x-ig-app-id': self.ig_app_id,
            'x-ig-www-claim': self.ig_www_claim,
            'x-requested-with': 'XMLHttpRequest'
        }

    def construct_data(self):
        shared_data = self.get_shared_data()
        self.csrf_token = shared_data['config']['csrf_token']
        self.key_id = shared_data['encryption']['key_id']
        self.encryption_version = shared_data['encryption']['version']
        self.public_key = shared_data['encryption']['public_key']
        self.roll_out_hash = shared_data['rollout_hash']

    def export_credential(self):
        cookies = base64.b64encode(pickle.dumps(self.session.cookies)).decode()
        credential = f'{self.csrf_token}:{self.roll_out_hash}:{self.ig_www_claim}:{cookies}'
        return credential

    def import_credential(self, credential):
        self.csrf_token, self.roll_out_hash, self.ig_www_claim, base64_cookies = credential.split(':')
        cookies = pickle.loads(base64.b64decode(base64_cookies.encode()))
        self.session.cookies.update(cookies)

    @staticmethod
    def encrypt_password(key_id, pub_key, password, version=10):
        key = Random.get_random_bytes(32)
        iv = bytes([0] * 12)

        time = int(datetime.datetime.now().timestamp())

        aes = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)
        aes.update(str(time).encode('utf-8'))
        encrypted_password, cipher_tag = aes.encrypt_and_digest(password.encode('utf-8'))

        pub_key_bytes = binascii.unhexlify(pub_key)
        seal_box = SealedBox(PublicKey(pub_key_bytes))
        encrypted_key = seal_box.encrypt(key)

        encrypted = bytes([1,
                           key_id,
                           *list(struct.pack('<h', len(encrypted_key))),
                           *list(encrypted_key),
                           *list(cipher_tag),
                           *list(encrypted_password)])
        encrypted = base64.b64encode(encrypted).decode('utf-8')

        return f'#PWD_INSTAGRAM_BROWSER:{version}:{time}:{encrypted}'

    def login(self, username, password, query_params=None, opt_into_one_tap=False):
        enc_password = self.encrypt_password(
            key_id=int(self.key_id),
            pub_key=self.public_key,
            password=password,
            version=self.encryption_version
        )

        resp = self.session.post(
            url='https://www.instagram.com/accounts/login/ajax/',
            headers={
                'content-type': 'application/x-www-form-urlencoded',
                'x-csrftoken': self.csrf_token,
                'x-ig-app-id': self.ig_app_id,
                'x-instagram-ajax': self.roll_out_hash,
                'x-ig-www-claim': self.ig_www_claim
            },
            data={
                'username': username,
                'enc_password': enc_password,
                'queryParams': '{}' if query_params is None else json.dumps(query_params),
                'optIntoOneTap': opt_into_one_tap
            }
        )

        self.update_csrf_token_from_headers(resp.headers)

        login_info = self.__validate_login(resp)

        if login_info.authenticated:
            self.ig_www_claim = resp.headers['x-ig-set-www-claim']

        return login_info

    @staticmethod
    def __validate_login(resp):
        try:
            login_info = LoginInfo(**resp.json())
        except json.JSONDecodeError:
            login_info = LoginInfo()

        if resp.status_code == 400 and login_info.message == 'checkpoint_required':
            raise InstagramChallengeRequiredException(
                'Challenge required, login to your account from browser '
                'and open this link https://instagram.com' + login_info.checkpoint_url
            )

        return login_info

    def logout(self):
        # don't know why, but it needs to update the csrf token before sending post request to logout
        self.csrf_token = self.get_shared_data()['config']['csrf_token']

        resp = self.session.post(
            url='https://www.instagram.com/accounts/logout/ajax/',
            headers={
                'content-type': 'application/x-www-form-urlencoded',
                'x-csrftoken': self.csrf_token,
                'x-ig-app-id': self.ig_app_id,
                'x-instagram-ajax': self.roll_out_hash,
                'x-ig-www-claim': self.ig_www_claim
            },
            data={
                'one_tap_app_login': 0
            }
        )

        return resp.json()

    def graphql_query(self, query_hash, variables):
        resp = self.session.get(
            url="https://www.instagram.com/graphql/query/",
            params={
                'query_hash': query_hash,
                'variables': json.dumps(variables)
            },
            headers={
                'accept': '*/*',
                'accept-language': 'en-US,en;q=0.9',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'x-csrftoken': self.csrf_token,
                'x-ig-app-id': self.ig_app_id,
                'x-ig-www-claim': self.ig_www_claim,
                'x-requested-with': 'XMLHttpRequest'
            }
        )

        self.update_csrf_token_from_headers(resp.headers)

        return resp.json()

    def profile(self, username):
        return User(self, username=username)

    def media(self, shortcode):
        return GraphMedia(self, shortcode=shortcode)

    def update_csrf_token_from_headers(self, headers):
        try:
            csrf_token = re.findall(r'csrftoken=([a-zA-Z0-9]+);', headers['Set-Cookie'])
        except KeyError:
            return

        if csrf_token:
            self.csrf_token = csrf_token[0]

    def __del__(self):
        if self.session:
            self.session.close()

        del self.session


class LoginInfo:
    """
    object that holds login information
    """
    errors: List = []
    error_type: str = None
    status: str = None
    user: bool = False
    user_id: str = None
    authenticated: bool = False
    one_tap_prompt: str = None
    message: str = None
    checkpoint_url: str = None
    lock: str = None
    flow_render_type: str = None

    def __init__(self, **kwargs):
        for i, v in kwargs.items():
            if i not in ['userId', 'oneTapPrompt']:
                setattr(self, i, v)

        self.user_id = kwargs.get('userId', None)
        self.one_tap_prompt = kwargs.get('oneTapPrompt', False)

    def __str__(self):
        return str(self.__dict__)


class User:
    id: str = None
    blocked_by_viewer: bool = False
    restricted_by_viewer: bool = False
    country_block: bool = False
    external_url: str = None
    external_url_linkshimmed: str = None
    fbid: str = None
    followers_count: int = 0
    following_count: int = 0
    mutual_followers_count: int = 0
    timeline_media_count: int = 0
    ig_tv_videos_count: int = 0
    saved_media_count: int = 0
    media_collections_count: int = 0
    full_name: str = None
    has_ar_effects: bool = False
    has_clips: bool = False
    has_guides: bool = False
    has_channel: bool = False
    has_blocked_viewer: bool = False
    highlight_reel_count: int = 0
    has_requested_viewer: bool = False
    is_bussiness_account: bool = False
    is_joined_recently: bool = False
    business_category_name: str = None
    overal_category_name: str = None
    category_enum: str = None
    category_name: str = None
    is_private: bool = False
    is_verified: bool = False
    profile_pic_url: str = None
    profile_pic_url_hd: str = None
    requested_by_viewer: bool = False
    should_show_category: bool = False
    username: str = None
    connected_fb_page: str = None
    edge: dict = {}

    def __init__(self, ig: Instagram, **kwargs):
        self.ig = ig
        for i, v in kwargs.items():
            if not i.startswith('edge'):
                setattr(self, i, v)

    def fetch_profile(self):
        resp = self.ig.session.get(f'https://instagram.com/{self.username}/?__a=1')
        raw_data = resp.json()
        try:
            data = raw_data['graphql']['user']
        except KeyError:
            raise InstagramProfileDoesntExists

        for i, v in data.items():
            if not i.startswith('edge'):
                setattr(self, i, v)
            else:
                self.edge.update({i: v})

        self.followers_count = data['edge_followed_by']['count']
        self.following_count = data['edge_follow']['count']
        self.mutual_followers_count = data['edge_mutual_followed_by']['count']
        self.ig_tv_videos_count = data['edge_felix_video_timeline']['count']
        self.timeline_media_count = data['edge_owner_to_timeline_media']['count']
        self.saved_media_count = data['edge_saved_media']['count']
        self.media_collections_count = data['edge_media_collections']['count']

        return raw_data

    def followers(self, fetch_size=24, include_reel=False, fetch_mutual=False, end_cursor=None):
        if self.id is None:
            self.fetch_profile()

        has_next = True

        while has_next:
            variables = {
                'id': self.id,
                'include_reel': include_reel,
                'fetch_mutual': fetch_mutual,
                'first': fetch_size
            }

            if end_cursor is not None:
                variables.update({'after': end_cursor})

            data = self.ig.graphql_query(
                query_hash=query_hash.USER_FOLLOWER,
                variables=variables
            )

            has_next = data['data']['user']['edge_followed_by']['page_info']['has_next_page']
            end_cursor = data['data']['user']['edge_followed_by']['page_info']['end_cursor']

            for node in data['data']['user']['edge_followed_by']['edges']:
                yield node['node'], end_cursor

            time.sleep(random.randint(10, 20))

    @property
    def following(self):
        pass

    @property
    def user_timeline_media(self):
        pass

    @property
    def ig_tv_videos(self):
        pass

    @property
    def saved_media(self):
        pass


class UserTimelineMedia:

    def __init__(self, user: User, user_timeline_media):
        self.user = user
        self.count = user_timeline_media['page_info']['count']

    def items(self, fetch_size=12, end_cursor=None):
        has_next = True
        end_cursor = end_cursor

        while has_next:
            variables = {
                'id': self.user.id,
                'first': fetch_size
            }

            if end_cursor is not None:
                variables.update({'after': end_cursor})

            resp = self.user.ig.graphql_query(
                query_hash=query_hash.USER_TIMELINE_MEDIA,
                variables=variables
            )

            data = resp.json()

            if resp.status_code != 200:
                raise exceptions.InstagramGenericErrorsException(data['message'])

            has_next = data['data']['user']['edge_owner_to_timline_media']['page_info']['has_next']
            end_cursor = data['data']['user']['edge_owner_to_timline_media']['page_info']['end_cursor']

            for media in data['data']['user']['edge_owner_to_timline_media']['edges']:
                yield media


class GraphMedia:

    def __init__(self, ig: Instagram, shortcode):
        self.ig = ig
        self.shortcode = shortcode
        self.data = self.fetch_data()

    def fetch_data(self):
        data = self.ig.graphql_query(
            query_hash=query_hash.MEDIA,
            variables={
                'shortcode': self.shortcode,
                'child_comment_count': 1,
                'fetch_comment_count': 1,
                'parent_comment_count': 1,
                'has_threaded_comments': True,
            }
        )

        return data

    @property
    def id(self):
        return self.data['data']['shortcode_media']['id']

    @property
    def status(self):
        return self.data['data']['status']

    def add_comment(self, comment_text, replied_to_comment_id=None):
        headers = self.ig.get_headers()
        headers.update({'content-type': 'application/x-www-form-urlencoded'})

        resp = self.ig.session.post(
            url=f"https://www.instagram.com/web/comments/{self.id}/add/",
            headers=self.ig.get_headers(),
            data={
                'comment_text': comment_text,
                'replied_to_comment_id': replied_to_comment_id
            }
        )

        self.ig.update_csrf_token_from_headers(resp.headers)

        return resp.json()

    def likes(self, fetch_size=24, include_reel=False, end_cursor=None):
        has_next = True

        while has_next:
            variables = {
                'shortcode': self.shortcode,
                'include_reel': include_reel,
                'first': fetch_size
            }

            if end_cursor is not None:
                variables.update({'after': end_cursor})

            data = self.ig.graphql_query(
                query_hash=query_hash.MEDIA_LIKES,
                variables=variables
            )

            has_next = data['data']['shortcode_media']['edge_liked_by']['page_info']['has_next_page']
            end_cursor = data['data']['shortcode_media']['edge_liked_by']['page_info']['end_cursor']

            for node in data['data']['shortcode_media']['edge_liked_by']['edges']:
                yield node['node'], end_cursor

            time.sleep(random.randint(10, 20))
