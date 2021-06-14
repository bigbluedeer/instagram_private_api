import json
import re
from socket import timeout, error as SocketError
from ssl import SSLError

from ..compat import (
    compat_urllib_request, compat_urllib_error,
    compat_http_client
)
from ..compatpatch import ClientCompatPatch
from ..errors import (
    ErrorHandler, ClientError, ClientLoginError, ClientConnectionError, ClientChallengeRequiredError
)
from ..http import MultipartFormDataEncoder

try:
    ConnectionError = ConnectionError  # pylint: disable=redefined-builtin
except NameError:  # Python 2:
    class ConnectionError(Exception):
        pass


class AccountsEndpointsMixin(object):
    """For endpoints in ``/accounts/``."""

    def login(self):
        """Login."""

        prelogin_params = self._call_api(
            'si/fetch_headers/',
            params='',
            query={'challenge_type': 'signup', 'guid': self.generate_uuid(True)},
            return_response=True)

        if not self.csrftoken:
            raise ClientError(
                'Unable to get csrf from prelogin.',
                error_response=self._read_response(prelogin_params))

        login_params = {
            'device_id': self.device_id,
            'guid': self.uuid,
            'adid': self.ad_id,
            'phone_id': self.phone_id,
            '_csrftoken': self.csrftoken,
            'username': self.username,
            'password': self.password,
            'login_attempt_count': '0',
        }

        try:
            login_response = self._call_api(
                'accounts/login/', params=login_params, return_response=True)
        except ClientChallengeRequiredError as error:
            print("challenge login required")
            login_response = self._challenge_login(error)

        if not self.csrftoken:
            raise ClientError(
                'Unable to get csrf from login.',
                error_response=self._read_response(login_response))

        login_json = json.loads(self._read_response(login_response))

        if not login_json.get('logged_in_user', {}).get('pk'):
            raise ClientLoginError('Unable to login.')

        if self.on_login:
            on_login_callback = self.on_login
            on_login_callback(self)

        # # Post-login calls in client
        # self.sync()
        # self.autocomplete_user_list()
        # self.feed_timeline()
        # self.ranked_recipients()
        # self.recent_recipients()
        # self.direct_v2_inbox()
        # self.news_inbox()
        # self.explore()

    def _challenge_login(self, error):
        """
        Login through challenge

        :param ClientChallengeRequiredError error: ClientChallengeRequiredError that occurred
        """
        # derived from the snippet at https://poorlau.com/blog/instagram-checkpoint-challenge-required/
        # the poorlau website is offline, but a cached version has been saved here:
        """
        https://web.archive.org/web/20210602152807/http://cc.bingj.com/cache.aspx?q=url%3Ahttps%253A%252F%252Fpoorlau
        .com%252Fblog%252Finstagram-checkpoint-challenge-required%252F&d=5040535175244228&mkt=en-WW&setlang=en-US&w=
        xlqoGnw1q9T0K_h9qZNHMczGhMb066NI)
        """
        challenge_url = error.challenge_url
        response = self._call_api(challenge_url, return_content=True)

        # extract data from the response content
        data = re.findall(r"window\._sharedData\s*=\s*({.*?});", response)

        # check that the security code input field is present
        if not data:
            raise ClientChallengeRequiredError("challenge failed, could not retrieve choice data from response",
                                               error_response=response)

        # make a choice for the challenge
        selected_choice = self._get_choice_type(data[0])

        # send choice data (response is not useful)
        choice_data = {'choice': selected_choice}
        self._call_api(challenge_url, params=choice_data, unsigned=True)

        security_code = None
        # only pass security code if valid
        while not len(security_code) == 6 and not security_code.isdigit():
            # only print if input was received
            if security_code:
                print("Wrong security code")

            security_code = input("Enter security code: ").strip()

        # send security code
        code_data = {'security_code': security_code}
        response = self._call_api(challenge_url, params=code_data, unsigned=True, return_content=True)

        # check if the verification was sucessfull
        if "Please check the code we sent you and try again" in response:
            return self.login()

        # check if the response requires a refresh
        if re.findall(r"http-equiv=\"refresh\"", response):
            # get the response content
            content = re.findall(r"content=\"(.*?)\"\s", response)[0]
            url = re.match(r".*?url=instagram://(.*?)", content)

            # make request to url
            response = self._call_api(url, return_response=True)

        return response

    def _get_choice_type(self, data):
        """Get a choice to use in the challenge"""
        if isinstance(data, str):
            data = json.loads(data)

        try:
            # check for the checkpoint choices in the extra data (probably only when one choice is already chosen)
            pre_choices = data["entry_data"]["Challenge"][0]["extraData"]["content"][-1]["fields"]

            if pre_choices is None:
                raise ClientLoginError("cannot retrieve choices from response, fields are empty. please solve the "
                                       "challenge on the website instead", error_response=json.dumps(data))

            choices = pre_choices[0]["values"]
        except KeyError:
            choices = []
            # get choices
            try:
                fields = data["entry_data"]["Challenge"][0]["fields"]
                try:
                    # check for phone number choice
                    choices.append({"label": f"Phone: {fields['phone_number']}", "value": 0})
                except KeyError:
                    pass

                try:
                    # check for email choice
                    choices.append({"label": f"Email: {fields['email']}", "value": 1})
                except KeyError:
                    pass
            except KeyError:
                pass
        except Exception:
            raise ClientChallengeRequiredError("unknown error while retrieving choices from response",
                                               error_response=json.dumps(data))

        if not choices:
            raise ClientChallengeRequiredError("challenge failed, could not retrieve choices",
                                               error_response=json.dumps(data))

        if len(choices) > 1:
            # multiple choices present
            possible_values = {}
            print("Select where to send the security code:")

            for choice in choices:
                print(f"{choice['label']} - {choice['value']}")
                possible_values[str(choice["value"])] = True

            selected_choice = None

            # only pass choice if valid
            while selected_choice not in possible_values.keys():
                # only print if input was received
                if selected_choice:
                    print(f"Choice \"{selected_choice}\" is not valid. Try again")

                selected_choice = input("Your choice: ").strip()
        else:
            # only one choice present
            print(f"Message with security code sent to: {choices[0]['label']}")
            selected_choice = choices[0]["value"]

        return selected_choice

    def current_user(self):
        """Get current user info"""
        params = self.authenticated_params
        res = self._call_api('accounts/current_user/', params=params, query={'edit': 'true'})
        if self.auto_patch:
            ClientCompatPatch.user(res['user'], drop_incompat_keys=self.drop_incompat_keys)
        return res

    def edit_profile(self, first_name, biography, external_url, email, phone_number, gender):
        """
        Edit profile

        :param first_name:
        :param biography:
        :param external_url:
        :param email: Required.
        :param phone_number:
        :param gender: male: 1, female: 2, unspecified: 3
        :return:
        """
        if int(gender) not in [1, 2, 3]:
            raise ValueError('Invalid gender: {0:d}'.format(int(gender)))
        if not email:
            raise ValueError('Email is required.')

        params = {
            'username': self.authenticated_user_name,
            'gender': int(gender),
            'phone_number': phone_number or '',
            'first_name': first_name or '',
            'biography': biography or '',
            'external_url': external_url or '',
            'email': email,
        }
        params.update(self.authenticated_params)
        res = self._call_api('accounts/edit_profile/', params=params)
        if self.auto_patch:
            ClientCompatPatch.user(res.get('user'))
        return res

    def remove_profile_picture(self):
        """Remove profile picture"""
        res = self._call_api(
            'accounts/remove_profile_picture/', params=self.authenticated_params)
        if self.auto_patch:
            ClientCompatPatch.user(res['user'], drop_incompat_keys=self.drop_incompat_keys)
        return res

    def change_profile_picture(self, photo_data):
        """
        Change profile picture

        :param photo_data: byte string of image
        :return:
        """
        endpoint = 'accounts/change_profile_picture/'
        json_params = json.dumps(self.authenticated_params)
        hash_sig = self._generate_signature(json_params)
        fields = [
            ('ig_sig_key_version', self.key_version),
            ('signed_body', hash_sig + '.' + json_params)
        ]
        files = [
            ('profile_pic', 'profile_pic', 'application/octet-stream', photo_data)
        ]

        content_type, body = MultipartFormDataEncoder().encode(fields, files)

        headers = self.default_headers
        headers['Content-Type'] = content_type
        headers['Content-Length'] = len(body)

        endpoint_url = '{0}{1}'.format(self.api_url.format(version='v1'), endpoint)
        req = compat_urllib_request.Request(endpoint_url, body, headers=headers)
        try:
            self.logger.debug('POST {0!s}'.format(endpoint_url))
            response = self.opener.open(req, timeout=self.timeout)
        except compat_urllib_error.HTTPError as e:
            error_response = self._read_response(e)
            self.logger.debug('RESPONSE: {0:d} {1!s}'.format(e.code, error_response))
            ErrorHandler.process(e, error_response)
        except (SSLError, timeout, SocketError,
                compat_urllib_error.URLError,  # URLError is base of HTTPError
                compat_http_client.HTTPException) as connection_error:
            raise ClientConnectionError('{} {}'.format(
                connection_error.__class__.__name__, str(connection_error)))

        post_response = self._read_response(response)
        self.logger.debug('RESPONSE: {0:d} {1!s}'.format(response.code, post_response))
        json_response = json.loads(post_response)

        if self.auto_patch:
            ClientCompatPatch.user(json_response['user'], drop_incompat_keys=self.drop_incompat_keys)

        return json_response

    def set_account_private(self):
        """Make account private"""
        res = self._call_api('accounts/set_private/', params=self.authenticated_params)
        if self.auto_patch:
            ClientCompatPatch.list_user(res['user'], drop_incompat_keys=self.drop_incompat_keys)
        return res

    def set_account_public(self):
        """Make account public"""""
        res = self._call_api('accounts/set_public/', params=self.authenticated_params)
        if self.auto_patch:
            ClientCompatPatch.list_user(res['user'], drop_incompat_keys=self.drop_incompat_keys)
        return res

    def logout(self):
        """Logout user"""
        params = {
            'phone_id': self.phone_id,
            '_csrftoken': self.csrftoken,
            'guid': self.uuid,
            'device_id': self.device_id,
            '_uuid': self.uuid
        }
        return self._call_api('accounts/logout/', params=params, unsigned=True)

    def presence_status(self):
        """Get presence status setting"""
        json_params = json.dumps({}, separators=(',', ':'))
        query = {
            'ig_sig_key_version': self.key_version,
            'signed_body': self._generate_signature(json_params) + '.' + json_params
        }
        return self._call_api('accounts/get_presence_disabled/', query=query)

    def set_presence_status(self, disabled):
        """
        Set presence status setting

        :param disabled: True if disabling, else False
        """
        params = {
            'disabled': '1' if disabled else '0'
        }
        params.update(self.authenticated_params)
        return self._call_api('accounts/set_presence_disabled/', params=params)

    def enable_presence_status(self):
        """Enable presence status setting"""
        return self.set_presence_status(False)

    def disable_presence_status(self):
        """Disable presence status setting"""
        return self.set_presence_status(True)
