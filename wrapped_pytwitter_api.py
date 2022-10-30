import http.server
import functools
import webbrowser
import logging

import requests
import authlib.integrations.requests_client
# noinspection PyPackageRequirements
import pytwitter  # pip 'package' is python-twitter-v2, module is pytwitter -RDP


class WrappedPyTwitterAPIRateLimitExceededException(pytwitter.PyTwitterError):
    pass


class WrappedPyTwitterAPIUnauthorizedException(pytwitter.PyTwitterError):
    pass


class WrappedPyTwitterAPIOAuth2FlowException(pytwitter.PyTwitterError):
    pass


class WrappedPyTwitterAPIServiceUnavailableException(pytwitter.PyTwitterError):
    pass


class WrappedPyTwitterAPI(pytwitter.Api):

    oauth2_flow_called_back_auth_url = None

    _authentication_refresh_token = None

    def __init__(self, *args, **kwargs):
        super(WrappedPyTwitterAPI, self).__init__(*args, **kwargs)

    class _AuthParametersCaptureRequestHandler(http.server.BaseHTTPRequestHandler):
        """
        Minimal handler for build in python3 httpd server. Captures the parameters made from callback URL to be
        used in continuing OAuth2 authentication flow
        """

        wrapped_api = None

        # noinspection PyMissingConstructor
        def __init__(self,  *args, wrapped_api, **kwargs):
            self.wrapped_api = wrapped_api
            super(http.server.BaseHTTPRequestHandler, self).__init__(*args, **kwargs)

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"Authorization complete! You can return to app.")
            self.wrapped_api.oauth2_flow_called_back_auth_url = self.path
            return self

    def OAuth2AuthenticationFlowHelper(self, local_ports_to_try, listen_ip="127.0.0.1"):

        # Start a minimal local HTTPD listener to get the authorization details.
        # When the Twitter OAUTH2.0 process redirects the local HTTPD listener will get the request. This way the user
        # doesn't have to copy and paste strings or anything like that
        httpd_bound_port = None
        httpd = None

        # The built in python httpd server does not have a way to pass back information gathered from the request it
        # served. And the built in python httpd server creates its own instance of a handler on demand so my subclass
        # of the handler can't be initialized the way I want.
        # Also there isn't a way for inner classes to access it's outer class.
        # To get around this, use the function tools module to create a partial instance of
        # AuthParametersCaptureRequestHandler with a reference to the WrappedPyTwitterAPI stuffed in. It's a dirty way
        # to pass the auth url back to the OAuth2 flow
        AuthCaptureHandler = functools.partial(self._AuthParametersCaptureRequestHandler, wrapped_api=self)

        # Start an HTTPD listening on the first available ephemeral port
        for httpd_bound_port in local_ports_to_try:
            # noinspection PyBroadException
            try:
                httpd = http.server.HTTPServer((listen_ip, httpd_bound_port), AuthCaptureHandler)
                break
            except Exception as e:
                raise WrappedPyTwitterAPIOAuth2FlowException(f"Could not start http listener on port "
                                                             f"'{httpd_bound_port}' reason '{e}'")

        if httpd is None:
            raise WrappedPyTwitterAPIOAuth2FlowException(f"Could not start http listener on any port "
                                                         f"'{local_ports_to_try}'")
        else:
            logging.debug(f"HTTPD listening on port {httpd_bound_port}")

        twitter_auth_callback_redirect_url = f"http://{listen_ip}:{httpd_bound_port}/"

        twitter_user_auth_url, code_verifier, _ = self.get_oauth2_authorize_url(redirect_uri=twitter_auth_callback_redirect_url)

        # Open the URL in the default browser of the environment
        logging.debug(f"Twitter OAuth URL '{twitter_user_auth_url}'")
        webbrowser.open(twitter_user_auth_url)

        # This should wait forever until the user clicks "Authorize App" on the Twitter site
        httpd.handle_request()

        # The AuthParametersCaptureRequestHandler passed to the httpd server will set the class variable
        # oauth2_flow_called_back_auth_url to 'capture' the parameters Twitter provides to continue the oauth flow.

        # Using the 'state' and 'code' values in the redirect URL that the Twitter OAUTH 2 calls, request a bearer token
        # for the user context. The user context is what lets this script make changes on behalf of the user that
        # "Authorized App"
        auth_credentials = self.generate_oauth2_access_token(self.oauth2_flow_called_back_auth_url,
                                                            code_verifier,
                                                            redirect_uri=twitter_auth_callback_redirect_url)

        # This bearer token in these credentials will expire!
        #
        # Unlike the bearer token value on the Twitter application dashboard, this token will expire in 2 hours.
        # The Twitter documentation is kind of confusing. However pytwitter will work fine while the token is valid.
        # After it has expired refresh_token will need to be called.

        self.set_access_token(auth_credentials['access_token'], auth_credentials.get("refresh_token", None))

        return auth_credentials

    def set_access_token(self, access_token, refresh_token=None):
        """
        Sets the API to use the provided access token for authenticated requests
        :param access_token: Token value from Twitter OAuth2
        :param refresh_token: Token for getting the next access_token
        :return: None
        """
        self._auth = authlib.integrations.requests_client.OAuth2Auth(
            token={"access_token": access_token, "token_type": "Bearer"}
        )

        self._authentication_refresh_token = refresh_token

    def refresh_access_token(self, refresh_token=None):
        """
        Use the refresh_token value to get a new temporary access token. On success the API object will be updated
        to use the new token. set_access_token does not need to be called directly.

        To refresh temporary access token "offline.access" MUST be one of the requested scopes

        :param refresh_token: The token provided by the last successful authentication or refresh
        :return: The new auth deatils, including the next refresh token
        :raises PyTwitterError: If refresh request did not return 200 HTTP status code
        """

        if self._authentication_refresh_token is None and refresh_token is None:
            raise WrappedPyTwitterAPIOAuth2FlowException("Can't refresh authentication. No refresh token specified")

        # Prefer a token passed to the function to the class var
        refresh_token_to_use = None
        if refresh_token is not None:
            refresh_token_to_use = refresh_token
        else:
            refresh_token_to_use = self._authentication_refresh_token

        twitter_refresh_url = "https://api.twitter.com/2/oauth2/token"

        # https://developer.twitter.com/en/docs/authentication/oauth-2-0/authorization-code
        refresh_token_response = requests.post(twitter_refresh_url,
                                               headers={"Content-Type": "application/x-www-form-urlencoded"},
                                               data={
                                                   "refresh_token": refresh_token_to_use,
                                                   "grant_type": "refresh_token",
                                                   "client_id": self.client_id
                                               })

        if refresh_token_response.status_code == 200:
            self.set_access_token(refresh_token_response.json()['access_token'],
                                  refresh_token_response.json().get("refresh_token", None))

            self.get_me(return_json=True)

        else:
            raise pytwitter.PyTwitterError(f"Token refresh returned status code '{refresh_token_response.status_code}'")
        return refresh_token_response.json()

    @staticmethod
    def _parse_response(resp: requests.Response) -> dict:
        """
        Overrides default pytwitter.Api behavior to raise more expressive exceptions.
        :param resp: Response
        :return: json data
        :raises WrappedPyTwitterAPIRateLimitExceededException: If the request exceeded rate limits. Caller needs to wait
        :raises WrappedPyTwitterAPIUnauthorizedException: If the request was not authorized. Could be access token has expired
        :raises PyTwitterError: Any other exceptional or error response
        """

        try:
            data = resp.json()
        except ValueError:
            raise pytwitter.PyTwitterError(f"Unknown error: {resp.content}")

        if resp.status_code == 429:
            raise WrappedPyTwitterAPIRateLimitExceededException(resp.json())
        elif resp.status_code == 401:
            raise WrappedPyTwitterAPIUnauthorizedException(resp.json())
        elif resp.status_code == 503:
            raise WrappedPyTwitterAPIServiceUnavailableException(resp.json())
        elif not resp.ok:
            raise pytwitter.PyTwitterError(data)

        # note:
        # If only errors will raise
        if "errors" in data and len(data.keys()) == 1:
            raise pytwitter.PyTwitterError(data["errors"])

        # v1 token not
        if "reason" in data:
            raise pytwitter.PyTwitterError(data)

        return data
