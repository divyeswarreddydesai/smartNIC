from __future__ import absolute_import

import re  # noqa: F401

# python 2 and python 3 compatibility library
import six
import uuid
from ntnx_vmm_py_client.api_client import ApiClient
from six.moves.urllib.parse import quote
from framework.logging.log import DEBUG
import ntnx_networking_py_client
from pathlib import Path
from ntnx_networking_py_client.models.common.v1.response.ApiResponseMetadata import ApiResponseMetadata
from ntnx_networking_py_client.models.common.v1.config.Flag import Flag
import json
from framework.logging.log import INFO
import sys
PY2 = sys.version_info[0] < 3
class NicApi(object):
    """IGNORE:
    NOTE: A placeholder for class level description
    IGNORE
    """  # noqa: E501

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = ApiClient()

        self.api_client = api_client
        self.__headers_to_skip = { 'authorization', 'cookie', 'host', 'user-agent' }
    def call(self, resource_path, method,
                 path_params=None, query_params=None, header_params=None,
                 body=None, post_params=None, files=None,
                 response_type=None, auth_settings=None, async_req=None,
                 _return_http_data_only=None, collection_formats=None,
                 _preload_content=True, _request_timeout=None):
        if not async_req:
            return self.api_call(resource_path, method,
                                   path_params, query_params, header_params,
                                   body, post_params, files,
                                   response_type, auth_settings,
                                   _return_http_data_only, collection_formats,
                                   _preload_content, _request_timeout)
        else:
            self.api_client.__initialize_threadpool()
            thread = self.api_client.__pool.apply_async(self.api_client, (resource_path,
                                           method, path_params, query_params,
                                           header_params, body,
                                           post_params, files,
                                           response_type, auth_settings,
                                           _return_http_data_only,
                                           collection_formats,
                                           _preload_content, _request_timeout))
            return thread
        
    def api_call(
            self, resource_path, method, path_params=None,
            query_params=None, header_params=None, body=None, post_params=None,
            files=None, response_type=None, auth_settings=None,
            _return_http_data_only=None, collection_formats=None,
            _preload_content=True, _request_timeout=None):

        config = self.api_client.configuration

        # Add User-Agent header from configuration
        if config.user_agent:
            self.api_client.add_default_header('User-Agent', config.user_agent)
        # INFO(self.api_client._ApiClient__default_headers)
        # header parameters
        header_params = header_params or {}
        # INFO(header_params)
        header_params.update(self.api_client._ApiClient__default_headers)

        # requestID for idempotence functionality
        if 'NTNX-Request-Id' not in header_params :
            requestId = str(uuid.uuid4())
            header_params['NTNX-Request-Id'] = requestId

        if body and hasattr(body, "get_reserved") and 'ETag' in body.get_reserved():
            header_params['If-Match'] = body.get_reserved()['ETag']

        if self.api_client._ApiClient__cookie:
            header_params['Cookie'] = self.api_client._ApiClient__cookie
            if "Authorization" in header_params:
                header_params.pop("Authorization")
        else :
            self.api_client._ApiClient__update_params_for_auth(header_params, query_params, auth_settings)

        if header_params:
            header_params = self.api_client._ApiClient__sanitize_for_serialization(header_params)
            header_params = dict(self.api_client._ApiClient__parameters_to_tuples(header_params, collection_formats))

        # path parameters
        if path_params:
            path_params = self.api_client._ApiClient__sanitize_for_serialization(path_params)
            path_params = self.api_client._ApiClient__parameters_to_tuples(path_params,
                                                    collection_formats)
            for k, v in path_params:
                # specified safe chars, encode everything
                resource_path = resource_path.replace(
                    '{%s}' % k,
                    quote(str(v), safe=config.safe_chars_for_path_param)
                )

        # query parameters
        if query_params:
            query_params = self.api_client._ApiClient__sanitize_for_serialization(query_params)
            query_params = self.api_client._ApiClient__parameters_to_tuples(query_params, collection_formats)

        # post parameters
        if post_params or files:
            post_params = self.api_client._ApiClient__prepare_post_parameters(post_params, files)
            post_params = self.api_client._ApiClient__sanitize_for_serialization(post_params)
            post_params = self.api_client._ApiClient__parameters_to_tuples(post_params, collection_formats)

        # body
        if body and 'application/octet-stream' not in header_params['Content-Type']:
            body = self.api_client._ApiClient__sanitize_for_serialization(body)

        # request url
        url = config.scheme + '://' + config.host + ':' + str(config.port) + resource_path
        INFO(url)
        # perform request and return response
        response_data = self.api_client.request(
            method, url, query_params=query_params, headers=header_params,
            post_params=post_params, body=body,
            _preload_content=_preload_content,
            _request_timeout=_request_timeout)

        # Retry one more time for 401 response with basic auth header and no cookie
        if response_data.status == 401:
            DEBUG("Retrying for an unauthorized request")
            self.api_client._ApiClient__refresh_cookie = True
            if 'Cookie' in header_params:
                header_params.update(self.api_client._ApiClient__default_headers)
                header_params.pop('Cookie')
                self.api_client._ApiClient__update_params_for_auth(header_params, query_params, auth_settings)

            response_data = self.api_client.request(
                method, url, query_params=query_params, headers=header_params,
                post_params=post_params, body=body,
                _preload_content=_preload_content,
                _request_timeout=_request_timeout)

            # Raise error if 401 persists
            if response_data.status == 401:
                raise ntnx_networking_py_client.rest.ApiException(http_resp=response_data)

        if self.api_client._ApiClient__refresh_cookie:
            self.api_client._ApiClient__update_cookies(response_data)

        self.last_response = response_data
        return_data = response_data
        try:
            if response_data.status != 204:
                # Download a file
                if response_data.getheader(name='Content-Type') == 'application/octet-stream':
                    download_path = self.api_client.__deserialize_file(response_data)
                    download_path = Path(download_path)
                    flag = Flag(name="hasError", value=False)
                    metadata = ApiResponseMetadata(flags=[flag])
                    data = {"path": download_path}
                    data["$objectType"] = "pathlib.Path"
                    data["$reserved"] = {}
                    data["$unknownFields"] = {}
                    # convert response type to class
                    if response_type is not None:
                        response_type = self.api_client.__getattr(response_type)
                        return response_type(data=data, metadata=metadata)
                    else:
                        resp_data= {"data": data, "metadata": metadata}
                        return resp_data
                else:
                    if _preload_content:
                        # Read the data from original urllib3 response
                        response_data.data = response_data.urllib3_response.data
                        # In the python 3, the response.data is bytes which needs to be decoded to string.
                        if six.PY3:
                            response_data.data = response_data.data.decode('utf-8')

                        return_data = json.loads(response_data.data)
                        return_data = self.api_client.__add_header_to_reserved(response_data, return_data, "ETag")
                        if response_type is None and "$objectType" in return_data:
                            response_type = return_data.get("$objectType")
                        if PY2:
                            inner_response_type = response_type.encode('utf-8', 'ignore')
                        else:
                            inner_response_type = response_type

                        return self.api_client.deserialize(return_data, inner_response_type)
                    else:
                        return_data = response_data
            else:
                if _preload_content:
                    return_data = None
        finally:
            if 'Content-Type' in header_params and header_params['Content-Type'] == 'application/octet-stream':
                response_data.urllib3_response.drain_conn()
                response_data.urllib3_response.release_conn()
        if _return_http_data_only:
            return (return_data)
        else:
            return (return_data, response_data.status,
                    response_data.getheaders())
    def associate_nic_to_nic_profile(self,nic_profile_id,nic_id, **kwargs):
        kwargs['_return_http_data_only'] = True

        params = dict(locals())
        for key, val in six.iteritems(params['kwargs']):
            params[key] = val
        del params['kwargs']
        del params['self']
        if ('nic_profile_id' not in params or params['nic_profile_id'] is None):
            raise ValueError("Missing the required parameter `nic_profile_id` when calling `create_image`")
        if ('nic_id' not in params or params['nic_id'] is None):
            raise ValueError("Missing the required parameter `nic_id` when calling `create_image`")
        else:
            params['body']={
                "hostNicReference":params['nic_id']
            }
        collection_formats = {}
        path_params = {}

        query_params = []

        header_params = {}
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client._select_header_accept(
            ['application/json'])  # noqa: E501
        if 'Accept' in params and params.get('Accept') is not None:
            header_params['Accept'] = params.get('Accept')
        # params['if_match']="YXBwbGljYXRpb24vanNvbg==:0"
        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client._select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501
        if 'Content-Type' in params and params.get('Content-Type') is not None:
            header_params['Content-Type'] = params.get('Content-Type')
        extra_params = []
        extra_params.append('async_req')
        extra_params.append('_return_http_data_only')
        extra_params.append('_preload_content')
        extra_params.append('_request_timeout')
        all_params = set(['body'])
        all_params.update(extra_params)
        for key, val in six.iteritems(params):
            if val is not None and key.lower() not in self.__headers_to_skip and key not in all_params:
                if key.lower() == 'if_match'.lower():
                    key = 'If-Match'
                elif key.lower() == 'if_none_match'.lower():
                    key = 'If-None-Match'
                header_params[key] = val
                
        form_params = []
        local_var_files = {}

        # Authentication setting
        auth_settings = ['basicAuthScheme']  # noqa: E501

        body_params = None
        if 'body' in params and params['body'] is not None:
            body_params = params['body']
        url=f'/api/networking/v4.0/config/nic-profiles/{params["nic_profile_id"]}/$actions/associate-host-nic'
        try:
            if kwargs.get('async_req'):
                return self.call(
                    url, 'POST',
                    path_params,
                    query_params,
                    header_params,
                    body=body_params,
                    post_params=form_params,
                    files=local_var_files,
                    response_type=None,  # noqa: E501
                    auth_settings=auth_settings,
                    async_req=params.get('async_req'),
                    _return_http_data_only=params.get('_return_http_data_only'),
                    _preload_content=params.get('_preload_content', False),
                    _request_timeout=params.get('_request_timeout'),
                    collection_formats=collection_formats)
            else:
                (data) = self.call(
                    url, 'POST',
                    path_params,
                    query_params,
                    header_params,
                    body=body_params,
                    post_params=form_params,
                    files=local_var_files,
                    response_type=None,  # noqa: E501
                    auth_settings=auth_settings,
                    async_req=params.get('async_req'),
                    _return_http_data_only=params.get('_return_http_data_only'),
                    _preload_content=params.get('_preload_content', False),
                    _request_timeout=params.get('_request_timeout'),
                    collection_formats=collection_formats)
                return data
        finally:
            pass
        
    def create_nic_profile(self,body,**kwargs):
        kwargs['_return_http_data_only'] = True

        params = dict(locals())
        for key, val in six.iteritems(params['kwargs']):
            params[key] = val
        del params['kwargs']
        del params['self']
        if ('body' not in params or params['body'] is None):
            raise ValueError("Missing the required parameter `body` when calling `create_image`")  # noqa: E501

        collection_formats = {}

        path_params = {}

        query_params = []

        header_params = {}
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client._select_header_accept(
            ['application/json'])  # noqa: E501
        if 'Accept' in params and params.get('Accept') is not None:
            header_params['Accept'] = params.get('Accept')

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client._select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501
        if 'Content-Type' in params and params.get('Content-Type') is not None:
            header_params['Content-Type'] = params.get('Content-Type')
        extra_params = []
        extra_params.append('async_req')
        extra_params.append('_return_http_data_only')
        extra_params.append('_preload_content')
        extra_params.append('_request_timeout')
        all_params = set(['body'])
        all_params.update(extra_params)
        for key, val in six.iteritems(params):
            if val is not None and key.lower() not in self.__headers_to_skip and key not in all_params:
                if key.lower() == 'if_match'.lower():
                    key = 'If-Match'
                elif key.lower() == 'if_none_match'.lower():
                    key = 'If-None-Match'
                header_params[key] = val
                
        form_params = []
        local_var_files = {}

        # Authentication setting
        auth_settings = ['basicAuthScheme']  # noqa: E501

        body_params = None
        if 'body' in params and params['body'] is not None:
            body_params = params['body']
        try:
            if kwargs.get('async_req'):
                return self.call(
                    '/api/networking/v4.0/config/nic-profiles', 'POST',
                    path_params,
                    query_params,
                    header_params,
                    body=body_params,
                    post_params=form_params,
                    files=local_var_files,
                    response_type=None,  # noqa: E501
                    auth_settings=auth_settings,
                    async_req=params.get('async_req'),
                    _return_http_data_only=params.get('_return_http_data_only'),
                    _preload_content=params.get('_preload_content', False),
                    _request_timeout=params.get('_request_timeout'),
                    collection_formats=collection_formats)
            else:
                (data) = self.call(
                    '/api/networking/v4.0/config/nic-profiles', 'POST',
                    path_params,
                    query_params,
                    header_params,
                    body=body_params,
                    post_params=form_params,
                    files=local_var_files,
                    response_type=None,  # noqa: E501
                    auth_settings=auth_settings,
                    async_req=params.get('async_req'),
                    _return_http_data_only=params.get('_return_http_data_only'),
                    _preload_content=params.get('_preload_content', False),
                    _request_timeout=params.get('_request_timeout'),
                    collection_formats=collection_formats)
                return data
        finally:
            pass
    def list_host_nics(self, _page=None, _limit=None, _filter=None, _orderby=None, _select=None, **kwargs):
        kwargs['_return_http_data_only'] = True

        params = dict(locals())
        for key, val in six.iteritems(params['kwargs']):
            params[key] = val
        del params['kwargs']
        del params['self']


        collection_formats = {}

        path_params = {}

        query_params = []
        if '_page' in params and params['_page'] is not None:
            query_params.append(('$page', params['_page']))  # noqa: E501
        if '_limit' in params and params['_limit'] is not None:
            query_params.append(('$limit', params['_limit']))  # noqa: E501
        if '_filter' in params and params['_filter'] is not None:
            query_params.append(('$filter', params['_filter']))  # noqa: E501
        if '_orderby' in params and params['_orderby'] is not None:
            query_params.append(('$orderby', params['_orderby']))  # noqa: E501
        if '_select' in params and params['_select'] is not None:
            query_params.append(('$select', params['_select']))  # noqa: E501

        header_params = {}
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client._select_header_accept(
            ['application/json'])  # noqa: E501
        if 'Accept' in params and params.get('Accept') is not None:
            header_params['Accept'] = params.get('Accept')

        # Process operation specific headers
        extra_params = []
        extra_params.append('async_req')
        extra_params.append('_return_http_data_only')
        extra_params.append('_preload_content')
        extra_params.append('_request_timeout')
        all_params = set(['_page', '_limit', '_filter', '_orderby', '_select'])
        all_params.update(extra_params)
        for key, val in six.iteritems(params):
            if val is not None and key.lower() not in self.__headers_to_skip and key not in all_params:
                if key.lower() == 'if_match'.lower():
                    key = 'If-Match'
                elif key.lower() == 'if_none_match'.lower():
                    key = 'If-None-Match'
                header_params[key] = val

        form_params = []
        local_var_files = {}

        # Authentication setting
        auth_settings = ['basicAuthScheme']  # noqa: E501

        body_params = None

        try:
            if kwargs.get('async_req'):
                return self.call(
                    '/api/clustermgmt/v4.0/config/host-nics', 'GET',
                    path_params,
                    query_params,
                    header_params,
                    body=body_params,
                    post_params=form_params,
                    files=local_var_files,
                    response_type=None,  # noqa: E501
                    auth_settings=auth_settings,
                    async_req=params.get('async_req'),
                    _return_http_data_only=params.get('_return_http_data_only'),
                    _preload_content=params.get('_preload_content', False),
                    _request_timeout=params.get('_request_timeout'),
                    collection_formats=collection_formats)
            else:
                (data) = self.call(
                    '/api/clustermgmt/v4.0/config/host-nics', 'GET',
                    path_params,
                    query_params,
                    header_params,
                    body=body_params,
                    post_params=form_params,
                    files=local_var_files,
                    response_type=None,  # noqa: E501
                    auth_settings=auth_settings,
                    async_req=params.get('async_req'),
                    _return_http_data_only=params.get('_return_http_data_only'),
                    _preload_content=params.get('_preload_content', False),
                    _request_timeout=params.get('_request_timeout'),
                    collection_formats=collection_formats)
                return data
        finally:
            pass

    def list_nic_profiles(self, _page=None, _limit=None, _filter=None, _orderby=None, _select=None, **kwargs):
        kwargs['_return_http_data_only'] = True

        params = dict(locals())
        for key, val in six.iteritems(params['kwargs']):
            params[key] = val
        del params['kwargs']
        del params['self']


        collection_formats = {}

        path_params = {}

        query_params = []
        if '_page' in params and params['_page'] is not None:
            query_params.append(('$page', params['_page']))  # noqa: E501
        if '_limit' in params and params['_limit'] is not None:
            query_params.append(('$limit', params['_limit']))  # noqa: E501
        if '_filter' in params and params['_filter'] is not None:
            query_params.append(('$filter', params['_filter']))  # noqa: E501
        if '_orderby' in params and params['_orderby'] is not None:
            query_params.append(('$orderby', params['_orderby']))  # noqa: E501
        if '_select' in params and params['_select'] is not None:
            query_params.append(('$select', params['_select']))  # noqa: E501

        header_params = {}
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client._select_header_accept(
            ['application/json'])  # noqa: E501
        if 'Accept' in params and params.get('Accept') is not None:
            header_params['Accept'] = params.get('Accept')

        # Process operation specific headers
        extra_params = []
        extra_params.append('async_req')
        extra_params.append('_return_http_data_only')
        extra_params.append('_preload_content')
        extra_params.append('_request_timeout')
        all_params = set(['_page', '_limit', '_filter', '_orderby', '_select'])
        all_params.update(extra_params)
        for key, val in six.iteritems(params):
            if val is not None and key.lower() not in self.__headers_to_skip and key not in all_params:
                if key.lower() == 'if_match'.lower():
                    key = 'If-Match'
                elif key.lower() == 'if_none_match'.lower():
                    key = 'If-None-Match'
                header_params[key] = val

        form_params = []
        local_var_files = {}

        # Authentication setting
        auth_settings = ['basicAuthScheme']  # noqa: E501

        body_params = None

        try:
            if kwargs.get('async_req'):
                return self.call(
                    '/api/networking/v4.0/config/nic-profiles', 'GET',
                    path_params,
                    query_params,
                    header_params,
                    body=body_params,
                    post_params=form_params,
                    files=local_var_files,
                    response_type=None,  # noqa: E501
                    auth_settings=auth_settings,
                    async_req=params.get('async_req'),
                    _return_http_data_only=params.get('_return_http_data_only'),
                    _preload_content=params.get('_preload_content', False),
                    _request_timeout=params.get('_request_timeout'),
                    collection_formats=collection_formats)
            else:
                (data) = self.call(
                    '/api/networking/v4.0/config/nic-profiles', 'GET',
                    path_params,
                    query_params,
                    header_params,
                    body=body_params,
                    post_params=form_params,
                    files=local_var_files,
                    response_type=None,  # noqa: E501
                    auth_settings=auth_settings,
                    async_req=params.get('async_req'),
                    _return_http_data_only=params.get('_return_http_data_only'),
                    _preload_content=params.get('_preload_content', False),
                    _request_timeout=params.get('_request_timeout'),
                    collection_formats=collection_formats)
                return data
        finally:
            pass

    
