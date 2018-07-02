# -*- coding: utf-8 -*-
"""
The main interface into the HP Network Automation SOAP API.
"""
# Import Python Libraries
from __future__ import absolute_import

# Import third party Libraries
from requests import Session
from requests import get as requests_get
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.packages.urllib3 import disable_warnings as RequestsDisableWarnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import xml.etree.ElementTree as ET
from zeep import Client as ZeepClient
from zeep import Transport as ZeepTransport
from zeep.exceptions import Fault as ZeepFaultException

# Import hpnapy Libraries
from .exceptions import HPNAConnectionError
from .exceptions import HPNAQueryParamError
from .exceptions import HPNAQueryError


class NAInterface:

    def __init__(self, url=None, ssl_verify=True):
        self._connector = _NAConnector(url, ssl_verify=ssl_verify)

    def login(self, username, password):
        self._connector.login(username, password)

    def list_device_groups(self, **kwargs):
        """
        List device groups that contain one or more devices.
        :param kwargs:
        software:   List only device groups for devices running this software
        vendor:     List only device groups for devices with this vendor name
        type:       List only device groups for devices of this type (Router, Switch, etc.)
        model:      List only device groups for devices of this model ("2500 (3000 series)", BIG-IP,
                    etc.)
        family:     List only device groups for devices in this device family ("Cisco IOS", F5,
                    etc.)
        parent:     List only device groups that are direct descendants of this parent device group
                    name
        """
        return self._connector.list_device_groups(**kwargs)

    def list_devices(self, **kwargs):
        """
        List devices.
        :param kwargs:
        software:       List only devices running this software
        vendor:         List only devices with this vendor name
        type:           List only devices of this type (Router, Switch, etc.)
        model:          List only devices of this model ("2500 (3000 series)", BIG-IP, etc.)
        family:         List only devices in this device family ("Cisco IOS", F5, etc.)
        group:          List only devices in this device group
        disabled:       List only devices that are unmanaged.
        pollexcluded:   List only devices excluded from polling.
        ids:            List only devices in this comma-separated list of IDs.
        hierarchy:      List only devices in this hierarchy layer.
        host:           List only devices with this host name
        ip:             List only devices with this IP Address
        realm:          List only devices in this realm
        startid:        List devices starting with DeviceIDs greater than or equal to this one.
        limitcount:     Return this many rows (maximum defaults to 10000).
        vtpdomain:      List only devices in this VTP domain
        """
        return self._connector.list_devices(**kwargs)

    def show_device(self, **kwargs):
        """
        Show a device's properties.
        :param kwargs:
        ip:         a.b.c.d where 0 <= a,b,c,d <= 255. You may optionally prefix the IP with SITE:
                    where SITE is the name of the Site the device is in.
        host:       A valid hostname
        fqdn:       A valid Fully Qualified Domain Name
        deviceid:   A device ID
        id:         A device ID
        nodeuuid:   A NNM node Uuid
        """
        return self._connector.show_device(**kwargs)


class _NAConnector:

    _wsdl_url_path = "/soap?wsdl"
    _soap_url_path = "/soap"
    _binding_string = "NetworkManagementApiBinding"

    def __init__(self, url, ssl_verify=True):
        self._transport = None
        self._zeep_client = None
        self._zeep_interface = None
        self._session_id = None
        self._url = url
        self._target_namespace = ''
        self._ssl_verify = True
        self._set_ssl_verify(ssl_verify)
        self._wsdl_url = self._get_wsdl_url()
        self._soap_url = self._get_soap_url()
        self._build_zeep_interface()
        if not self._zeep_interface:
            raise HPNAConnectionError("Unable to establish connection to HP NA SOAP API.")

    def _set_ssl_verify(self, ssl_verify=True):
        if not ssl_verify:
            RequestsDisableWarnings(InsecureRequestWarning)
        self._ssl_verify = ssl_verify

    def _get_wsdl_url(self):
        return "{0}{1}".format(self._url, _NAConnector._wsdl_url_path)

    def _get_soap_url(self):
        return "{0}{1}".format(self._url, _NAConnector._soap_url_path)

    def _get_wsdl_namespace_from_url(self):
        wsdl_xml_response = self._get_http_get_request_from_url(
            '%s%s' % (self._url, _NAConnector._wsdl_url_path))
        xml_root = _NAConnector._convert_string_to_element_tree(wsdl_xml_response)
        try:
            self._target_namespace = xml_root.attrib['targetNamespace']
        except ET.ParseError:
            raise HPNAConnectionError("Unable to parse WSDL response from HP Network Automation"
                                      "URL.")
        if self._target_namespace == '':
            raise HPNAConnectionError("Unable to extract target namespace from WSDL URL.")

    def _get_http_get_request_from_url(self, url):
        try:
            r = requests_get(url, verify=self._ssl_verify)
        except RequestsConnectionError:
            raise HPNAConnectionError("Failed to connect to HP Network Automation URL.")
        if r.status_code != 200:
            raise HPNAConnectionError("Failed to connect to HP Network Automation URL.")
        return r.text

    @staticmethod
    def _convert_string_to_element_tree(xml_string):
        try:
            root = ET.fromstring(xml_string)
        except ET.ParseError:
            raise HPNAConnectionError("Unable to parse XML response from HP Network Automation"
                                      "URL.")
        return root

    def _build_zeep_interface(self):
        self._get_wsdl_namespace_from_url()
        transport = self._get_ssl_transport()
        self._zeep_client = self._get_zeep_client(transport)
        self._zeep_interface = self._get_zeep_interface()

    def _get_ssl_transport(self):
        session = Session()
        if self._ssl_verify is False:
            session.verify = False
        return ZeepTransport(session=session)

    def _get_zeep_client(self, transport_to_bind=None):
        if not transport_to_bind:
            raise HPNAConnectionError("SOAP client cannot be instantiated without a transport.")
        zeep_client = ZeepClient(wsdl=self._wsdl_url, transport=transport_to_bind)
        return zeep_client

    def _get_zeep_interface(self):
        zeep_interface = self._zeep_client.create_service(
            '{{{0}}}{1}'.format(self._target_namespace, _NAConnector._binding_string),
            self._soap_url)
        return zeep_interface

    def login(self, username, password):
        user_login_params = self._zeep_client.get_type('ns0:loginInputParms')
        updated_user_login_parms = user_login_params(username=username, password=password)
        login_response = self._zeep_interface.login(updated_user_login_parms)
        if _NAConnector._is_login_response_valid(login_response):
            self._session_id = login_response.Text
        else:
            raise HPNAConnectionError("Authentication failure to HP NA SOAP API.")

    @staticmethod
    def _is_login_response_valid(login_response):
        try:
            if login_response.Status == '200 Logged in':
                return True
        except AttributeError:
            pass
        return False

    def _get_api_parameters(self, parameter_string, **kwargs):
        query_parms = self._zeep_client.get_type('{{{0}}}{1}'.format(self._target_namespace,
                                                                     parameter_string))
        try:
            updated_query_parms = query_parms(sessionid=self._session_id, **kwargs)
        except TypeError:
            raise HPNAQueryParamError("Invalid parameter value passed.")
        return updated_query_parms

    @staticmethod
    def _raise_hpna_fault_exception():
        raise HPNAQueryError("An error occurred during execution.")

    def _validate_api_response(self, api_response):
        try:
            if api_response.Status == '200':
                return
        except AttributeError:
            self._raise_hpna_fault_exception()
        raise HPNAQueryError("HP NA API Execution error: Status:{0}, Text:{1}".format(
            api_response.Status, api_response.Text))

    def _get_extracted_result_set(self, api_result):
        try:
            if api_result.ResultSet.Row:
                return api_result.ResultSet.Row
        except AttributeError:
            self._raise_hpna_fault_exception()
        return []

    def _prune_results(self, api_result_set, filtered_key):
        response = []
        try:
            for entry in api_result_set:
                response.append(entry[filtered_key])
        except AttributeError:
            self._raise_hpna_fault_exception()
        return response

    def list_device_groups(self, **kwargs):
        query_parms = self._get_api_parameters("list_device_groupInputParms", **kwargs)
        try:
            api_response = self._zeep_interface.list_device_group(query_parms)
        except ZeepFaultException:
            _NAConnector._raise_hpna_fault_exception()
        self._validate_api_response(api_response)
        extracted_result = self._get_extracted_result_set(api_response)
        return self._prune_results(extracted_result, "name")

    def list_devices(self, **kwargs):
        query_parms = self._get_api_parameters("list_deviceInputParms", **kwargs)
        try:
            api_response = self._zeep_interface.list_device(query_parms)
        except ZeepFaultException:
            _NAConnector._raise_hpna_fault_exception()
        self._validate_api_response(api_response)
        return self._get_extracted_result_set(api_response)

    def show_device(self, **kwargs):
        query_parms = self._get_api_parameters("show_deviceInputParms", **kwargs)
        try:
            api_response = self._zeep_interface.show_device(query_parms)
        except ZeepFaultException:
            _NAConnector._raise_hpna_fault_exception()
        self._validate_api_response(api_response)
        return api_response
