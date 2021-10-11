# -*- coding: utf-8 -*-
"""
The main interface into the HP Network Automation SOAP API.
"""
# Import Python Libraries
from __future__ import absolute_import
from base64 import b64decode

# Import third party Libraries
from requests import Session
from requests import get as requests_get
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.packages.urllib3 import disable_warnings as RequestsDisableWarnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import xml.etree.ElementTree as ET
from zeep import Client as ZeepClient
from zeep import Transport as ZeepTransport
from zeep import Settings as ZeepSettings
from zeep.exceptions import Fault as ZeepFaultException

# Import hpnapy Libraries
from .exceptions import HPNAConnectionError
from .exceptions import HPNAQueryParamError
from .exceptions import HPNAQueryError


class NAInterface:

    def __init__(self, url=None, ssl_verify=True):
        self._connector = _NAConnector(url, ssl_verify=ssl_verify)

    @staticmethod
    def _decode_b64_response(encoded_string):
        try:
            decoded_response = b64decode(encoded_string)
            return decoded_response.decode('utf-8')
        except ValueError:
            return encoded_string

    def login(self, username, password):
        """
        Log in to the API and store the session ID.

        The session ID must be captured to send additional API calls. This function can be run
        periodically to refresh the session ID.

        Parameters
        ----------
        username : str
            NA username
        password : str
            NA password

        Raises
        ----------
        HPNAConnectionError
            Exception stating that there was a failure to authenticate or reach the system.

        Examples
        ----------

        >>> na = NAInterface('https://foo.bar')
        >>> na.login('username', 'password')

        """
        self._connector.login(username, password)

    def acquire_resource_id(self, **kwargs):
        return self._connector.execute_single_result_call("acquire_resource_id", **kwargs)

    def activate_device(self, **kwargs):
        return self._connector.execute_single_result_call("activate_device", **kwargs)

    def add_advanced_diagnostic(self, **kwargs):
        return self._connector.execute_single_result_call("add_advanced_diagnostic", **kwargs)

    def add_advanced_script(self, **kwargs):
        return self._connector.execute_single_result_call("add_advanced_script", **kwargs)

    def add_authentication(self, **kwargs):
        return self._connector.execute_single_result_call("add_authentication", **kwargs)

    def add_change_plan(self, **kwargs):
        """
        Added in NA 10.21.
        """
        return self._connector.execute_single_result_call("add_change_plan", **kwargs)

    def add_command_script(self, **kwargs):
        return self._connector.execute_single_result_call("add_command_script", **kwargs)

    def add_device(self, **kwargs):
        return self._connector.execute_single_result_call("add_device", **kwargs)

    def add_device_context(self, **kwargs):
        return self._connector.execute_single_result_call("add_device_context", **kwargs)

    def add_device_group(self, **kwargs):
        return self._connector.execute_single_result_call("add_device_group", **kwargs)

    def add_device_relationship(self, **kwargs):
        return self._connector.execute_single_result_call("add_device_relationship", **kwargs)

    def add_device_template(self, **kwargs):
        return self._connector.execute_single_result_call("add_device_template", **kwargs)

    def add_device_to_group(self, **kwargs):
        return self._connector.execute_single_result_call("add_device_to_group", **kwargs)

    def add_diagnostic(self, **kwargs):
        return self._connector.execute_single_result_call("add_diagnostic", **kwargs)

    def add_event(self, **kwargs):
        return self._connector.execute_single_result_call("add_event", **kwargs)

    def add_event_rule(self, **kwargs):
        return self._connector.execute_single_result_call("add_event_rule", **kwargs)

    def add_group(self, **kwargs):
        return self._connector.execute_single_result_call("add_group", **kwargs)

    def add_group_to_parent_group(self, **kwargs):
        return self._connector.execute_single_result_call("add_group_to_parent_group", **kwargs)

    def add_image(self, **kwargs):
        return self._connector.execute_single_result_call("add_image", **kwargs)

    def add_imageoption(self, **kwargs):
        return self._connector.execute_single_result_call("add_imageoption", **kwargs)

    def add_ip(self, **kwargs):
        return self._connector.execute_single_result_call("add_ip", **kwargs)

    def add_metadata(self, **kwargs):
        return self._connector.execute_single_result_call("add_metadata", **kwargs)

    def add_metadata_field(self, **kwargs):
        return self._connector.execute_single_result_call("add_metadata_field", **kwargs)

    def add_parent_group(self, **kwargs):
        return self._connector.execute_single_result_call("add_parent_group", **kwargs)

    def add_partition(self, **kwargs):
        return self._connector.execute_single_result_call("add_partition", **kwargs)

    def add_resource_id(self, **kwargs):
        return self._connector.execute_single_result_call("add_resource_id", **kwargs)

    def add_resource_id_pool(self, **kwargs):
        return self._connector.execute_single_result_call("add_resource_id_pool", **kwargs)

    def add_role(self, **kwargs):
        return self._connector.execute_single_result_call("add_role", **kwargs)

    def add_service_type(self, **kwargs):
        return self._connector.execute_single_result_call("add_service_type", **kwargs)

    def add_system_message(self, **kwargs):
        return self._connector.execute_single_result_call("add_system_message", **kwargs)

    def add_user(self, **kwargs):
        return self._connector.execute_single_result_call("add_user", **kwargs)

    def add_user_to_group(self, **kwargs):
        return self._connector.execute_single_result_call("add_user_to_group", **kwargs)

    def add_vlan(self, **kwargs):
        return self._connector.execute_single_result_call("add_vlan", **kwargs)

    def add_vlan_trunk(self, **kwargs):
        return self._connector.execute_single_result_call("add_vlan_trunk", **kwargs)

    def annotate_access(self, **kwargs):
        return self._connector.execute_single_result_call("annotate_access", **kwargs)

    def annotate_config(self, **kwargs):
        return self._connector.execute_single_result_call("annotate_config", **kwargs)

    def assign_auto_remediation_script(self, **kwargs):
        return self._connector.execute_single_result_call("assign_auto_remediation_script", **kwargs)

    def assign_driver(self, **kwargs):
        return self._connector.execute_single_result_call("assign_driver", **kwargs)

    def check_policy_compliance(self, **kwargs):
        return self._connector.execute_single_result_call("check_policy_compliance", **kwargs)

    def configure_syslog(self, **kwargs):
        return self._connector.execute_single_result_call("configure_syslog", **kwargs)

    def create_policy(self, **kwargs):
        return self._connector.execute_single_result_call("create_policy", **kwargs)

    def create_policy_rule(self, **kwargs):
        return self._connector.execute_single_result_call("create_policy_rule", **kwargs)

    def create_rule_condition(self, **kwargs):
        return self._connector.execute_single_result_call("create_rule_condition", **kwargs)

    def create_rule_exception(self, **kwargs):
        return self._connector.execute_single_result_call("create_rule_exception", **kwargs)

    def deactivate_device(self, **kwargs):
        return self._connector.execute_single_result_call("deactivate_device", **kwargs)

    def del_access(self, **kwargs):
        return self._connector.execute_single_result_call("del_access", **kwargs)

    def del_authentication(self, **kwargs):
        return self._connector.execute_single_result_call("del_authentication", **kwargs)

    def del_cache(self, **kwargs):
        return self._connector.execute_single_result_call("del_cache", **kwargs)

    def del_change_plan(self, **kwargs):
        """
        Added in NA 10.21.
        """
        return self._connector.execute_single_result_call("del_change_plan", **kwargs)

    def del_device(self, **kwargs):
        return self._connector.execute_single_result_call("del_device", **kwargs)

    def del_device_context(self, **kwargs):
        return self._connector.execute_single_result_call("del_device_context", **kwargs)

    def del_device_data(self, **kwargs):
        return self._connector.execute_single_result_call("del_device_data", **kwargs)

    def del_device_from_group(self, **kwargs):
        return self._connector.execute_single_result_call("del_device_from_group", **kwargs)

    def del_device_relationship(self, **kwargs):
        return self._connector.execute_single_result_call("del_device_relationship", **kwargs)

    def del_device_template(self, **kwargs):
        return self._connector.execute_single_result_call("del_device_template", **kwargs)

    def del_drivers(self, **kwargs):
        return self._connector.execute_single_result_call("del_drivers", **kwargs)

    def del_event(self, **kwargs):
        return self._connector.execute_single_result_call("del_event", **kwargs)

    def del_group(self, **kwargs):
        return self._connector.execute_single_result_call("del_group", **kwargs)

    def del_group_from_parent_group(self, **kwargs):
        return self._connector.execute_single_result_call("del_group_from_parent_group", **kwargs)

    def del_ip(self, **kwargs):
        return self._connector.execute_single_result_call("del_ip", **kwargs)

    def del_metadata(self, **kwargs):
        return self._connector.execute_single_result_call("del_metadata", **kwargs)

    def del_metadata_field(self, **kwargs):
        return self._connector.execute_single_result_call("del_metadata_field", **kwargs)

    def del_partition(self, **kwargs):
        return self._connector.execute_single_result_call("del_partition", **kwargs)

    def del_resource_id(self, **kwargs):
        return self._connector.execute_single_result_call("del_resource_id", **kwargs)

    def del_resource_id_pool(self, **kwargs):
        return self._connector.execute_single_result_call("del_resource_id_pool", **kwargs)

    def del_role(self, **kwargs):
        return self._connector.execute_single_result_call("del_role", **kwargs)

    def del_script(self, **kwargs):
        return self._connector.execute_single_result_call("del_script", **kwargs)

    def del_service_type(self, **kwargs):
        return self._connector.execute_single_result_call("del_service_type", **kwargs)

    def del_session(self, **kwargs):
        return self._connector.execute_single_result_call("del_session", **kwargs)

    def del_system_message(self, **kwargs):
        return self._connector.execute_single_result_call("del_system_message", **kwargs)

    def del_task(self, **kwargs):
        return self._connector.execute_single_result_call("del_task", **kwargs)

    def del_user(self, **kwargs):
        return self._connector.execute_single_result_call("del_user", **kwargs)

    def del_user_from_group(self, **kwargs):
        return self._connector.execute_single_result_call("del_user_from_group", **kwargs)

    def del_vlan(self, **kwargs):
        return self._connector.execute_single_result_call("del_vlan", **kwargs)

    def del_vlan_trunk(self, **kwargs):
        return self._connector.execute_single_result_call("del_vlan_trunk", **kwargs)

    def delete_image(self, **kwargs):
        return self._connector.execute_single_result_call("delete_image", **kwargs)

    def delete_policy(self, **kwargs):
        return self._connector.execute_single_result_call("delete_policy", **kwargs)

    def delete_policy_rule(self, **kwargs):
        return self._connector.execute_single_result_call("delete_policy_rule", **kwargs)

    def delete_rule_condition(self, **kwargs):
        return self._connector.execute_single_result_call("delete_rule_condition", **kwargs)

    def delete_rule_exception(self, **kwargs):
        return self._connector.execute_single_result_call("delete_rule_exception", **kwargs)

    def deploy_change_plan(self, **kwargs):
        """
        Added in NA 10.21.
        """
        return self._connector.execute_single_result_call("deploy_change_plan", **kwargs)

    def deploy_config(self, **kwargs):
        return self._connector.execute_single_result_call("deploy_config", **kwargs)

    def deploy_image(self, **kwargs):
        return self._connector.execute_single_result_call("deploy_image", **kwargs)

    def diff_config(self, **kwargs):
        return self._connector.execute_single_result_call("diff_config", **kwargs)

    def disable_device(self, **kwargs):
        return self._connector.execute_single_result_call("disable_device", **kwargs)

    def discover_driver(self, **kwargs):
        return self._connector.execute_single_result_call("discover_driver", **kwargs)

    def discover_drivers(self, **kwargs):
        return self._connector.execute_single_result_call("discover_drivers", **kwargs)

    def enable_device(self, **kwargs):
        return self._connector.execute_single_result_call("enable_device", **kwargs)

    def export_policy(self, **kwargs):
        return self._connector.execute_single_result_call("export_policy", **kwargs)

    def fulltextsearch(self, **kwargs):
        return self._connector.execute_single_result_call("fulltextsearch", **kwargs)

    def get_snapshot(self, **kwargs):
        return self._connector.execute_single_result_call("get_snapshot", **kwargs)

    def import_policy(self, **kwargs):
        return self._connector.execute_single_result_call("import_policy", **kwargs)

    def list_access(self, **kwargs):
        return self._connector.execute_multi_result_call("list_access", **kwargs)

    def list_access_all(self, **kwargs):
        return self._connector.execute_multi_result_call("list_access_all", **kwargs)

    def list_acl(self, **kwargs):
        return self._connector.execute_multi_result_call("list_acl", **kwargs)

    def list_all_drivers(self, **kwargs):
        return self._connector.execute_multi_result_call("list_all_drivers", **kwargs)

    def list_authentication(self, **kwargs):
        return self._connector.execute_multi_result_call("list_authentication", **kwargs)

    def list_basicip(self, **kwargs):
        return self._connector.execute_multi_result_call("list_basicip", **kwargs)

    def list_change_plan(self, **kwargs):
        """
        Added in NA 10.21.
        """
        return self._connector.execute_multi_result_call("list_change_plan", **kwargs)

    def list_config(self, **kwargs):
        return self._connector.execute_multi_result_call("list_config", **kwargs)

    def list_config_all(self, **kwargs):
        return self._connector.execute_multi_result_call("list_config_all", **kwargs)

    def list_config_id(self, **kwargs):
        return self._connector.execute_multi_result_call("list_config_id", **kwargs)

    def list_core(self, **kwargs):
        return self._connector.execute_multi_result_call("list_core", **kwargs)

    def list_custom_data_definition(self, **kwargs):
        return self._connector.execute_multi_result_call("list_custom_data_definition", **kwargs)

    def list_device(self, **kwargs):
        return self._connector.execute_multi_result_call("list_device", **kwargs)

    def list_device_context_variables(self, **kwargs):
        return self._connector.execute_multi_result_call("list_device_context_variables", **kwargs)

    def list_device_data(self, **kwargs):
        return self._connector.execute_multi_result_call("list_device_data", **kwargs)

    def list_device_family(self, **kwargs):
        return self._connector.execute_multi_result_call("list_device_family", **kwargs)

    def list_device_group(self, **kwargs):
        return self._connector.execute_multi_result_call("list_device_group", **kwargs)

    def list_device_id(self, **kwargs):
        return self._connector.execute_multi_result_call("list_device_id", **kwargs)

    def list_device_model(self, **kwargs):
        return self._connector.execute_multi_result_call("list_device_model", **kwargs)

    def list_device_nnm(self, **kwargs):
        return self._connector.execute_multi_result_call("list_device_nnm", **kwargs)

    def list_device_relationships(self, **kwargs):
        return self._connector.execute_multi_result_call("list_device_relationships", **kwargs)

    def list_device_software(self, **kwargs):
        return self._connector.execute_multi_result_call("list_device_software", **kwargs)

    def list_device_template(self, **kwargs):
        return self._connector.execute_multi_result_call("list_device_template", **kwargs)

    def list_device_type(self, **kwargs):
        return self._connector.execute_multi_result_call("list_device_type", **kwargs)

    def list_device_vendor(self, **kwargs):
        return self._connector.execute_multi_result_call("list_device_vendor", **kwargs)

    def list_device_vtp(self, **kwargs):
        return self._connector.execute_multi_result_call("list_device_vtp", **kwargs)

    def list_deviceinfo(self, **kwargs):
        return self._connector.execute_multi_result_call("list_deviceinfo", **kwargs)

    def list_diagnostic(self, **kwargs):
        return self._connector.execute_multi_result_call("list_diagnostic", **kwargs)

    def list_diagnostic_all(self, **kwargs):
        return self._connector.execute_multi_result_call("list_diagnostic_all", **kwargs)

    def list_event(self, **kwargs):
        return self._connector.execute_multi_result_call("list_event", **kwargs)

    def list_group_id(self, **kwargs):
        return self._connector.execute_multi_result_call("list_group_id", **kwargs)

    def list_groups(self, **kwargs):
        return self._connector.execute_multi_result_call("list_groups", **kwargs)

    def list_icmp(self, **kwargs):
        return self._connector.execute_multi_result_call("list_icmp", **kwargs)

    def list_image(self, **kwargs):
        return self._connector.execute_multi_result_call("list_image", **kwargs)

    def list_imageoption(self, **kwargs):
        return self._connector.execute_multi_result_call("list_imageoption", **kwargs)

    def list_imageset(self, **kwargs):
        return self._connector.execute_multi_result_call("list_imageset", **kwargs)

    def list_int(self, **kwargs):
        return self._connector.execute_multi_result_call("list_int", **kwargs)

    def list_ip(self, **kwargs):
        return self._connector.execute_multi_result_call("list_ip", **kwargs)

    def list_ip_all(self, **kwargs):
        return self._connector.execute_multi_result_call("list_ip_all", **kwargs)

    def list_metadata(self, **kwargs):
        return self._connector.execute_multi_result_call("list_metadata", **kwargs)

    def list_metadata_field(self, **kwargs):
        return self._connector.execute_multi_result_call("list_metadata_field", **kwargs)

    def list_module(self, **kwargs):
        return self._connector.execute_multi_result_call("list_module", **kwargs)

    def list_ospfneighbor(self, **kwargs):
        return self._connector.execute_multi_result_call("list_ospfneighbor", **kwargs)

    def list_partition(self, **kwargs):
        return self._connector.execute_multi_result_call("list_partition", **kwargs)

    def list_policies(self, **kwargs):
        return self._connector.execute_multi_result_call("list_policies", **kwargs)

    def list_policy_id(self, **kwargs):
        return self._connector.execute_multi_result_call("list_policy_id", **kwargs)

    def list_policy_rule(self, **kwargs):
        return self._connector.execute_multi_result_call("list_policy_rule", **kwargs)

    def list_port(self, **kwargs):
        return self._connector.execute_multi_result_call("list_port", **kwargs)

    def list_port_channels(self, **kwargs):
        return self._connector.execute_multi_result_call("list_port_channels", **kwargs)

    def list_relationship_type(self, **kwargs):
        return self._connector.execute_multi_result_call("list_relationship_type", **kwargs)

    def list_relationships_for_device(self, **kwargs):
        return self._connector.execute_multi_result_call("list_relationships_for_device", **kwargs)

    def list_resource_id(self, **kwargs):
        return self._connector.execute_multi_result_call("list_resource_id", **kwargs)

    def list_resource_id_custom_field_data(self, **kwargs):
        return self._connector.execute_multi_result_call("list_resource_id_custom_field_data", **kwargs)

    def list_resource_id_pool(self, **kwargs):
        return self._connector.execute_multi_result_call("list_resource_id_pool", **kwargs)

    def list_resource_id_pool_all(self, **kwargs):
        return self._connector.execute_multi_result_call("list_resource_id_pool_all", **kwargs)

    def list_role(self, **kwargs):
        return self._connector.execute_multi_result_call("list_role", **kwargs)

    def list_routing(self, **kwargs):
        return self._connector.execute_multi_result_call("list_routing", **kwargs)

    def list_rule_condition(self, **kwargs):
        return self._connector.execute_multi_result_call("list_rule_condition", **kwargs)

    def list_script(self, **kwargs):
        return self._connector.execute_multi_result_call("list_script", **kwargs)

    def list_script_id(self, **kwargs):
        return self._connector.execute_multi_result_call("list_script_id", **kwargs)

    def list_script_mode(self, **kwargs):
        return self._connector.execute_multi_result_call("list_script_mode", **kwargs)

    def list_session(self, **kwargs):
        return self._connector.execute_multi_result_call("list_session", **kwargs)

    def list_site(self, **kwargs):
        return self._connector.execute_multi_result_call("list_site", **kwargs)

    def list_sys_oids_all(self, **kwargs):
        return self._connector.execute_multi_result_call("list_sys_oids_all", **kwargs)

    def list_system_message(self, **kwargs):
        return self._connector.execute_multi_result_call("list_system_message", **kwargs)

    def list_task(self, **kwargs):
        return self._connector.execute_multi_result_call("list_task", **kwargs)

    def list_task_all(self, **kwargs):
        return self._connector.execute_multi_result_call("list_task_all", **kwargs)

    def list_template_devices(self, **kwargs):
        return self._connector.execute_multi_result_call("list_template_devices", **kwargs)

    def list_topology(self, **kwargs):
        return self._connector.execute_multi_result_call("list_topology", **kwargs)

    def list_topology_graph(self, **kwargs):
        return self._connector.execute_multi_result_call("list_topology_graph", **kwargs)

    def list_topology_ip(self, **kwargs):
        return self._connector.execute_multi_result_call("list_topology_ip", **kwargs)

    def list_topology_mac(self, **kwargs):
        return self._connector.execute_multi_result_call("list_topology_mac", **kwargs)

    def list_trunk_port(self, **kwargs):
        return self._connector.execute_multi_result_call("list_trunk_port", **kwargs)

    def list_user(self, **kwargs):
        return self._connector.execute_multi_result_call("list_user", **kwargs)

    def list_user_id(self, **kwargs):
        return self._connector.execute_multi_result_call("list_user_id", **kwargs)

    def list_user_site(self, **kwargs):
        return self._connector.execute_multi_result_call("list_user_site", **kwargs)

    def list_view(self, **kwargs):
        return self._connector.execute_multi_result_call("list_view", **kwargs)

    def list_vlan(self, **kwargs):
        return self._connector.execute_multi_result_call("list_vlan", **kwargs)

    def list_vlan_on_port(self, **kwargs):
        return self._connector.execute_multi_result_call("list_vlan_on_port", **kwargs)

    def list_vlan_ports(self, **kwargs):
        return self._connector.execute_multi_result_call("list_vlan_ports", **kwargs)

    def list_vtp_domain(self, **kwargs):
        return self._connector.execute_multi_result_call("list_vtp_domain", **kwargs)

    def mod_advanced_diagnostic(self, **kwargs):
        return self._connector.execute_single_result_call("mod_advanced_diagnostic", **kwargs)

    def mod_advanced_script(self, **kwargs):
        return self._connector.execute_single_result_call("mod_advanced_script", **kwargs)

    def mod_authentication(self, **kwargs):
        return self._connector.execute_single_result_call("mod_authentication", **kwargs)

    def mod_caseinsensitive(self, **kwargs):
        return self._connector.execute_single_result_call("mod_caseinsensitive", **kwargs)

    def mod_change_plan(self, **kwargs):
        """
        Added in NA 10.21.
        """
        return self._connector.execute_single_result_call("mod_change_plan", **kwargs)

    def mod_command_script(self, **kwargs):
        return self._connector.execute_single_result_call("mod_command_script", **kwargs)

    def mod_custom_data(self, **kwargs):
        return self._connector.execute_single_result_call("mod_custom_data", **kwargs)

    def mod_device(self, **kwargs):
        return self._connector.execute_single_result_call("mod_device", **kwargs)

    def mod_device_group(self, **kwargs):
        return self._connector.execute_single_result_call("mod_device_group", **kwargs)

    def mod_device_relationship(self, **kwargs):
        return self._connector.execute_single_result_call("mod_device_relationship", **kwargs)

    def mod_device_template(self, **kwargs):
        return self._connector.execute_single_result_call("mod_device_template", **kwargs)

    def mod_device_template_config(self, **kwargs):
        return self._connector.execute_single_result_call("mod_device_template_config", **kwargs)

    def mod_diagnostic(self, **kwargs):
        return self._connector.execute_single_result_call("mod_diagnostic", **kwargs)

    def mod_group(self, **kwargs):
        return self._connector.execute_single_result_call("mod_group", **kwargs)

    def mod_ip(self, **kwargs):
        return self._connector.execute_single_result_call("mod_ip", **kwargs)

    def mod_metadata(self, **kwargs):
        return self._connector.execute_single_result_call("mod_metadata", **kwargs)

    def mod_metadata_field(self, **kwargs):
        return self._connector.execute_single_result_call("mod_metadata_field", **kwargs)

    def mod_module(self, **kwargs):
        return self._connector.execute_single_result_call("mod_module", **kwargs)

    def mod_oraclecaseinsensitive(self, **kwargs):
        return self._connector.execute_single_result_call("mod_oraclecaseinsensitive", **kwargs)

    def mod_partition(self, **kwargs):
        return self._connector.execute_single_result_call("mod_partition", **kwargs)

    def mod_policy(self, **kwargs):
        return self._connector.execute_single_result_call("mod_policy", **kwargs)

    def mod_policy_rule(self, **kwargs):
        return self._connector.execute_single_result_call("mod_policy_rule", **kwargs)

    def mod_port(self, **kwargs):
        return self._connector.execute_single_result_call("mod_port", **kwargs)

    def mod_resource_id_custom_field_data(self, **kwargs):
        return self._connector.execute_single_result_call("mod_resource_id_custom_field_data", **kwargs)

    def mod_resource_id_pool(self, **kwargs):
        return self._connector.execute_single_result_call("mod_resource_id_pool", **kwargs)

    def mod_role(self, **kwargs):
        return self._connector.execute_single_result_call("mod_role", **kwargs)

    def mod_rule_condition(self, **kwargs):
        return self._connector.execute_single_result_call("mod_rule_condition", **kwargs)

    def mod_server_option(self, **kwargs):
        return self._connector.execute_single_result_call("mod_server_option", **kwargs)

    def mod_site(self, **kwargs):
        return self._connector.execute_single_result_call("mod_site", **kwargs)

    def mod_task(self, **kwargs):
        return self._connector.execute_single_result_call("mod_task", **kwargs)

    def mod_topology_graph(self, **kwargs):
        return self._connector.execute_single_result_call("mod_topology_graph", **kwargs)

    def mod_unmanaged_device(self, **kwargs):
        return self._connector.execute_single_result_call("mod_unmanaged_device", **kwargs)

    def mod_user(self, **kwargs):
        return self._connector.execute_single_result_call("mod_user", **kwargs)

    def mod_user_group(self, **kwargs):
        return self._connector.execute_single_result_call("mod_user_group", **kwargs)

    def mod_vlan(self, **kwargs):
        return self._connector.execute_single_result_call("mod_vlan", **kwargs)

    def mod_vlan_trunk(self, **kwargs):
        return self._connector.execute_single_result_call("mod_vlan_trunk", **kwargs)

    def os_ping(self, **kwargs):
        return self._connector.execute_single_result_call("os_ping", **kwargs)

    def os_traceroute(self, **kwargs):
        return self._connector.execute_single_result_call("os_traceroute", **kwargs)

    def pause_polling(self, **kwargs):
        return self._connector.execute_single_result_call("pause_polling", **kwargs)

    def ping(self, **kwargs):
        return self._connector.execute_single_result_call("ping", **kwargs)

    def port_scan(self, **kwargs):
        return self._connector.execute_single_result_call("port_scan", **kwargs)

    def provision_device(self, **kwargs):
        return self._connector.execute_single_result_call("provision_device", **kwargs)

    def reboot_device(self, **kwargs):
        return self._connector.execute_single_result_call("reboot_device", **kwargs)

    def release_resource_id(self, **kwargs):
        return self._connector.execute_single_result_call("release_resource_id", **kwargs)

    def reload_content(self, **kwargs):
        return self._connector.execute_single_result_call("reload_content", **kwargs)

    def reload_drivers(self, **kwargs):
        return self._connector.execute_single_result_call("reload_drivers", **kwargs)

    def reload_plugins(self, **kwargs):
        return self._connector.execute_single_result_call("reload_plugins", **kwargs)

    def reload_server_options(self, **kwargs):
        return self._connector.execute_single_result_call("reload_server_options", **kwargs)

    def remove_auto_remediation_script(self, **kwargs):
        return self._connector.execute_single_result_call("remove_auto_remediation_script", **kwargs)

    def resume_polling(self, **kwargs):
        return self._connector.execute_single_result_call("resume_polling", **kwargs)

    def run_advanced_script(self, **kwargs):
        return self._connector.execute_single_result_call("run_advanced_script", **kwargs)

    def run_checkdb(self, **kwargs):
        return self._connector.execute_single_result_call("run_checkdb", **kwargs)

    def run_command_script(self, **kwargs):
        return self._connector.execute_single_result_call("run_command_script", **kwargs)

    def run_diagnostic(self, **kwargs):
        return self._connector.execute_single_result_call("run_diagnostic", **kwargs)

    def run_external_application(self, **kwargs):
        return self._connector.execute_single_result_call("run_external_application", **kwargs)

    def run_gc(self, **kwargs):
        return self._connector.execute_single_result_call("run_gc", **kwargs)

    def run_script(self, **kwargs):
        return self._connector.execute_single_result_call("run_script", **kwargs)

    def set_core_status(self, **kwargs):
        return self._connector.execute_single_result_call("set_core_status", **kwargs)

    def set_policy_rule_logic(self, **kwargs):
        return self._connector.execute_single_result_call("set_policy_rule_logic", **kwargs)

    def show_access(self, **kwargs):
        return self._connector.execute_single_result_call("show_access", **kwargs)

    def show_acl(self, **kwargs):
        return self._connector.execute_single_result_call("show_acl", **kwargs)

    def show_basicip(self, **kwargs):
        return self._connector.execute_single_result_call("show_basicip", **kwargs)

    def show_cache_info(self, **kwargs):
        return self._connector.execute_single_result_call("show_cache_info", **kwargs)

    def show_caseinsensitive(self, **kwargs):
        return self._connector.execute_single_result_call("show_caseinsensitive", **kwargs)

    def show_change_plan(self, **kwargs):
        """
        Added in NA 10.21.
        """
        return self._connector.execute_single_result_call("show_change_plan", **kwargs)

    def show_config(self, **kwargs):
        return self._connector.execute_single_result_call("show_config", **kwargs)

    def show_configlet(self, **kwargs):
        return self._connector.execute_single_result_call("show_configlet", **kwargs)

    def show_device(self, **kwargs):
        return self._connector.execute_single_result_call("show_device", **kwargs)

    def show_device_config(self, **kwargs):
        encoded_response =  self._connector.execute_single_result_call("show_device_config",
                                                                       **kwargs)
        return NAInterface._decode_b64_response(encoded_response)

    def show_device_credentials(self, **kwargs):
        return self._connector.execute_single_result_call("show_device_credentials", **kwargs)

    def show_device_family(self, **kwargs):
        return self._connector.execute_single_result_call("show_device_family", **kwargs)

    def show_device_latest_diff(self, **kwargs):
        return self._connector.execute_single_result_call("show_device_latest_diff", **kwargs)

    def show_device_template(self, **kwargs):
        return self._connector.execute_single_result_call("show_device_template", **kwargs)

    def show_device_template_config(self, **kwargs):
        return self._connector.execute_single_result_call("show_device_template_config", **kwargs)

    def show_device_template_config_variables(self, **kwargs):
        return self._connector.execute_single_result_call("show_device_template_config_variables", **kwargs)

    def show_deviceinfo(self, **kwargs):
        return self._connector.execute_single_result_call("show_deviceinfo", **kwargs)

    def show_diagnostic(self, **kwargs):
        return self._connector.execute_single_result_call("show_diagnostic", **kwargs)

    def show_driver(self, **kwargs):
        return self._connector.execute_single_result_call("show_driver", **kwargs)

    def show_event(self, **kwargs):
        return self._connector.execute_single_result_call("show_event", **kwargs)

    def show_group(self, **kwargs):
        return self._connector.execute_single_result_call("show_group", **kwargs)

    def show_icmp(self, **kwargs):
        return self._connector.execute_single_result_call("show_icmp", **kwargs)

    def show_int(self, **kwargs):
        return self._connector.execute_single_result_call("show_int", **kwargs)

    def show_ip(self, **kwargs):
        return self._connector.execute_single_result_call("show_ip", **kwargs)

    def show_latest_access(self, **kwargs):
        return self._connector.execute_single_result_call("show_latest_access", **kwargs)

    def show_metadata(self, **kwargs):
        return self._connector.execute_single_result_call("show_metadata", **kwargs)

    def show_metadata_field(self, **kwargs):
        return self._connector.execute_single_result_call("show_metadata_field", **kwargs)

    def show_module(self, **kwargs):
        return self._connector.execute_single_result_call("show_module", **kwargs)

    def show_oraclecaseinsensitive(self, **kwargs):
        return self._connector.execute_single_result_call("show_oraclecaseinsensitive", **kwargs)

    def show_ospfneighbor(self, **kwargs):
        return self._connector.execute_single_result_call("show_ospfneighbor", **kwargs)

    def show_permission(self, **kwargs):
        return self._connector.execute_single_result_call("show_permission", **kwargs)

    def show_policy(self, **kwargs):
        return self._connector.execute_single_result_call("show_policy", **kwargs)

    def show_policy_compliance(self, **kwargs):
        return self._connector.execute_multi_result_call("show_policy_compliance", **kwargs)

    def show_policy_rule(self, **kwargs):
        return self._connector.execute_single_result_call("show_policy_rule", **kwargs)

    def show_polling_status(self, **kwargs):
        return self._connector.execute_single_result_call("show_polling_status", **kwargs)

    def show_port(self, **kwargs):
        return self._connector.execute_single_result_call("show_port", **kwargs)

    def show_resource_id(self, **kwargs):
        return self._connector.execute_single_result_call("show_resource_id", **kwargs)

    def show_resource_id_custom_field_data(self, **kwargs):
        return self._connector.execute_single_result_call("show_resource_id_custom_field_data", **kwargs)

    def show_resource_id_pool(self, **kwargs):
        return self._connector.execute_single_result_call("show_resource_id_pool", **kwargs)

    def show_role(self, **kwargs):
        return self._connector.execute_single_result_call("show_role", **kwargs)

    def show_routing(self, **kwargs):
        return self._connector.execute_single_result_call("show_routing", **kwargs)

    def show_rule_condition(self, **kwargs):
        return self._connector.execute_single_result_call("show_rule_condition", **kwargs)

    def show_rule_compliance(self, **kwargs):
        """
        Added in NA 10.40.
        """
        return self._connector.execute_multi_result_call("show_rule_compliance", **kwargs)

    def show_script(self, **kwargs):
        return self._connector.execute_single_result_call("show_script", **kwargs)

    def show_server_option(self, **kwargs):
        return self._connector.execute_single_result_call("show_server_option", **kwargs)

    def show_service_type(self, **kwargs):
        return self._connector.execute_single_result_call("show_service_type", **kwargs)

    def show_session(self, **kwargs):
        return self._connector.execute_single_result_call("show_session", **kwargs)

    def show_session_commands(self, **kwargs):
        return self._connector.execute_single_result_call("show_session_commands", **kwargs)

    def show_snapshot(self, **kwargs):
        return self._connector.execute_single_result_call("show_snapshot", **kwargs)

    def show_system_message(self, **kwargs):
        return self._connector.execute_single_result_call("show_system_message", **kwargs)

    def show_task(self, **kwargs):
        return self._connector.execute_single_result_call("show_task", **kwargs)

    def show_topology(self, **kwargs):
        return self._connector.execute_single_result_call("show_topology", **kwargs)

    def show_user(self, **kwargs):
        return self._connector.execute_single_result_call("show_user", **kwargs)

    def show_user_group(self, **kwargs):
        return self._connector.execute_single_result_call("show_user_group", **kwargs)

    def show_version(self, **kwargs):
        return self._connector.execute_single_result_call("show_version", **kwargs)

    def show_vlan(self, **kwargs):
        return self._connector.execute_single_result_call("show_vlan", **kwargs)

    def show_vtp(self, **kwargs):
        return self._connector.execute_single_result_call("show_vtp", **kwargs)

    def stop_task(self, **kwargs):
        return self._connector.execute_single_result_call("stop_task", **kwargs)

    def stop_task_all(self, **kwargs):
        return self._connector.execute_single_result_call("stop_task_all", **kwargs)

    def synchronize(self, **kwargs):
        return self._connector.execute_single_result_call("synchronize", **kwargs)

    def test_config(self, **kwargs):
        return self._connector.execute_single_result_call("test_config", **kwargs)

    def test_software(self, **kwargs):
        return self._connector.execute_single_result_call("test_software", **kwargs)

    def undeploy_image(self, **kwargs):
        return self._connector.execute_single_result_call("undeploy_image", **kwargs)

    def update_dynamic_group(self, **kwargs):
        return self._connector.execute_single_result_call("update_dynamic_group", **kwargs)
    
    def snmp_get(self, **kwargs):
        return self._connector.execute_single_result_call("snmp_get", **kwargs)
    
    def snmp_set(self, **kwargs):
        return self._connector.execute_single_result_call("snmp_set", **kwargs)
    
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
        settings = ZeepSettings(strict=False)
        zeep_client = ZeepClient(wsdl=self._wsdl_url, transport=transport_to_bind, settings=settings)
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
            if api_response.Status in ['200', '201', '204', '221', '501', '511']:
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
            pass
        return []

    def _get_extracted_single_result(self, api_result):
        try:
            if api_result.ResultSet.Row:
                return api_result.ResultSet.Row[0]
        except AttributeError:
            try:
                return api_result.Text
            except AttributeError:
                pass
        return None

    def _get_api_query_response(self, command_to_call, **kwargs):
        query_parms = self._get_api_parameters("{0}InputParms".format(command_to_call), **kwargs)
        try:
            api_response = self._zeep_interface[command_to_call](query_parms)
        except ZeepFaultException:
            _NAConnector._raise_hpna_fault_exception()
        self._validate_api_response(api_response)
        return api_response

    def execute_single_result_call(self, command_to_call, **kwargs):
        api_response = self._get_api_query_response(command_to_call, **kwargs)
        extracted_result = self._get_extracted_single_result(api_response)
        return extracted_result

    def execute_multi_result_call(self, command_to_call, **kwargs):
        api_response = self._get_api_query_response(command_to_call, **kwargs)
        extracted_result = self._get_extracted_result_set(api_response)
        return extracted_result
