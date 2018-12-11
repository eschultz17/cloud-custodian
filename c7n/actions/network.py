# Copyright 2017-2018 Capital One Services, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import six

from c7n.exceptions import PolicyExecutionError
from c7n import utils

from .core import Action


class ModifyVpcSecurityGroupsAction(Action):
    """Common actions for modifying security groups on a resource

    Can target either physical groups as a list of group ids or
    symbolic groups like 'matched', 'network-location' or 'all'. 'matched' uses
    the annotations of the 'security-group' interface filter. 'network-location' uses
    the annotations of the 'network-location' interface filter for `SecurityGroupMismatch`.

    Note an interface always gets at least one security group, so
    we mandate the specification of an isolation/quarantine group
    that can be specified if there would otherwise be no groups.

    type: modify-security-groups
        add: []
        remove: [] | matched | network-location
        isolation-group: sg-xyz
    """
    schema_alias = True
    schema = {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'type': {'enum': ['modify-security-groups']},
            'add': {'oneOf': [
                {'type': 'string'},
                {'type': 'array', 'items': {
                    'type': 'string'}}]},
            'remove': {'oneOf': [
                {'type': 'array', 'items': {
                    'type': 'string'}},
                {'enum': [
                    'matched', 'network-location', 'all',
                    {'type': 'string'}]}]},
            'isolation-group': {'oneOf': [
                {'type': 'string'},
                {'type': 'array', 'items': {
                    'type': 'string'}}]}},
        'anyOf': [
            {'required': ['isolation-group', 'remove', 'type']},
            {'required': ['add', 'remove', 'type']},
            {'required': ['add', 'type']}]
    }

    def get_security_group_ids_and_names(self, data):
        """
        Returns Security Group ids and names.
        Raises PolicyExecutionError if group names are not found
        """
        group_ids = []
        group_names = []

        # Can assume sg's won't start with 'sg-'
        # https://docs.aws.amazon.com/cli/latest/reference/ec2/create-security-group.html
        if isinstance(data, list):
            group_ids = [id for id in data if id.startswith('sg-')]
            group_names = [name for name in data if not name.startswith('sg-')]
        elif isinstance(data, six.string_types):
            if data.startswith('sg-') or data in ["all", "matched", "network-location"]:
                group_ids = [data]
            else:
                group_names = [data]

        if len(group_names) > 0:
            client = utils.local_session(
                self.manager.session_factory).client('ec2')

            filtered_sgs = client.describe_security_groups(
                Filters=[
                    {
                        'Name': 'group-name',
                        'Values': group_names
                    }
                ]
            )['SecurityGroups']

            filtered_ids = [
                {
                    'GroupName': a.get('GroupName', None),
                    'GroupId': a.get('GroupId', None),
                    'VpcId': a.get('VpcId', None)
                }
                for a in filtered_sgs
            ]
            if not filtered_ids or len(filtered_ids) == 0:
                raise PolicyExecutionError(
                    "Security Groups not found: requested: %s, found: %s" %
                    (group_names, filtered_ids))
            group_names = filtered_ids
        return group_ids, group_names

    def parse_groups(self, r, target_group_ids, target_group_names, rgroups, action):
        """
        Parse user-provided groups in policy and resolves security groups
        from either names or whitelisted names (matched, network-location, all)
        """
        groups = []

        if action == 'remove':
            # Parse remove_groups
            if 'matched' in target_group_ids:
                return r.get('c7n:matched-security-groups', ())
            elif 'network-location' in target_group_ids:
                for reason in r.get('c7n:NetworkLocation', ()):
                    if reason['reason'] == 'SecurityGroupMismatch':
                        return list(reason['security-groups'])
            elif 'all' in target_group_ids:
                return rgroups

        group_names_ids = [g['GroupId'] for g in target_group_names
            if g.get('VpcId', None) == r.get('VpcId', None)]
        # removes duplicate values
        groups = list(set(group_names_ids + target_group_ids))

        return groups

    def get_resource_security_groups(self, r, metadata_key=None):
        """
        Returns Security Groups based for a variety of vpc attached resources
        """
        if r.get('Groups'):
            if metadata_key and isinstance(r['Groups'][0], dict):
                rgroups = [g[metadata_key] for g in r['SecurityGroups']]
            else:
                rgroups = [g['GroupId'] for g in r['Groups']]
        elif r.get('SecurityGroups'):
            # elb, ec2, elasticache, efs, dax vpc resource security groups
            if metadata_key and isinstance(r['SecurityGroups'][0], dict):
                rgroups = [g[metadata_key] for g in r['SecurityGroups']]
            else:
                rgroups = [g for g in r['SecurityGroups']]
        elif r.get('VpcSecurityGroups'):
            # rds resource security groups
            if metadata_key and isinstance(r['VpcSecurityGroups'][0], dict):
                rgroups = [g[metadata_key] for g in r['VpcSecurityGroups']]
            else:
                rgroups = [g for g in r['VpcSecurityGroups']]
        elif r.get('VPCOptions', {}).get('SecurityGroupIds', []):
            # elasticsearch resource security groups
            if metadata_key and isinstance(
                    r['VPCOptions']['SecurityGroupIds'][0], dict):
                rgroups = [g[metadata_key] for g in r[
                    'VPCOptions']['SecurityGroupIds']]
            else:
                rgroups = [g for g in r['VPCOptions']['SecurityGroupIds']]
        # use as substitution for 'Groups' or '[Vpc]SecurityGroups'
        # unsure if necessary - defer to coverage report
        elif metadata_key and r.get(metadata_key):
            rgroups = [g for g in r[metadata_key]]

        return rgroups

    def get_groups(self, resources, metadata_key=None):
        """Parse policies to get lists of security groups to attach to each resource

        For each input resource, parse the various add/remove/isolation-
        group policies for 'modify-security-groups' to find the resulting
        set of VPC security groups to attach to that resource.

        The 'metadata_key' parameter can be used for two purposes at
        the moment; The first use is for resources' APIs that return a
        list of security group IDs but use a different metadata key
        than 'Groups' or 'SecurityGroups'.

        The second use is for when there are richer objects in the 'Groups' or
        'SecurityGroups' lists. The custodian actions need to act on lists of
        just security group IDs, so the metadata_key can be used to select IDs
        from the richer objects in the provided lists.

        Returns a list of lists containing the resulting VPC security groups
        that should end up on each resource passed in.

        :param resources: List of resources containing VPC Security Groups
        :param metadata_key: Metadata key for security groups list
        :return: List of lists of security groups per resource

        """
        # parse the add, remove, and isolation group params to return the
        # list of security groups that will end up on the resource
        # target_group_ids = self.data.get('groups', 'matched')

        add_ids, add_names = self.get_security_group_ids_and_names(
            self.data.get('add', None))
        remove_ids, remove_names = self.get_security_group_ids_and_names(
            self.data.get('remove', None))
        isolation_ids, isolation_names = self.get_security_group_ids_and_names(
            self.data.get('isolation-group', None))
        return_groups = []

        for idx, r in enumerate(resources):
            rgroups = self.get_resource_security_groups(r, metadata_key)
            add_groups = self.parse_groups(r, add_ids, add_names, rgroups, "add")
            remove_groups = self.parse_groups(r, remove_ids, remove_names, rgroups, "remove")

            # seems extraneous with list?
            # if not remove_groups and not add_groups:
            #     continue

            for g in remove_groups:
                if g in rgroups:
                    rgroups.remove(g)
            for g in add_groups:
                if g not in rgroups:
                    rgroups.append(g)

            if not rgroups:
                rgroups = self.parse_groups(r, isolation_ids, isolation_names, rgroups, "isolation")

            return_groups.append(rgroups)

        return return_groups
