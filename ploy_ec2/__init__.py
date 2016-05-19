from __future__ import print_function, unicode_literals
from lazy import lazy
from operator import itemgetter
from ploy.common import BaseMaster, StartupScriptMixin
from ploy.plain import Instance as BaseInstance
from ploy.config import BaseMassager, BooleanMassager, IntegerMassager
from ploy.config import HooksMassager, PathMassager
from ploy.config import StartupScriptMassager
import argparse
import datetime
import logging
import os
import paramiko
import re
import sys
import time


log = logging.getLogger('ploy_ec2')


re_hex_byte = '[0-9a-fA-F]{2}'
re_fingerprint = "(?:%s:){15}%s" % (re_hex_byte, re_hex_byte)
re_fingerprint_info = "^.*?(\d*)\s*(%s)(.*)$" % re_fingerprint
fingerprint_regexp = re.compile(re_fingerprint_info, re.MULTILINE)
fingerprint_type_regexp = re.compile("\((.*?)\)")


def get_fingerprints(data):
    fingerprints = []
    for match in fingerprint_regexp.findall(data):
        info = dict(keylen=match[0], fingerprint=match[1])
        try:
            info['keylen'] = int(info['keylen'])
        except ValueError:
            info['keylen'] = None
        key_info = match[2].lower()
        if '(rsa1)' in key_info or 'ssh_host_key' in key_info:
            info['keytype'] = 'rsa1'
        elif '(rsa)' in key_info or 'ssh_host_rsa_key' in key_info:
            info['keytype'] = 'rsa'
        elif '(dsa)' in key_info or 'ssh_host_dsa_key' in key_info:
            info['keytype'] = 'dsa'
        elif '(ecdsa)' in key_info or 'ssh_host_ecdsa_key' in key_info:
            info['keytype'] = 'ecdsa'
        else:
            match = fingerprint_type_regexp.search(key_info)
            if match:
                info['keytype'] = match.group(1)
        fingerprints.append(info)
    return sorted(fingerprints, key=itemgetter('fingerprint'))


class ConnMixin(object):
    @lazy
    def ec2_conn(self):
        region_id = self.config.get(
            'region',
            self.master.master_config.get('region', None))
        if region_id is None:
            log.error("No region set in ec2-instance:%s or ec2-master:%s config" % (self.id, self.master.id))
            sys.exit(1)
        return self.master.get_ec2_conn(region_id)


class Instance(BaseInstance, StartupScriptMixin, ConnMixin):
    max_startup_script_size = 16 * 1024
    sectiongroupname = 'ec2-instance'

    def get_massagers(self):
        return get_instance_massagers()

    def get_console_output(self):
        return self.ec2_instance.get_console_output().output

    def get_fingerprints(self):
        output = self.ec2_instance.get_console_output().output
        if output is None or output.strip() == '':
            raise paramiko.SSHException('No console output (yet) for %s' % self.get_host())
        return get_fingerprints(output)

    def get_fingerprint(self):
        for fingerprint in self.get_fingerprints():
            if fingerprint.get('keytype') == 'rsa':
                return fingerprint['fingerprint']
        raise paramiko.SSHException('Fingerprint not in console output of %s' % self.get_host())

    @lazy
    def ec2_instance(self):
        ec2_instances = []
        for reservation in self.ec2_conn.get_all_instances():
            for ec2_instance in reservation.instances:
                if ec2_instance.state in ['shutting-down', 'terminated']:
                    continue
                tags = getattr(ec2_instance, 'tags', {})
                if not tags or not tags.get('Name'):
                    groups = set(x.name for x in ec2_instance.groups)
                    if groups != self.config['securitygroups']:
                        continue
                else:
                    if tags['Name'] != self.id:
                        continue
                ec2_instances.append(ec2_instance)
        if len(ec2_instances) < 1:
            log.info("Instance '%s' unavailable.", self.id)
            return
        elif len(ec2_instances) > 1:
            log.warn("More than one instance found, using first.")
        ec2_instance = ec2_instances[0]
        log.info("Instance '%s' (%s) available.", self.id, ec2_instance.id)
        return ec2_instance

    def image(self):
        images = self.ec2_conn.get_all_images([self.config['image']])
        return images[0]

    def securitygroups(self):
        sgs = []
        for sgid in self.config.get('securitygroups', []):
            sgs.append(self.master.securitygroups.get(sgid, create=True))
        return sgs

    def get_host(self):
        return self.ec2_instance.public_dns_name

    def _status(self):
        ec2_instance = self.ec2_instance
        if ec2_instance is None:
            return 'unavailable'
        return ec2_instance.state

    def status(self):
        ec2_instance = self.ec2_instance
        if ec2_instance is None:
            return
        status = self._status()
        if status != 'running':
            log.info("Instance state: %s", status)
            return
        log.info("Instance running.")
        log.info("Instances DNS name %s", ec2_instance.dns_name)
        log.info("Instances private DNS name %s", ec2_instance.private_dns_name)
        log.info("Instances public DNS name %s", ec2_instance.public_dns_name)
        output = ec2_instance.get_console_output().output
        if output is None or output.strip() == '':
            log.warn("Console output not (yet) available. SSH fingerprint verification not possible.")
        else:
            log.info("Console output available. SSH fingerprint verification possible.")

    def stop(self):
        from boto.exception import EC2ResponseError

        ec2_instance = self.ec2_instance
        if ec2_instance is None:
            return
        if ec2_instance.state != 'running':
            log.info("Instance state: %s", ec2_instance.state)
            log.info("Instance not stopped")
            return
        try:
            rc = self.ec2_conn.stop_instances([ec2_instance.id])
            ec2_instance._update(rc[0])
        except EC2ResponseError as e:
            log.error(e.error_message)
            if 'cannot be stopped' in e.error_message:
                log.error("Did you mean to terminate the instance?")
            log.info("Instance not stopped")
            return
        log.info("Instance stopped")

    def terminate(self):
        ec2_instance = self.ec2_instance
        if ec2_instance is None:
            return
        if ec2_instance.state not in ('running', 'stopped'):
            log.info("Instance state: %s", ec2_instance.state)
            log.info("Instance not terminated")
            return
        volumes_to_delete = []
        if 'snapshots' in self.config and self.config.get('delete-volumes-on-terminate', False):
            snapshots = self.master.snapshots
            volumes = dict((x.volume_id, d) for d, x in ec2_instance.block_device_mapping.items())
            for volume in self.ec2_conn.get_all_volumes(volume_ids=volumes.keys()):
                snapshot_id = volume.snapshot_id
                if snapshot_id in snapshots:
                    volumes_to_delete.append(volume)
        rc = self.ec2_conn.terminate_instances([ec2_instance.id])
        ec2_instance._update(rc[0])
        log.info("Instance terminating")
        if len(volumes_to_delete):
            log.info("Instance terminating, waiting until it's terminated")
            while ec2_instance.state != 'terminated':
                time.sleep(5)
                sys.stdout.write(".")
                sys.stdout.flush()
                ec2_instance.update()
            sys.stdout.write("\n")
            sys.stdout.flush()
            log.info("Instance terminated")
            for volume in volumes_to_delete:
                log.info("Deleting volume %s", volume.id)
                volume.delete()

    def start(self, overrides=None):
        config = self.get_config(overrides)
        placement = config['placement']
        ec2_instance = self.ec2_instance
        if ec2_instance is not None:
            log.info("Instance state: %s", ec2_instance.state)
            if ec2_instance.state == 'stopping':
                log.info("The instance is currently stopping")
                return
            if ec2_instance.state == 'stopped':
                log.info("Starting stopped instance '%s'" % self.id)
                ec2_instance.modify_attribute('instanceType', config.get('instance_type', 'm1.small'))
                if 'device_map' in config:
                    ec2_instance.modify_attribute('blockDeviceMapping', config.get('device_map', None))
                ec2_instance.start()
            else:
                log.info("Instance already started, waiting until it's available")
        else:
            log.info("Creating instance '%s'" % self.id)
            reservation = self.image().run(
                1, 1, config['keypair'],
                instance_type=config.get('instance_type', 'm1.small'),
                block_device_map=config.get('device_map', None),
                security_groups=self.securitygroups(),
                user_data=self.startup_script(overrides=overrides),
                placement=placement)
            ec2_instance = reservation.instances[0]
            log.info("Instance '%s' created, waiting until it's available", ec2_instance.id)
        while ec2_instance.state != 'running':
            if ec2_instance.state != 'pending':
                log.error("Something went wrong, instance status: %s", ec2_instance.state)
                return
            time.sleep(5)
            sys.stdout.write(".")
            sys.stdout.flush()
            ec2_instance.update()
        sys.stdout.write("\n")
        sys.stdout.flush()
        self.ec2_conn.create_tags([ec2_instance.id], {"Name": self.id})
        ip = config.get('ip', None)
        if ip is not None:
            addresses = [x for x in self.ec2_conn.get_all_addresses()
                         if x.public_ip == ip]
            if len(addresses) > 0:
                if addresses[0].instance_id != ec2_instance.id:
                    if ec2_instance.use_ip(addresses[0]):
                        log.info("Assigned IP %s to instance '%s'", addresses[0].public_ip, self.id)
                    else:
                        log.error("Couldn't assign IP %s to instance '%s'", addresses[0].public_ip, self.id)
                        return
        volumes = dict((x.id, x) for x in self.ec2_conn.get_all_volumes())
        for volume_id, device in config.get('volumes', []):
            if volume_id not in volumes:
                try:
                    volume = self.master.volumes[volume_id].volume(placement)
                except KeyError:
                    log.error("Unknown volume %s" % volume_id)
                    return
            else:
                volume = volumes[volume_id]
            if volume_id != volume.id:
                volume_id = "%s (%s)" % (volume_id, volume.id)
            if volume.attachment_state() == 'attached':
                if volume.attach_data.instance_id == ec2_instance.id:
                    continue
                log.error(
                    "Volume %s already attached to instance %s.",
                    volume.id, volume.attach_data.instance_id)
                sys.exit(1)
            log.info("Attaching storage %s on %s" % (volume_id, device))
            self.ec2_conn.attach_volume(volume.id, ec2_instance.id, device)

        snapshots = dict((x.id, x) for x in self.ec2_conn.get_all_snapshots(owner="self"))
        for snapshot_id, device in config.get('snapshots', []):
            if snapshot_id not in snapshots:
                log.error("Unknown snapshot %s" % snapshot_id)
                return
            log.info("Creating volume from snapshot: %s" % snapshot_id)
            snapshot = snapshots[snapshot_id]
            volume = self.ec2_conn.create_volume(snapshot.volume_size, placement, snapshot_id)
            log.info("Attaching storage (%s on %s)" % (volume.id, device))
            self.ec2_conn.attach_volume(volume.id, ec2_instance.id, device)

        return ec2_instance

    def snapshot(self, devs=None):
        if devs is None:
            devs = set()
        else:
            devs = set(devs)
        volume_ids = [x[0] for x in self.config.get('volumes', []) if x[1] in devs]
        volumes = dict((x.id, x) for x in self.ec2_conn.get_all_volumes(volume_ids=volume_ids))
        for volume_id in volume_ids:
            volume = volumes[volume_id]
            date = datetime.datetime.now().strftime("%Y%m%d%H%M")
            description = "%s-%s" % (date, volume_id)
            log.info("Creating snapshot for volume %s on %s (%s)" % (volume_id, self.id, description))
            volume.create_snapshot(description=description)


class Connection(ConnMixin):
    """ This is more or less a dummy object to get a connection to AWS for
        Fabric scripts. """
    def __init__(self, master, sid, config):
        self.id = sid
        self.master = master
        self.config = config

    def get_host(self):
        return None


class Volume(object):
    def __init__(self, name, config, master):
        self.name = name
        self.config = config
        self.master = master

    def volume(self, placement):
        volumes = {}
        for volume in self.master.ec2_conn.get_all_volumes():
            name_tag = volume.tags.get('Name')
            if not name_tag:
                continue
            volumes[name_tag] = volume
        if self.name in volumes:
            return volumes[self.name]
        if 'size' not in self.config:
            log.error("Missing option 'size' for [ec2-volume:%s].", self.name)
        volume = self.master.ec2_conn.create_volume(
            self.config['size'], placement,
            snapshot=self.config.get('snapshot'),
            volume_type=self.config.get('volume_type'),
            iops=self.config.get('iops'),
            encrypted=self.config.get('encrypted'))
        self.master.ec2_conn.create_tags(volume.id, {'Name': self.name})
        return volume

    def __contains__(self, name):
        return name in self.volumes


class InfoBase(object):
    def __init__(self, master):
        self.master = master
        self.config = self.master.main_config.get(self.sectiongroupname, {})
        self._cache = {}

    def __getitem__(self, key):
        if key not in self._cache:
            self._cache[key] = self.klass(key, self.config[key], self.master)
        return self._cache[key]


class Volumes(InfoBase):
    sectiongroupname = 'ec2-volume'
    klass = Volume

    def __init__(self, master):
        InfoBase.__init__(self, master)


class Securitygroups(object):
    def __init__(self, master):
        self.master = master
        self.update()

    def update(self):
        self.securitygroups = dict((x.name, x) for x in self.master.ec2_conn.get_all_security_groups())

    def get(self, sgid, create=False):
        if 'ec2-securitygroup' not in self.master.main_config:
            log.error("No security groups defined in configuration.")
            sys.exit(1)
        securitygroup = self.master.main_config['ec2-securitygroup'][sgid]
        if sgid not in self.securitygroups:
            if not create:
                raise KeyError
            if 'description' in securitygroup:
                description = securitygroup['description']
            else:
                description = "security settings for %s" % sgid
            sg = self.master.ec2_conn.create_security_group(sgid, description)
            self.update()
        else:
            sg = self.securitygroups[sgid]
        if create:
            from boto.ec2.securitygroup import GroupOrCIDR

            rules = {}
            for rule in sg.rules:
                for grant in rule.grants:
                    if grant.cidr_ip:
                        key = (
                            rule.ip_protocol,
                            int(rule.from_port),
                            int(rule.to_port),
                            grant.cidr_ip)
                    else:
                        key = (
                            rule.ip_protocol,
                            int(rule.from_port),
                            int(rule.to_port),
                            grant.name)
                    rules[key] = (rule, grant)
            # cleanup rules from config
            connections = []
            for connection in securitygroup['connections']:
                if connection[3].endswith("-%s" % sg.owner_id):
                    # backward compatibility, strip the owner_id
                    connection = (
                        connection[0],
                        connection[1],
                        connection[2],
                        connection[3].rstrip("-%s" % sg.owner_id))
                connections.append(connection)
            # delete rules which aren't defined in the config
            for connection in set(rules).difference(connections):
                rule, grant = rules[connection]
                status = sg.revoke(
                    ip_protocol=rule.ip_protocol,
                    from_port=int(rule.from_port),
                    to_port=int(rule.to_port),
                    cidr_ip=grant.cidr_ip,
                    src_group=grant)
                if status:
                    del rules[connection]
            for connection in connections:
                if connection in rules:
                    continue
                cidr_ip = None
                src_group = None
                if '/' in connection[3]:
                    cidr_ip = connection[3]
                else:
                    src_group = GroupOrCIDR()
                    src_group.name = connection[3]
                    src_group.ownerid = sg.owner_id
                sg.authorize(
                    ip_protocol=connection[0],
                    from_port=connection[1],
                    to_port=connection[2],
                    cidr_ip=cidr_ip,
                    src_group=src_group)
        return sg


class MasterConnection(BaseInstance, ConnMixin):
    def status(self):
        instances = {}
        known = {}
        unknown = set()
        for reservation in self.ec2_conn.get_all_instances():
            for ec2_instance in reservation.instances:
                instance = instances.setdefault(ec2_instance.id, {})
                instance['id'] = ec2_instance.id
                instance['status'] = ec2_instance.state
                instance['ip'] = ec2_instance.ip_address
                tags = getattr(ec2_instance, 'tags', {})
                name = instance['name'] = tags['Name']
                if name in self.master.ctrl.instances:
                    known.setdefault(name, set()).add(ec2_instance.id)
                else:
                    unknown.add(ec2_instance.id)
        for name in sorted(self.master.instances):
            if name == self.id:
                continue
            if name in known:
                infos = [instances[x] for x in known[name]]
            else:
                infos = [dict(
                    id='n/a',
                    status='terminated',
                    name=name,
                    ip=self.master.instances[name].config.get('ip'))]
            for info in infos:
                log.info("%-10s %-20s %15s %15s" % (info['id'], info['name'], info['status'], info['ip']))
        if unknown:
            log.warn("Unknown instances:")
            for iid in unknown:
                instance = instances[iid]
                log.warn("%-10s %-20s %15s %15s" % (iid, instance['name'], instance['status'], instance['ip']))


class Master(BaseMaster):
    sectiongroupname = 'ec2-master'
    section_info = {
        None: Instance,
        'ec2-instance': Instance,
        'ec2-connection': Connection}

    def __init__(self, *args, **kwargs):
        BaseMaster.__init__(self, *args, **kwargs)
        self.instance = MasterConnection(self, self.id, self.master_config)
        self.instance.sectiongroupname = 'ez-master'
        self.instances[self.id] = self.instance

    @lazy
    def credentials(self):
        aws_id = None
        aws_key = None
        if 'AWS_ACCESS_KEY_ID' not in os.environ or 'AWS_SECRET_ACCESS_KEY' not in os.environ:
            try:
                id_file = self.master_config['access-key-id']
                key_file = self.master_config['secret-access-key']
            except KeyError:
                log.error("You need to either set the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables or add the path to files containing them to the config. You can find the values at http://aws.amazon.com under 'Your Account'-'Security Credentials'.")
                sys.exit(1)
            id_file = os.path.abspath(os.path.expanduser(id_file))
            if not os.path.exists(id_file):
                log.error("The access-key-id file at '%s' doesn't exist.", id_file)
                sys.exit(1)
            key_file = os.path.abspath(os.path.expanduser(key_file))
            if not os.path.exists(key_file):
                log.error("The secret-access-key file at '%s' doesn't exist.", key_file)
                sys.exit(1)
            aws_id = open(id_file).readline().strip()
            aws_key = open(key_file).readline().strip()
        return (aws_id, aws_key)

    @lazy
    def regions(self):
        from boto.ec2 import regions

        (aws_id, aws_key) = self.credentials
        return dict((x.name, x) for x in regions(
            aws_access_key_id=aws_id, aws_secret_access_key=aws_key
        ))

    @property
    def snapshots(self):
        return dict((x.id, x) for x in self.ec2_conn.get_all_snapshots(owner="self"))

    def get_ec2_conn(self, region_id):
        (aws_id, aws_key) = self.credentials
        try:
            region = self.regions[region_id]
        except KeyError:
            log.error("Region '%s' not found in regions returned by EC2.", region_id)
            sys.exit(1)
        return region.connect(
            aws_access_key_id=aws_id, aws_secret_access_key=aws_key
        )

    @lazy
    def ec2_conn(self):
        region_id = self.master_config.get('region', None)
        if region_id is None:
            log.error("No region set in ec2-master:%s config" % self.id)
            sys.exit(1)
        return self.get_ec2_conn(region_id)

    @lazy
    def securitygroups(self):
        return Securitygroups(self)

    @lazy
    def volumes(self):
        return Volumes(self)


class SecuritygroupsMassager(BaseMassager):
    def __call__(self, config, sectionname):
        value = BaseMassager.__call__(self, config, sectionname)
        securitygroups = []
        for securitygroup in value.split(','):
            securitygroups.append(securitygroup.strip())
        return set(securitygroups)


class DevicemapMassager(BaseMassager):
    def __call__(self, config, sectionname):
        from boto.ec2.blockdevicemapping import BlockDeviceMapping
        from boto.ec2.blockdevicemapping import BlockDeviceType

        value = BaseMassager.__call__(self, config, sectionname)
        device_map = BlockDeviceMapping()
        for mapping in value.split():
            device_path, ephemeral_name = mapping.split(':')
            device = BlockDeviceType()
            device.ephemeral_name = ephemeral_name
            device_map[device_path] = device
        return device_map


class VolumesMassager(BaseMassager):
    def __call__(self, config, sectionname):
        value = BaseMassager.__call__(self, config, sectionname)
        volumes = []
        for line in value.split('\n'):
            volume = line.split()
            if not len(volume):
                continue
            volumes.append((volume[0], volume[1]))
        return tuple(volumes)


class SnapshotsMassager(BaseMassager):
    def __call__(self, config, sectionname):
        value = BaseMassager.__call__(self, config, sectionname)
        snapshots = []
        for line in value.split('\n'):
            snapshot = line.split()
            if not len(snapshot):
                continue
            snapshots.append((snapshot[0], snapshot[1]))
        return tuple(snapshots)


class ConnectionsMassager(BaseMassager):
    def __call__(self, config, sectionname):
        value = BaseMassager.__call__(self, config, sectionname)
        connections = []
        for line in value.split('\n'):
            connection = line.split()
            if not len(connection):
                continue
            connections.append((connection[0], int(connection[1]),
                                int(connection[2]), connection[3]))
        return tuple(connections)


class ListSnapshotsCmd(object):

    def __init__(self, ctrl):
        self.ctrl = ctrl

    def __call__(self, argv, help):
        parser = argparse.ArgumentParser(
            prog="%s list snapshots" % self.ctrl.progname,
            description=help)
        parser.parse_args(argv)
        snapshots = []
        for master in self.ctrl.get_masters('snapshots'):
            snapshots.extend(master.snapshots.values())
        snapshots = sorted(snapshots, key=lambda x: x.start_time)
        print("id            time                      size   volume       progress description")
        for snapshot in snapshots:
            info = snapshot.__dict__
            print("{id} {start_time} {volume_size:>4} GB {volume_id} {progress:>8} {description}".format(**info))


def get_instance_massagers(sectiongroupname='instance'):
    return [
        HooksMassager(sectiongroupname, 'hooks'),
        PathMassager(sectiongroupname, 'ssh-key-filename'),
        StartupScriptMassager(sectiongroupname, 'startup_script'),
        SecuritygroupsMassager(sectiongroupname, 'securitygroups'),
        VolumesMassager(sectiongroupname, 'volumes'),
        DevicemapMassager(sectiongroupname, 'device_map'),
        SnapshotsMassager(sectiongroupname, 'snapshots'),
        BooleanMassager(sectiongroupname, 'delete-volumes-on-terminate')]


def get_list_commands(ctrl):
    return [
        ('snapshots', ListSnapshotsCmd(ctrl))]


def get_massagers():
    massagers = []

    sectiongroupname = 'ec2-master'
    massagers.extend([
        PathMassager(sectiongroupname, 'access-key-id'),
        PathMassager(sectiongroupname, 'secret-access-key')])

    sectiongroupname = 'ec2-instance'
    massagers.extend(get_instance_massagers(sectiongroupname))

    sectiongroupname = 'ec2-securitygroup'
    massagers.extend([
        ConnectionsMassager(sectiongroupname, 'connections')])

    sectiongroupname = 'ec2-volume'
    massagers.extend([
        IntegerMassager(sectiongroupname, 'size'),
        IntegerMassager(sectiongroupname, 'iops'),
        BooleanMassager(sectiongroupname, 'encrypted')])

    return massagers


def get_macro_cleaners(main_config):
    def clean_instance(macro):
        for key in macro.keys():
            if key in ('ip', 'volumes'):
                del macro[key]

    return {"ec2-instance": clean_instance}


def get_masters(ctrl):
    masters = ctrl.config.get('ec2-master', {})
    for master, master_config in masters.items():
        yield Master(ctrl, master, master_config)


plugin = dict(
    get_list_commands=get_list_commands,
    get_massagers=get_massagers,
    get_macro_cleaners=get_macro_cleaners,
    get_masters=get_masters)
