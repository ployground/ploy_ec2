from __future__ import unicode_literals
from mock import patch
from ploy import Controller
from unittest import TestCase
import os
import tempfile
import shutil


class MockConsoleOutput(object):
    def __init__(self, output):
        self.output = output


class MockInstance(object):
    def __init__(self):
        self.state = 'running'
        self._public_ip = "257.1.2.3"
        self._private_ip = "10.0.0.1"
        self._console_output = ''

    @property
    def dns_name(self):
        return "ec2-%s.example.com" % self._public_ip.replace('.', '-')

    @property
    def private_dns_name(self):
        return "ec2-%s.example.com" % self._private_ip.replace('.', '-')

    @property
    def public_dns_name(self):
        return "ec2-%s.example.com" % self._public_ip.replace('.', '-')

    def get_console_output(self):
        return MockConsoleOutput(self._console_output)


class MockReservation(object):
    def __init__(self):
        self.instances = []


class MockSecuritygroup(object):
    def __init__(self, name):
        self.name = name


class MockConnection(object):
    def __init__(self):
        self.reservations = []

    def get_all_instances(self):
        return self.reservations[:]


class MockRegion(object):
    def __init__(self):
        self.connection = MockConnection()

    def connect(self, aws_access_key_id=None, aws_secret_access_key=None):
        return self.connection


class EC2SetupTests(TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.ctrl = Controller(self.directory)
        self._boto_ec2_regions_mock = patch("boto.ec2.regions")
        self.boto_ec2_regions_mock = self._boto_ec2_regions_mock.start()

    def tearDown(self):
        self.boto_ec2_regions_mock = self.boto_ec2_regions_mock.stop()
        del self.boto_ec2_regions_mock
        shutil.rmtree(self.directory)
        del self.directory

    def _write_config(self, content):
        with open(os.path.join(self.directory, 'ploy.conf'), 'w') as f:
            f.write(content)

    def testNoRegionSet(self):
        self._write_config('\n'.join([
            '[ec2-master:default]',
            '[ec2-instance:foo]']))
        with patch('ploy_ec2.log') as LogMock:
            with self.assertRaises(SystemExit):
                self.ctrl(['./bin/ploy', 'status', 'foo'])
        LogMock.error.assert_called_with('No region set in ec2-instance:foo or ec2-master:default config')

    def testNoAWSCredentialsSet(self):
        self._write_config('\n'.join([
            '[ec2-master:default]',
            'region = eu-west-1',
            '[ec2-instance:foo]']))
        with patch('ploy_ec2.log') as LogMock:
            with self.assertRaises(SystemExit):
                self.ctrl(['./bin/ploy', 'status', 'foo'])
        LogMock.error.assert_called_with("You need to either set the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables or add the path to files containing them to the config. You can find the values at http://aws.amazon.com under 'Your Account'-'Security Credentials'.")

    def testAWSCredentialKeyFileMissing(self):
        key = os.path.join(self.directory, 'key')
        secret = os.path.join(self.directory, 'secret')
        self._write_config('\n'.join([
            '[ec2-master:default]',
            'region = eu-west-1',
            'access-key-id = %s' % key,
            'secret-access-key = %s' % secret,
            '[ec2-instance:foo]']))
        with patch('ploy_ec2.log') as LogMock:
            with self.assertRaises(SystemExit):
                self.ctrl(['./bin/ploy', 'status', 'foo'])
        LogMock.error.assert_called_with("The access-key-id file at '%s' doesn't exist.", key)

    def testAWSCredentialSecretFileMissing(self):
        key = os.path.join(self.directory, 'key')
        with open(key, 'w') as f:
            f.write('ham')
        secret = os.path.join(self.directory, 'secret')
        self._write_config('\n'.join([
            '[ec2-master:default]',
            'region = eu-west-1',
            'access-key-id = %s' % key,
            'secret-access-key = %s' % secret,
            '[ec2-instance:foo]']))
        with patch('ploy_ec2.log') as LogMock:
            with self.assertRaises(SystemExit):
                self.ctrl(['./bin/ploy', 'status', 'foo'])
        LogMock.error.assert_called_with("The secret-access-key file at '%s' doesn't exist.", secret)

    def testUnknownRegion(self):
        key = os.path.join(self.directory, 'key')
        with open(key, 'w') as f:
            f.write('ham')
        secret = os.path.join(self.directory, 'secret')
        with open(secret, 'w') as f:
            f.write('egg')
        self._write_config('\n'.join([
            '[ec2-master:default]',
            'region = eu-west-1',
            'access-key-id = %s' % key,
            'secret-access-key = %s' % secret,
            '[ec2-instance:foo]']))
        self.boto_ec2_regions_mock.return_value = []
        with patch('ploy_ec2.log') as LogMock:
            with self.assertRaises(SystemExit):
                self.ctrl(['./bin/ploy', 'status', 'foo'])
        LogMock.error.assert_called_with("Region '%s' not found in regions returned by EC2.", 'eu-west-1')

    def testAWSKeysInEnvironment(self):
        self._write_config('\n'.join([
            '[ec2-master:default]',
            'region = eu-west-1',
            '[ec2-instance:foo]']))
        region = MockRegion()
        region.name = 'eu-west-1'
        self.boto_ec2_regions_mock.return_value = [region]
        with patch('ploy_ec2.log') as LogMock:
            if 'AWS_ACCESS_KEY_ID' in os.environ:  # pragma: no cover
                del os.environ['AWS_ACCESS_KEY_ID']
            os.environ['AWS_ACCESS_KEY_ID'] = 'ham'
            if 'AWS_SECRET_ACCESS_KEY' in os.environ:  # pragma: no cover
                del os.environ['AWS_SECRET_ACCESS_KEY']
            os.environ['AWS_SECRET_ACCESS_KEY'] = 'egg'
            try:
                self.ctrl(['./bin/ploy', 'status', 'foo'])
            except SystemExit:  # pragma: no cover - only if something is wrong
                self.fail("SystemExit raised")
            finally:
                if 'AWS_ACCESS_KEY_ID' in os.environ:
                    del os.environ['AWS_ACCESS_KEY_ID']
                if 'AWS_SECRET_ACCESS_KEY' in os.environ:
                    del os.environ['AWS_SECRET_ACCESS_KEY']
        self.boto_ec2_regions_mock.assert_called_with(
            aws_access_key_id=None, aws_secret_access_key=None)
        LogMock.info.assert_called_with("Instance '%s' unavailable.", 'foo')


class EC2Tests(TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.ctrl = Controller(self.directory)
        self._boto_ec2_regions_mock = patch("boto.ec2.regions")
        self.boto_ec2_regions_mock = self._boto_ec2_regions_mock.start()
        try:  # pragma: no cover - we support both
            self._ssh_client_mock = patch("paramiko.SSHClient")
        except ImportError:  # pragma: no cover - we support both
            self._ssh_client_mock = patch("ssh.SSHClient")
        self.ssh_client_mock = self._ssh_client_mock.start()
        try:  # pragma: no cover - we support both
            self._ssh_config_mock = patch("paramiko.SSHConfig")
        except ImportError:  # pragma: no cover - we support both
            self._ssh_config_mock = patch("ssh.SSHConfig")
        self.ssh_config_mock = self._ssh_config_mock.start()
        self.ssh_config_mock().lookup.return_value = {}
        self._os_execvp_mock = patch("os.execvp")
        self.os_execvp_mock = self._os_execvp_mock.start()
        self.key = os.path.join(self.directory, 'key')
        with open(self.key, 'w') as f:
            f.write('ham')
        self.secret = os.path.join(self.directory, 'secret')
        with open(self.secret, 'w') as f:
            f.write('egg')

    def tearDown(self):
        self.os_execvp_mock = self._os_execvp_mock.stop()
        del self.os_execvp_mock
        self.ssh_config_mock = self._ssh_config_mock.stop()
        del self.ssh_config_mock
        self.ssh_client_mock = self._ssh_client_mock.stop()
        del self.ssh_client_mock
        self.boto_ec2_regions_mock = self.boto_ec2_regions_mock.stop()
        del self.boto_ec2_regions_mock
        shutil.rmtree(self.directory)
        del self.directory

    def _write_config(self, content):
        with open(os.path.join(self.directory, 'ploy.conf'), 'w') as f:
            f.write('\n'.join([
                '[ec2-master:default]',
                'region = eu-west-1',
                'access-key-id = %s' % self.key,
                'secret-access-key = %s' % self.secret]))
            f.write('\n')
            f.write(content)

    def testStatusOnUnavailableInstance(self):
        self._write_config('\n'.join([
            '[ec2-instance:foo]']))
        region = MockRegion()
        region.name = 'eu-west-1'
        self.boto_ec2_regions_mock.return_value = [region]
        with patch('ploy_ec2.log') as LogMock:
            try:
                self.ctrl(['./bin/ploy', 'status', 'foo'])
            except SystemExit:  # pragma: no cover - only if something is wrong
                self.fail("SystemExit raised")
        self.boto_ec2_regions_mock.assert_called_with(
            aws_access_key_id='ham', aws_secret_access_key='egg')
        LogMock.info.assert_called_with("Instance '%s' unavailable.", 'foo')

    def testNoSecurityGroupDefined(self):
        return NotImplemented

    def testStatus(self):
        self._write_config('\n'.join([
            '[ec2-instance:foo]',
            'securitygroups = foo']))
        region = MockRegion()
        region.name = 'eu-west-1'
        reservation = MockReservation()
        region.connection.reservations.append(reservation)
        instance = MockInstance()
        instance.id = 'i-12345678'
        instance.groups = [MockSecuritygroup('foo')]
        reservation.instances.append(instance)
        self.boto_ec2_regions_mock.return_value = [region]
        with patch('ploy_ec2.log') as LogMock:
            try:
                self.ctrl(['./bin/ploy', 'status', 'foo'])
            except SystemExit:  # pragma: no cover - only if something is wrong
                self.fail("SystemExit raised")
        self.boto_ec2_regions_mock.assert_called_with(
            aws_access_key_id='ham', aws_secret_access_key='egg')
        self.assertEquals(
            LogMock.info.call_args_list, [
                (("Instance '%s' (%s) available.", 'foo', instance.id), {}),
                (("Instance running.",), {}),
                (("Instances DNS name %s", 'ec2-257-1-2-3.example.com'), {}),
                (("Instances private DNS name %s", 'ec2-10-0-0-1.example.com'), {}),
                (("Instances public DNS name %s", 'ec2-257-1-2-3.example.com'), {})])

    # def testInstanceHasNoStatus(self):
    #     key = os.path.join(self.directory, 'key')
    #     with open(key, 'w') as f:
    #         f.write('ham')
    #     secret = os.path.join(self.directory, 'secret')
    #     with open(secret, 'w') as f:
    #         f.write('egg')
    #     self._write_config('\n'.join([
    #         '[ec2-master:default]',
    #         'region = eu-west-1',
    #         'access-key-id = %s' % key,
    #         'secret-access-key = %s' % secret,
    #         '[ec2-instance:foo]']))
    #     region = MockRegion()
    #     region.name = 'eu-west-1'
    #     self.boto_ec2_regions_mock.return_value = [region]
    #     with patch('sys.stderr') as StdErrMock:
    #         with self.assertRaises(SystemExit):
    #             self.ctrl(['./bin/ploy', 'status', 'foo'])
    #     import pdb; pdb.set_trace( )
    #     output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    #     self.assertIn("invalid choice: 'foo'", output)
    #
    # def testInstanceCantBeStarted(self):
    #     self._write_config('\n'.join([
    #         '[ec2-instance:foo]']))
    #     with patch('sys.stderr') as StdErrMock:
    #         with self.assertRaises(SystemExit):
    #             self.ctrl(['./bin/ploy', 'start', 'foo'])
    #     output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    #     self.assertIn("invalid choice: 'foo'", output)
    #
    # def testInstanceCantBeStopped(self):
    #     self._write_config('\n'.join([
    #         '[ec2-instance:foo]']))
    #     with patch('sys.stderr') as StdErrMock:
    #         with self.assertRaises(SystemExit):
    #             self.ctrl(['./bin/ploy', 'stop', 'foo'])
    #     output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    #     self.assertIn("invalid choice: 'foo'", output)
    #
    # def testInstanceCantBeTerminated(self):
    #     self._write_config('\n'.join([
    #         '[ec2-instance:foo]']))
    #     with patch('sys.stderr') as StdErrMock:
    #         with self.assertRaises(SystemExit):
    #             self.ctrl(['./bin/ploy', 'stop', 'foo'])
    #     output = "".join(x[0][0] for x in StdErrMock.write.call_args_list)
    #     self.assertIn("invalid choice: 'foo'", output)
    #
    # def testSSHWithNoHost(self):
    #     self._write_config('\n'.join([
    #         '[ec2-instance:foo]']))
    #     with patch('ploy.log') as LogMock:
    #         with self.assertRaises(SystemExit):
    #             self.ctrl(['./bin/ploy', 'ssh', 'foo'])
    #     self.assertEquals(
    #         LogMock.error.call_args_list, [
    #             (("Couldn't validate fingerprint for ssh connection.",), {}),
    #             (("No host set in config.",), {}),
    #             (('Is the server finished starting up?',), {})])
    #
    # def testSSHWithNoFingerprint(self):
    #     self._write_config('\n'.join([
    #         '[ec2-instance:foo]',
    #         'host = localhost']))
    #     with patch('ploy.log') as LogMock:
    #         with self.assertRaises(SystemExit):
    #             self.ctrl(['./bin/ploy', 'ssh', 'foo'])
    #     self.assertEquals(
    #         LogMock.error.call_args_list, [
    #             (("Couldn't validate fingerprint for ssh connection.",), {}),
    #             (("No fingerprint set in config.",), {}),
    #             (('Is the server finished starting up?',), {})])
    #
    # def testSSH(self):
    #     self._write_config('\n'.join([
    #         '[ec2-instance:foo]',
    #         'host = localhost',
    #         'fingerprint = foo']))
    #     try:
    #         self.ctrl(['./bin/ploy', 'ssh', 'foo'])
    #     except SystemExit:
    #         self.fail("SystemExit raised")
    #     known_hosts = os.path.join(self.directory, 'known_hosts')
    #     self.os_execvp_mock.assert_called_with(
    #         ['ssh', '-o', 'UserKnownHostsFile=%s' % known_hosts, '-l', 'root', 'localhost'])


def _write_config(directory, content):
    key = os.path.join(directory, 'key')
    with open(key, 'w') as f:
        f.write('ham')
    secret = os.path.join(directory, 'secret')
    with open(secret, 'w') as f:
        f.write('egg')
    with open(os.path.join(directory, 'ploy.conf'), 'w') as f:
        f.write('\n'.join([
            '[ec2-master:default]',
            'region = eu-west-1',
            'access-key-id = %s' % key,
            'secret-access-key = %s' % secret]))
        f.write('\n')
        f.write(content)


def test_instance_massagers():
    directory = tempfile.mkdtemp()
    ctrl = Controller(directory)
    ctrl.configfile = os.path.join(directory, 'ploy.conf')
    _write_config(directory, '\n'.join([
        '[instance:bar]',
        'master = default',
        'startup_script = startup.sh',
        '[ec2-instance:ham]']))
    massagers = ctrl.instances['bar'].config.massagers
    assert massagers != {}
    assert ctrl.instances['bar'].config == {
        'startup_script': {'path': os.path.join(directory, 'startup.sh')},
        'master': 'default'}


def test_get_fingerprints():
    from ploy_ec2 import get_fingerprints
    import textwrap
    data = textwrap.dedent("""
        ec2: -----BEGIN SSH HOST KEY FINGERPRINTS-----
        ec2: 2048 a6:7f:6a:a5:8a:7c:26:45:46:ca:d9:d9:8c:f2:64:27 /etc/ssh/ssh_host_key.pub
        ec2: 2048 b6:57:b7:52:4e:36:94:ab:9c:ec:a1:b3:56:71:80:e0 /etc/ssh/ssh_host_rsa_key.pub
        ec2: 1024 62:47:49:82:83:9a:d8:1d:b8:c6:8f:dd:4d:d8:9a:2e /etc/ssh/ssh_host_dsa_key.pub
        ec2: -----END SSH HOST KEY FINGERPRINTS-----
        """)
    result = get_fingerprints(data)
    assert result == [
        dict(keylen=1024, keytype='dsa', fingerprint='62:47:49:82:83:9a:d8:1d:b8:c6:8f:dd:4d:d8:9a:2e'),
        dict(keylen=2048, keytype='rsa1', fingerprint='a6:7f:6a:a5:8a:7c:26:45:46:ca:d9:d9:8c:f2:64:27'),
        dict(keylen=2048, keytype='rsa', fingerprint='b6:57:b7:52:4e:36:94:ab:9c:ec:a1:b3:56:71:80:e0')]

    data = textwrap.dedent("""
        -----BEGIN SSH HOST KEY FINGERPRINTS-----
        2048 2e:68:49:26:49:07:67:31:f1:33:92:18:09:c3:6a:ae /etc/ssh/ssh_host_rsa_key.pub (RSA)
        1024 4b:99:0e:4a:a4:3e:b4:e5:ef:42:5e:43:07:93:91:a0 /etc/ssh/ssh_host_dsa_key.pub (DSA)
        -----END SSH HOST KEY FINGERPRINTS-----
        """)
    result = get_fingerprints(data)
    assert result == [
        dict(keylen=2048, keytype='rsa', fingerprint='2e:68:49:26:49:07:67:31:f1:33:92:18:09:c3:6a:ae'),
        dict(keylen=1024, keytype='dsa', fingerprint='4b:99:0e:4a:a4:3e:b4:e5:ef:42:5e:43:07:93:91:a0')]

    data = textwrap.dedent("""
        ec2: #############################################################
        ec2: -----BEGIN SSH HOST KEY FINGERPRINTS-----
        ec2: 1024 7b:0d:a3:0d:9e:fc:f3:97:bb:a8:d2:1d:05:3f:d5:f9  root@ip-172-31-27-225 (DSA)
        ec2: 256 96:c6:3c:47:7b:11:eb:8a:ca:78:ed:20:d6:21:f2:b7  root@ip-172-31-27-225 (ECDSA)
        ec2: 256 56:0f:1a:4d:cc:66:0a:9e:90:d5:1d:98:3a:03:ef:b6  root@ip-172-31-27-225 (ED25519)
        ec2: 2048 b6:8a:43:51:72:af:49:88:a5:d6:c5:7f:3c:fd:91:70  root@ip-172-31-27-225 (RSA1)
        ec2: 2048 ef:85:3d:e6:ab:c4:18:88:81:63:08:0f:32:8a:9d:e0  root@ip-172-31-27-225 (RSA)
        ec2: -----END SSH HOST KEY FINGERPRINTS-----
        ec2: #############################################################
        """)
    result = get_fingerprints(data)
    assert result == [
        dict(keylen=256, keytype='ed25519', fingerprint='56:0f:1a:4d:cc:66:0a:9e:90:d5:1d:98:3a:03:ef:b6'),
        dict(keylen=1024, keytype='dsa', fingerprint='7b:0d:a3:0d:9e:fc:f3:97:bb:a8:d2:1d:05:3f:d5:f9'),
        dict(keylen=256, keytype='ecdsa', fingerprint='96:c6:3c:47:7b:11:eb:8a:ca:78:ed:20:d6:21:f2:b7'),
        dict(keylen=2048, keytype='rsa1', fingerprint='b6:8a:43:51:72:af:49:88:a5:d6:c5:7f:3c:fd:91:70'),
        dict(keylen=2048, keytype='rsa', fingerprint='ef:85:3d:e6:ab:c4:18:88:81:63:08:0f:32:8a:9d:e0')]

    data = textwrap.dedent("""
        Generating public/private rsa key pair.
        Your identification has been saved in /etc/ssh/ssh_host_rsa_key.
        Your public key has been saved in /etc/ssh/ssh_host_rsa_key.pub.
        The key fingerprint is:
        31:57:c4:d7:ee:34:9a:0d:f3:bb:89:39:5d:47:cd:73 root@ip-10-9-28-89
        The key's randomart image is:
        +--[ RSA 2048]----+
        |           oo  . |
        |           .. . .|
        |        o .  . o.|
        |         +   o oE|
        |        S     B++|
        |             o o+|
        |              . +|
        |             .oo.|
        |             o.o.|
        +-----------------+
        Generating public/private dsa key pair.
        Your identification has been saved in /etc/ssh/ssh_host_dsa_key.
        Your public key has been saved in /etc/ssh/ssh_host_dsa_key.pub.
        The key fingerprint is:
        da:01:9b:79:49:90:83:d6:df:6e:e6:75:34:2d:12:85 root@ip-10-9-28-89
        The key's randomart image is:
        +--[ DSA 1024]----+
        |     o..     o.  |
        |    o +.    E    |
        |   .  .o..   . . |
        |       *... . + .|
        |      + S.   o o |
        |       + .+ . .  |
        |      . .+ . .   |
        |          .      |
        |                 |
        +-----------------+
        Generating public/private ecdsa key pair.
        Your identification has been saved in /etc/ssh/ssh_host_ecdsa_key.
        Your public key has been saved in /etc/ssh/ssh_host_ecdsa_key.pub.
        The key fingerprint is:
        01:b7:73:92:41:4e:b2:f8:df:6a:72:7a:49:d7:4f:1d root@ip-10-9-28-89
        The key's randomart image is:
        +--[ECDSA  256]---+
        |      o.=        |
        |     . B +       |
        |    . . B .      |
        |     .   =     E |
        |      . S  .   ..|
        |       .... . . .|
        |       ..o.  o   |
        |      . =.    .  |
        |      .*.        |
        +-----------------+
        """)
    result = get_fingerprints(data)
    assert result == [
        dict(keylen=None, fingerprint='01:b7:73:92:41:4e:b2:f8:df:6a:72:7a:49:d7:4f:1d'),
        dict(keylen=None, fingerprint='31:57:c4:d7:ee:34:9a:0d:f3:bb:89:39:5d:47:cd:73'),
        dict(keylen=None, fingerprint='da:01:9b:79:49:90:83:d6:df:6e:e6:75:34:2d:12:85')]
