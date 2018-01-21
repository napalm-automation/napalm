"""Test confirm commit calls and results"""

from xml.etree import ElementTree as etree

from unittest.mock import patch, Mock

from napalm.junos import JunOSDriver


_COMMIT_PENDING = """
<commit-information>
  <commit-history>
    <sequence-number>0</sequence-number>
    <user>admin</user>
    <client>netconf</client>
    <date-time seconds="1509285719">2017-10-29 14:01:59 UTC</date-time>
    <comment>commit confirmed, rollback in 10mins</comment>
    <log>napalm_confirm_ffff</log>
  </commit-history>
  <commit-history>
    <sequence-number>2</sequence-number>
    <user>root</user>
    <client>other</client>
    <date-time seconds="1509284620">2017-10-29 13:43:40 UTC</date-time>
  </commit-history>
</commit-information>
"""

_COMMIT_NOT_PENDING = """
<commit-information>
  <commit-history>
    <sequence-number>0</sequence-number>
    <user>admin</user>
    <client>netconf</client>
    <date-time seconds="1509285774">2017-10-29 14:02:54 UTC</date-time>
  </commit-history>
  <commit-history>
    <sequence-number>1</sequence-number>
    <user>admin</user>
    <client>netconf</client>
    <date-time seconds="1509285719">2017-10-29 14:01:59 UTC</date-time>
    <comment>commit confirmed, rollback in 10mins</comment>
    <log>napalm_confirm_95850e80</log>
  </commit-history>
  <commit-history>
    <sequence-number>2</sequence-number>
    <user>root</user>
    <client>other</client>
    <date-time seconds="1509284620">2017-10-29 13:43:40 UTC</date-time>
  </commit-history>
</commit-information>
"""


@patch('napalm.junos.junos.uuid.uuid4', lambda: 'ffff-ffff-ffff-fff')
@patch('napalm.junos.junos.Device')
def test_junos_commit_confirm_and_pending(mocked_device):
    commits = Mock(return_value=etree.fromstring(_COMMIT_PENDING))
    commit_object = Mock()
    mocked_device.return_value.cu.commit = commit_object
    mocked_device.return_value.rpc.get_commit_information = commits
    j = JunOSDriver(username='someuser', password='somepass', hostname='foo')
    j.commit_config(confirmed=10, message='boo')
    commit_object.assert_called_with(
        comment='boo_napalm_confirm_ffff',
        confirm=10,
        ignore_warning=False
    )
    assert j.has_pending_commit_confirm
    j.commit_confirm()
    commit_object.assert_called_with(
        comment=None,
        confirm=None,
        ignore_warning=False
    )
    assert not j.has_pending_commit_confirm
    assert commits.called


@patch('napalm.junos.junos.Device')
def test_junos_commit_no_pending(mocked_device):
    commit_object = Mock()
    mocked_device.return_value.cu.commit = commit_object
    j = JunOSDriver(username='someuser', password='somepass', hostname='foo')
    j.commit_config(message='some message')
    commit_object.assert_called_with(
        comment='some message',
        confirm=None,
        ignore_warning=False
    )
    assert not j.has_pending_commit_confirm


@patch('napalm.junos.junos.Device')
def test_junos_no_pending_with_rpc_call(mocked_device):
    j = JunOSDriver(username='someuser', password='somepass', hostname='foo')
    commits = Mock(return_value=etree.fromstring(_COMMIT_NOT_PENDING))
    mocked_device.return_value.rpc.get_commit_information = commits
    j._pending_commit_string = 'ffff'
    assert not j.has_pending_commit_confirm
    assert commits.called
    

@patch('napalm.junos.junos.uuid.uuid4', lambda: 'ffff-ffff-ffff-fff')
@patch('napalm.junos.junos.Device')
def test_junos_revert_commit_confirm(mocked_device):
    commits = Mock(return_value=etree.fromstring(_COMMIT_PENDING))
    commit_object = Mock()
    mocked_device.return_value.cu.commit = commit_object
    mocked_device.return_value.rpc.get_commit_information = commits
    j = JunOSDriver(username='someuser', password='somepass', hostname='foo')
    j.commit_config(confirmed=10, message='boo')
    j.revert_commit_confirm()
    commit_object.assert_called_with(
        comment=None,
        confirm=None,
        ignore_warning=False
    )
    assert not j.has_pending_commit_confirm
