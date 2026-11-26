from __future__ import annotations

from datetime import datetime, timezone

from .config import Config, get_config
from .enroll import generate_enroll_mail
from .utils import get_from_xml, xml_escape

XML_HEADER = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<!DOCTYPE ActiveSync PUBLIC "-//MICROSOFT//DTD ActiveSync//EN" "http://www.microsoft.com/">'
)


def OnHTTPOptions() -> dict[str, str]:
    return {
        "MS-Server-ActiveSync": "15.1",
        "MS-ASProtocolVersions": "2.0,2.1,2.5,12.0,12.1,14.0,14.1,16.0,16.1",
        "MS-ASProtocolCommands": (
            "Sync,SendMail,SmartForward,SmartReply,GetAttachment,GetHierarchy,"
            "CreateCollection,DeleteCollection,MoveCollection,FolderSync,FolderCreate,"
            "FolderDelete,FolderUpdate,MoveItems,GetItemEstimate,MeetingResponse,Search,"
            "Settings,Ping,ItemOperations,Provision,ResolveRecipients,ValidateCert,Find"
        ),
        "Allow": "OPTIONS,POST",
        "Public": "OPTIONS,POST",
    }


def OnWrongPolicy(cmd: str) -> str:
    if cmd == "sync":
        return XML_HEADER + """
<Sync xmlns="AirSync:">
  <Status>144</Status>
</Sync>
"""
    if cmd == "foldersync":
        return XML_HEADER + """
<FolderSync xmlns="FolderHierarchy:">
  <Status>144</Status>
</FolderSync>
"""
    if cmd == "getitemestimate":
        return XML_HEADER + """
<GetItemEstimate xmlns="GetItemEstimate:">
  <Status>144</Status>
</GetItemEstimate>
"""
    return XML_HEADER


def OnProvision(xml: str) -> str:
    try:
        policy_key = int(get_from_xml("PolicyKey", xml))
    except Exception:
        policy_key = None

    try:
        policy_status = int(get_from_xml("Status", xml))
    except Exception:
        policy_status = None

    if policy_key is None or (policy_key == 0 and policy_status is None):
        return XML_HEADER + """
<Provision xmlns="Provision:">
  <Status>1</Status>
  <Policies>
    <Policy>
      <PolicyType>MS-EAS-Provisioning-WBXML</PolicyType>
      <Status>1</Status>
      <PolicyKey>0</PolicyKey>
      <Data>
        <EASProvisionDoc>
          <DevicePasswordEnabled>0</DevicePasswordEnabled>
        </EASProvisionDoc>
      </Data>
    </Policy>
  </Policies>
</Provision>
"""

    return XML_HEADER + """
<Provision xmlns="Provision:">
  <Status>1</Status>
  <Policies>
    <Policy>
      <PolicyType>MS-EAS-Provisioning-WBXML</PolicyType>
      <Status>1</Status>
      <PolicyKey>1337</PolicyKey>
    </Policy>
  </Policies>
</Provision>
"""


def OnSettings() -> str:
    return XML_HEADER + """
<Settings xmlns="Settings:">
  <Status>1</Status>
</Settings>
"""


def OnFolderSync(xml: str) -> str:
    try:
        sync_key = int(get_from_xml("SyncKey", xml))
    except Exception:
        sync_key = 0

    if sync_key == 0:
        return XML_HEADER + """
<FolderSync xmlns="FolderHierarchy:">
  <Status>1</Status>
  <SyncKey>1337</SyncKey>
  <Changes>
  <Count>4</Count>
    <Add>
      <ServerId>fakeinbox</ServerId>
      <ParentId>0</ParentId>
      <DisplayName>Inbox</DisplayName>
      <Type>2</Type>
    </Add>
    <Add>
      <ServerId>fakedrafts</ServerId>
      <ParentId>0</ParentId>
      <DisplayName>Drafts</DisplayName>
      <Type>3</Type>
    </Add>
    <Add>
      <ServerId>faketrash</ServerId>
      <ParentId>0</ParentId>
      <DisplayName>Trash</DisplayName>
      <Type>4</Type>
    </Add>
    <Add>
      <ServerId>fakesent</ServerId>
      <ParentId>0</ParentId>
      <DisplayName>Sent Items</DisplayName>
      <Type>5</Type>
    </Add>
  </Changes>
</FolderSync>
"""
    if sync_key == 1337:
        return XML_HEADER + f"""
<FolderSync xmlns="FolderHierarchy:">
  <Status>1</Status>
  <SyncKey>{sync_key}</SyncKey>
</FolderSync>
"""
    return XML_HEADER + f"""
<FolderSync xmlns="FolderHierarchy:">
  <Status>9</Status>
  <SyncKey>{sync_key}</SyncKey>
</FolderSync>
"""


def OnGetItemEstimate(xml: str) -> str:
    try:
        collection_id = get_from_xml("CollectionId", xml) or "inbox"
    except Exception:
        collection_id = "inbox"

    estimate = 1 if collection_id == "fakeinbox" else 0
    safe_collection_id = xml_escape(collection_id)

    return XML_HEADER + f"""
<GetItemEstimate xmlns="GetItemEstimate:">
  <Response>
    <Status>1</Status>
    <Collection>
      <CollectionId>{safe_collection_id}</CollectionId>
      <Estimate>{estimate}</Estimate>
    </Collection>
  </Response>
</GetItemEstimate>
"""


def OnSync(
    xml: str,
    subject: str,
    email: str,
    name: str,
    device_id: str,
    device_type: str,
    protocol_version: str,
    ip: str,
    ua: str,
    config: Config | None = None,
) -> str:
    cfg = config or get_config()

    try:
        sync_key = int(get_from_xml("SyncKey", xml))
    except Exception:
        sync_key = 0

    try:
        collection_id = get_from_xml("CollectionId", xml) or "inbox"
    except Exception:
        collection_id = "inbox"

    safe_collection_id = xml_escape(collection_id)

    # No messages in Drafts/Trash/Sent
    if collection_id in ("fakedrafts", "faketrash", "fakesent"):
        return XML_HEADER + f"""
<Sync xmlns="AirSync:">
  <Collections>
    <Collection>
      <Class>Email</Class>
      <SyncKey>{sync_key if sync_key > 0 else 1}</SyncKey>
      <CollectionId>{safe_collection_id}</CollectionId>
      <Status>1</Status>
      <Commands/>
    </Collection>
  </Collections>
</Sync>
"""

    # Invalid collection
    if collection_id != "fakeinbox":
        return XML_HEADER + """
<Sync xmlns="AirSync:">
  <Status>12</Status>
</Sync>
"""

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    plain, html_body = generate_enroll_mail(
        subject=subject,
        email=email,
        name=name,
        device_id=device_id,
        device_type=device_type,
        protocol_version=protocol_version,
        ip=ip,
        ua=ua,
        config=cfg,
    )
    plain_xml = xml_escape(plain)
    html_xml = xml_escape(html_body)
    safe_email = xml_escape(email)
    safe_subject = xml_escape(cfg.mail.subject)
    safe_from = xml_escape(f'"{cfg.mail.from_name}" <{cfg.mail.from_address}>')

    if sync_key < 1000:
        return XML_HEADER + f"""
<Sync xmlns:Email="Email:" xmlns:AirSyncBase="AirSyncBase:" xmlns="AirSync:">
  <Collections>
    <Collection>
      <Class>Email</Class>
      <SyncKey>{sync_key + 1}</SyncKey>
      <CollectionId>{safe_collection_id}</CollectionId>
      <Status>1</Status>
      <Commands>
        <Add>
          <ServerId>fakemail</ServerId>
          <ApplicationData>
            <Email:Subject>{safe_subject}</Email:Subject>
            <Email:To>{safe_email}</Email:To>
            <Email:From>{safe_from}</Email:From>
            <Email:DateReceived>{now}</Email:DateReceived>
            <Email:Read>0</Email:Read>
            <Email:Importance>2</Email:Importance>
            <Email:Flag>
              <Email:FlagStatus>2</Email:FlagStatus>
              <Email:FlagType>FollowUp</Email:FlagType>
            </Email:Flag>
            <AirSyncBase:Body>
              <AirSyncBase:Type>2</AirSyncBase:Type>
              <AirSyncBase:Truncated>0</AirSyncBase:Truncated>
              <AirSyncBase:EstimatedDataSize>{len(html_body.encode("utf-8"))}</AirSyncBase:EstimatedDataSize>
              <AirSyncBase:Data>{html_xml}</AirSyncBase:Data>
            </AirSyncBase:Body>
            <Email:Body>{plain_xml}</Email:Body>
          </ApplicationData>
        </Add>
      </Commands>
    </Collection>
  </Collections>
</Sync>
"""

    return XML_HEADER + f"""
<Sync xmlns="AirSync:">
  <Collections>
    <Collection>
      <SyncKey>{sync_key}</SyncKey>
      <CollectionId>{safe_collection_id}</CollectionId>
      <Status>3</Status>
    </Collection>
  </Collections>
</Sync>
"""


def OnMoveItems() -> str:
    return XML_HEADER + """
<MoveItems xmlns="Move:">
  <Status>1</Status>
  <Response>
    <SrcMsgId>fakemail</SrcMsgId>
    <Status>5</Status>
    <DstMsgId>fakemail</DstMsgId>
  </Response>
</MoveItems>
"""
