from datetime import datetime

from .utils import get_from_xml, xml_escape
from .enroll import generate_enroll_mail

XML_HEADER = """<?xml version="1.0" encoding="utf-8"?><!DOCTYPE ActiveSync PUBLIC "-//MICROSOFT//DTD ActiveSync//EN" "http://www.microsoft.com/">"""


def OnHTTPOptions() -> dict:
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
        "Public": "OPTIONS,POST"
    }


def OnWrongPolicy(cmd: str) -> str:
    if cmd == "sync":
        return XML_HEADER + """
<Sync xmlns="AirSync:">
  <Status>144</Status>
</Sync>
"""
    elif cmd == "foldersync":
        return XML_HEADER + """
<FolderSync xmlns="FolderHierarchy:">
  <Status>144</Status>
</FolderSync>
"""
    elif cmd == "getitemestimate":
        return XML_HEADER + """
<GetItemEstimate xmlns="GetItemEstimate:">
  <Status>144</Status>
</GetItemEstimate>
"""
    # Fallback if needed
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

    if policy_key is None or policy_key == 0 and policy_status is None:
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

    if policy_key == 0 and policy_status == 1:
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
    elif sync_key == 1337:
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
        collectionId = get_from_xml("CollectionId", xml) or "inbox"
    except Exception:
        collectionId = "inbox"

    if collectionId == "fakeinbox":
        estimate = 1
    else:
        estimate = 0

    return XML_HEADER + f"""
<GetItemEstimate xmlns="GetItemEstimate:">
  <Response>
    <Status>1</Status>
    <Collection>
      <CollectionId>{collectionId}</CollectionId>
      <Estimate>{estimate}</Estimate>
    </Collection>
  </Response>
</GetItemEstimate>
"""


def OnSync(xml: str, claims: dict, deviceId: str, deviceType: str, protocol_version: str, ip: str, ua: str) -> str:
    try:
        sync_key = int(get_from_xml("SyncKey", xml))
    except Exception:
        sync_key = 0

    try:
        collectionId = get_from_xml("CollectionId", xml)
    except Exception:
        collectionId = "inbox"

    # No messages in Drafts/Trash/Sent
    if collectionId in ("fakedrafts", "faketrash", "fakesent"):
        return XML_HEADER + f"""
<Sync xmlns="AirSync:">
  <Collections>
    <Collection>
      <Class>Email</Class>
      <SyncKey>{sync_key if sync_key > 0 else 1}</SyncKey>
      <CollectionId>{collectionId}</CollectionId>
      <Status>1</Status>
      <Commands/>
    </Collection>
  </Collections>
</Sync>
"""

    # Invalid collection
    if collectionId != "fakeinbox":
        return XML_HEADER + """
<Sync xmlns="AirSync:">
  <Status>12</Status>
</Sync>
"""

    c_email = claims["email"]
    c_username = claims["user"]["SamAccountName"]
    c_name = claims["name"]

    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    plain, html = generate_enroll_mail(
        c_email,
        c_name,
        deviceId, deviceType,
        protocol_version, ip, ua
    )
    plain = xml_escape(plain)
    html = xml_escape(html)

    if sync_key < 1000:
        return XML_HEADER + f"""
<Sync xmlns:Email="Email:" xmlns:AirSyncBase="AirSyncBase:" xmlns="AirSync:">
  <Collections>
    <Collection>
      <Class>Email</Class>
      <SyncKey>{sync_key+1}</SyncKey>
      <CollectionId>{collectionId}</CollectionId>
      <Status>1</Status>
      <Commands>
        <Add>
          <ServerId>fakemail</ServerId>
          <ApplicationData>
            <Email:Subject>*** ACTION REQUIRED ***🐰</Email:Subject>
            <Email:To>{c_email}</Email:To>
            <Email:From>"uniIT Exchange ActiveSync MFA🥚" &lt;noreply@uni-graz.at&gt;</Email:From>
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
              <AirSyncBase:EstimatedDataSize>{len(html)}</AirSyncBase:EstimatedDataSize>
              <AirSyncBase:Data>{html}</AirSyncBase:Data>
            </AirSyncBase:Body>
            <Email:Body>{plain}</Email:Body>
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
      <CollectionId>{collectionId}</CollectionId>
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
