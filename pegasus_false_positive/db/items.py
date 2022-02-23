import pathlib
import plistlib

from peewee import Model, CharField, IntegerField, BlobField, AutoField, TimestampField, FloatField, CompositeKey, \
    BooleanField


class Files(Model):
    class Meta:
        db_table = 'Files'

    fileID = CharField(primary_key=True)
    domain = CharField()
    relativePath = CharField()
    flags = IntegerField()
    file = BlobField()

    @classmethod
    def full_path(cls, relative_path):
        obj = cls.get(cls.relativePath == relative_path)
        return pathlib.Path(obj.fileID[:2]) / obj.fileID

    @classmethod
    def get_file_attributes_by_relative_path(cls, relative_path):
        obj = cls.get_or_none(cls.relativePath == relative_path)
        if obj is not None:
            return plistlib.loads(obj.file, fmt=plistlib.FMT_BINARY)
        else:
            return None

    @classmethod
    def get_file_attributes_by_file_id(cls, file_id):
        obj = cls.get_or_none(cls.fileID == file_id)
        if obj is not None:
            return plistlib.loads(obj.file, fmt=plistlib.FMT_BINARY)
        else:
            return None

    @classmethod
    def get_last_file(cls):
        return cls.select(cls.file).get()


class Message(Model):
    class Meta:
        db_table = 'message'

    ROWID = IntegerField(primary_key=True)
    guid = CharField()
    text = CharField()
    replace = IntegerField()
    service_center = CharField()
    handle_id = IntegerField()
    subject = CharField()
    country = CharField()
    attributedBody = BlobField()
    version = IntegerField()
    type = IntegerField()
    service = CharField()
    account = CharField()
    account_guid = CharField()
    error = IntegerField()
    date = IntegerField()
    date_read = IntegerField()
    date_delivered = IntegerField()
    is_delivered = IntegerField()
    is_finished = IntegerField()
    is_emote = IntegerField()
    is_from_me = IntegerField()
    is_empty = IntegerField()
    is_delayed = IntegerField()
    is_auto_reply = IntegerField()
    is_prepared = IntegerField()
    is_read = IntegerField()
    is_system_message = IntegerField()
    is_sent = IntegerField()
    has_dd_results = IntegerField()
    is_service_message = IntegerField()
    is_forward = IntegerField()
    was_downgraded = IntegerField()
    is_archive = IntegerField()
    cache_has_attachments = IntegerField()
    cache_roomnames = CharField()
    was_data_detected = IntegerField()
    was_deduplicated = IntegerField()
    is_audio_message = IntegerField()
    is_played = IntegerField()
    date_played = IntegerField()
    item_type = IntegerField()
    other_handle = IntegerField()
    group_title = CharField()
    group_action_type = IntegerField()
    share_status = IntegerField()
    share_direction = IntegerField()
    is_expirable = IntegerField()
    expire_state = IntegerField()
    message_action_type = IntegerField()
    message_source = IntegerField()
    associated_message_guid = CharField()
    associated_message_type = IntegerField()
    balloon_bundle_id = CharField()
    payload_data = BlobField()
    expressive_send_style_id = CharField()
    associated_message_range_location = IntegerField()
    associated_message_range_length = IntegerField()
    time_expressive_send_played = IntegerField()
    message_summary_info = BlobField()
    ck_sync_state = IntegerField()
    ck_record_id = CharField()
    ck_record_change_tag = CharField()
    destination_caller_id = CharField()
    sr_ck_sync_state = IntegerField()
    sr_ck_record_id = CharField()
    sr_ck_record_change_tag = CharField()
    is_corrupt = IntegerField()
    reply_to_guid = CharField()
    sort_id = IntegerField()
    is_spam = IntegerField()
    has_unseen_mention = IntegerField()
    thread_originator_guid = CharField()
    thread_originator_part = CharField()

    @classmethod
    def get_last(cls):
        return cls.select().where(cls.is_from_me == 0).order_by(cls.ROWID.desc()).get()


class Chat(Model):
    class Meta:
        db_table = 'chat'

    ROWID = IntegerField(primary_key=True)
    guid = CharField()
    style = IntegerField()
    state = IntegerField()
    account_id = CharField()
    properties = BlobField()
    chat_identifier = CharField()
    service_name = CharField()
    room_name = CharField()
    account_login = CharField()
    is_archived = IntegerField()
    last_addressed_handle = CharField()
    display_name = CharField()
    group_id = CharField()
    is_filtered = IntegerField()
    successful_query = IntegerField()
    engram_id = CharField()
    server_change_token = CharField()
    ck_sync_state = IntegerField()
    original_group_id = CharField()
    last_read_message_timestamp = IntegerField()
    sr_server_change_token = CharField()
    sr_ck_sync_state = IntegerField()
    cloudkit_record_id = CharField()
    sr_cloudkit_record_id = CharField()
    last_addressed_sim_id = CharField()
    is_blackholed = IntegerField()

    @classmethod
    def get_last(cls):
        return cls.select().where(cls.service_name == "SMS").order_by(cls.ROWID.desc()).get()


class Handle(Model):
    class Meta:
        db_table = 'handle'

    ROWID = IntegerField(primary_key=True)
    id = CharField()
    country = CharField()
    service = CharField()
    uncanonicalized_id = CharField()
    person_centric_id = CharField()

    @classmethod
    def get_last(cls):
        return cls.select().where(cls.service.contains("SMS")).order_by(cls.ROWID.desc()).get()


class ChatHandleJoin(Model):
    class Meta:
        db_table = 'chat_handle_join'

    chat_id = IntegerField()
    handle_id = IntegerField()


class ChatMessageJoin(Model):
    class Meta:
        db_table = 'chat_message_join'

    chat_id = IntegerField()
    message_id = IntegerField()
    message_date = IntegerField()


class Urls(Model):
    class Meta:
        db_table = 'urls'

    id = IntegerField(primary_key=True)
    url = CharField()
    title = CharField()
    visit_count = IntegerField()
    typed_count = IntegerField()
    last_visit_time = IntegerField()
    hidden = IntegerField()

    @classmethod
    def get_last(cls):
        return cls.select().order_by(cls.id.desc()).get()


class HistoryItems(Model):
    class Meta:
        db_table = 'history_items'

    id = AutoField(primary_key=True)
    url = CharField()
    domain_expansion = CharField()
    visit_count = IntegerField()
    daily_visit_counts = BlobField()
    weekly_visit_counts = BlobField()
    autocomplete_triggers = BlobField()
    should_recompute_derived_visit_counts = IntegerField()
    visit_count_score = IntegerField()

    @classmethod
    def get_last(cls):
        return cls.select().order_by(cls.id.desc()).get()


class HistoryVisits(Model):
    class Meta:
        db_table = 'history_visits'

    id = AutoField(primary_key=True)
    history_item = IntegerField()
    visit_time = FloatField()
    title = CharField()
    load_successful = BooleanField()
    http_non_get = BooleanField()
    synthesized = BooleanField()
    redirect_source = IntegerField()
    redirect_destination = IntegerField()
    origin = IntegerField()
    generation = IntegerField()
    attributes = IntegerField()
    score = IntegerField()

    @classmethod
    def get_last(cls):
        return cls.select().order_by(cls.id.desc()).get()


class ZProcess(Model):
    class Meta:
        db_table = 'ZPROCESS'

    Z_PK = AutoField(primary_key=True)
    Z_ENT = IntegerField()
    Z_OPT = IntegerField()
    ZFIRSTTIMESTAMP = TimestampField()
    ZTIMESTAMP = TimestampField()
    ZBUNDLENAME = CharField()
    ZPROCNAME = CharField()

    @classmethod
    def get_last(cls):
        return cls.select().order_by(cls.Z_PK.desc()).get()

    @classmethod
    def get_first_process(cls, timestamp):
        return cls.select().where(cls.ZFIRSTTIMESTAMP > timestamp).order_by(cls.Z_PK).get()


class ZLiveUsage(Model):
    class Meta:
        db_table = 'ZLIVEUSAGE'

    Z_PK = AutoField(primary_key=True)
    Z_ENT = IntegerField()
    Z_OPT = IntegerField()
    ZKIND = IntegerField()
    ZMETADATA = IntegerField()
    ZTAG = IntegerField()
    ZHASPROCESS = IntegerField()
    ZBILLCYCLEEND = TimestampField()
    ZTIMESTAMP = TimestampField()
    ZWIFIIN = FloatField()
    ZWIFIOUT = FloatField()
    ZWWANIN = FloatField()
    ZWWANOUT = FloatField()

    @classmethod
    def get_last(cls):
        return cls.select().order_by(cls.Z_PK.desc()).get()

    @classmethod
    def get_first_zlive(cls, timestamp):
        return cls.select().where(cls.ZTIMESTAMP > timestamp).order_by(cls.Z_PK).get()


class Access(Model):
    class Meta:
        db_table = 'access'
        primary_key = CompositeKey('service', 'client', 'client_type', 'indirect_object_identifier_type')

    service = CharField()
    client = CharField()
    client_type = IntegerField()
    auth_value = IntegerField()
    auth_reason = IntegerField()
    auth_version = IntegerField()
    csreq = BlobField()
    policy_id = IntegerField()
    indirect_object_identifier_type = IntegerField()
    indirect_object_identifier = CharField()
    indirect_object_code_identity = BlobField()
    flags = IntegerField()
    last_modified = IntegerField()


class Tabs(Model):
    class Meta:
        db_table = 'tabs'

    id = AutoField(primary_key=True)
    uuid = CharField()
    title = CharField()
    url = CharField()
    user_visible_url = CharField()
    order_index = IntegerField()
    last_viewed_time = FloatField()
    readinglist_bookmark_id = IntegerField()
    opened_from_link = BooleanField()
    showing_reader = BooleanField()
    reader_view_top_scroll_offset = IntegerField()
    private_browsing = BooleanField()
    displaying_standalone_image = BooleanField()
    browser_window_uuid = CharField()
    browser_window_id = IntegerField()

    @classmethod
    def get_by_order_index(cls):
        return cls.select().order_by(cls.order_index).get()

    @classmethod
    def update_order_index(cls, order_index):
        return cls.update(order_index=order_index + 1).where(cls.order_index >= order_index).execute()


class TabSession(Model):
    class Meta:
        db_table = 'tab_sessions'

    id = AutoField(primary_key=True)
    tab_uuid = CharField()
    session_data = BlobField()
    uncompressed_session_data_size = IntegerField()

    @classmethod
    def update_session_data(cls, order_index):
        return cls.update(order_index=order_index + 1).where(cls.order_index >= order_index).execute()


class BrowserWindows(Model):
    class Meta:
        db_table = 'browser_windows'

    id = AutoField(primary_key=True)
    uuid = CharField()
    type = IntegerField()
    active_document_index = IntegerField()
    active_private_document_index = IntegerField()
    active_document_is_valid = BooleanField()
    tab_state_successfully_loaded = BooleanField()
    legacy_plist_file_version = IntegerField()
    scene_ID = CharField()

    @classmethod
    def get_last(cls):
        return cls.select().order_by(cls.id.desc()).get_or_none()


class IconMapping(Model):
    class Meta:
        db_table = 'icon_mapping'

    id = AutoField(primary_key=True)
    page_url = CharField()
    type = IntegerField()
    icon_id = IntegerField()

    @classmethod
    def get_last(cls):
        return cls.select().order_by(cls.id.desc()).get()


class Favicons(Model):
    class Meta:
        db_table = 'favicons'

    id = AutoField(primary_key=True)
    url = CharField()
    icon_type = IntegerField()

    @classmethod
    def get_last(cls):
        return cls.select().order_by(cls.id.desc()).get()


class FaviconBitmaps(Model):
    class Meta:
        db_table = 'favicon_bitmaps'

    id = AutoField(primary_key=True)
    icon_id = IntegerField()
    last_updated = IntegerField()
    image_data = BlobField()
    width = IntegerField()
    height = IntegerField()
    last_requested = IntegerField()

    @classmethod
    def get_last(cls):
        return cls.select().order_by(cls.id.desc()).get()